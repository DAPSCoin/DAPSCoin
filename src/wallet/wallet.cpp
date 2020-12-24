// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2018 The PIVX developers
// Copyright (c) 2018-2020 The DAPS Project developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "wallet/wallet.h"

#include "base58.h"
#include "checkpoints.h"
#include "coincontrol.h"
#include "kernel.h"
#include "masternode-budget.h"
#include "net.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "script/sign.h"
#include "swifttx.h"
#include "timedata.h"
#include "util.h"
#include "utilmoneystr.h"

#include "secp256k1.h"
#include <assert.h>
#include <boost/algorithm/string.hpp>

#include "ecdhutil.h"
#include "obfuscation.h"
#include "secp256k1_bulletproofs.h"
#include "secp256k1_commitment.h"
#include "secp256k1_generator.h"
#include "txdb.h"
#include <boost/algorithm/string/replace.hpp>
#include <boost/filesystem/operations.hpp>
#include <boost/thread.hpp>
#include "masternodeconfig.h"


using namespace std;


/**
 * Settings
 */
CFeeRate payTxFee(DEFAULT_TRANSACTION_FEE);
CAmount maxTxFee = DEFAULT_TRANSACTION_MAXFEE;
unsigned int nTxConfirmTarget = 1;
bool bSpendZeroConfChange = true;
bool bdisableSystemnotifications = false; // Those bubbles can be annoying and slow down the UI when you get lots of trx
bool fSendFreeTransactions = false;
bool fPayAtLeastCustomFee = true;
int64_t nStartupTime = GetTime();
int64_t nReserveBalance = 0;

#include "uint256.h"

//Elliptic Curve Diffie Helman: encodes and decodes the amount b and mask a
void ecdhEncode(unsigned char* unmasked, unsigned char* amount, const unsigned char* sharedSec, int size)
{
    uint256 sharedSec1 = Hash(sharedSec, sharedSec + size);
    uint256 sharedSec2 = Hash(sharedSec1.begin(), sharedSec1.end());

    for (int i = 0; i < 32; i++) {
        unmasked[i] ^= *(sharedSec1.begin() + i);
    }
    unsigned char temp[32];
    memcpy(temp, amount, 32);
    for (int i = 0; i < 32; i++) {
        amount[i] = temp[i % 8] ^ *(sharedSec2.begin() + i);
    }
}
void ecdhDecode(unsigned char* masked, unsigned char* amount, const unsigned char* sharedSec, int size)
{
    uint256 sharedSec1 = Hash(sharedSec, sharedSec + size);
    uint256 sharedSec2 = Hash(sharedSec1.begin(), sharedSec1.end());

    for (int i = 0; i < 32; i++) {
        masked[i] ^= *(sharedSec1.begin() + i);
    }

    unsigned char temp[32];
    memcpy(temp, amount, 32);
    memset(amount, 0, 8);
    for (int i = 0; i < 32; i++) {
        amount[i] = temp[i % 8] ^ *(sharedSec2.begin() + i);
    }
}

static std::string ValueFromAmountToString(const CAmount &amount) {
    bool sign = amount < 0;
    int64_t n_abs = (sign ? -amount : amount);
    int64_t quotient = n_abs / COIN;
    int64_t remainder = n_abs % COIN;
    std::string ret(strprintf("%s%d.%08d", sign ? "-" : "", quotient, remainder));
    return ret;
}

void ECDHInfo::ComputeSharedSec(const CKey& priv, const CPubKey& pubKey, CPubKey& sharedSec)
{
    sharedSec.Set(pubKey.begin(), pubKey.end());
    unsigned char temp[65];
    memcpy(temp, sharedSec.begin(), sharedSec.size());
    if (!secp256k1_ec_pubkey_tweak_mul(temp, sharedSec.size(), priv.begin()))
        throw runtime_error("Cannot compute EC multiplication: secp256k1_ec_pubkey_tweak_mul");
    sharedSec.Set(temp, temp + 33);
}

void ECDHInfo::Encode(const CKey& mask, const CAmount& amount, const CPubKey& sharedSec, uint256& encodedMask, uint256& encodedAmount)
{
    memcpy(encodedMask.begin(), mask.begin(), 32);
    memcpy(encodedAmount.begin(), &amount, 32);
    ecdhEncode(encodedMask.begin(), encodedAmount.begin(), sharedSec.begin(), sharedSec.size());
}

void ECDHInfo::Decode(unsigned char* encodedMask, unsigned char* encodedAmount, const CPubKey& sharedSec, CKey& decodedMask, CAmount& decodedAmount)
{
    unsigned char tempAmount[32], tempDecoded[32];
    memcpy(tempDecoded, encodedMask, 32);
    decodedMask.Set(tempDecoded, tempDecoded + 32, 32);
    memcpy(tempAmount, encodedAmount, 32);
    memcpy(tempDecoded, decodedMask.begin(), 32);
    ecdhDecode(tempDecoded, tempAmount, sharedSec.begin(), sharedSec.size());
    memcpy(&decodedAmount, tempAmount, 8);

    decodedMask.Set(tempDecoded, tempDecoded + 32, true);
    memcpy(&decodedAmount, tempAmount, 8);
}


/**
 * Fees smaller than this (in duffs) are considered zero fee (for transaction creation)
 * We are ~100 times smaller then bitcoin now (2015-06-23), set minTxFee 10 times higher
 * so it's still 10 times lower comparing to bitcoin.
 * Override with -mintxfee
 */
CFeeRate CWallet::minTxFee = CFeeRate(10000);

/** @defgroup mapWallet
 *
 * @{
 */

struct CompareValueOnly {
    bool operator()(const pair<CAmount, pair<const CWalletTx*, unsigned int> >& t1,
        const pair<CAmount, pair<const CWalletTx*, unsigned int> >& t2) const
    {
        return t1.first < t2.first;
    }
};

std::string COutput::ToString() const
{
    return strprintf("COutput(%s, %d, %d) [%s]", tx->GetHash().ToString(), i, nDepth, FormatMoney(tx->vout[i].nValue));
}

const CWalletTx* CWallet::GetWalletTx(const uint256& hash) const
{
    LOCK(cs_wallet);
    std::map<uint256, CWalletTx>::const_iterator it = mapWallet.find(hash);
    if (it == mapWallet.end())
        return NULL;
    return &(it->second);
}

std::vector<CWalletTx> CWallet::getWalletTxs()
{
    LOCK(cs_wallet);
    std::vector<CWalletTx> result;
    result.reserve(mapWallet.size());
    for (const auto& entry : mapWallet) {
        result.emplace_back(entry.second);
    }
    return result;
}

bool CWallet::checkPassPhraseRule(const char* pass)
{
    bool upper = false;
    bool lower = false;
    bool digit = false;
    bool symbol = false;
    std::string passphrase(pass);
    for (int i = 0; i < passphrase.size(); i++) {
        if (isupper(passphrase[i])) {
            upper = true;
            continue;
        } else if (islower(passphrase[i])) {
            lower = true;
            continue;
        } else if (isdigit(passphrase[i])) {
            digit = true;
            continue;
        } else if (!symbol) {
            symbol = true;
            continue;
        }

        if (upper && lower && digit && symbol)
            break;
    }

    return upper && lower && digit && symbol;
}
CPubKey CWallet::GenerateNewKey()
{
    AssertLockHeld(cs_wallet);                                 // mapKeyMetadata
    bool fCompressed = CanSupportFeature(FEATURE_COMPRPUBKEY); // default to compressed public keys if we want 0.6.0 wallets

    CKey secret;
    secret.MakeNewKey(fCompressed);

    // Compressed public keys were introduced in version 0.6.0
    if (fCompressed)
        SetMinVersion(FEATURE_COMPRPUBKEY);
    CPubKey pubkey = secret.GetPubKey();
    assert(secret.VerifyPubKey(pubkey));

    // Create new metadata
    int64_t nCreationTime = GetTime();
    mapKeyMetadata[pubkey.GetID()] = CKeyMetadata(nCreationTime);
    if (!nTimeFirstKey || nCreationTime < nTimeFirstKey)
        nTimeFirstKey = nCreationTime;

    if (!AddKeyPubKey(secret, pubkey))
        throw std::runtime_error("CWallet::GenerateNewKey() : AddKey failed");
    return pubkey;
}

bool CWallet::AddKeyPubKey(const CKey& secret, const CPubKey& pubkey)
{
    AssertLockHeld(cs_wallet); // mapKeyMetadata
    if (!CCryptoKeyStore::AddKeyPubKey(secret, pubkey))
        return false;

    // check if we need to remove from watch-only
    CScript script;
    script = GetScriptForDestination(pubkey);
    if (HaveWatchOnly(script))
        RemoveWatchOnly(script);

    if (!fFileBacked)
        return true;
    if (!IsCrypted()) {
        return CWalletDB(strWalletFile).WriteKey(pubkey, secret.GetPrivKey(), mapKeyMetadata[pubkey.GetID()]);
    }
    return true;
}

bool CWallet::SetHDChain(const CHDChain& chain, bool memonly)
{
    LOCK(cs_wallet);

    if (!CCryptoKeyStore::SetHDChain(chain))
        return false;

    if (!memonly && !CWalletDB(strWalletFile).WriteHDChain(chain))
        throw std::runtime_error(std::string(__func__) + ": WriteHDChain failed");

    return true;
}

bool CWallet::SetCryptedHDChain(const CHDChain& chain, bool memonly)
{
    LOCK(cs_wallet);

    if (!CCryptoKeyStore::SetCryptedHDChain(chain))
        return false;

    if (!memonly) {
        if (!fFileBacked)
            return false;
        if (pwalletdbEncryption) {
            if (!pwalletdbEncryption->WriteCryptedHDChain(chain))
                throw std::runtime_error(std::string(__func__) + ": WriteCryptedHDChain failed");
        } else {
            if (!CWalletDB(strWalletFile).WriteCryptedHDChain(chain))
                throw std::runtime_error(std::string(__func__) + ": WriteCryptedHDChain failed");
        }
    }

    return true;
}

bool CWallet::GetDecryptedHDChain(CHDChain& hdChainRet)
{
    LOCK(cs_wallet);

    CHDChain hdChainTmp;

    if (!GetHDChain(hdChainTmp)) {
        return false;
    }

    if (!DecryptHDChain(hdChainTmp))
        return false;

    // make sure seed matches this chain
    if (hdChainTmp.GetID() != hdChainTmp.GetSeedHash())
        return false;

    hdChainRet = hdChainTmp;

    return true;
}

void CWallet::GenerateNewHDChain(std::string* phrase)
{
    CHDChain newHdChain;

    // NOTE: empty mnemonic means "generate a new one for me"
    std::string strMnemonic = GetArg("-mnemonic", "");
    // NOTE: default mnemonic passphrase is an empty string
    std::string strMnemonicPassphrase = GetArg("-mnemonicpassphrase", "");

    if (phrase) {
        strMnemonic = *phrase;
        strMnemonicPassphrase = "";
    }

    SecureVector vchMnemonic(strMnemonic.begin(), strMnemonic.end());
    SecureVector vchMnemonicPassphrase(strMnemonicPassphrase.begin(), strMnemonicPassphrase.end());

    if (!newHdChain.SetMnemonic(vchMnemonic, vchMnemonicPassphrase, true))
        throw std::runtime_error(std::string(__func__) + ": SetMnemonic failed");

    if (!SetHDChain(newHdChain, false))
        throw std::runtime_error(std::string(__func__) + ": SetHDChain failed");

    if (phrase) {
        CreatePrivacyAccount(true);
    }
}

bool CWallet::IsHDEnabled()
{
    CHDChain hdChainCurrent;
    return GetHDChain(hdChainCurrent);
}

bool CWallet::WriteStakingStatus(bool status)
{
    walletStakingInProgress = true;
    return CWalletDB(strWalletFile).WriteStakingStatus(status);
}
bool CWallet::ReadStakingStatus()
{
    return CWalletDB(strWalletFile).ReadStakingStatus();
}

bool CWallet::Write2FA(bool status)
{
    return CWalletDB(strWalletFile).Write2FA(status);
}
bool CWallet::Read2FA()
{
    return CWalletDB(strWalletFile).Read2FA();
}

bool CWallet::Write2FASecret(std::string secret)
{
    return CWalletDB(strWalletFile).Write2FASecret(secret);
}
std::string CWallet::Read2FASecret()
{
    return CWalletDB(strWalletFile).Read2FASecret();
}

bool CWallet::Write2FAPeriod(int period)
{
    return CWalletDB(strWalletFile).Write2FAPeriod(period);
}
int CWallet::Read2FAPeriod()
{
    return CWalletDB(strWalletFile).Read2FAPeriod();
}

bool CWallet::Write2FALastTime(uint64_t lastTime)
{
    return CWalletDB(strWalletFile).Write2FALastTime(lastTime);
}
uint64_t CWallet::Read2FALastTime()
{
    return CWalletDB(strWalletFile).Read2FALastTime();
}

bool CWallet::AddCryptedKey(const CPubKey& vchPubKey,
    const vector<unsigned char>& vchCryptedSecret)
{
    if (!CCryptoKeyStore::AddCryptedKey(vchPubKey, vchCryptedSecret))
        return false;
    if (!fFileBacked)
        return true;
    {
        LOCK(cs_wallet);
        if (pwalletdbEncryption)
            return pwalletdbEncryption->WriteCryptedKey(vchPubKey,
                vchCryptedSecret,
                mapKeyMetadata[vchPubKey.GetID()]);
        else
            return CWalletDB(strWalletFile).WriteCryptedKey(vchPubKey, vchCryptedSecret, mapKeyMetadata[vchPubKey.GetID()]);
    }
    return false;
}

bool CWallet::LoadKeyMetadata(const CPubKey& pubkey, const CKeyMetadata& meta)
{
    AssertLockHeld(cs_wallet); // mapKeyMetadata
    if (meta.nCreateTime && (!nTimeFirstKey || meta.nCreateTime < nTimeFirstKey))
        nTimeFirstKey = meta.nCreateTime;

    mapKeyMetadata[pubkey.GetID()] = meta;
    return true;
}

bool CWallet::LoadCryptedKey(const CPubKey& vchPubKey, const std::vector<unsigned char>& vchCryptedSecret)
{
    return CCryptoKeyStore::AddCryptedKey(vchPubKey, vchCryptedSecret);
}

bool CWallet::AddCScript(const CScript& redeemScript)
{
    if (!CCryptoKeyStore::AddCScript(redeemScript))
        return false;
    if (!fFileBacked)
        return true;
    return CWalletDB(strWalletFile).WriteCScript(Hash160(redeemScript), redeemScript);
}

bool CWallet::LoadCScript(const CScript& redeemScript)
{
    /* A sanity check was added in pull #3843 to avoid adding redeemScripts
     * that never can be redeemed. However, old wallets may still contain
     * these. Do not add them to the wallet and warn. */
    if (redeemScript.size() > MAX_SCRIPT_ELEMENT_SIZE) {
        std::string strAddr = CBitcoinAddress(CScriptID(redeemScript)).ToString();
        LogPrintf("%s: Warning: This wallet contains a redeemScript of size %i which exceeds maximum size %i thus can never be redeemed. Do not use address %s.\n",
            __func__, redeemScript.size(), MAX_SCRIPT_ELEMENT_SIZE, strAddr);
        return true;
    }

    return CCryptoKeyStore::AddCScript(redeemScript);
}

bool CWallet::AddWatchOnly(const CScript& dest)
{
    if (!CCryptoKeyStore::AddWatchOnly(dest))
        return false;
    nTimeFirstKey = 1; // No birthday information for watch-only keys.
    NotifyWatchonlyChanged(true);
    if (!fFileBacked)
        return true;
    return CWalletDB(strWalletFile).WriteWatchOnly(dest);
}

bool CWallet::RemoveWatchOnly(const CScript& dest)
{
    AssertLockHeld(cs_wallet);
    if (!CCryptoKeyStore::RemoveWatchOnly(dest))
        return false;
    if (!HaveWatchOnly())
        NotifyWatchonlyChanged(false);
    if (fFileBacked)
        if (!CWalletDB(strWalletFile).EraseWatchOnly(dest))
            return false;

    return true;
}

bool CWallet::LoadWatchOnly(const CScript& dest)
{
    return CCryptoKeyStore::AddWatchOnly(dest);
}

bool CWallet::RescanAfterUnlock(int fromHeight)
{
    if (IsLocked()) {
        return false;
    }

    if (fImporting || fReindex) {
        return false;
    }
    CBlockIndex* pindex;

    if (fromHeight == 0) {
        LOCK2(cs_main, cs_wallet);
        //rescan from scanned position stored in database
        int scannedHeight = 0;
        CWalletDB(strWalletFile).ReadScannedBlockHeight(scannedHeight);
        if (scannedHeight > chainActive.Height() || scannedHeight == 0) {
            pindex = chainActive.Genesis();
        } else {
            pindex = chainActive[scannedHeight];
        }

        {
            if (mapWallet.size() > 0) {
                //looking for highest blocks
                for (map<uint256, CWalletTx>::iterator it = mapWallet.begin(); it != mapWallet.end(); ++it) {
                    CWalletTx* wtx = &((*it).second);
                    uint256 wtxid = (*it).first;
                    if (mapBlockIndex.count(wtx->hashBlock) == 1) {
                        CBlockIndex* pForTx = mapBlockIndex[wtx->hashBlock];
                        if (pForTx != NULL && pForTx->nHeight > pindex->nHeight) {
                            if (chainActive.Contains(pForTx)) {
                                pindex = pForTx;
                            }
                        }
                    }
                }
            }
        }
    } else {
        LOCK2(cs_main, cs_wallet);
        //scan from a specific block height
        if (fromHeight > chainActive.Height()) {
            pindex = chainActive[chainActive.Height()];
        } else {
            pindex = chainActive[fromHeight];
        }
    }

    ScanForWalletTransactions(pindex, true, fromHeight != 0?pindex->nHeight:-1);
    return true;
}

bool CWallet::Unlock(const SecureString& strWalletPassphrase, bool anonymizeOnly)
{
    CCrypter crypter;
    CKeyingMaterial vMasterKey;
    bool rescanNeeded = false;

    {
        LOCK(cs_wallet);
        for (const MasterKeyMap::value_type& pMasterKey : mapMasterKeys) {
            if (!crypter.SetKeyFromPassphrase(strWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod))
                return false;
            if (!crypter.Decrypt(pMasterKey.second.vchCryptedKey, vMasterKey))
                continue; // try another master key
            if (CCryptoKeyStore::Unlock(vMasterKey)) {
                fWalletUnlockAnonymizeOnly = anonymizeOnly;
                rescanNeeded = true;
                break;
            }
        }
    }

    if (rescanNeeded) {
        pwalletMain->RescanAfterUnlock(0);
        walletUnlockCountStatus++;
        return true;
    }

    return false;
}

bool CWallet::ChangeWalletPassphrase(const SecureString& strOldWalletPassphrase, const SecureString& strNewWalletPassphrase)
{
    bool fWasLocked = IsLocked();
    bool rescanNeeded = false;
    SecureString strOldWalletPassphraseFinal = strOldWalletPassphrase;

    {
        LOCK(cs_wallet);
        Lock();

        CCrypter crypter;
        CKeyingMaterial vMasterKey;
        for (MasterKeyMap::value_type& pMasterKey : mapMasterKeys) {
            if (!crypter.SetKeyFromPassphrase(strOldWalletPassphraseFinal, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod))
                return false;
            if (!crypter.Decrypt(pMasterKey.second.vchCryptedKey, vMasterKey))
                return false;
            if (CCryptoKeyStore::Unlock(vMasterKey)) {
                int64_t nStartTime = GetTimeMillis();
                crypter.SetKeyFromPassphrase(strNewWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod);
                pMasterKey.second.nDeriveIterations = pMasterKey.second.nDeriveIterations * (100 / ((double)(GetTimeMillis() - nStartTime)));

                nStartTime = GetTimeMillis();
                crypter.SetKeyFromPassphrase(strNewWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod);
                pMasterKey.second.nDeriveIterations = (pMasterKey.second.nDeriveIterations + pMasterKey.second.nDeriveIterations * 100 / ((double)(GetTimeMillis() - nStartTime))) / 2;

                if (pMasterKey.second.nDeriveIterations < 25000)
                    pMasterKey.second.nDeriveIterations = 25000;

                LogPrintf("Wallet passphrase changed to an nDeriveIterations of %i\n", pMasterKey.second.nDeriveIterations);

                if (!crypter.SetKeyFromPassphrase(strNewWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod))
                    return false;
                if (!crypter.Encrypt(vMasterKey, pMasterKey.second.vchCryptedKey))
                    return false;
                CWalletDB(strWalletFile).WriteMasterKey(pMasterKey.first, pMasterKey.second);
                if (fWasLocked)
                    Lock();

                nTimeFirstKey = 1;
                rescanNeeded = true;
                break;
            }
        }
    }

    if (rescanNeeded) {
        pwalletMain->RescanAfterUnlock(0);
        return true;
    }

    return false;
}

void CWallet::SetBestChain(const CBlockLocator& loc)
{
    CWalletDB walletdb(strWalletFile);
    walletdb.WriteBestBlock(loc);
}

bool CWallet::SetMinVersion(enum WalletFeature nVersion, CWalletDB* pwalletdbIn, bool fExplicit)
{
    LOCK(cs_wallet); // nWalletVersion
    if (nWalletVersion >= nVersion)
        return true;

    // when doing an explicit upgrade, if we pass the max version permitted, upgrade all the way
    if (fExplicit && nVersion > nWalletMaxVersion)
        nVersion = FEATURE_LATEST;

    nWalletVersion = nVersion;

    if (nVersion > nWalletMaxVersion)
        nWalletMaxVersion = nVersion;

    if (fFileBacked) {
        CWalletDB* pwalletdb = pwalletdbIn ? pwalletdbIn : new CWalletDB(strWalletFile);
        if (nWalletVersion > 40000)
            pwalletdb->WriteMinVersion(nWalletVersion);
        if (!pwalletdbIn)
            delete pwalletdb;
    }

    return true;
}

bool CWallet::SetMaxVersion(int nVersion)
{
    LOCK(cs_wallet); // nWalletVersion, nWalletMaxVersion
    // cannot downgrade below current version
    if (nWalletVersion > nVersion)
        return false;

    nWalletMaxVersion = nVersion;

    return true;
}

set<uint256> CWallet::GetConflicts(const uint256& txid) const
{
    set<uint256> result;
    AssertLockHeld(cs_wallet);

    std::map<uint256, CWalletTx>::const_iterator it = mapWallet.find(txid);
    if (it == mapWallet.end())
        return result;
    const CWalletTx& wtx = it->second;

    std::pair<TxSpends::const_iterator, TxSpends::const_iterator> range;

    for (const CTxIn& txin : wtx.vin) {
        COutPoint prevout = findMyOutPoint(txin);
        if (mapTxSpends.count(prevout) <= 1)
            continue; // No conflict if zero or one spends
        range = mapTxSpends.equal_range(prevout);
        for (TxSpends::const_iterator it = range.first; it != range.second; ++it)
            result.insert(it->second);
    }
    return result;
}

void CWallet::SyncMetaData(pair<TxSpends::iterator, TxSpends::iterator> range)
{
    // We want all the wallet transactions in range to have the same metadata as
    // the oldest (smallest nOrderPos).
    // So: find smallest nOrderPos:

    int nMinOrderPos = std::numeric_limits<int>::max();
    const CWalletTx* copyFrom = NULL;
    for (TxSpends::iterator it = range.first; it != range.second; ++it) {
        const uint256& hash = it->second;
        int n = mapWallet[hash].nOrderPos;
        if (n < nMinOrderPos) {
            nMinOrderPos = n;
            copyFrom = &mapWallet[hash];
        }
    }
    // Now copy data from copyFrom to rest:
    for (TxSpends::iterator it = range.first; it != range.second; ++it) {
        const uint256& hash = it->second;
        CWalletTx* copyTo = &mapWallet[hash];
        if (copyFrom == copyTo) continue;
        copyTo->mapValue = copyFrom->mapValue;
        copyTo->vOrderForm = copyFrom->vOrderForm;
        // fTimeReceivedIsTxTime not copied on purpose
        // nTimeReceived not copied on purpose
        copyTo->nTimeSmart = copyFrom->nTimeSmart;
        copyTo->fFromMe = copyFrom->fFromMe;
        copyTo->strFromAccount = copyFrom->strFromAccount;
        // nOrderPos not copied on purpose
        // cached members not copied on purpose
    }
}

/**
 * Outpoint is spent if any non-conflicted transaction
 * spends it:
 */
bool CWallet::IsSpent(const uint256& hash, unsigned int n)
{
    const COutPoint outpoint(hash, n);
    std::string keyImageHex;

    pair<TxSpends::const_iterator, TxSpends::const_iterator> range;
    range = mapTxSpends.equal_range(outpoint);
    for (TxSpends::const_iterator it = range.first; it != range.second; ++it) {
        const uint256& wtxid = it->second;
        std::map<uint256, CWalletTx>::const_iterator mit = mapWallet.find(wtxid);
        if (mit != mapWallet.end() && int(mit->second.GetDepthInMainChain()) > int(0)) {
            keyImagesSpends[keyImageHex] = true;
            return true; // Spent
        }
    }

    std::string outString = outpoint.hash.GetHex() + std::to_string(outpoint.n);
    CKeyImage ki = outpointToKeyImages[outString];
    if (IsKeyImageSpend1(ki.GetHex(), uint256())) {
        return true;
    }

    return false;
}

void CWallet::AddToSpends(const COutPoint& outpoint, const uint256& wtxid)
{
    mapTxSpends.insert(make_pair(outpoint, wtxid));
    pair<TxSpends::iterator, TxSpends::iterator> range;
    range = mapTxSpends.equal_range(outpoint);
    SyncMetaData(range);
    inSpendQueueOutpoints.erase(outpoint);
}

std::string CWallet::GetTransactionType(const CTransaction& tx)
{
    if (mapWallet.count(tx.GetHash()) < 1) return "other";
    if (tx.IsCoinBase() || tx.IsCoinStake() || tx.IsCoinAudit()) return "other";
    bool fAllFromMe = true;
    bool fToMe = false;
    bool fAllToMe = true;
    for(size_t i = 0; i < tx.vin.size(); i++) {
        if (!IsMine(tx.vin[i])) {
            fAllFromMe = false;
            break;
        }
    }

    if (fAllFromMe) return "withdrawal";
    for(size_t i = 0; i < tx.vout.size(); i++) {
        if (IsMine(tx.vout[i])) {
            fToMe = true;
        } else {
            fAllToMe = false;
        }
    }

    if (fToMe) return "deposit";

    return "other";
}

void CWallet::AddToSpends(const uint256& wtxid)
{
    assert(mapWallet.count(wtxid));
    CWalletTx& thisTx = mapWallet[wtxid];
    if (thisTx.IsCoinBase()) // Coinbases don't spend anything!
        return;
    for (const CTxIn& txin : thisTx.vin) {
        CKeyImage ki = txin.keyImage;
        COutPoint prevout = findMyOutPoint(txin);
        if (!prevout.IsNull() && isMatchMyKeyImage(ki, prevout)) {
            AddToSpends(prevout, wtxid);
            continue;
        }
    }

    if (thisTx.IsCoinStake()) {
        COutPoint prevout = thisTx.vin[0].prevout;
        AddToSpends(prevout, wtxid);
        std::string outpoint = prevout.hash.GetHex() + std::to_string(prevout.n);
        outpointToKeyImages[outpoint] = thisTx.vin[0].keyImage;
    }
}

bool CWallet::isMatchMyKeyImage(const CKeyImage& ki, const COutPoint& out)
{
    if (mapWallet.count(out.hash) == 0) return false;
    std::string outpoint = out.hash.GetHex() + std::to_string(out.n);
    CKeyImage computed = outpointToKeyImages[outpoint];
    bool ret = (computed == ki);
    return ret;
}

bool CWallet::GetMasternodeVinAndKeys(CTxIn& txinRet, CPubKey& pubKeyRet, CKey& keyRet, std::string strTxHash, std::string strOutputIndex)
{
    // wait for reindex and/or import to finish
    if (fImporting || fReindex) return false;

    // Find possible candidates
    std::vector<COutput> vPossibleCoins;
    AvailableCoins(vPossibleCoins, true, NULL, false, ONLY_1000000);
    if (vPossibleCoins.empty()) {
        LogPrintf("CWallet::GetMasternodeVinAndKeys -- Could not locate any valid masternode vin\n");
        return false;
    }

    if (strTxHash.empty()) // No output specified, select the first one
        return GetVinAndKeysFromOutput(vPossibleCoins[0], txinRet, pubKeyRet, keyRet);

    // Find specific vin
    uint256 txHash = uint256S(strTxHash);

    int nOutputIndex;
    try {
        nOutputIndex = std::stoi(strOutputIndex.c_str());
    } catch (const std::exception& e) {
        LogPrintf("%s: %s on strOutputIndex\n", __func__, e.what());
        return false;
    }

    for (COutput& out : vPossibleCoins)
        if (out.tx->GetHash() == txHash && out.i == nOutputIndex) // found it!
            return GetVinAndKeysFromOutput(out, txinRet, pubKeyRet, keyRet);

    LogPrintf("CWallet::GetMasternodeVinAndKeys -- Could not locate specified masternode vin\n");
    return false;
}

bool CWallet::GetVinAndKeysFromOutput(COutput out, CTxIn& txinRet, CPubKey& pubKeyRet, CKey& keyRet)
{
    // wait for reindex and/or import to finish
    if (fImporting || fReindex) return false;

    CScript pubScript;

    txinRet = CTxIn(out.tx->GetHash(), out.i);
    pubScript = out.tx->vout[out.i].scriptPubKey; // the inputs PubKey

    CTxDestination address1;
    ExtractDestination(pubScript, address1);
    CBitcoinAddress address2(address1);

    CKeyID keyID;
    if (!address2.GetKeyID(keyID)) {
        LogPrintf("CWallet::GetVinAndKeysFromOutput -- Address does not refer to a key\n");
        return false;
    }

    if (!GetKey(keyID, keyRet)) {
        LogPrintf("CWallet::GetVinAndKeysFromOutput -- Private key for address is not known\n");
        return false;
    }

    pubKeyRet = keyRet.GetPubKey();
    return true;
}

bool CWallet::EncryptWallet(const SecureString& strWalletPassphrase)
{
    if (IsCrypted())
        return false;

    CKeyingMaterial vMasterKey;
    RandAddSeedPerfmon();

    vMasterKey.resize(WALLET_CRYPTO_KEY_SIZE);
    GetRandBytes(&vMasterKey[0], WALLET_CRYPTO_KEY_SIZE);

    CMasterKey kMasterKey;
    RandAddSeedPerfmon();

    kMasterKey.vchSalt.resize(WALLET_CRYPTO_SALT_SIZE);
    GetRandBytes(&kMasterKey.vchSalt[0], WALLET_CRYPTO_SALT_SIZE);

    CCrypter crypter;
    int64_t nStartTime = GetTimeMillis();
    crypter.SetKeyFromPassphrase(strWalletPassphrase, kMasterKey.vchSalt, 25000, kMasterKey.nDerivationMethod);
    kMasterKey.nDeriveIterations = 2500000 / ((double)(GetTimeMillis() - nStartTime));

    nStartTime = GetTimeMillis();
    crypter.SetKeyFromPassphrase(strWalletPassphrase, kMasterKey.vchSalt, kMasterKey.nDeriveIterations, kMasterKey.nDerivationMethod);
    kMasterKey.nDeriveIterations = (kMasterKey.nDeriveIterations + kMasterKey.nDeriveIterations * 100 / ((double)(GetTimeMillis() - nStartTime))) / 2;

    if (kMasterKey.nDeriveIterations < 25000)
        kMasterKey.nDeriveIterations = 25000;

    LogPrintf("Encrypting Wallet with an nDeriveIterations of %i\n", kMasterKey.nDeriveIterations);

    if (!crypter.SetKeyFromPassphrase(strWalletPassphrase, kMasterKey.vchSalt, kMasterKey.nDeriveIterations, kMasterKey.nDerivationMethod))
        return false;
    if (!crypter.Encrypt(vMasterKey, kMasterKey.vchCryptedKey))
        return false;

    {
        LOCK(cs_wallet);
        mapMasterKeys[++nMasterKeyMaxID] = kMasterKey;
        if (fFileBacked) {
            assert(!pwalletdbEncryption);
            pwalletdbEncryption = new CWalletDB(strWalletFile);
            if (!pwalletdbEncryption->TxnBegin()) {
                delete pwalletdbEncryption;
                pwalletdbEncryption = NULL;
                return false;
            }
            pwalletdbEncryption->WriteMasterKey(nMasterKeyMaxID, kMasterKey);
        }

        // must get current HD chain before EncryptKeys
        CHDChain hdChainCurrent;
        GetHDChain(hdChainCurrent);

        if (!EncryptKeys(vMasterKey)) {
            if (fFileBacked) {
                pwalletdbEncryption->TxnAbort();
                delete pwalletdbEncryption;
            }
            // We now probably have half of our keys encrypted in memory, and half not...
            // die and let the user reload their unencrypted wallet.
            assert(false);
        }

        if (!hdChainCurrent.IsNull()) {
            assert(EncryptHDChain(vMasterKey));

            CHDChain hdChainCrypted;
            assert(GetHDChain(hdChainCrypted));

            // ids should match, seed hashes should not
            assert(hdChainCurrent.GetID() == hdChainCrypted.GetID());
            assert(hdChainCurrent.GetSeedHash() != hdChainCrypted.GetSeedHash());

            assert(SetCryptedHDChain(hdChainCrypted, false));
        }

        // Encryption was introduced in version 0.4.0
        SetMinVersion(FEATURE_WALLETCRYPT, pwalletdbEncryption, true);

        if (fFileBacked) {
            if (!pwalletdbEncryption->TxnCommit()) {
                delete pwalletdbEncryption;
                // We now have keys encrypted in memory, but not on disk...
                // die to avoid confusion and let the user reload their unencrypted wallet.
                assert(false);
            }

            delete pwalletdbEncryption;
            pwalletdbEncryption = NULL;
        }

        Lock();

        // Need to completely rewrite the wallet file; if we don't, bdb might keep
        // bits of the unencrypted private key in slack space in the database file.
        CDB::Rewrite(strWalletFile);
    }
    NotifyStatusChanged(this);

    return true;
}

int64_t CWallet::IncOrderPosNext(CWalletDB* pwalletdb)
{
    AssertLockHeld(cs_wallet); // nOrderPosNext
    int64_t nRet = nOrderPosNext++;
    if (pwalletdb) {
        pwalletdb->WriteOrderPosNext(nOrderPosNext);
    } else {
        CWalletDB(strWalletFile).WriteOrderPosNext(nOrderPosNext);
    }
    return nRet;
}

void CWallet::MarkDirty()
{
    {
        LOCK(cs_wallet);
        for (PAIRTYPE(const uint256, CWalletTx) & item : mapWallet)
            item.second.MarkDirty();
    }
}

bool CWallet::AddToWallet(const CWalletTx& wtxIn, bool fFromLoadWallet)
{
    uint256 hash = wtxIn.GetHash();
    const uint256& hashBlock = wtxIn.hashBlock;
    CBlockIndex* p = mapBlockIndex[hashBlock];
    if (p) {
        for (CTxIn in : wtxIn.vin) {
            pblocktree->WriteKeyImage(in.keyImage.GetHex(), hashBlock);
        }
    }

    CWalletDB db(strWalletFile);
    for (size_t i = 0; i < wtxIn.vout.size(); i++) {
        std::string outpoint = hash.GetHex() + std::to_string(i);
        if (outpointToKeyImages.count(outpoint) == 1 && outpointToKeyImages[outpoint].IsValid()) continue;
        CKeyImage ki;
        //reading key image
        if (db.ReadKeyImage(outpoint, ki)) {
            if (ki.IsFullyValid()) {
                outpointToKeyImages[outpoint] = ki;
                continue;
            }
        }
        if (IsMine(wtxIn.vout[i])) {
            if (generateKeyImage(wtxIn.vout[i].scriptPubKey, ki)) {
                outpointToKeyImages[outpoint] = ki;
                db.WriteKeyImage(outpoint, ki);
            }
        }
    }

    if (fFromLoadWallet) {
        mapWallet[hash] = wtxIn;
        CWalletTx& wtx = mapWallet[hash];
        wtx.BindWallet(this);
        wtxOrdered.insert(make_pair(wtx.nOrderPos, TxPair(&wtx, (CAccountingEntry*)0)));
        AddToSpends(hash);
    } else {
        LOCK(cs_wallet);
        // Inserts only if not already there, returns tx inserted or tx found
        pair<map<uint256, CWalletTx>::iterator, bool> ret = mapWallet.insert(make_pair(hash, wtxIn));
        CWalletTx& wtx = (*ret.first).second;
        wtx.BindWallet(this);
        bool fInsertedNew = ret.second;
        if (fInsertedNew) {
            if (!wtx.nTimeReceived)
                wtx.nTimeReceived = GetAdjustedTime();
            wtx.nOrderPos = IncOrderPosNext();
            wtxOrdered.insert(make_pair(wtx.nOrderPos, TxPair(&wtx, (CAccountingEntry*)0)));
            wtx.nTimeSmart = ComputeTimeSmart(wtx);
            AddToSpends(hash);
        }

        bool fUpdated = false;
        if (!fInsertedNew) {
            // Merge
            if (wtxIn.hashBlock != 0 && wtxIn.hashBlock != wtx.hashBlock) {
                wtx.hashBlock = wtxIn.hashBlock;
                fUpdated = true;
            }
            if (wtxIn.nIndex != -1 && (wtxIn.vMerkleBranch != wtx.vMerkleBranch || wtxIn.nIndex != wtx.nIndex)) {
                wtx.vMerkleBranch = wtxIn.vMerkleBranch;
                wtx.nIndex = wtxIn.nIndex;
                fUpdated = true;
            }
            if (wtxIn.fFromMe && wtxIn.fFromMe != wtx.fFromMe) {
                wtx.fFromMe = wtxIn.fFromMe;
                fUpdated = true;
            }
        }

        //// debug print
        //LogPrintf("AddToWallet %s  %s%s\n", wtxIn.GetHash().ToString(), (fInsertedNew ? "new" : ""), (fUpdated ? "update" : ""));

        // Write to disk
        if (fInsertedNew || fUpdated)
            if (!wtx.WriteToDisk())
                return false;

        // Break debit/credit balance caches:
        wtx.MarkDirty();
        //LogPrintf("MarkDirty %s  %s%s\n", wtxIn.GetHash().ToString(), (fInsertedNew ? "new" : ""), (fUpdated ? "update" : ""));

        // Notify UI of new or updated transaction
        NotifyTransactionChanged(this, hash, fInsertedNew ? CT_NEW : CT_UPDATED);

        // notify an external script when a wallet transaction comes in or is updated
        std::string strCmd = GetArg("-walletnotify", "");

        if (!strCmd.empty()) {
            boost::replace_all(strCmd, "%s", wtxIn.GetHash().GetHex());
            boost::thread t(runCommand, strCmd); // thread runs free
        }
    }
    return true;
}

/**
 * Add a transaction to the wallet, or update it.
 * pblock is optional, but should be provided if the transaction is known to be in a block.
 * If fUpdate is true, existing transactions will be updated.
 */
bool CWallet::AddToWalletIfInvolvingMe(const CTransaction& tx, const CBlock* pblock, bool fUpdate)
{
    {
        AssertLockHeld(cs_wallet);
        bool fExisted = mapWallet.count(tx.GetHash()) != 0;
        if (fExisted && !fUpdate) return false;
        IsTransactionForMe(tx);
        if (pblock && mapBlockIndex.count(pblock->GetHash()) == 1) {
            if (!IsLocked()) {
                try {
                    CWalletDB(strWalletFile).WriteScannedBlockHeight(mapBlockIndex[pblock->GetHash()]->nHeight);
                } catch (const std::exception& e) {
                    LogPrintf("Cannot open data base or wallet is locked\n");
                }
            }
        }
        if (fExisted || IsMine(tx) || IsFromMe(tx)) {
            CWalletTx wtx(this, tx);
            // Get merkle branch if transaction was found in a block
            if (pblock)
                wtx.SetMerkleBranch(*pblock);
            return AddToWallet(wtx);
        }
    }
    return false;
}

void CWallet::SyncTransaction(const CTransaction& tx, const CBlock* pblock)
{
    if (IsLocked()) return;
    LOCK2(cs_main, cs_wallet);
    if (!AddToWalletIfInvolvingMe(tx, pblock, true)) {
        return; // Not one of ours
    }
    // If a transaction changes 'conflicted' state, that changes the balance
    // available of the outputs it spends. So force those to be
    // recomputed, also:
    for (const CTxIn& txin : tx.vin) {
        COutPoint prevout = findMyOutPoint(txin);
        if (mapWallet.count(prevout.hash))
            mapWallet[prevout.hash].MarkDirty();
    }
}

void CWallet::EraseFromWallet(const uint256& hash)
{
    if (!fFileBacked)
        return;
    {
        LOCK(cs_wallet);
        if (mapWallet.erase(hash))
            CWalletDB(strWalletFile).EraseTx(hash);
    }
    return;
}


isminetype CWallet::IsMine(const CTxIn& txin) const
{
    {
        LOCK(cs_wallet);
        COutPoint prevout = findMyOutPoint(txin);
        map<uint256, CWalletTx>::const_iterator mi = mapWallet.find(prevout.hash);
        if (mi != mapWallet.end()) {
            const CWalletTx& prev = (*mi).second;
            if (prevout.n < prev.vout.size())
                return IsMine(prev.vout[prevout.n]);
        }
    }
    return ISMINE_NO;
}

COutPoint CWallet::findMyOutPoint(const CTxIn& txin) const
{
    std::string prevout = txin.prevout.hash.GetHex() + std::to_string(txin.prevout.n);
    if (outpointToKeyImages.count(prevout) == 1 && outpointToKeyImages[prevout] == txin.keyImage) return txin.prevout;

    for (size_t i = 0; i < txin.decoys.size(); i++) {
        std::string out = txin.decoys[i].hash.GetHex() + std::to_string(txin.decoys[i].n);
        if (outpointToKeyImages.count(out) == 1 && outpointToKeyImages[out] == txin.keyImage) return txin.decoys[i];
    }

    COutPoint outpoint;
    {
        //AssertLockHeld(cs_wallet); // mapWallet
        bool ret = false;
        CWalletTx prev;
        if (mapWallet.count(txin.prevout.hash))
            prev = mapWallet[txin.prevout.hash];
        if (txin.prevout.n < prev.vout.size())
            ret = IsMine(prev.vout[txin.prevout.n]);
        if (ret) {
            CKeyImage ki;
            if (generateKeyImage(prev.vout[txin.prevout.n].scriptPubKey, ki)) {
                if (ki == txin.keyImage) {
                    outpoint = txin.prevout;
                    prevout = txin.prevout.hash.GetHex() + std::to_string(txin.prevout.n);
                    outpointToKeyImages[prevout] = ki;
                    return outpoint;
                }
            }
        }

        for (size_t i = 0; i < txin.decoys.size(); i++) {
            if (mapWallet.count(txin.decoys[i].hash))
                prev = mapWallet[txin.decoys[i].hash];
            else
                continue;
            if (txin.decoys[i].n < prev.vout.size())
                ret = IsMine(prev.vout[txin.decoys[i].n]);
            if (ret) {
                CKeyImage ki;
                if (generateKeyImage(prev.vout[txin.decoys[i].n].scriptPubKey, ki)) {
                    if (ki == txin.keyImage) {
                        outpoint = txin.decoys[i];
                        std::string out = txin.decoys[i].hash.GetHex() + std::to_string(txin.decoys[i].n);
                        outpointToKeyImages[out] = ki;
                        return outpoint;
                    }
                }
            }
        }
    }
    return outpoint;
}

CAmount CWallet::GetDebit(const CTxIn& txin, const isminefilter& filter) const
{
    {
        LOCK(cs_wallet);
        if (txin.prevout.IsNull()) return 0;
        COutPoint prevout = findMyOutPoint(txin);
        map<uint256, CWalletTx>::const_iterator mi = mapWallet.find(prevout.hash);
        if (mi != mapWallet.end()) {
            const CWalletTx& prev = (*mi).second;
            if (prevout.n < prev.vout.size())
                if (IsMine(prev.vout[prevout.n]) & filter)
                    return getCTxOutValue(prev, prev.vout[prevout.n]);
        }
    }
    return 0;
}

bool CWallet::IsDenominated(const CTxIn& txin) const
{
    {
        LOCK(cs_wallet);
        COutPoint prevout = findMyOutPoint(txin);
        map<uint256, CWalletTx>::const_iterator mi = mapWallet.find(prevout.hash);
        if (mi != mapWallet.end()) {
            const CWalletTx& prev = (*mi).second;
            if (prevout.n < prev.vout.size()) return IsDenominatedAmount(getCTxOutValue(prev, prev.vout[prevout.n]));
        }
    }
    return false;
}

bool CWallet::IsDenominatedAmount(CAmount nInputAmount) const
{
    for (CAmount d : obfuScationDenominations)
        if (nInputAmount == d)
            return true;
    return false;
}

bool CWallet::IsChange(const CTxOut& txout) const
{
    if (::IsMine(*this, txout.scriptPubKey)) {
        CTxDestination address;
        if (!ExtractDestination(txout.scriptPubKey, address))
            return true;

        LOCK(cs_wallet);
        if (!mapAddressBook.count(address))
            return true;
    }
    return false;
}

int64_t CWalletTx::GetTxTime() const
{
    int64_t n = nTimeSmart;
    return n ? n : nTimeReceived;
}

int64_t CWalletTx::GetComputedTxTime() const
{
    LOCK(cs_main);
    return GetTxTime();
}

int CWalletTx::GetRequestCount() const
{
    // Returns -1 if it wasn't being tracked
    int nRequests = -1;
    {
        LOCK(pwallet->cs_wallet);
        if (IsCoinBase()) {
            // Generated block
            if (hashBlock != 0) {
                map<uint256, int>::const_iterator mi = pwallet->mapRequestCount.find(hashBlock);
                if (mi != pwallet->mapRequestCount.end())
                    nRequests = (*mi).second;
            }
        } else {
            // Did anyone request this transaction?
            map<uint256, int>::const_iterator mi = pwallet->mapRequestCount.find(GetHash());
            if (mi != pwallet->mapRequestCount.end()) {
                nRequests = (*mi).second;

                // How about the block it's in?
                if (nRequests == 0 && hashBlock != 0) {
                    map<uint256, int>::const_iterator mi = pwallet->mapRequestCount.find(hashBlock);
                    if (mi != pwallet->mapRequestCount.end())
                        nRequests = (*mi).second;
                    else
                        nRequests = 1; // If it's in someone else's block it must have got out
                }
            }
        }
    }
    return nRequests;
}

CAmount CWalletTx::GetDebit(const isminefilter& filter) const
{
    if (vin.empty())
        return 0;

    CAmount debit = 0;
    if (filter & ISMINE_SPENDABLE) {
        if (fDebitCached)
            debit += nDebitCached;
        else {
            nDebitCached = pwallet->GetDebit(*this, ISMINE_SPENDABLE);
            fDebitCached = true;
            debit += nDebitCached;
        }
    }
    if (filter & ISMINE_WATCH_ONLY) {
        if (fWatchDebitCached)
            debit += nWatchDebitCached;
        else {
            nWatchDebitCached = pwallet->GetDebit(*this, ISMINE_WATCH_ONLY);
            fWatchDebitCached = true;
            debit += nWatchDebitCached;
        }
    }
    return debit;
}

CAmount CWalletTx::GetCredit(const isminefilter& filter) const
{
    // Must wait until coinbase is safely deep enough in the chain before valuing it
    if (IsCoinBase() && GetBlocksToMaturity() > 0)
        return 0;

    CAmount credit = 0;
    if (filter & ISMINE_SPENDABLE) {
        // GetBalance can assume transactions in mapWallet won't change
        if (fCreditCached)
            credit += nCreditCached;
        else {
            nCreditCached = pwallet->GetCredit(*this, ISMINE_SPENDABLE);
            fCreditCached = true;
            credit += nCreditCached;
        }
    }
    if (filter & ISMINE_WATCH_ONLY) {
        if (fWatchCreditCached)
            credit += nWatchCreditCached;
        else {
            nWatchCreditCached = pwallet->GetCredit(*this, ISMINE_WATCH_ONLY);
            fWatchCreditCached = true;
            credit += nWatchCreditCached;
        }
    }
    return credit;
}

CAmount CWalletTx::GetImmatureCredit(bool fUseCache) const
{
    LOCK(cs_main);
    if (IsInMainChainImmature()) {
        if (fUseCache && fImmatureCreditCached)
            return nImmatureCreditCached;
        nImmatureCreditCached = pwallet->GetCredit(*this, ISMINE_SPENDABLE);
        fImmatureCreditCached = true;
        return nImmatureCreditCached;
    }
    return 0;
}

CAmount CWalletTx::GetAvailableCredit(bool fUseCache) const
{
    if (pwallet == 0)
        return 0;

    // Must wait until coinbase is safely deep enough in the chain before valuing it
    if (IsCoinBase() && GetBlocksToMaturity() > 0)
        return 0;

    if (fUseCache && fAvailableCreditCached) {
        if (nAvailableCreditCached) {
            return nAvailableCreditCached;
        }
    }

    CAmount nCredit = 0;
    uint256 hashTx = GetHash();
    for (unsigned int i = 0; i < vout.size(); i++) {
        //dont count if output is in mempool
        COutPoint outpoint(hashTx, i);
        if (pwallet->inSpendQueueOutpoints.count(outpoint) == 1) continue;

        if (!pwallet->IsSpent(hashTx, i)) {
            const CTxOut& txout = vout[i];
            CAmount cre = pwallet->GetCredit(*this, txout, ISMINE_SPENDABLE);
            if (cre == 0 && fCreditCached) {
                fCreditCached = false;
                cre = pwallet->GetCredit(*this, txout, ISMINE_SPENDABLE);
            }
            nCredit += cre;
        }
    }

    nAvailableCreditCached = nCredit;
    fAvailableCreditCached = true;
    return nCredit;
}

// Return sum of unlocked coins
CAmount CWalletTx::GetUnlockedCredit() const
{
    if (pwallet == 0)
        return 0;

    // Must wait until coinbase is safely deep enough in the chain before valuing it
    if (IsCoinBase() && GetBlocksToMaturity() > 0)
        return 0;

    CAmount nCredit = 0;
    uint256 hashTx = GetHash();
    for (unsigned int i = 0; i < vout.size(); i++) {
        const CTxOut& txout = vout[i];

        if (pwallet->IsSpent(hashTx, i) || pwallet->IsLockedCoin(hashTx, i)) continue;
        if (fMasterNode && pwallet->getCTxOutValue(*this, vout[i]) == 1000000 * COIN) continue; // do not count MN-like outputs

        nCredit += pwallet->GetCredit(*this, txout, ISMINE_SPENDABLE);
    }

    return nCredit;
}

// Return sum of unlocked coins
CAmount CWalletTx::GetLockedCredit() const
{
    if (pwallet == 0)
        return 0;

    // Must wait until coinbase is safely deep enough in the chain before valuing it
    if (IsCoinBase() && GetBlocksToMaturity() > 0)
        return 0;

    CAmount nCredit = 0;
    uint256 hashTx = GetHash();
    for (unsigned int i = 0; i < vout.size(); i++) {
        const CTxOut& txout = vout[i];

        // Skip spent coins
        if (pwallet->IsSpent(hashTx, i)) continue;

        // Add locked coins
        if (pwallet->IsLockedCoin(hashTx, i)) {
            nCredit += pwallet->GetCredit(*this, txout, ISMINE_SPENDABLE);
        }

        // Add masternode collaterals which are handled likc locked coins
         else if (fMasterNode && pwallet->getCTxOutValue(*this, vout[i]) == 1000000 * COIN) {
            nCredit += pwallet->GetCredit(*this, txout, ISMINE_SPENDABLE);
        }

    }

    return nCredit;
}

CAmount CWalletTx::GetImmatureWatchOnlyCredit(const bool& fUseCache) const
{
    LOCK(cs_main);
    if (IsInMainChainImmature()) {
        if (fUseCache && fImmatureWatchCreditCached)
            return nImmatureWatchCreditCached;
        nImmatureWatchCreditCached = pwallet->GetCredit(*this, ISMINE_WATCH_ONLY);
        fImmatureWatchCreditCached = true;
        return nImmatureWatchCreditCached;
    }

    return 0;
}

CAmount CWalletTx::GetAvailableWatchOnlyCredit(const bool& fUseCache) const
{
    if (pwallet == 0)
        return 0;

    // Must wait until coinbase is safely deep enough in the chain before valuing it
    if (IsCoinBase() && GetBlocksToMaturity() > 0)
        return 0;

    if (fUseCache && fAvailableWatchCreditCached)
        return nAvailableWatchCreditCached;

    CAmount nCredit = 0;
    for (unsigned int i = 0; i < vout.size(); i++) {
        if (!pwallet->IsSpent(GetHash(), i)) {
            const CTxOut& txout = vout[i];
            nCredit += pwallet->GetCredit(*this, txout, ISMINE_WATCH_ONLY);
        }
    }

    nAvailableWatchCreditCached = nCredit;
    fAvailableWatchCreditCached = true;
    return nCredit;
}

void CWalletTx::GetAmounts(list<COutputEntry>& listReceived,
    list<COutputEntry>& listSent,
    CAmount& nFee,
    string& strSentAccount,
    const isminefilter& filter) const
{
    nFee = 0;
    listReceived.clear();
    listSent.clear();
    strSentAccount = strFromAccount;

    // Compute fee:
    CAmount nDebit = GetDebit(filter);
    nFee = nTxFee;

    // Sent/received.
    for (unsigned int i = 0; i < vout.size(); ++i) {
        const CTxOut& txout = vout[i];
        isminetype fIsMine = pwallet->IsMine(txout);
        // Only need to handle txouts if AT LEAST one of these is true:
        //   1) they debit from us (sent)
        //   2) the output is to us (received)
        if (nDebit > 0) {
            // Don't report 'change' txouts
            if (pwallet->IsChange(txout))
                continue;
        } else if (!(fIsMine & filter))
            continue;

        // In either case, we need to get the destination address
        CTxDestination address;
        if (!ExtractDestination(txout.scriptPubKey, address)) {
            if (!IsCoinStake() && !IsCoinBase()) {
                LogPrintf("CWalletTx::GetAmounts: Unknown transaction type found, txid %s\n", this->GetHash().ToString());
            }
            address = CNoDestination();
        }

        COutputEntry output = {address, pwallet->getCTxOutValue(*this, txout), (int)i};

        // If we are debited by the transaction, add the output as a "sent" entry
        if (nDebit > 0)
            listSent.push_back(output);

        // If we are receiving the output, add it as a "received" entry
        if (fIsMine & filter)
            listReceived.push_back(output);
    }
}

void CWalletTx::GetAccountAmounts(const string& strAccount, CAmount& nReceived, CAmount& nSent, CAmount& nFee, const isminefilter& filter) const
{
    nReceived = nSent = nFee = 0;

    CAmount allFee;
    string strSentAccount;
    list<COutputEntry> listReceived;
    list<COutputEntry> listSent;
    GetAmounts(listReceived, listSent, allFee, strSentAccount, filter);

    if (strAccount == strSentAccount) {
        for (const COutputEntry& s : listSent)
            nSent += s.amount;
        nFee = allFee;
    }
    {
        LOCK(pwallet->cs_wallet);
        for (const COutputEntry& r : listReceived) {
            if (pwallet->mapAddressBook.count(r.destination)) {
                map<CTxDestination, CAddressBookData>::const_iterator mi = pwallet->mapAddressBook.find(r.destination);
                if (mi != pwallet->mapAddressBook.end() && (*mi).second.name == strAccount)
                    nReceived += r.amount;
            } else if (strAccount.empty()) {
                nReceived += r.amount;
            }
        }
    }
}


bool CWalletTx::WriteToDisk()
{
    return CWalletDB(pwallet->strWalletFile).WriteTx(GetHash(), *this);
}

/**
 * Scan the block chain (starting in pindexStart) for transactions
 * from or to us. If fUpdate is true, found transactions that already
 * exist in the wallet will be updated.
 * @returns -1 if process was cancelled or the number of tx added to the wallet.
 */
int CWallet::ScanForWalletTransactions(CBlockIndex* pindexStart, bool fUpdate, bool fromStartup, int height)
{
    int ret = 0;
    int64_t nNow = GetTime();
    CBlockIndex* pindex = pindexStart;
    {
        LOCK2(cs_main, cs_wallet);
        if (pindexStart == chainActive.Genesis()) {
            pindex = chainActive.Tip();
        } else if (height == -1) {
            // no need to read and scan block, if block was created before
            // our wallet birthday (as adjusted for block time variability)
            while (pindex && nTimeFirstKey && (pindex->GetBlockTime() < (nTimeFirstKey - 7200))) {
                pindex = chainActive.Next(pindex);
            }
        }

        ShowProgress(_("Rescanning..."), 0); // show rescan progress in GUI as dialog or on splashscreen, if -rescan on startup
        double dProgressStart = Checkpoints::GuessVerificationProgress(pindex, false);
        double dProgressTip = Checkpoints::GuessVerificationProgress(chainActive.Tip(), false);
        while (!IsLocked() && pindex) {
            if (pindex->nHeight % 100 == 0 && dProgressTip - dProgressStart > 0.0)
                ShowProgress(_("Rescanning..."), std::max(1, std::min(99, (int)((Checkpoints::GuessVerificationProgress(pindex, false) - dProgressStart) / (dProgressTip - dProgressStart) * 100))));

            if (fromStartup && ShutdownRequested()) {
                return -1;
            }

            CBlock block;
            ReadBlockFromDisk(block, pindex);
            for (CTransaction& tx : block.vtx) {
                if (AddToWalletIfInvolvingMe(tx, &block, fUpdate))
                    ret++;
            }
            pindex = chainActive.Next(pindex);
            if (GetTime() >= nNow + 60) {
                nNow = GetTime();
                LogPrintf("Still rescanning. At block %d. Progress=%f\n", pindex->nHeight, Checkpoints::GuessVerificationProgress(pindex));
            }
            if (ShutdownRequested()) {
                LogPrintf("Rescan aborted at block %d. Please rescanwallettransactions %f from the Debug Console to continue.\n", pindex->nHeight, pindex->nHeight);
                return false;
            }
        }
        ShowProgress(_("Rescanning... Please do not interrupt this process as it could lead to a corrupt wallet."), 100); // hide progress dialog in GUI
    }
    return ret;
}

void CWallet::ReacceptWalletTransactions()
{
    LOCK2(cs_main, cs_wallet);
    for (PAIRTYPE(const uint256, CWalletTx) & item : mapWallet) {
        const uint256& wtxid = item.first;
        CWalletTx& wtx = item.second;
        assert(wtx.GetHash() == wtxid);

        int nDepth = wtx.GetDepthInMainChain();

        if (!wtx.IsCoinBase() && nDepth < 0) {
            // Try to add to memory pool
            LOCK(mempool.cs);
            wtx.AcceptToMemoryPool(false);
        }
    }
}

bool CWalletTx::InMempool() const
{
    LOCK(mempool.cs);
    if (mempool.exists(GetHash())) {
        return true;
    }
    return false;
}

void CWalletTx::RelayWalletTransaction(std::string strCommand)
{
    LOCK(cs_main);
    if (!IsCoinBase()) {
        if (GetDepthInMainChain() == 0) {
            uint256 hash = GetHash();
            LogPrintf("Relaying wtx %s\n", hash.ToString());

            if (strCommand == "ix") {
                mapTxLockReq.insert(make_pair(hash, (CTransaction) * this));
                CreateNewLock(((CTransaction) * this));
                RelayTransactionLockReq((CTransaction) * this, true);
            } else {
                RelayTransaction((CTransaction) * this);
            }
        }
    }
}

set<uint256> CWalletTx::GetConflicts() const
{
    set<uint256> result;
    if (pwallet != NULL) {
        uint256 myHash = GetHash();
        result = pwallet->GetConflicts(myHash);
        result.erase(myHash);
    }
    return result;
}

void CWallet::ResendWalletTransactions()
{
    // Do this infrequently and randomly to avoid giving away
    // that these are our transactions.
    if (GetTime() < nNextResend)
        return;
    bool fFirst = (nNextResend == 0);
    nNextResend = GetTime() + GetRand(30 * 60);
    if (fFirst)
        return;

    // Only do it if there's been a new block since last time
    if (nTimeBestReceived < nLastResend)
        return;
    nLastResend = GetTime();

    // Rebroadcast any of our txes that aren't in a block yet
    LogPrintf("ResendWalletTransactions()\n");
    {
        LOCK(cs_wallet);
        // Sort them in chronological order
        multimap<unsigned int, CWalletTx*> mapSorted;
        for (PAIRTYPE(const uint256, CWalletTx) & item : mapWallet) {
            CWalletTx& wtx = item.second;
            // Don't rebroadcast until it's had plenty of time that
            // it should have gotten in already by now.
            if (nTimeBestReceived - (int64_t)wtx.nTimeReceived > 5 * 60)
                mapSorted.insert(make_pair(wtx.nTimeReceived, &wtx));
        }
        for (PAIRTYPE(const unsigned int, CWalletTx*) & item : mapSorted) {
            CWalletTx& wtx = *item.second;
            wtx.RelayWalletTransaction();
        }
    }
}

/** @} */ // end of mapWallet


/** @defgroup Actions
 *
 * @{
 */

CAmount CWallet::GetBalance()
{
    CAmount nTotal = 0;
    {
        LOCK2(cs_main, cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it) {
            const CWalletTx* pcoin = &(*it).second;
            if (pcoin->IsTrusted()) {
                CAmount ac = pcoin->GetAvailableCredit();
                nTotal += ac;
            }
        }
    }
    dirtyCachedBalance = nTotal;
    return nTotal;
}

CAmount CWallet::GetSpendableBalance()
{
    CAmount nLockedBalance = 0;
    CAmount nTotal = 0;
    {
        LOCK2(cs_main, cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it) {
            const CWalletTx* pcoin = &(*it).second;
            if (pcoin->IsTrusted()) {
                if (!((pcoin->IsCoinBase() || pcoin->IsCoinStake()) && pcoin->GetBlocksToMaturity() > 0 && pcoin->IsInMainChain())) {
                    nTotal += pcoin->GetAvailableCredit();
                }
            }
        }
    }

    nLockedBalance = pwalletMain->GetLockedCoins();
    nTotal = nTotal - nLockedBalance;
    return nTotal;
}


CAmount CWallet::GetUnlockedCoins() const
{
    if (fLiteMode) return 0;

    CAmount nTotal = 0;
    {
        LOCK2(cs_main, cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it) {
            const CWalletTx* pcoin = &(*it).second;

            if (pcoin->IsTrusted() && pcoin->GetDepthInMainChain() > 0)
                nTotal += pcoin->GetUnlockedCredit();
        }
    }

    return nTotal;
}

CAmount CWallet::GetLockedCoins() const
{
    if (fLiteMode) return 0;

    CAmount nTotal = 0;
    {
        LOCK2(cs_main, cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it) {
            const CWalletTx* pcoin = &(*it).second;

            if (pcoin->IsTrusted() && pcoin->GetDepthInMainChain() > 0)
                nTotal += pcoin->GetLockedCredit();
        }
    }

    return nTotal;
}


CAmount CWallet::GetUnconfirmedBalance() const
{
    CAmount nTotal = 0;
    {
        LOCK2(cs_main, cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it) {
            const CWalletTx* pcoin = &(*it).second;
            if (!IsFinalTx(*pcoin) || (!pcoin->IsTrusted() && pcoin->GetDepthInMainChain() == 0))
                nTotal += pcoin->GetAvailableCredit(false);
        }
    }
    return nTotal;
}

CAmount CWallet::GetImmatureBalance() const
{
    CAmount nTotal = 0;
    {
        LOCK2(cs_main, cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it) {
            const CWalletTx* pcoin = &(*it).second;
            nTotal += pcoin->GetImmatureCredit(false);
        }
    }
    return nTotal;
}

CAmount CWallet::GetWatchOnlyBalance() const
{
    CAmount nTotal = 0;
    {
        LOCK2(cs_main, cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it) {
            const CWalletTx* pcoin = &(*it).second;
            if (pcoin->IsTrusted())
                nTotal += pcoin->GetAvailableWatchOnlyCredit();
        }
    }

    return nTotal;
}

CAmount CWallet::GetUnconfirmedWatchOnlyBalance() const
{
    CAmount nTotal = 0;
    {
        LOCK2(cs_main, cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it) {
            const CWalletTx* pcoin = &(*it).second;
            if (!IsFinalTx(*pcoin) || (!pcoin->IsTrusted() && pcoin->GetDepthInMainChain() == 0))
                nTotal += pcoin->GetAvailableWatchOnlyCredit();
        }
    }
    return nTotal;
}

CAmount CWallet::GetImmatureWatchOnlyBalance() const
{
    CAmount nTotal = 0;
    {
        LOCK2(cs_main, cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it) {
            const CWalletTx* pcoin = &(*it).second;
            nTotal += pcoin->GetImmatureWatchOnlyCredit();
        }
    }
    return nTotal;
}

/**
 * populate vCoins with vector of available COutputs.
 */
void CWallet::AvailableCoins(vector<COutput>& vCoins, bool fOnlyConfirmed, const CCoinControl* coinControl, bool fIncludeZeroValue, AvailableCoinsType nCoinType, bool fUseIX)
{
    if (IsLocked()) return;
    vCoins.clear();

    {
        LOCK2(cs_main, cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it) {
            const uint256& wtxid = it->first;
            const CWalletTx* pcoin = &(*it).second;

            int cannotSpend = 0;
            AvailableCoins(wtxid, pcoin, vCoins, cannotSpend, fOnlyConfirmed, coinControl, fIncludeZeroValue, nCoinType, fUseIX);
        }
    }
}

bool CWallet::AvailableCoins(const uint256 wtxid, const CWalletTx* pcoin, vector<COutput>& vCoins, int cannotSpend, bool fOnlyConfirmed, const CCoinControl* coinControl, bool fIncludeZeroValue, AvailableCoinsType nCoinType, bool fUseIX)
{
    if (IsLocked()) return false;
    cannotSpend = 0;
    {
        if (!CheckFinalTx(*pcoin))
            return false;

        if (fOnlyConfirmed && !pcoin->IsTrusted())
            return false;

        if ((pcoin->IsCoinBase() || pcoin->IsCoinStake()) && pcoin->GetBlocksToMaturity() > 0)
            return false;
        int nDepth = pcoin->GetDepthInMainChain(false);
        // do not use IX for inputs that have less then 6 blockchain confirmations
        if (fUseIX && nDepth < 6)
            return false;
        // We should not consider coins which aren't at least in our mempool
        // It's possible for these to be conflicted via ancestors which we may never be able to detect
        if (nDepth <= 0)
            return false;
        for (unsigned int i = 0; i < pcoin->vout.size(); i++) {
            if (pcoin->vout[i].IsEmpty()) {
                cannotSpend++;
                continue;
            }
            bool found = false;
            CAmount value = getCTxOutValue(*pcoin, pcoin->vout[i]);
            if (nCoinType == ONLY_DENOMINATED) {
                found = IsDenominatedAmount(value);
            } else if (nCoinType == ONLY_NOT1000000IFMN) {
                found = !(fMasterNode && value == 1000000 * COIN);
            } else if (nCoinType == ONLY_NONDENOMINATED_NOT1000000IFMN) {
                if (IsCollateralAmount(value)) return false; // do not use collateral amounts
                found = !IsDenominatedAmount(value);
                if (found && fMasterNode) found = value != 1000000 * COIN; // do not use Hot MN funds
            } else if (nCoinType == ONLY_1000000) {
                found = value == 1000000 * COIN;
            } else {
                COutPoint outpoint(pcoin->GetHash(), i);
                if (IsCollateralized(outpoint)) {
                    continue;
                }
                found = true;
            }
            if (!found) continue;

            if (value <= COIN / 10) continue; //dust

            isminetype mine = IsMine(pcoin->vout[i]);
            if (mine == ISMINE_NO)
                continue;
            if (mine == ISMINE_WATCH_ONLY)
                continue;
            if (IsLockedCoin(wtxid, i) && nCoinType != ONLY_1000000)
                continue;
            if (value <= 0 && !fIncludeZeroValue)
                continue;
            if (coinControl && coinControl->HasSelected() && !coinControl->fAllowOtherInputs &&
                !coinControl->IsSelected(wtxid, i))
                continue;

            bool fIsSpendable = false;
            if ((mine & ISMINE_SPENDABLE) != ISMINE_NO)
                fIsSpendable = true;

            if (IsSpent(wtxid, i)) {
                cannotSpend++;
                continue;
            }

            vCoins.emplace_back(COutput(pcoin, i, nDepth, fIsSpendable));
        }
    }
    return true;
}

map<CBitcoinAddress, vector<COutput> > CWallet::AvailableCoinsByAddress(bool fConfirmed, CAmount maxCoinValue)
{
    std::vector<COutput> vCoins;
    AvailableCoins(vCoins, fConfirmed);

    map<CBitcoinAddress, vector<COutput> > mapCoins;
    for (COutput out : vCoins) {
        CAmount value = getCOutPutValue(out);
        if (maxCoinValue > 0 && value > maxCoinValue)
            continue;

        CTxDestination address;
        if (!ExtractDestination(out.tx->vout[out.i].scriptPubKey, address))
            continue;

        mapCoins[CBitcoinAddress(address)].push_back(out);
    }

    return mapCoins;
}

static CAmount ApproximateBestSubset(int numOut, int ringSize, vector<pair<CAmount, pair<const CWalletTx*, unsigned int> > > vValue, const CAmount& nTotalLower, const CAmount& nTargetValue, vector<char>& vfBest, CAmount& nBest, int iterations = 1000)
{
    vector<char> vfIncluded;

    vfBest.assign(vValue.size(), true);
    nBest = nTotalLower;
    int estimateTxSize = 0;
    CAmount nFeeNeeded = 0;
    seed_insecure_rand();

    for (int nRep = 0; nRep < iterations && nBest != nTargetValue + nFeeNeeded; nRep++) {
        vfIncluded.assign(vValue.size(), false);
        CAmount nTotal = 0;
        bool fReachedTarget = false;
        for (int nPass = 0; nPass < 2 && !fReachedTarget; nPass++) {
            int numSelected = 0;
            for (unsigned int i = 0; i < vValue.size(); i++) {
                //The solver here uses a randomized algorithm,
                //the randomness serves no real security purpose but is just
                //needed to prevent degenerate behavior and it is important
                //that the rng is fast. We do not use a constant random sequence,
                //because there may be some privacy improvement by making
                //the selection random.
                if (nPass == 0 ? insecure_rand() & 1 : !vfIncluded[i]) {
                    nTotal += vValue[i].first;
                    vfIncluded[i] = true;
                    numSelected++;
                    estimateTxSize = CWallet::ComputeTxSize(numSelected, numOut, ringSize);
                    nFeeNeeded = CWallet::GetMinimumFee(estimateTxSize, nTxConfirmTarget, mempool);
                    nFeeNeeded += BASE_FEE;
                    if (nTotal >= nTargetValue + nFeeNeeded) {
                        fReachedTarget = true;
                        if (nTotal < nBest) {
                            nBest = nTotal;
                            vfBest = vfIncluded;
                        }
                        nTotal -= vValue[i].first;
                        vfIncluded[i] = false;
                        numSelected--;
                    }
                }
            }
        }
    }
    return nFeeNeeded;
}


// TODO: find appropriate place for this sort function
// move denoms down
bool less_then_denom(const COutput& out1, const COutput& out2)
{
    const CWalletTx* pcoin1 = out1.tx;
    const CWalletTx* pcoin2 = out2.tx;

    bool found1 = false;
    bool found2 = false;
    for (CAmount d : obfuScationDenominations) // loop through predefined denoms
    {
        if (pwalletMain->getCTxOutValue(*pcoin1, pcoin1->vout[out1.i]) == d) found1 = true;
        if (pwalletMain->getCTxOutValue(*pcoin2, pcoin2->vout[out2.i]) == d) found2 = true;
    }
    return (!found1 && found2);
}

bool CWallet::SelectStakeCoins(std::set<std::pair<const CWalletTx*, unsigned int> >& setCoins, CAmount nTargetAmount)
{
    LOCK(cs_main);
    std::vector<COutput> vCoins;
    AvailableCoins(vCoins, true, NULL, false, STAKABLE_COINS);
    CAmount nAmountSelected = 0;

    for (const COutput& out : vCoins) {
        //make sure not to outrun target amount
        CAmount value = getCOutPutValue(out);
        if (nAmountSelected + value > nTargetAmount)
            continue;

        int64_t nTxTime = out.tx->GetTxTime();

        //check for min age
        if (GetAdjustedTime() - nTxTime < nStakeMinAge)
            continue;

        //check that it is matured
        if (out.nDepth < (out.tx->IsCoinStake() ? Params().COINBASE_MATURITY() : 10))
            continue;

        //add to our stake set
        setCoins.insert(make_pair(out.tx, out.i));
        nAmountSelected += value;
    }
    return true;
}

bool CWallet::MintableCoins()
{
    std::vector<COutput> vCoins;

    {
        LOCK2(cs_main, cs_wallet);
        CAmount nBalance = GetBalance();

        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it) {
            const uint256& wtxid = it->first;
            const CWalletTx* pcoin = &(*it).second;

            int cannotSpend = 0;
            {
                AvailableCoins(wtxid, pcoin, vCoins, cannotSpend, true);
                if (!vCoins.empty()) {
                    for (const COutput& out : vCoins) {
                        int64_t nTxTime = out.tx->GetTxTime();
                        //add in-wallet minimum staking
                        CAmount nVal = getCOutPutValue(out);
                        //nTxTime <= nTime: only stake with UTXOs that are received before nTime time
                        if ((GetAdjustedTime() > nStakeMinAge + nTxTime) && (nVal >= MINIMUM_STAKE_AMOUNT))
                            return true;
                    }
                }
            }
        }
    }

    return false;
}

StakingStatusError CWallet::StakingCoinStatus(CAmount& minFee, CAmount& maxFee)
{
    minFee = 0;
    maxFee = 0;
    CAmount nBalance = GetBalance();
    if (nBalance < MINIMUM_STAKE_AMOUNT) {
        return StakingStatusError::UNSTAKABLE_BALANCE_TOO_LOW;
    }
    if (nBalance - nReserveBalance < MINIMUM_STAKE_AMOUNT) {
        return StakingStatusError::UNSTAKABLE_BALANCE_RESERVE_TOO_HIGH;
    }

    std::vector<COutput> vCoins, coinsUnderThreshold, coinsOverThreshold;
    StakingStatusError ret = StakingStatusError::STAKING_OK;
    CAmount nSpendableBalance = GetSpendableBalance();

    {
        LOCK2(cs_main, cs_wallet);
        {
            uint32_t nTime = ReadAutoConsolidateSettingTime();
            nTime = (nTime == 0)? GetAdjustedTime() : nTime;

            for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it) {
                const uint256& wtxid = it->first;
                const CWalletTx* pcoin = &(*it).second;

                {
                    if (!CheckFinalTx(*pcoin))
                        continue;

                    int nDepth = pcoin->GetDepthInMainChain(false);

                    // We should not consider coins which aren't at least in our mempool
                    // It's possible for these to be conflicted via ancestors which we may never be able to detect
                    if (nDepth <= 0)
                        continue;

                    if (pcoin->GetTxTime() > nTime) continue;

                    for (unsigned int i = 0; i < pcoin->vout.size(); i++) {
                        if (pcoin->vout[i].IsEmpty()) {
                            continue;
                        }
                        CAmount value = getCTxOutValue(*pcoin, pcoin->vout[i]);
                        if (value == 1000000 * COIN) {
                            COutPoint outpoint(wtxid, i);
                            if (IsCollateralized(outpoint)) {
                                continue;
                            }
                        }
                        if (value <= COIN / 10) continue; //dust

                        isminetype mine = IsMine(pcoin->vout[i]);
                        if (mine == ISMINE_NO)
                            continue;
                        if (mine == ISMINE_WATCH_ONLY)
                            continue;
                        if (IsLockedCoin(wtxid, i))
                            continue;
                        if (value <= 0)
                            continue;
                        if (IsSpent(wtxid, i)) {
                            continue;
                        }

                        {
                            COutPoint outpoint(wtxid, i);
                            if (inSpendQueueOutpoints.count(outpoint)) {
                                continue;
                            }
                        }
                        COutput out(pcoin, i, nDepth, true);
                        if (value >= MINIMUM_STAKE_AMOUNT) {
                            coinsOverThreshold.push_back(out);
                        } else {
                            coinsUnderThreshold.push_back(out);
                        }

                        vCoins.emplace_back(out);
                    }
                }
            }

            //compute the number of consolidatation transaction will be made
            int numUTXOs = coinsUnderThreshold.size();
            int numConsolidationTxs = numUTXOs > 0? 1:0;
            minFee = ComputeFee(numUTXOs % (MAX_TX_INPUTS + 1), 1, MIN_RING_SIZE);
            maxFee = ComputeFee((numUTXOs >= MAX_TX_INPUTS? MAX_TX_INPUTS : numUTXOs + 1) % (MAX_TX_INPUTS + 1), 1, MAX_RING_SIZE);
            while (numUTXOs > MAX_TX_INPUTS) {
                numUTXOs -= (MAX_TX_INPUTS - 1);
                numConsolidationTxs++;
                minFee += ComputeFee(MAX_TX_INPUTS, 1, MIN_RING_SIZE);
                maxFee += ComputeFee(MAX_TX_INPUTS, 1, MAX_RING_SIZE);
            }

            if (nReserveBalance == 0) {
                if (coinsUnderThreshold.size() == 0) {
                    return StakingStatusError::STAKING_OK;
                } else {
                    if (nBalance < MINIMUM_STAKE_AMOUNT + maxFee) {
                        return StakingStatusError::UNSTAKABLE_BALANCE_TOO_LOW_CONSOLIDATION_FAILED;
                    }
                    return StakingStatusError::STAKABLE_NEED_CONSOLIDATION;
                }
            } else {
                set<pair<const CWalletTx*, unsigned int> > setCoinsRet;
                CAmount nValueRet;
                //check whether need consolidation
                int ringSize = MIN_RING_SIZE + secp256k1_rand32() % (MAX_RING_SIZE - MIN_RING_SIZE + 1);
                CAmount MaxFeeSpendingReserve = ComputeFee(1, 2, MAX_RING_SIZE);
                CAmount estimatedFee = 0;
                bool selectCoinRet = SelectCoinsMinConf(true, estimatedFee, ringSize, 2, nReserveBalance + MaxFeeSpendingReserve, 1, 6, vCoins, setCoinsRet, nValueRet);
                if (!selectCoinRet) {
                    //fail to even select coins to consolidation for reserve funds => ask to reduce
                    return StakingStatusError::UNSTAKABLE_BALANCE_RESERVE_TOO_HIGH_CONSOLIDATION_FAILED;
                }
                minFee += estimatedFee;
                maxFee += estimatedFee;
                return StakingStatusError::STAKABLE_NEED_CONSOLIDATION_WITH_RESERVE_BALANCE;
            }

            /* if (nReserveBalance == 0 && coinsOverThreshold.empty() && nBalance > MINIMUM_STAKE_AMOUNT) {
                if (nSpendableBalance < MINIMUM_STAKE_AMOUNT) {
                    return StakingStatusError::UNSTAKABLE_DUE_TO_CONSILIDATION_FAILED;  //not enough spendable balance
                }
                set<pair<const CWalletTx*, unsigned int> > setCoinsRet;
                CAmount nValueRet;
                int ringSize = MIN_RING_SIZE + secp256k1_rand32() % (MAX_RING_SIZE - MIN_RING_SIZE + 1);
                bool selectCoinRet = SelectCoins(true, ringSize, 1, MINIMUM_STAKE_AMOUNT, setCoinsRet, nValueRet, NULL, AvailableCoinsType::ALL_COINS, false);
                if (!selectCoinRet) {
                    return StakingStatusError::UNSTAKABLE_DUE_TO_CONSILIDATION_FAILED;  //not enough spendable balance
                }

                return StakingStatusError::NEED_CONSOLIDATION_UTXO_UNDER_THRESHOLD;
            }

            if (nReserveBalance > 0) {

            }*/
        }
    }


    return ret;
}

bool CWallet::SelectCoinsMinConf(bool needFee, CAmount& feeNeeded, int ringSize, int numOut, const CAmount& nTargetValue, int nConfMine, int nConfTheirs, std::vector<COutput> vCoins, set<pair<const CWalletTx*, unsigned int> >& setCoinsRet, CAmount& nValueRet)
{
    setCoinsRet.clear();
    nValueRet = 0;
    feeNeeded = 0;
    CAmount feeForOneInput = 0;
    // List of values less than target
    pair<CAmount, pair<const CWalletTx*, unsigned int> > coinLowestLarger;
    coinLowestLarger.first = std::numeric_limits<CAmount>::max();
    coinLowestLarger.second.first = NULL;
    vector<pair<CAmount, pair<const CWalletTx*, unsigned int> > > vValue;
    CAmount nTotalLower = 0;

    random_shuffle(vCoins.begin(), vCoins.end(), GetRandInt);
    // move denoms down on the list
    sort(vCoins.begin(), vCoins.end(), less_then_denom);

    // try to find nondenom first to prevent unneeded spending of mixed coins
    for (unsigned int tryDenom = 0; tryDenom < 2; tryDenom++) {
        if (fDebug) LogPrint("selectcoins", "tryDenom: %d\n", tryDenom);
        vValue.clear();
        nTotalLower = 0;
        for (const COutput& output : vCoins) {
            if (!output.fSpendable)
                continue;

            const CWalletTx* pcoin = output.tx;
            CAmount n = 0;
            if (output.nDepth < (pcoin->IsFromMe(ISMINE_ALL) ? nConfMine : nConfTheirs))
                continue;

            if (!IsSpent(pcoin->GetHash(), output.i)) {
                n = getCTxOutValue(*pcoin, pcoin->vout[output.i]);
            }
            if (n == 0) continue;
            int i = output.i;

            pair<CAmount, pair<const CWalletTx*, unsigned int> > coin = make_pair(n, make_pair(pcoin, i));
            if (needFee) {
                feeNeeded = ComputeFee(vValue.size() + 1, numOut, ringSize);
                feeForOneInput = ComputeFee(1, numOut, ringSize);
            }
            if (n == nTargetValue + feeForOneInput) {
                setCoinsRet.clear();
                setCoinsRet.insert(coin.second);
                nValueRet = coin.first;
                feeNeeded = feeForOneInput;
                return true;
            } else if (n < nTargetValue + feeNeeded) {
                vValue.push_back(coin);
                nTotalLower += n;
            } else if (n < coinLowestLarger.first) {
                coinLowestLarger = coin;
            }
        }

        if (vValue.size() <= MAX_TX_INPUTS) {
            if (nTotalLower == nTargetValue + feeNeeded) {
                for (unsigned int i = 0; i < vValue.size(); ++i) {
                    setCoinsRet.insert(vValue[i].second);
                    nValueRet += vValue[i].first;
                }
                return true;
            }
        }
        if (nTotalLower < nTargetValue + feeNeeded) {
            if (coinLowestLarger.second.first == NULL) // there is no input larger than nTargetValue
            {
                if (tryDenom == 0)
                    // we didn't look at denom yet, let's do it
                    continue;
                else {
                    // we looked at everything possible and didn't find anything, no luck
                    return false;
                }
            }
            setCoinsRet.insert(coinLowestLarger.second);
            nValueRet += coinLowestLarger.first;
            return true;
        } else {
            CAmount maxFee = ComputeFee(50, numOut, ringSize);
            if (vValue.size() <= MAX_TX_INPUTS) {
                //putting all into the transaction
                string s = "CWallet::SelectCoinsMinConf best subset: ";
                for (unsigned int i = 0; i < vValue.size(); i++) {
                    setCoinsRet.insert(vValue[i].second);
                    nValueRet += vValue[i].first;
                    s += FormatMoney(vValue[i].first) + " ";
                }
                LogPrintf("%s - total %s\n", s, FormatMoney(nValueRet));
                return true;
            } else {

            }
        }
        break;
    }

    if (vValue.size() <= MAX_TX_INPUTS) {
        //putting all into the transaction
        string s = "CWallet::SelectCoinsMinConf best subset: ";
        for (unsigned int i = 0; i < vValue.size(); i++) {
            setCoinsRet.insert(vValue[i].second);
            nValueRet += vValue[i].first;
            s += FormatMoney(vValue[i].first) + " ";
        }
        LogPrintf("%s - total %s\n", s, FormatMoney(nValueRet));
        return true;
    }

    // Solve subset sum by stochastic approximation
    sort(vValue.rbegin(), vValue.rend(), CompareValueOnly());
    //fees for 50 inputs
    feeNeeded = ComputeFee(50, numOut, ringSize);
    //check if the sum of first 50 largest UTXOs > nTargetValue + nfeeNeeded
    for (unsigned int i = 0; i <= MAX_TX_INPUTS; i++) {
        nValueRet += vValue[i].first;
    }
    if (nValueRet < nTargetValue + feeNeeded) {
        nValueRet = 0;
        for (unsigned int i = 0; i < vValue.size(); i++) {
            setCoinsRet.insert(vValue[i].second);
        }
        return false; //transaction too large
    }
    nValueRet = 0;

    vector<char> vfBest;
    CAmount nBest;
    feeNeeded = ApproximateBestSubset(numOut, ringSize, vValue, nTotalLower, nTargetValue, vfBest, nBest, 1000);

    // If we have a bigger coin and (either the stochastic approximation didn't find a good solution,
    //                                   or the next bigger coin is closer), return the bigger coin
    if (coinLowestLarger.second.first &&
        ((nBest != nTargetValue + feeNeeded && nBest < nTargetValue + feeNeeded) || coinLowestLarger.first <= nBest)) {
        setCoinsRet.insert(coinLowestLarger.second);
        nValueRet += coinLowestLarger.first;
    } else {
        string s = "CWallet::SelectCoinsMinConf best subset: ";
        for (unsigned int i = 0; i < vValue.size(); i++) {
            if (vfBest[i]) {
                setCoinsRet.insert(vValue[i].second);
                nValueRet += vValue[i].first;
                s += FormatMoney(vValue[i].first) + " ";
            }
        }
        LogPrintf("%s - total %s\n", s, FormatMoney(nBest));
    }

    return true;
}

void CWallet::resetPendingOutPoints()
{
    LOCK2(cs_main, cs_wallet);
    if (chainActive.Height() > 0 && !inSpendQueueOutpoints.empty()) return;
    {
        {
            LOCK(mempool.cs);
            {
                inSpendQueueOutpoints.clear();
                for (std::map<uint256, CTxMemPoolEntry>::const_iterator it = mempool.mapTx.begin(); it != mempool.mapTx.end(); ++it) {
                    const CTransaction& tx = it->second.GetTx();
                    for (size_t i = 0; i < tx.vin.size(); i++) {
                        COutPoint prevout = findMyOutPoint(tx.vin[i]);
                        if (prevout.hash.IsNull()) {
                            break;
                        } else {
                            inSpendQueueOutpoints[prevout] = true;
                        }
                    }
                }
            }
        }
    }
}

bool CWallet::SelectCoins(bool needFee, CAmount& estimatedFee, int ringSize, int numOut, const CAmount& nTargetValue, set<pair<const CWalletTx*, unsigned int> >& setCoinsRet, CAmount& nValueRet, const CCoinControl* coinControl, AvailableCoinsType coin_type, bool useIX)
{
    // Note: this function should never be used for "always free" tx types like dstx
    std::vector<COutput> vCoins;
    vCoins.clear();

    {
        LOCK2(cs_main, cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it) {
            const uint256& wtxid = it->first;
            const CWalletTx* pcoin = &(*it).second;

            int nDepth = pcoin->GetDepthInMainChain(false);
            if ((pcoin->IsCoinBase() || pcoin->IsCoinStake()) && pcoin->GetBlocksToMaturity() > 0)
                continue;
            if (nDepth == 0 && !pcoin->InMempool())
                continue;
            for (size_t i = 0; i < pcoin->vout.size(); i++) {
                if (pcoin->vout[i].IsEmpty()) continue;
                isminetype mine = IsMine(pcoin->vout[i]);
                if (mine == ISMINE_NO)
                    continue;
                if (mine == ISMINE_WATCH_ONLY)
                    continue;
                CAmount decodedAmount;
                CKey decodedBlind;
                RevealTxOutAmount(*pcoin, pcoin->vout[i], decodedAmount, decodedBlind);
                if (decodedAmount == 1000000 * COIN) {
                    COutPoint outpoint(wtxid, i);
                    if (IsCollateralized(outpoint)) {
                        continue;
                    }
                }

                std::vector<unsigned char> commitment;
                if (!decodedBlind.IsValid()) {
                    unsigned char blind[32];
                    CreateCommitmentWithZeroBlind(decodedAmount, blind, commitment);
                } else {
                    CreateCommitment(decodedBlind.begin(), decodedAmount, commitment);
                }
                if (pcoin->vout[i].commitment != commitment) {
                    LogPrintf("%s: Commitment not match hash = %s, i = %d, commitment = %s, recomputed = %s, revealed mask = %s\n", __func__, pcoin->GetHash().GetHex(), i, HexStr(&pcoin->vout[i].commitment[0], &pcoin->vout[i].commitment[0] + 33), HexStr(&commitment[0], &commitment[0] + 33), HexStr(decodedBlind.begin(), decodedBlind.begin() + 32));
                    continue;
                }

                {
                    COutPoint outpoint(wtxid, i);
                    if (inSpendQueueOutpoints.count(outpoint)) {
                        continue;
                    }
                }
                vCoins.push_back(COutput(pcoin, i, nDepth, true));
            }
        }
    }

    // coin control -> return all selected outputs (we want all selected to go into the transaction for sure)
    if (coinControl && coinControl->HasSelected()) {
        for (const COutput& out : vCoins) {
            if (!out.fSpendable)
                continue;

            nValueRet += getCOutPutValue(out);
            setCoinsRet.insert(make_pair(out.tx, out.i));
        }
        return (nValueRet >= nTargetValue);
    }

    return (SelectCoinsMinConf(needFee, estimatedFee, ringSize, numOut, nTargetValue, 1, 6, vCoins, setCoinsRet, nValueRet) ||
            SelectCoinsMinConf(needFee, estimatedFee, ringSize, numOut, nTargetValue, 1, 1, vCoins, setCoinsRet, nValueRet) ||
            (bSpendZeroConfChange && SelectCoinsMinConf(needFee, estimatedFee, ringSize, numOut, nTargetValue, 0, 1, vCoins, setCoinsRet, nValueRet)));
}

bool CWallet::IsCollateralized(const COutPoint& outpoint)
{
    for (CMasternodeConfig::CMasternodeEntry mne : masternodeConfig.getEntries()) {
        if (mne.getTxHash() == outpoint.hash.GetHex() && mne.getOutputIndex() == outpoint.n) {
            return true;
        }
    }
    return false;
}

bool CWallet::IsMasternodeController()
{
    return masternodeConfig.getEntries().size() > 0;
}

bool CWallet::IsCollateralAmount(CAmount nInputAmount) const
{
    return nInputAmount != 0 && nInputAmount % OBFUSCATION_COLLATERAL == 0 && nInputAmount < OBFUSCATION_COLLATERAL * 5 && nInputAmount > OBFUSCATION_COLLATERAL;
}

bool CWallet::GetBudgetSystemCollateralTX(CTransaction& tx, uint256 hash, bool useIX)
{
    CWalletTx wtx;
    if (GetBudgetSystemCollateralTX(wtx, hash, useIX)) {
        tx = (CTransaction)wtx;
        return true;
    }
    return false;
}

bool CWallet::GetBudgetSystemCollateralTX(CWalletTx& tx, uint256 hash, bool useIX)
{
    // make our change address
    CReserveKey reservekey(pwalletMain);

    CScript scriptChange;
    scriptChange << OP_RETURN << ToByteVector(hash);

    CAmount nFeeRet = 0;
    std::string strFail = "";
    vector<pair<CScript, CAmount> > vecSend;
    vecSend.push_back(make_pair(scriptChange, BUDGET_FEE_TX));

    CCoinControl* coinControl = NULL;
    bool success = CreateTransaction(vecSend, tx, reservekey, nFeeRet, strFail, coinControl, ALL_COINS, useIX, (CAmount)0);
    if (!success) {
        LogPrintf("GetBudgetSystemCollateralTX: Error - %s\n", strFail);
        return false;
    }

    return true;
}

bool CWallet::CreateCommitment(const CAmount val, CKey& blind, std::vector<unsigned char>& commitment)
{
    blind.MakeNewKey(true);
    return CreateCommitment(blind.begin(), val, commitment);
}

bool CWallet::CreateCommitmentWithZeroBlind(const CAmount val, unsigned char* pBlind, std::vector<unsigned char>& commitment)
{
    memset(pBlind, 0, 32);
    return CreateCommitment(pBlind, val, commitment);
}

bool CWallet::CreateCommitment(const unsigned char* blind, CAmount val, std::vector<unsigned char>& commitment)
{
    secp256k1_context2* both = GetContext();
    secp256k1_pedersen_commitment commitmentD;
    if (!secp256k1_pedersen_commit(both, &commitmentD, blind, val, &secp256k1_generator_const_h, &secp256k1_generator_const_g)) {
        return false;
    }
    unsigned char output[33];
    if (!secp256k1_pedersen_commitment_serialize(both, output, &commitmentD)) {
        return false;
    }
    std::copy(output, output + 33, std::back_inserter(commitment));
    return true;
}

int CWallet::ComputeTxSize(size_t numIn, size_t numOut, size_t ringSize)
{
    int txinSize = 36 + 4 + 33 + 36 * ringSize;
    int txoutSize = 8 + 35 + 33 + 32 + 32 + 32 + 33;
    int bpSize = numOut == 1 ? 675 : 738;
    int txSize = 4 + numIn * txinSize + numOut * txoutSize + 4 + 1 + 8 + 4 + bpSize + 8 + 32 + (numIn + 1) * (ringSize + 1) * 32 + 33;
    return txSize;
}

//compute the amount that let users send reserve balance
CAmount CWallet::ComputeReserveUTXOAmount() {
    CAmount fee = ComputeFee(1, 2, MAX_RING_SIZE);
    return nReserveBalance + fee;
}

int CWallet::ComputeFee(size_t numIn, size_t numOut, size_t ringSize)
{
    int txSize = ComputeTxSize(numIn, numOut, ringSize);
    CAmount nFeeNeeded = GetMinimumFee(txSize, nTxConfirmTarget, mempool);
    nFeeNeeded += BASE_FEE;
    return nFeeNeeded;
}

bool CWallet::CreateTransactionBulletProof(const CKey& txPrivDes, const CPubKey& recipientViewKey, CScript scriptPubKey, const CAmount& nValue, CWalletTx& wtxNew, CReserveKey& reservekey, CAmount& nFeeRet, std::string& strFailReason, const CCoinControl* coinControl, AvailableCoinsType coin_type, bool useIX, CAmount nFeePay, int ringSize, bool sendtoMyself)
{
    vector<pair<CScript, CAmount> > vecSend;
    vecSend.push_back(make_pair(scriptPubKey, nValue));
    return CreateTransactionBulletProof(txPrivDes, recipientViewKey, vecSend, wtxNew, reservekey, nFeeRet, strFailReason, coinControl, coin_type, useIX, nFeePay, ringSize, sendtoMyself);
}

//settingTime = 0 => auto consolidate on
//settingTime > 0 => only consolidate transactions came before this settingTime
bool CWallet::WriteAutoConsolidateSettingTime(uint32_t settingTime)
{
    return CWalletDB(strWalletFile).WriteAutoConsolidateSettingTime(settingTime);
}

uint32_t CWallet::ReadAutoConsolidateSettingTime()
{
    return CWalletDB(strWalletFile).ReadAutoConsolidateSettingTime();
}

bool CWallet::IsAutoConsolidateOn()
{
    return ReadAutoConsolidateSettingTime() == 0;
}

bool CWallet::CreateTransactionBulletProof(const CKey& txPrivDes, const CPubKey& recipientViewKey, const std::vector<std::pair<CScript, CAmount> >& vecSend, CWalletTx& wtxNew, CReserveKey& reservekey, CAmount& nFeeRet, std::string& strFailReason, const CCoinControl* coinControl, AvailableCoinsType coin_type, bool useIX, CAmount nFeePay, int ringSize, bool tomyself)
{
    if (useIX && nFeePay < CENT) nFeePay = CENT;

    //randomize ring size
    unsigned char rand_seed[16];
    memcpy(rand_seed, txPrivDes.begin(), 16);
    secp256k1_rand_seed(rand_seed);
    ringSize = MIN_RING_SIZE + secp256k1_rand32() % (MAX_RING_SIZE - MIN_RING_SIZE + 1);

    //Currently we only allow transaction with one or two recipients
    //If two, the second recipient is a change output
    if (vecSend.size() > 1) {
        strFailReason = _("Currently the Number of supported recipients must be 1");
        return false;
    }

    CAmount nValue = 0;

    for (const PAIRTYPE(CScript, CAmount) & s : vecSend) {
        if (nValue < 0) {
            strFailReason = _("Transaction amounts must be positive");
            return false;
        }
        nValue += s.second;
    }
    if (vecSend.empty() || nValue < 0) {
        strFailReason = _("Transaction amounts must be positive");
        return false;
    }

    wtxNew.fTimeReceivedIsTxTime = true;
    wtxNew.BindWallet(this);
    CMutableTransaction txNew;
    txNew.hasPaymentID = wtxNew.hasPaymentID;
    txNew.paymentID = wtxNew.paymentID;
    CAmount nSpendableBalance = GetSpendableBalance();
    bool ret = true;
    {
        LOCK2(cs_main, cs_wallet);
        {
            nFeeRet = 0;
            if (nFeePay > 0) nFeeRet = nFeePay;
            unsigned int nBytes = 0;
            int iterations = 0;
            while (true && iterations < 10) {
                iterations++;
                txNew.vin.clear();
                txNew.vout.clear();
                wtxNew.fFromMe = true;

                CAmount nTotalValue = nValue + nFeeRet;
                double dPriority = 0;

                // vouts to the payees
                for (const PAIRTYPE(CScript, CAmount) & s : vecSend) {
                    CTxOut txout(s.second, s.first);
                    CPubKey txPub = txPrivDes.GetPubKey();
                    txPrivKeys.push_back(txPrivDes);
                    std::copy(txPub.begin(), txPub.end(), std::back_inserter(txout.txPub));
                    if (txout.IsDust(::minRelayTxFee)) {
                        strFailReason = _("Transaction amount too small");
                        ret = false;
                        break;
                    }
                    CPubKey sharedSec;
                    ECDHInfo::ComputeSharedSec(txPrivDes, recipientViewKey, sharedSec);
                    EncodeTxOutAmount(txout, txout.nValue, sharedSec.begin());
                    txNew.vout.push_back(txout);
                    nBytes += ::GetSerializeSize(*(CTxOut*)&txout, SER_NETWORK, PROTOCOL_VERSION);
                }

                if (!ret) break;

                // Choose coins to use
                set<pair<const CWalletTx*, unsigned int> > setCoins;
                CAmount nValueIn = 0;
                CAmount estimateFee;
                if (!SelectCoins(true, estimateFee, ringSize, 2, nTotalValue, setCoins, nValueIn, coinControl, coin_type, useIX)) {
                    if (coin_type == ALL_COINS) {
                        if (nSpendableBalance < nTotalValue + estimateFee) {
                            //spendable is less than total + fee
                           if (estimateFee > 0)
                               //fee is greater than 0, causing insufficient funds
                                strFailReason = "Insufficient funds. Transaction requires a fee of " + ValueFromAmountToString(estimateFee);
                            else if (nReserveBalance <= nTotalValue && nReserveBalance != 0)
                               //reserve less than/equal total value
                                strFailReason = "Insufficient reserved funds! Your wallet is staking with a reserve balance of " + ValueFromAmountToString(nReserveBalance) + " less than the sending amount " + ValueFromAmountToString(nTotalValue);
                        } else if (nTotalValue >= nReserveBalance && nReserveBalance != 0) {
                               //total greater than equal to reserve
                                strFailReason = "Insufficient reserved funds! Your wallet is staking with a reserve balance of " + ValueFromAmountToString(nReserveBalance) + " less than the sending amount " + ValueFromAmountToString(nTotalValue);
                        } else if (setCoins.size() > MAX_TX_INPUTS) {
                            //max inputs
                            strFailReason = _("You have attempted to send more than 50 UTXOs in a single transaction. To work around this limitation, please either lower the total amount of the transaction or send two separate transactions with 50% of your total desired amount.");
                        } else {
                            //other
                            strFailReason = _("Error in CreateTransactionBulletProof. Please try again.");
                        }
                    }

                    ret = false;
                    break;
                }

                CAmount nChange = nValueIn - nValue - nFeeRet;

                if (nChange >= 0) {
                    // Fill a vout to ourself
                    CScript scriptChange;
                    scriptChange = GetScriptForDestination(coinControl->receiver);

                    CTxOut newTxOut(nChange, scriptChange);
                    txPrivKeys.push_back(coinControl->txPriv);
                    CPubKey txPubChange = coinControl->txPriv.GetPubKey();
                    std::copy(txPubChange.begin(), txPubChange.end(), std::back_inserter(newTxOut.txPub));
                    nBytes += ::GetSerializeSize(*(CTxOut*)&newTxOut, SER_NETWORK, PROTOCOL_VERSION);
                    //formulae for ring signature size
                    int rsSize = ComputeTxSize(setCoins.size(), 2, ringSize);
                    nBytes = rsSize;
                    CAmount nFeeNeeded = max(nFeePay, GetMinimumFee(nBytes, nTxConfirmTarget, mempool));
                    nFeeNeeded += BASE_FEE;
                    LogPrintf("%s: nFeeNeeded=%d, rsSize=%d\n", __func__, nFeeNeeded, rsSize);
                    if (nFeeNeeded < COIN) nFeeNeeded = COIN;
                    newTxOut.nValue -= nFeeNeeded;
                    txNew.nTxFee = nFeeNeeded;
                    if (newTxOut.nValue < 0) {
                        if (nSpendableBalance > nValueIn) {
                            continue;
                        }
                        ret = false;
                        break;
                    }
                    CPubKey shared;
                    computeSharedSec(txNew, newTxOut, shared);
                    EncodeTxOutAmount(newTxOut, newTxOut.nValue, shared.begin());
                    if (tomyself)
                        txNew.vout.push_back(newTxOut);
                    else {
                        vector<CTxOut>::iterator position = txNew.vout.begin() + GetRandInt(txNew.vout.size() + 1);
                        txNew.vout.insert(position, newTxOut);
                    }
                } else {
                    if (nSpendableBalance > nValueIn) {
                        continue;
                    }
                    ret = false;
                    break;
                }

                // Fill vin
                for (const PAIRTYPE(const CWalletTx*, unsigned int) & coin : setCoins)
                    txNew.vin.push_back(CTxIn(coin.first->GetHash(), coin.second));

                // Embed the constructed transaction data in wtxNew.
                *static_cast<CTransaction*>(&wtxNew) = CTransaction(txNew);
                break;
            }
            if (ret && !makeRingCT(wtxNew, ringSize, strFailReason)) {
                ret = false;
            }

            if (ret && !generateBulletProofAggregate(wtxNew)) {
                strFailReason = _("Failed to generate bulletproof");
                ret = false;
            }

            if (ret) {
                //set transaction output amounts as 0
                for (size_t i = 0; i < wtxNew.vout.size(); i++) {
                    wtxNew.vout[i].nValue = 0;
                }

                if (!CommitTransaction(wtxNew, reservekey, (!useIX ? "tx" : "ix"))) {
                    inSpendQueueOutpointsPerSession.clear();
                    ret = false;
                    strFailReason = _("Error: The transaction was rejected! This might happen if some of the coins in your wallet were already spent, such as if you used a copy of wallet.dat and coins were spent in the copy but not marked as spent here.");
                }
                for (size_t i = 0; i < inSpendQueueOutpointsPerSession.size(); i++) {
                    inSpendQueueOutpoints[inSpendQueueOutpointsPerSession[i]] = true;
                }
                inSpendQueueOutpointsPerSession.clear();

                uint256 hash = wtxNew.GetHash();
                int maxTxPrivKeys = txPrivKeys.size() > wtxNew.vout.size() ? wtxNew.vout.size() : txPrivKeys.size();
                for (int i = 0; i < maxTxPrivKeys; i++) {
                    std::string key = hash.GetHex() + std::to_string(i);
                    CWalletDB(strWalletFile).WriteTxPrivateKey(key, CBitcoinSecret(txPrivKeys[i]).ToString());
                }
                txPrivKeys.clear();
            }
        }
    }

    return ret;
}

bool CWallet::CreateTransaction(const vector<pair<CScript, CAmount> >& vecSend,
    CWalletTx& wtxNew,
    CReserveKey& reservekey,
    CAmount& nFeeRet,
    std::string& strFailReason,
    const CCoinControl* coinControl,
    AvailableCoinsType coin_type,
    bool useIX,
    CAmount nFeePay)
{
    if (useIX && nFeePay < CENT) nFeePay = CENT;

    CAmount nValue = 0;

    for (const PAIRTYPE(CScript, CAmount) & s : vecSend) {
        if (nValue < 0) {
            strFailReason = _("Transaction amounts must be positive");
            return false;
        }
        nValue += s.second;
    }
    if (vecSend.empty() || nValue < 0) {
        strFailReason = _("Transaction amounts must be positive");
        return false;
    }

    wtxNew.fTimeReceivedIsTxTime = true;
    wtxNew.BindWallet(this);
    CMutableTransaction txNew;
    txNew.hasPaymentID = wtxNew.hasPaymentID;
    txNew.paymentID = wtxNew.paymentID;
    wtxNew.txType = TX_TYPE_REVEAL_AMOUNT;
    txNew.txType = TX_TYPE_REVEAL_AMOUNT;
    txNew.nTxFee = wtxNew.nTxFee;

    {
        LOCK2(cs_main, cs_wallet);
        {
            nFeeRet = txNew.nTxFee;
            if (nFeePay > 0) nFeeRet = nFeePay;
            while (true) {
                txNew.vin.clear();
                txNew.vout.clear();
                wtxNew.fFromMe = true;

                CAmount nTotalValue = nValue + nFeeRet;
                double dPriority = 0;

                // vouts to the payees
                if (coinControl && !coinControl->fSplitBlock) {
                    for (const PAIRTYPE(CScript, CAmount) & s : vecSend) {
                        CTxOut txout(s.second, s.first);
                        if (txout.IsDust(::minRelayTxFee)) {
                            strFailReason = _("Transaction amount too small");
                            return false;
                        }
                        txNew.vout.push_back(txout);
                    }
                } else //UTXO Splitter Transaction
                {
                    int nSplitBlock;

                    if (coinControl)
                        nSplitBlock = coinControl->nSplitBlock;
                    else
                        nSplitBlock = 1;

                    for (const PAIRTYPE(CScript, CAmount) & s : vecSend) {
                        for (int i = 0; i < nSplitBlock; i++) {
                            if (i == nSplitBlock - 1) {
                                uint64_t nRemainder = s.second % nSplitBlock;
                                txNew.vout.push_back(CTxOut((s.second / nSplitBlock) + nRemainder, s.first));
                            } else
                                txNew.vout.push_back(CTxOut(s.second / nSplitBlock, s.first));
                        }
                    }
                }

                // Choose coins to use
                set<pair<const CWalletTx*, unsigned int> > setCoins;
                CAmount nValueIn = 0;
                CAmount estimatedFee = 0;
                if (!SelectCoins(true, estimatedFee, 10, 2, nTotalValue, setCoins, nValueIn, coinControl, coin_type, useIX)) {
                    if (coin_type == ALL_COINS) {
                        strFailReason = _("Insufficient funds.");
                    } else if (coin_type == ONLY_NOT1000000IFMN) {
                        strFailReason = _("Unable to locate enough funds for this transaction that are not equal 10000 DAPS.");
                    } else {
                        strFailReason = _("Error in CreateTransaction. Please try again.");
                    }

                    return false;
                }


                for (PAIRTYPE(const CWalletTx*, unsigned int) pcoin : setCoins) {
                    CAmount nCredit = pcoin.first->vout[pcoin.second].nValue;
                    //The coin age after the next block (depth+1) is used instead of the current,
                    //reflecting an assumption the user would accept a bit more delay for
                    //a chance at a free transaction.
                    //But mempool inputs might still be in the mempool, so their age stays 0
                    int age = pcoin.first->GetDepthInMainChain();
                    if (age != 0)
                        age += 1;
                    dPriority += (double)nCredit * age;
                }

                CAmount nChange = nValueIn - nValue - nFeeRet;

                //over pay for denominated transactions
                if (coin_type == ONLY_DENOMINATED) {
                    nFeeRet += nChange;
                    nChange = 0;
                    wtxNew.mapValue["DS"] = "1";
                }

                if (nChange > 0) {
                    // Fill a vout to ourself
                    // TODO: pass in scriptChange instead of reservekey so
                    // change transaction isn't always pay-to-dapscoin-address
                    CScript scriptChange;

                    // coin control: send change to custom address

                    // Note: We use a new key here to keep it from being obvious which side is the change.
                    //  The drawback is that by not reusing a previous key, the change may be lost if a
                    //  backup is restored, if the backup doesn't have the new private key for the change.
                    //  If we reused the old key, it would be possible to add code to look for and
                    //  rediscover unknown transactions that were written with keys of ours to recover
                    //  post-backup change.

                    // Reserve a new key pair from key pool
                    CPubKey vchPubKey;
                    bool ret;
                    ret = reservekey.GetReservedKey(vchPubKey);
                    assert(ret); // should never fail, as we just unlocked

                    scriptChange = GetScriptForDestination(vchPubKey);

                    CTxOut newTxOut(nChange, scriptChange);

                    // Never create dust outputs; if we would, just
                    // add the dust to the fee.
                    if (newTxOut.IsDust(::minRelayTxFee)) {
                        nFeeRet += nChange;
                        nChange = 0;
                        reservekey.ReturnKey();
                    } else {
                        // Insert change txn at random position:
                        vector<CTxOut>::iterator position = txNew.vout.begin() + GetRandInt(txNew.vout.size() + 1);
                        txNew.vout.insert(position, newTxOut);
                    }
                } else
                    reservekey.ReturnKey();

                // Fill vin
                for (const PAIRTYPE(const CWalletTx*, unsigned int) & coin : setCoins)
                    txNew.vin.push_back(CTxIn(coin.first->GetHash(), coin.second));

                // Sign
                int nIn = 0;
                for (const PAIRTYPE(const CWalletTx*, unsigned int) & coin : setCoins)
                    if (!SignSignature(*this, *coin.first, txNew, nIn++)) {
                        strFailReason = _("Signing transaction failed");
                        return false;
                    }
                // Embed the constructed transaction data in wtxNew.
                *static_cast<CTransaction*>(&wtxNew) = CTransaction(txNew);

                // Limit size
                unsigned int nBytes = ::GetSerializeSize(*(CTransaction*)&wtxNew, SER_NETWORK, PROTOCOL_VERSION);
                if (nBytes >= MAX_STANDARD_TX_SIZE) {
                    strFailReason = _("Transaction too large");
                    return false;
                }
                dPriority = wtxNew.ComputePriority(dPriority, nBytes);

                // Can we complete this as a free transaction?
                if (fSendFreeTransactions && nBytes <= MAX_FREE_TRANSACTION_CREATE_SIZE) {
                    // Not enough fee: enough priority?
                    double dPriorityNeeded = mempool.estimatePriority(nTxConfirmTarget);
                    // Not enough mempool history to estimate: use hard-coded AllowFree.
                    if (dPriorityNeeded <= 0 && AllowFree(dPriority))
                        break;

                    // Small enough, and priority high enough, to send for free
                    if (dPriorityNeeded > 0 && dPriority >= dPriorityNeeded)
                        break;
                }

                CAmount nFeeNeeded = max(nFeePay, GetMinimumFee(nBytes, nTxConfirmTarget, mempool));

                // If we made it here and we aren't even able to meet the relay fee on the next pass, give up
                // because we must be at the maximum allowed fee.
                if (nFeeNeeded < ::minRelayTxFee.GetFee(nBytes)) {
                    strFailReason = _("Transaction too large for fee policy");
                    return false;
                }

                break;
            }
        }
    }
    return true;
}

bool CWallet::generateBulletProofAggregate(CTransaction& tx)
{
    unsigned char proof[2000];
    size_t len = 2000;
    const size_t MAX_VOUT = 5;
    unsigned char nonce[32];
    GetRandBytes(nonce, 32);
    unsigned char blinds[MAX_VOUT][32];
    uint64_t values[MAX_VOUT];
    size_t i = 0;
    const unsigned char* blind_ptr[MAX_VOUT];
    if (tx.vout.size() > MAX_VOUT) return false;
    memset(blinds, 0, tx.vout.size() * 32);
    for (i = 0; i < tx.vout.size(); i++) {
        memcpy(&blinds[i][0], tx.vout[i].maskValue.inMemoryRawBind.begin(), 32);
        blind_ptr[i] = blinds[i];
        values[i] = tx.vout[i].nValue;
    }
    int ret = secp256k1_bulletproof_rangeproof_prove(GetContext(), GetScratch(), GetGenerator(), proof, &len, values, NULL, blind_ptr, tx.vout.size(), &secp256k1_generator_const_h, 64, nonce, NULL, 0);
    std::copy(proof, proof + len, std::back_inserter(tx.bulletproofs));
    return ret;
}

bool CWallet::makeRingCT(CTransaction& wtxNew, int ringSize, std::string& strFailReason)
{
    LogPrintf("Making RingCT using ring size=%d\n", ringSize);
    int myIndex;
    if (!selectDecoysAndRealIndex(wtxNew, myIndex, ringSize)) {
        return false;
    }
    secp256k1_context2* both = GetContext();

    for (CTxOut& out : wtxNew.vout) {
        if (!out.IsEmpty()) {
            secp256k1_pedersen_commitment commitment;
            CKey blind;
            blind.Set(out.maskValue.inMemoryRawBind.begin(), out.maskValue.inMemoryRawBind.end(), true);
            if (!secp256k1_pedersen_commit(both, &commitment, blind.begin(), out.nValue, &secp256k1_generator_const_h, &secp256k1_generator_const_g))
                throw runtime_error("Cannot commit commitment");
            unsigned char output[33];
            if (!secp256k1_pedersen_commitment_serialize(both, output, &commitment))
                throw runtime_error("Cannot serialize commitment");
            out.commitment.clear();
            std::copy(output, output + 33, std::back_inserter(out.commitment));
        }
    }

    const size_t MAX_VIN = MAX_TX_INPUTS;
    const size_t MAX_DECOYS = MAX_RING_SIZE; //padding 1 for safety reasons
    const size_t MAX_VOUT = 5;

    if (wtxNew.vin.size() > MAX_TX_INPUTS || wtxNew.vin.size() == 0) {
        strFailReason = _("You have attempted to send a total value that is comprised of more than 50 smaller deposits. This is a rare occurrence, and lowering the total value sent, or sending the same total value in two separate transactions will usually work around this limitation.");
        return false;
    }

    for (size_t i = 0; i < wtxNew.vin.size(); i++) {
        if (wtxNew.vin[i].decoys.size() != wtxNew.vin[0].decoys.size()) {
            strFailReason = _("All inputs should have the same number of decoys");
            return false;
        }
    }

    if (wtxNew.vin[0].decoys.size() > MAX_DECOYS || wtxNew.vin[0].decoys.size() < MIN_RING_SIZE) {
        strFailReason = _("Too many decoys");
        return false; //maximum decoys = 15
    }

    std::vector<secp256k1_pedersen_commitment> myInputCommiments;
    int totalCommits = wtxNew.vin.size() + wtxNew.vout.size();
    int npositive = wtxNew.vin.size();
    unsigned char myBlinds[MAX_VIN + MAX_VIN + MAX_VOUT + 1][32]; //myBlinds is used for compuitng additional private key in the ring =
    memset(myBlinds, 0, (MAX_VIN + MAX_VIN + MAX_VOUT + 1) * 32);
    const unsigned char* bptr[MAX_VIN + MAX_VIN + MAX_VOUT + 1];
    //all in pubkeys + an additional public generated from commitments
    unsigned char allInPubKeys[MAX_VIN + 1][MAX_DECOYS + 1][33];
    unsigned char allKeyImages[MAX_VIN + 1][33];
    unsigned char allInCommitments[MAX_VIN][MAX_DECOYS + 1][33];
    unsigned char allOutCommitments[MAX_VOUT][33];

    int myBlindsIdx = 0;
    //additional member in the ring = Sum of All input public keys + sum of all input commitments - sum of all output commitments
    for (size_t j = 0; j < wtxNew.vin.size(); j++) {
        COutPoint myOutpoint;
        if (myIndex == -1) {
            myOutpoint = wtxNew.vin[j].prevout;
        } else {
            myOutpoint = wtxNew.vin[j].decoys[myIndex];
        }
        CTransaction& inTx = mapWallet[myOutpoint.hash];
        CKey tmp;
        if (!findCorrespondingPrivateKey(inTx.vout[myOutpoint.n], tmp))
            throw runtime_error("Cannot find private key corresponding to the input");
        memcpy(&myBlinds[myBlindsIdx][0], tmp.begin(), 32);
        bptr[myBlindsIdx] = &myBlinds[myBlindsIdx][0];
        myBlindsIdx++;
    }

    //Collecting input commitments blinding factors
    for (CTxIn& in : wtxNew.vin) {
        COutPoint myOutpoint;
        if (myIndex == -1) {
            myOutpoint = in.prevout;
        } else {
            myOutpoint = in.decoys[myIndex];
        }
        CTransaction& inTx = mapWallet[myOutpoint.hash];
        secp256k1_pedersen_commitment inCommitment;
        if (!secp256k1_pedersen_commitment_parse(both, &inCommitment, &(inTx.vout[myOutpoint.n].commitment[0]))) {
            strFailReason = _("Cannot parse the commitment for inputs");
            return false;
        }

        myInputCommiments.push_back(inCommitment);
        CAmount tempAmount;
        CKey tmp;
        RevealTxOutAmount(inTx, inTx.vout[myOutpoint.n], tempAmount, tmp);
        if (tmp.IsValid()) memcpy(&myBlinds[myBlindsIdx][0], tmp.begin(), 32);
        //verify input commitments
        std::vector<unsigned char> recomputedCommitment;
        if (!CreateCommitment(&myBlinds[myBlindsIdx][0], tempAmount, recomputedCommitment))
            throw runtime_error("Cannot create pedersen commitment");
        if (recomputedCommitment != inTx.vout[myOutpoint.n].commitment) {
            strFailReason = _("Input commitments are not correct");
            return false;
        }

        bptr[myBlindsIdx] = myBlinds[myBlindsIdx];
        myBlindsIdx++;
    }

    //collecting output commitment blinding factors
    for (CTxOut& out : wtxNew.vout) {
        if (!out.IsEmpty()) {
            if (out.maskValue.inMemoryRawBind.IsValid()) {
                memcpy(&myBlinds[myBlindsIdx][0], out.maskValue.inMemoryRawBind.begin(), 32);
            }
            bptr[myBlindsIdx] = &myBlinds[myBlindsIdx][0];
            myBlindsIdx++;
        }
    }
    CKey newBlind;
    newBlind.MakeNewKey(true);
    memcpy(&myBlinds[myBlindsIdx][0], newBlind.begin(), 32);
    bptr[myBlindsIdx] = &myBlinds[myBlindsIdx][0];

    int myRealIndex = 0;
    if (myIndex != -1) {
        myRealIndex = myIndex + 1;
    }

    int PI = myRealIndex;
    unsigned char SIJ[MAX_VIN + 1][MAX_DECOYS + 1][32];
    unsigned char LIJ[MAX_VIN + 1][MAX_DECOYS + 1][33];
    unsigned char RIJ[MAX_VIN + 1][MAX_DECOYS + 1][33];
    unsigned char ALPHA[MAX_VIN + 1][32];
    unsigned char AllPrivKeys[MAX_VIN + 1][32];

    //generating LIJ and RIJ at PI: LIJ[j][PI], RIJ[j][PI], j=0..wtxNew.vin.size()
    for (size_t j = 0; j < wtxNew.vin.size(); j++) {
        COutPoint myOutpoint;
        if (myIndex == -1) {
            myOutpoint = wtxNew.vin[j].prevout;
        } else {
            myOutpoint = wtxNew.vin[j].decoys[myIndex];
        }
        CTransaction& inTx = mapWallet[myOutpoint.hash];
        CKey tempPk;
        //looking for private keys corresponding to my real inputs
        if (!findCorrespondingPrivateKey(inTx.vout[myOutpoint.n], tempPk)) {
            strFailReason = _("Cannot find corresponding private key");
            return false;
        }
        memcpy(AllPrivKeys[j], tempPk.begin(), 32);
        //copying corresponding key images
        memcpy(allKeyImages[j], wtxNew.vin[j].keyImage.begin(), 33);
        //copying corresponding in public keys
        CPubKey tempPubKey = tempPk.GetPubKey();
        memcpy(allInPubKeys[j][PI], tempPubKey.begin(), 33);

        memcpy(allInCommitments[j][PI], &(inTx.vout[myOutpoint.n].commitment[0]), 33);
        CKey alpha;
        alpha.MakeNewKey(true);
        memcpy(ALPHA[j], alpha.begin(), 32);
        CPubKey LIJ_PI = alpha.GetPubKey();
        memcpy(LIJ[j][PI], LIJ_PI.begin(), 33);
        PointHashingSuccessively(tempPubKey, alpha.begin(), RIJ[j][PI]);
    }

    //computing additional input pubkey and key images
    //additional private key = sum of all existing private keys + sum of all blinds in - sum of all blind outs
    unsigned char outSum[32];
    if (!secp256k1_pedersen_blind_sum(both, outSum, (const unsigned char* const*)bptr, npositive + totalCommits, 2 * npositive))
        throw runtime_error("Cannot compute pedersen blind sum");
    memcpy(myBlinds[myBlindsIdx], outSum, 32);
    memcpy(AllPrivKeys[wtxNew.vin.size()], outSum, 32);
    CKey additionalPkKey;
    additionalPkKey.Set(myBlinds[myBlindsIdx], myBlinds[myBlindsIdx] + 32, true);
    CPubKey additionalPubKey = additionalPkKey.GetPubKey();
    memcpy(allInPubKeys[wtxNew.vin.size()][PI], additionalPubKey.begin(), 33);
    PointHashingSuccessively(additionalPubKey, myBlinds[myBlindsIdx], allKeyImages[wtxNew.vin.size()]);

    //verify that additional public key = sum of wtx.vin.size() real public keys + sum of wtx.vin.size() commitments - sum of wtx.vout.size() commitments - commitment to zero of transction fee

    //filling LIJ & RIJ at [j][PI]
    CKey alpha_additional;
    alpha_additional.MakeNewKey(true);
    memcpy(ALPHA[wtxNew.vin.size()], alpha_additional.begin(), 32);
    CPubKey LIJ_PI_additional = alpha_additional.GetPubKey();
    memcpy(LIJ[wtxNew.vin.size()][PI], LIJ_PI_additional.begin(), 33);
    PointHashingSuccessively(additionalPubKey, alpha_additional.begin(), RIJ[wtxNew.vin.size()][PI]);

    //Initialize SIJ except S[..][PI]
    for (int i = 0; i < (int)wtxNew.vin.size() + 1; i++) {
        for (int j = 0; j < (int)wtxNew.vin[0].decoys.size() + 1; j++) {
            if (j != PI) {
                CKey randGen;
                randGen.MakeNewKey(true);
                memcpy(SIJ[i][j], randGen.begin(), 32);
            }
        }
    }

    //extract all public keys
    for (int i = 0; i < (int)wtxNew.vin.size(); i++) {
        std::vector<COutPoint> decoysForIn;
        decoysForIn.push_back(wtxNew.vin[i].prevout);
        for (int j = 0; j < (int)wtxNew.vin[i].decoys.size(); j++) {
            decoysForIn.push_back(wtxNew.vin[i].decoys[j]);
        }
        for (int j = 0; j < (int)wtxNew.vin[0].decoys.size() + 1; j++) {
            if (j != PI) {
                CTransaction txPrev;
                uint256 hashBlock;
                if (!GetTransaction(decoysForIn[j].hash, txPrev, hashBlock)) {
                    return false;
                }
                CPubKey extractedPub;
                if (!ExtractPubKey(txPrev.vout[decoysForIn[j].n].scriptPubKey, extractedPub)) {
                    strFailReason = _("Cannot extract public key from script pubkey");
                    return false;
                }
                memcpy(allInPubKeys[i][j], extractedPub.begin(), 33);
                memcpy(allInCommitments[i][j], &(txPrev.vout[decoysForIn[j].n].commitment[0]), 33);
            }
        }
    }

    secp256k1_pedersen_commitment allInCommitmentsPacked[MAX_VIN][MAX_DECOYS + 1];
    secp256k1_pedersen_commitment allOutCommitmentsPacked[MAX_VOUT + 1]; //+1 for tx fee

    for (size_t i = 0; i < wtxNew.vout.size(); i++) {
        memcpy(&(allOutCommitments[i][0]), &(wtxNew.vout[i].commitment[0]), 33);
        if (!secp256k1_pedersen_commitment_parse(both, &allOutCommitmentsPacked[i], allOutCommitments[i])) {
            strFailReason = _("Cannot parse the commitment for inputs");
            return false;
        }
    }

    //commitment to tx fee, blind = 0
    unsigned char txFeeBlind[32];
    memset(txFeeBlind, 0, 32);
    if (!secp256k1_pedersen_commit(both, &allOutCommitmentsPacked[wtxNew.vout.size()], txFeeBlind, wtxNew.nTxFee, &secp256k1_generator_const_h, &secp256k1_generator_const_g)) {
        strFailReason = _("Cannot parse the commitment for transaction fee");
        return false;
    }

    //filling the additional pubkey elements for decoys: allInPubKeys[wtxNew.vin.size()][..]
    //allInPubKeys[wtxNew.vin.size()][j] = sum of allInPubKeys[..][j] + sum of allInCommitments[..][j] - sum of allOutCommitments
    const secp256k1_pedersen_commitment* outCptr[MAX_VOUT + 1];
    for (size_t i = 0; i < wtxNew.vout.size() + 1; i++) {
        outCptr[i] = &allOutCommitmentsPacked[i];
    }
    secp256k1_pedersen_commitment inPubKeysToCommitments[MAX_VIN][MAX_DECOYS + 1];
    for (int i = 0; i < (int)wtxNew.vin.size(); i++) {
        for (int j = 0; j < (int)wtxNew.vin[0].decoys.size() + 1; j++) {
            secp256k1_pedersen_serialized_pubkey_to_commitment(allInPubKeys[i][j], 33, &inPubKeysToCommitments[i][j]);
        }
    }

    for (int j = 0; j < (int)wtxNew.vin[0].decoys.size() + 1; j++) {
        if (j != PI) {
            const secp256k1_pedersen_commitment* inCptr[MAX_VIN * 2];
            for (int k = 0; k < (int)wtxNew.vin.size(); k++) {
                if (!secp256k1_pedersen_commitment_parse(both, &allInCommitmentsPacked[k][j], allInCommitments[k][j])) {
                    strFailReason = _("Cannot parse the commitment for inputs");
                    return false;
                }
                inCptr[k] = &allInCommitmentsPacked[k][j];
            }
            for (size_t k = wtxNew.vin.size(); k < 2 * wtxNew.vin.size(); k++) {
                inCptr[k] = &inPubKeysToCommitments[k - wtxNew.vin.size()][j];
            }
            secp256k1_pedersen_commitment out;
            size_t length;
            //convert allInPubKeys to pederson commitment to compute sum of all in public keys
            if (!secp256k1_pedersen_commitment_sum(both, inCptr, wtxNew.vin.size() * 2, outCptr, wtxNew.vout.size() + 1, &out))
                throw runtime_error("Cannot compute sum of commitment");
            if (!secp256k1_pedersen_commitment_to_serialized_pubkey(&out, allInPubKeys[wtxNew.vin.size()][j], &length))
                throw runtime_error("Cannot covert from commitment to public key");
        }
    }

    //Computing C
    int PI_interator = PI + 1; //PI_interator: PI + 1 .. wtxNew.vin[0].decoys.size() + 1 .. PI
    //unsigned char SIJ[wtxNew.vin.size() + 1][wtxNew.vin[0].decoys.size() + 1][32];
    //unsigned char LIJ[wtxNew.vin.size() + 1][wtxNew.vin[0].decoys.size() + 1][33];
    //unsigned char RIJ[wtxNew.vin.size() + 1][wtxNew.vin[0].decoys.size() + 1][33];
    unsigned char CI[MAX_DECOYS + 1][32];
    unsigned char tempForHash[2 * (MAX_VIN + 1) * 33 + 32];
    unsigned char* tempForHashPtr = tempForHash;
    for (size_t i = 0; i < wtxNew.vin.size() + 1; i++) {
        memcpy(tempForHashPtr, &LIJ[i][PI][0], 33);
        tempForHashPtr += 33;
        memcpy(tempForHashPtr, &RIJ[i][PI][0], 33);
        tempForHashPtr += 33;
    }
    uint256 ctsHash = GetTxSignatureHash(wtxNew);
    memcpy(tempForHashPtr, ctsHash.begin(), 32);

    if (PI_interator == (int)wtxNew.vin[0].decoys.size() + 1) PI_interator = 0;
    uint256 temppi1 = Hash(tempForHash, tempForHash + 2 * (wtxNew.vin.size() + 1) * 33 + 32);
    if (PI_interator == 0) {
        memcpy(CI[0], temppi1.begin(), 32);
    } else {
        memcpy(CI[PI_interator], temppi1.begin(), 32);
    }

    while (PI_interator != PI) {
        for (int j = 0; j < (int)wtxNew.vin.size() + 1; j++) {
            //compute LIJ
            unsigned char CP[33];
            memcpy(CP, allInPubKeys[j][PI_interator], 33);
            if (!secp256k1_ec_pubkey_tweak_mul(CP, 33, CI[PI_interator])) {
                strFailReason = _("Cannot compute LIJ for ring signature in secp256k1_ec_pubkey_tweak_mul");
                return false;
            }
            if (!secp256k1_ec_pubkey_tweak_add(CP, 33, SIJ[j][PI_interator])) {
                strFailReason = _("Cannot compute LIJ for ring signature in secp256k1_ec_pubkey_tweak_add");
                return false;
            }
            memcpy(LIJ[j][PI_interator], CP, 33);

            //compute RIJ
            //first compute CI * I
            memcpy(RIJ[j][PI_interator], allKeyImages[j], 33);
            if (!secp256k1_ec_pubkey_tweak_mul(RIJ[j][PI_interator], 33, CI[PI_interator])) {
                strFailReason = _("Cannot compute RIJ for ring signature in secp256k1_ec_pubkey_tweak_mul");
                return false;
            }

            //compute S*H(P)
            unsigned char SHP[33];
            CPubKey tempP;
            tempP.Set(allInPubKeys[j][PI_interator], allInPubKeys[j][PI_interator] + 33);
            PointHashingSuccessively(tempP, SIJ[j][PI_interator], SHP);
            //convert shp into commitment
            secp256k1_pedersen_commitment SHP_commitment;
            secp256k1_pedersen_serialized_pubkey_to_commitment(SHP, 33, &SHP_commitment);

            //convert CI*I into commitment
            secp256k1_pedersen_commitment cii_commitment;
            secp256k1_pedersen_serialized_pubkey_to_commitment(RIJ[j][PI_interator], 33, &cii_commitment);

            const secp256k1_pedersen_commitment* twoElements[2];
            twoElements[0] = &SHP_commitment;
            twoElements[1] = &cii_commitment;

            secp256k1_pedersen_commitment sum;
            if (!secp256k1_pedersen_commitment_sum_pos(both, twoElements, 2, &sum))
                throw runtime_error("Cannot compute sum of commitments");
            size_t tempLength;
            if (!secp256k1_pedersen_commitment_to_serialized_pubkey(&sum, RIJ[j][PI_interator], &tempLength)) {
                strFailReason = _("Cannot compute two elements and serialize it to pubkey");
            }
        }

        PI_interator++;
        if (PI_interator == (int)wtxNew.vin[0].decoys.size() + 1) PI_interator = 0;

        int prev, ciIdx;
        if (PI_interator == 0) {
            prev = wtxNew.vin[0].decoys.size();
            ciIdx = 0;
        } else {
            prev = PI_interator - 1;
            ciIdx = PI_interator;
        }

        tempForHashPtr = tempForHash;
        for (int i = 0; i < (int)wtxNew.vin.size() + 1; i++) {
            memcpy(tempForHashPtr, LIJ[i][prev], 33);
            tempForHashPtr += 33;
            memcpy(tempForHashPtr, RIJ[i][prev], 33);
            tempForHashPtr += 33;
        }
        memcpy(tempForHashPtr, ctsHash.begin(), 32);
        uint256 ciHashTmp = Hash(tempForHash, tempForHash + 2 * (wtxNew.vin.size() + 1) * 33 + 32);
        memcpy(CI[ciIdx], ciHashTmp.begin(), 32);
    }

    //compute S[j][PI] = alpha_j - c_pi * x_j, x_j = private key corresponding to key image I
    for (size_t j = 0; j < wtxNew.vin.size() + 1; j++) {
        unsigned char cx[32];
        memcpy(cx, CI[PI], 32);
        if (!secp256k1_ec_privkey_tweak_mul(cx, AllPrivKeys[j]))
            throw runtime_error("Cannot compute EC mul");
        const unsigned char* sumArray[2];
        sumArray[0] = ALPHA[j];
        sumArray[1] = cx;
        if (!secp256k1_pedersen_blind_sum(both, SIJ[j][PI], sumArray, 2, 1))
            throw runtime_error("Cannot compute pedersen blind sum");
    }
    memcpy(wtxNew.c.begin(), CI[0], 32);
    //i for decoy index => PI
    for (int i = 0; i < (int)wtxNew.vin[0].decoys.size() + 1; i++) {
        std::vector<uint256> S_column;
        for (int j = 0; j < (int)wtxNew.vin.size() + 1; j++) {
            uint256 t;
            memcpy(t.begin(), SIJ[j][i], 32);
            S_column.push_back(t);
        }
        wtxNew.S.push_back(S_column);
    }
    wtxNew.ntxFeeKeyImage.Set(allKeyImages[wtxNew.vin.size()], allKeyImages[wtxNew.vin.size()] + 33);
    return true;
}

bool CWallet::MakeShnorrSignature(CTransaction& wtxNew)
{
    LOCK(cs_wallet);
    {
        if (wtxNew.IsCoinAudit() || wtxNew.IsCoinBase()) return true;
        //this only generates shnorr signature if either wtxNew is a staking transaction or wtxNew only spends collateralized
        if (!wtxNew.IsCoinStake()) return true;

        //generate shnorr per input
        uint256 ctsHash = GetTxInSignatureHash(wtxNew.vin[0]);

        return MakeShnorrSignatureTxIn(wtxNew.vin[0], ctsHash);
    }
}

bool CWallet::MakeShnorrSignatureTxIn(CTxIn& txin, uint256 cts)
{
    COutPoint prevout = txin.prevout;
    const CTransaction& prev = mapWallet[prevout.hash];
    CTxOut out = prev.vout[prevout.n];
    CKey pk;
    if (!findCorrespondingPrivateKey(out, pk)) {
        return false;
    }
    CPubKey P = pk.GetPubKey();

    unsigned char R[33];
    CKey r;
    r.MakeNewKey(true);
    PointHashingSuccessively(P, r.begin(), R);
    unsigned char buff[33 + 32];
    memcpy(buff, R, 33);
    memcpy(buff + 33, cts.begin(), 32);
    uint256 e = Hash(buff, buff + 65);
    //compute s = r + e * pk (private key)

    unsigned char ex[32];
    memcpy(ex, e.begin(), 32);
    if (!secp256k1_ec_privkey_tweak_mul(ex, pk.begin())) return false;
    if (!secp256k1_ec_privkey_tweak_add(ex, r.begin())) return false;
    std::copy(ex, ex + 32, std::back_inserter(txin.s));
    //copy R to masternodeStealthAddress
    std::copy(R, R + 33, std::back_inserter(txin.R));
    return true;
}

bool CWallet::selectDecoysAndRealIndex(CTransaction& tx, int& myIndex, int ringSize)
{
    LogPrintf("Selecting coinbase decoys for transaction\n");
    if (coinbaseDecoysPool.size() <= 100) {
        for (int i = chainActive.Height() - Params().COINBASE_MATURITY(); i > 0; i--) {
            if (coinbaseDecoysPool.size() > 100) break;
            CBlockIndex* p = chainActive[i];
            CBlock b;
            if (ReadBlockFromDisk(b, p)) {
                int coinbaseIdx = 0;
                if (p->IsProofOfStake()) {
                    coinbaseIdx = 1;
                }
                //dont select poa as decoy
                if (b.posBlocksAudited.size() > 0) continue;
                CTransaction& coinbase = b.vtx[coinbaseIdx];

                for (size_t i = 0; i < coinbase.vout.size(); i++) {
                    if (!coinbase.vout[i].IsNull() && !coinbase.vout[i].commitment.empty() && coinbase.vout[i].nValue > 0 && !coinbase.vout[i].IsEmpty()) {
                        if ((secp256k1_rand32() % 100) <= CWallet::PROBABILITY_NEW_COIN_SELECTED) {
                            COutPoint newOutPoint(coinbase.GetHash(), i);
                            if (pwalletMain->coinbaseDecoysPool.count(newOutPoint) == 1) {
                                continue;
                            }
                            //add new coinbase transaction to the pool
                            if (pwalletMain->coinbaseDecoysPool.size() >= CWallet::MAX_DECOY_POOL) {
                                int selected = secp256k1_rand32() % CWallet::MAX_DECOY_POOL;
                                map<COutPoint, uint256>::const_iterator it = std::next(coinbaseDecoysPool.begin(), selected);
                                pwalletMain->coinbaseDecoysPool[newOutPoint] = p->GetBlockHash();
                            } else {
                                pwalletMain->coinbaseDecoysPool[newOutPoint] = p->GetBlockHash();
                            }
                        }
                    }
                }
            }
        }
    }
    //Choose decoys
    myIndex = -1;
    for (size_t i = 0; i < tx.vin.size(); i++) {
        //generate key images and choose decoys
        CTransaction txPrev;
        uint256 hashBlock;
        if (!GetTransaction(tx.vin[i].prevout.hash, txPrev, hashBlock)) {
            LogPrintf("\nSelected transaction is not in the main chain\n");
            return false;
        }

        CBlockIndex* atTheblock = mapBlockIndex[hashBlock];
        CBlockIndex* tip = chainActive.Tip();
        if (!chainActive.Contains(atTheblock)) continue;
        uint256 hashTip = tip->GetBlockHash();
        //verify that tip and hashBlock must be in the same fork
        if (!atTheblock) {
            continue;
        } else {
            CBlockIndex* ancestor = tip->GetAncestor(atTheblock->nHeight);
            if (ancestor != atTheblock) {
                continue;
            }
        }

        CKeyImage ki;
        if (!generateKeyImage(txPrev.vout[tx.vin[i].prevout.n].scriptPubKey, ki)) {
            LogPrintf("Cannot generate key image\n");
            return false;
        } else {
            tx.vin[i].keyImage = ki;
        }

        pendingKeyImages.push_back(ki.GetHex());
        int numDecoys = 0;
        if (txPrev.IsCoinAudit() || txPrev.IsCoinBase() || txPrev.IsCoinStake()) {
            if ((int)coinbaseDecoysPool.size() >= ringSize * 5) {
                while (numDecoys < ringSize) {
                    bool duplicated = false;
                    map<COutPoint, uint256>::const_iterator it = std::next(coinbaseDecoysPool.begin(), secp256k1_rand32() % coinbaseDecoysPool.size());
                    if (mapBlockIndex.count(it->second) < 1) continue;
                    CBlockIndex* atTheblock = mapBlockIndex[it->second];
                    if (!atTheblock || !chainActive.Contains(atTheblock)) continue;
                    if (!chainActive.Contains(atTheblock)) continue;
                    if (1 + chainActive.Height() - atTheblock->nHeight < DecoyConfirmationMinimum) continue;
                    COutPoint outpoint = it->first;
                    for (size_t d = 0; d < tx.vin[i].decoys.size(); d++) {
                        if (tx.vin[i].decoys[d] == outpoint) {
                            duplicated = true;
                            break;
                        }
                    }
                    if (duplicated) {
                        continue;
                    }
                    tx.vin[i].decoys.push_back(outpoint);
                    numDecoys++;
                }
            } else if ((int)coinbaseDecoysPool.size() >= ringSize) {
                for (size_t j = 0; j < coinbaseDecoysPool.size(); j++) {
                    map<COutPoint, uint256>::const_iterator it = std::next(coinbaseDecoysPool.begin(), j);
                    if (mapBlockIndex.count(it->second) < 1) continue;
                    CBlockIndex* atTheblock = mapBlockIndex[it->second];
                    if (!atTheblock || !chainActive.Contains(atTheblock)) continue;
                    if (!chainActive.Contains(atTheblock)) continue;
                    if (1 + chainActive.Height() - atTheblock->nHeight < DecoyConfirmationMinimum) continue;
                    COutPoint outpoint = it->first;
                    tx.vin[i].decoys.push_back(outpoint);
                    numDecoys++;
                    if (numDecoys == ringSize) break;
                }
            } else {
                LogPrintf("Not enough decoys. Please wait approximately 10 minutes and try again.\n");
                return false;
            }
        } else {
            std::map<COutPoint, uint256> decoySet = userDecoysPool;
            decoySet.insert(coinbaseDecoysPool.begin(), coinbaseDecoysPool.end());
            if ((int)decoySet.size() >= ringSize * 5) {
                while (numDecoys < ringSize) {
                    bool duplicated = false;
                    map<COutPoint, uint256>::const_iterator it = std::next(decoySet.begin(), secp256k1_rand32() % decoySet.size());
                    if (mapBlockIndex.count(it->second) < 1) continue;
                    CBlockIndex* atTheblock = mapBlockIndex[it->second];
                    if (!atTheblock || !chainActive.Contains(atTheblock)) continue;
                    if (!chainActive.Contains(atTheblock)) continue;
                    if (1 + chainActive.Height() - atTheblock->nHeight < DecoyConfirmationMinimum) continue;
                    COutPoint outpoint = it->first;
                    for (size_t d = 0; d < tx.vin[i].decoys.size(); d++) {
                        if (tx.vin[i].decoys[d] == outpoint) {
                            duplicated = true;
                            break;
                        }
                    }
                    if (duplicated) {
                        continue;
                    }
                    tx.vin[i].decoys.push_back(outpoint);
                    numDecoys++;
                }
            } else if ((int)decoySet.size() >= ringSize) {
                for (size_t j = 0; j < decoySet.size(); j++) {
                    map<COutPoint, uint256>::const_iterator it = std::next(decoySet.begin(), j);
                    if (mapBlockIndex.count(it->second) < 1) continue;
                    CBlockIndex* atTheblock = mapBlockIndex[it->second];
                    if (!atTheblock || !chainActive.Contains(atTheblock)) continue;
                    if (!chainActive.Contains(atTheblock)) continue;
                    if (1 + chainActive.Height() - atTheblock->nHeight < DecoyConfirmationMinimum) continue;
                    COutPoint outpoint = it->first;
                    tx.vin[i].decoys.push_back(outpoint);
                    numDecoys++;
                    if (numDecoys == ringSize) break;
                }
            } else {
                LogPrintf("Not enough decoys. Please wait approximately 10 minutes and try again.\n");
                return false;
            }
        }
    }
    myIndex = secp256k1_rand32() % (tx.vin[0].decoys.size() + 1) - 1;

    for (size_t i = 0; i < tx.vin.size(); i++) {
        COutPoint prevout = tx.vin[i].prevout;
        inSpendQueueOutpointsPerSession.push_back(prevout);
    }
    if (myIndex != -1) {
        for (size_t i = 0; i < tx.vin.size(); i++) {
            if (tx.vin[i].decoys.size() <= myIndex || tx.vin[i].decoys.size() != ringSize) {
                throw runtime_error("Failed to annonymize the transaction, please wait about 10 minutes to re-create your transaction");
            }
            COutPoint prevout = tx.vin[i].prevout;
            tx.vin[i].prevout = tx.vin[i].decoys[myIndex];
            tx.vin[i].decoys[myIndex] = prevout;
        }
    }

    return true;
}

bool CWallet::CreateTransaction(CScript scriptPubKey, const CAmount& nValue, CWalletTx& wtxNew, CReserveKey& reservekey, CAmount& nFeeRet, std::string& strFailReason, const CCoinControl* coinControl, AvailableCoinsType coin_type, bool useIX, CAmount nFeePay)
{
    vector<pair<CScript, CAmount> > vecSend;
    vecSend.push_back(make_pair(scriptPubKey, nValue));
    return CreateTransaction(vecSend, wtxNew, reservekey, nFeeRet, strFailReason, coinControl, coin_type, useIX, nFeePay);
}

bool CWallet::computeSharedSec(const CTransaction& tx, const CTxOut& out, CPubKey& sharedSec) const
{
    if (tx.txType == TX_TYPE_REVEAL_AMOUNT || tx.txType == TX_TYPE_REVEAL_BOTH) {
        sharedSec.Set(out.txPub.begin(), out.txPub.end());
    } else {
        CKey view;
        myViewPrivateKey(view);
        ECDHInfo::ComputeSharedSec(view, out.txPub, sharedSec);
    }
    return true;
}

void CWallet::AddComputedPrivateKey(const CTxOut& out)
{
    if (IsLocked()) return;
    {
        LOCK(cs_wallet);
        CKey spend, view;
        mySpendPrivateKey(spend);
        myViewPrivateKey(view);

        unsigned char aR[33];
        CPubKey txPub = out.txPub;
        //copy R into a
        memcpy(aR, txPub.begin(), txPub.size());
        if (!secp256k1_ec_pubkey_tweak_mul(aR, txPub.size(), view.begin())) {
            throw runtime_error("Failed to do secp256k1_ec_privkey_tweak_mul");
        }
        uint256 HS = Hash(aR, aR + txPub.size());

        //Compute private key to spend
        //x = Hs(aR) + b, b = spend private key
        unsigned char HStemp[32];
        unsigned char spendTemp[32];
        memcpy(HStemp, HS.begin(), 32);
        if (!secp256k1_ec_privkey_tweak_add(HStemp, spend.begin()))
            throw runtime_error("Failed to do secp256k1_ec_privkey_tweak_add");
        CKey privKey;
        privKey.Set(HStemp, HStemp + 32, true);
        CPubKey computed = privKey.GetPubKey();
        CScript scriptPubKey = GetScriptForDestination(computed);
        if (scriptPubKey == out.scriptPubKey) {
            AddKey(privKey);
        } else {
            LogPrintf("AddComputedPrivateKey: Fail to generate corresponding private key\n");
        }
    }
}

// ppcoin: create coin stake transaction
bool CWallet::CreateCoinStake(const CKeyStore& keystore, unsigned int nBits, int64_t nSearchInterval, CMutableTransaction& txNew, unsigned int& nTxNewTime)
{
    // The following split & combine thresholds are important to security
    // Should not be adjusted if you don't understand the consequences
    //int64_t nCombineThreshold = 0;
    int static wlIdx = 0;
    txNew.vin.clear();
    txNew.vout.clear();

    // Mark coin stake transaction
    CScript scriptEmpty;
    scriptEmpty.clear();
    txNew.vout.push_back(CTxOut(0, scriptEmpty));
    txNew.txType = TX_TYPE_REVEAL_BOTH;

    // Choose coins to use
    CAmount nSpendableBalance = 0;
    CAmount nTargetAmount = 9223372036854775807;
    if (nReserveBalance > 0) {
        nSpendableBalance = GetSpendableBalance();
        if (nSpendableBalance <= nReserveBalance) {
            return false;
        }
        nTargetAmount = nSpendableBalance - nReserveBalance;
    }

    // presstab HyperStake - Initialize as static and don't update the set on every run of CreateCoinStake() in order to lighten resource use
    static std::set<pair<const CWalletTx*, unsigned int> > setStakeCoins;
    static int nLastStakeSetUpdate = 0;
    if (GetTime() - nLastStakeSetUpdate > nStakeSetUpdateTime) {
        setStakeCoins.clear();
        nLastStakeSetUpdate = GetTime();
    }

    vector<const CWalletTx*> vwtxPrev;

    CAmount nCredit = 0;
    CScript scriptPubKeyKernel;

    //prevent staking a time that won't be accepted
    if (GetAdjustedTime() <= chainActive.Tip()->nTime) {
        MilliSleep(10000);
    }

    {
        LOCK2(cs_main, cs_wallet);
        std::vector<map<uint256, CWalletTx>::const_iterator> tobeRemoveds;
        if (wlIdx == (int)mapWallet.size()) {
            wlIdx = 0;
        }

        for (map<uint256, CWalletTx>::const_iterator it = std::next(mapWallet.begin(), wlIdx); it != mapWallet.end(); ++it) {
            wlIdx = (wlIdx + 1) % mapWallet.size();
            const uint256& wtxid = it->first;
            const CWalletTx* pcoin = &(*it).second;
            // Make sure the wallet is unlocked and shutdown hasn't been requested
            if (IsLocked() || ShutdownRequested())
                    return false;
            std::vector<COutput> vCoins;
            int cannotSpend = 0;
            {
                AvailableCoins(wtxid, pcoin, vCoins, cannotSpend, true, NULL, false, STAKABLE_COINS, false);
            }

            CAmount nAmountSelected = 0;
            for (const COutput& out : vCoins) {
                //make sure not to outrun target amount
                CAmount value = getCOutPutValue(out);
                if (value < MINIMUM_STAKE_AMOUNT) continue;
                if (value == 1000000 * COIN) {
                    COutPoint outpoint(out.tx->GetHash(), out.i);
                    if (IsCollateralized(outpoint)) {
                        continue;
                    }
                }
                if (nAmountSelected + value >= nTargetAmount)
                    continue;

                int64_t nTxTime = out.tx->GetTxTime();
                //check for min age
                if (GetAdjustedTime() < nStakeMinAge + nTxTime)
                    continue;

                //check that it is matured

                if (out.nDepth < (out.tx->IsCoinStake() ? Params().COINBASE_MATURITY() : 10))
                    continue;

                {
                    COutPoint outpoint(out.tx->GetHash(), out.i);
                    if (inSpendQueueOutpoints.count(outpoint)) {
                        continue;
                    }
                }

                //add to our stake set
                setStakeCoins.insert(make_pair(out.tx, out.i));
                nAmountSelected += value;
            }

            for (PAIRTYPE(const CWalletTx*, unsigned int) pcoin : setStakeCoins) {
                // Make sure the wallet is unlocked and shutdown hasn't been requested
                if (IsLocked() || ShutdownRequested())
                    return false;

                //make sure that enough time has elapsed between
                CBlockIndex* pindex = NULL;
                BlockMap::iterator it = mapBlockIndex.find(pcoin.first->hashBlock);
                if (it != mapBlockIndex.end()) {
                    pindex = it->second;
                } else {
                    if (fDebug) {
                        LogPrintf("CreateCoinStake() failed to find block index\n");
                    }
                    continue;
                }

                // Read block header
                CBlockHeader block = pindex->GetBlockHeader();
                bool fKernelFound = false;
                uint256 hashProofOfStake = 0;
                COutPoint prevoutStake = COutPoint(pcoin.first->GetHash(), pcoin.second);
                nTxNewTime = GetAdjustedTime();

                CKey view, spend;
                myViewPrivateKey(view);
                mySpendPrivateKey(spend);
                CPubKey sharedSec;
                computeSharedSec(*pcoin.first, pcoin.first->vout[pcoin.second], sharedSec);
                //iterates each utxo inside of CheckStakeKernelHash()
                if (CheckStakeKernelHash(nBits, block, *pcoin.first, prevoutStake, sharedSec.begin(), nTxNewTime, nHashDrift, false, hashProofOfStake, true)) {
                    //Double check that this will pass time requirements
                    if (nTxNewTime <= chainActive.Tip()->GetMedianTimePast()) {
                        LogPrintf("CreateCoinStake() : kernel found, but it is too far in the past\n");
                        continue;
                    }

                    // Found a kernel
                    if (fDebug && GetBoolArg("-printcoinstake", false))
                        LogPrintf("CreateCoinStake : kernel found\n");

                    vector<valtype> vSolutions;
                    txnouttype whichType;
                    CScript scriptPubKeyOut;
                    scriptPubKeyKernel = pcoin.first->vout[pcoin.second].scriptPubKey;
                    if (!Solver(scriptPubKeyKernel, whichType, vSolutions)) {
                        LogPrintf("CreateCoinStake : failed to parse kernel\n");
                        break;
                    }

                    if (fDebug && GetBoolArg("-printcoinstake", false))
                        LogPrintf("CreateCoinStake : parsed kernel type=%d\n", whichType);
                    if (whichType != TX_PUBKEY && whichType != TX_PUBKEYHASH) {
                        if (fDebug && GetBoolArg("-printcoinstake", false))
                            LogPrintf("CreateCoinStake : no support for kernel type=%d\n", whichType);
                        break; // only support pay to public key and pay to address
                    }
                    if (whichType == TX_PUBKEYHASH) // pay to address type
                    {
                        //convert to pay to public key type
                        CKey key;
                        if (!keystore.GetKey(uint160(vSolutions[0]), key)) {
                            if (fDebug && GetBoolArg("-printcoinstake", false))
                                LogPrintf("CreateCoinStake : failed to get key for kernel type=%d\n", whichType);
                            break; // unable to find corresponding public key
                        }

                        scriptPubKeyOut << key.GetPubKey() << OP_CHECKSIG;
                    } else
                        scriptPubKeyOut = scriptPubKeyKernel;

                    CTxIn in(pcoin.first->GetHash(), pcoin.second);
                    if (!generateKeyImage(scriptPubKeyKernel, in.keyImage)) {
                        LogPrintf("CreateCoinStake : cannot generate key image\n");
                        break;
                    }
                    //copy encryption key so that full nodes can decode the amount in the txin
                    std::copy(sharedSec.begin(), sharedSec.begin() + 33, std::back_inserter(in.encryptionKey));
                    txNew.vin.push_back(in);

                    //first UTXO for the staked amount
                    CAmount val = getCTxOutValue(*pcoin.first, pcoin.first->vout[pcoin.second]);
                    nCredit += val;
                    vwtxPrev.push_back(pcoin.first);
                    //create a new pubkey
                    CKey myTxPriv;
                    myTxPriv.MakeNewKey(true);
                    CPubKey txPub = myTxPriv.GetPubKey();
                    CPubKey newPub;
                    ComputeStealthDestination(myTxPriv, view.GetPubKey(), spend.GetPubKey(), newPub);
                    scriptPubKeyOut = GetScriptForDestination(newPub);
                    CTxOut out(0, scriptPubKeyOut);
                    std::copy(txPub.begin(), txPub.end(), std::back_inserter(out.txPub));
                    txNew.vout.push_back(out);

                    //second UTXO for staking reward
                    //create a new pubkey
                    CKey myTxPrivStaking;
                    myTxPrivStaking.MakeNewKey(true);
                    CPubKey txPubStaking = myTxPrivStaking.GetPubKey();
                    CPubKey newPubStaking;
                    ComputeStealthDestination(myTxPrivStaking, view.GetPubKey(), spend.GetPubKey(), newPubStaking);
                    CScript scriptPubKeyOutStaking = GetScriptForDestination(newPubStaking);
                    CTxOut outStaking(0, scriptPubKeyOutStaking);
                    std::copy(txPubStaking.begin(), txPubStaking.end(), std::back_inserter(outStaking.txPub));
                    txNew.vout.push_back(outStaking);
                    //the staking process for the moment only accept one UTXO as staking coin
                    if (fDebug && GetBoolArg("-printcoinstake", false))
                        LogPrintf("CreateCoinStake : added kernel type=%d\n", whichType);
                    fKernelFound = true;
                    break;
                }
                if (fKernelFound) {
                    LogPrintf("CreateCoinStake: Kernel is found\n");
                    break; // if kernel is found stop searching
                }
            }
            if (nCredit == 0)
                continue;

            // Calculate reward
            CAmount nReward;
            const CBlockIndex* pIndex0 = chainActive.Tip();
            nReward = PoSBlockReward();
            txNew.vout[1].nValue = nCredit;
            txNew.vout[2].nValue = nReward;
            /*if (stakingMode == STAKING_WITH_CONSOLIDATION || STAKING_WITH_CONSOLIDATION_WITH_STAKING_NEWW_FUNDS) {
                //the first output contains all funds (input + rewards + fee)
                if (nCredit + nReward > (MINIMUM_STAKE_AMOUNT + 100000*COIN)*2) {
                    txNew.vout[1].nValue = (nCredit + nReward)/2;
                    txNew.vout[2].nValue = (nCredit + nReward) - txNew.vout[1].nValue;
                }
            }*/

            // Limit size
            unsigned int nBytes = ::GetSerializeSize(txNew, SER_NETWORK, PROTOCOL_VERSION);
            if (nBytes >= DEFAULT_BLOCK_MAX_SIZE / 5)
                return error("CreateCoinStake : exceeded coinstake size limit");

            //Masternode payment
            if (!FillBlockPayee(txNew, 0, true)) {
                LogPrintf("%s: Cannot fill block payee\n", __func__);
                return false;
            }

            //Check whether team rewards should be included in this block
            CBlockIndex* pindexPrev = chainActive.Tip();
            CAmount blockValue = GetBlockValue(pindexPrev);
            if (blockValue > PoSBlockReward()) {
                CAmount teamReward = blockValue - PoSBlockReward();
                const std::string foundational = FOUNDATION_WALLET;
                CPubKey foundationalGenPub, pubView, pubSpend;
                bool hasPaymentID;
                uint64_t paymentID;
                if (!CWallet::DecodeStealthAddress(foundational, pubView, pubSpend, hasPaymentID, paymentID)) {
                    LogPrintf("%s: Cannot decode foundational address\n", __func__);
                    continue;
                }
                CKey foundationTxPriv;
                foundationTxPriv.MakeNewKey(true);
                CPubKey foundationTxPub = foundationTxPriv.GetPubKey();
                ComputeStealthDestination(foundationTxPriv, pubView, pubSpend, foundationalGenPub);
                CScript foundationalScript = GetScriptForDestination(foundationalGenPub);
                CTxOut foundationalOut(teamReward, foundationalScript);
                std::copy(foundationTxPriv.begin(), foundationTxPriv.end(), std::back_inserter(foundationalOut.txPriv));
                std::copy(foundationTxPub.begin(), foundationTxPub.end(), std::back_inserter(foundationalOut.txPub));
                txNew.vout.push_back(foundationalOut);
            }
            //Encoding amount
            CPubKey sharedSec1;
            //In this case, use the transaction pubkey to encode the transactiona amount
            //so that every fullnode can verify the exact transaction amount within the transaction
            for (size_t i = 1; i < txNew.vout.size(); i++) {
                sharedSec1.Set(txNew.vout[i].txPub.begin(), txNew.vout[i].txPub.end());
                EncodeTxOutAmount(txNew.vout[i], txNew.vout[i].nValue, sharedSec1.begin());
                //create commitment
                unsigned char zeroBlind[32];
                memset(zeroBlind, 0, 32);
                txNew.vout[i].commitment.clear();
                CreateCommitment(zeroBlind, txNew.vout[i].nValue, txNew.vout[i].commitment);
            }

            // ECDSA sign
            int nIn = 0;
            for (const CWalletTx* pcoin : vwtxPrev) {
                if (!SignSignature(*this, *pcoin, txNew, nIn++))
                    return error("CreateCoinStake : failed to sign coinstake");
            }
            // Successfully generated coinstake
            nLastStakeSetUpdate = 0; //this will trigger stake set to repopulate next round
            return true;
        }
    }
    return false;
}

/**
 * Call after CreateTransaction unless you want to abort
 */
bool CWallet::CommitTransaction(CWalletTx& wtxNew, CReserveKey& reservekey, std::string strCommand)
{
    {
        LOCK2(cs_main, cs_wallet);
        LogPrintf("CommitTransaction:\n%s", wtxNew.ToString());
        {
            // This is only to keep the database open to defeat the auto-flush for the
            // duration of this scope.  This is the only place where this optimization
            // maybe makes sense; please don't do it anywhere else.
            CWalletDB* pwalletdb = fFileBacked ? new CWalletDB(strWalletFile, "r") : NULL;

            // Take key pair from key pool so it won't be used again
            reservekey.KeepKey();

            // Add tx to wallet, because if it has change it's also ours,
            // otherwise just for transaction history.
            AddToWallet(wtxNew);

            // Notify that old coins are spent
            {
                set<uint256> updated_hahes;
                for (const CTxIn& txin : wtxNew.vin) {
                    // notify only once
                    COutPoint prevout = findMyOutPoint(txin);
                    if (updated_hahes.find(prevout.hash) != updated_hahes.end()) continue;

                    CWalletTx& coin = mapWallet[prevout.hash];
                    coin.BindWallet(this);
                    NotifyTransactionChanged(this, prevout.hash, CT_UPDATED);
                    updated_hahes.insert(prevout.hash);
                }
            }

            if (fFileBacked)
                delete pwalletdb;
        }

        // Track how many getdata requests our transaction gets
        mapRequestCount[wtxNew.GetHash()] = 0;

        // Broadcast
        if (!wtxNew.AcceptToMemoryPool(false)) {
            // This must not fail. The transaction has already been signed and recorded.
            LogPrintf("CommitTransaction() : Error: Transaction not valid\n");
            return false;
        }
        LogPrintf("CommitTransaction() : hash: %s\n", wtxNew.GetHash().GetHex());
        wtxNew.RelayWalletTransaction(strCommand);
    }
    return true;
}

bool CWallet::AddAccountingEntry(const CAccountingEntry& acentry, CWalletDB & pwalletdb)
{
    if (!pwalletdb.WriteAccountingEntry_Backend(acentry))
        return false;

    laccentries.push_back(acentry);
    CAccountingEntry & entry = laccentries.back();
    wtxOrdered.insert(make_pair(entry.nOrderPos, TxPair((CWalletTx*)0, &entry)));

    return true;
}

CAmount CWallet::GetMinimumFee(unsigned int nTxBytes, unsigned int nConfirmTarget, const CTxMemPool& pool)
{
    CAmount nFeeNeeded = payTxFee.GetFee(nTxBytes);
    return nFeeNeeded;
}

void CWallet::ScanWalletKeyImages()
{
    if (IsLocked()) return;
    CWalletDB db(strWalletFile);
    for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it) {
        const CWalletTx wtxIn = it->second;
        uint256 hash = wtxIn.GetHash();
        AddToSpends(hash);
    }
}

DBErrors CWallet::LoadWallet(bool& fFirstRunRet)
{
    if (!fFileBacked)
        return DB_LOAD_OK;
    fFirstRunRet = false;
    DBErrors nLoadWalletRet = CWalletDB(strWalletFile, "cr+").LoadWallet(this);
    if (nLoadWalletRet == DB_NEED_REWRITE) {
        if (CDB::Rewrite(strWalletFile, "\x04pool")) {
            LOCK(cs_wallet);
            setKeyPool.clear();
            // Note: can't top-up keypool here, because wallet is locked.
            // User will be prompted to unlock wallet the next operation
            // the requires a new key.
        }
    }

    if (nLoadWalletRet != DB_LOAD_OK)
        return nLoadWalletRet;
    fFirstRunRet = !vchDefaultKey.IsValid();

    uiInterface.LoadWallet(this);
    ScanWalletKeyImages();

    return DB_LOAD_OK;
}


DBErrors CWallet::ZapWalletTx(std::vector<CWalletTx>& vWtx)
{
    if (!fFileBacked)
        return DB_LOAD_OK;
    DBErrors nZapWalletTxRet = CWalletDB(strWalletFile, "cr+").ZapWalletTx(this, vWtx);
    if (nZapWalletTxRet == DB_NEED_REWRITE) {
        if (CDB::Rewrite(strWalletFile, "\x04pool")) {
            LOCK(cs_wallet);
            setKeyPool.clear();
            // Note: can't top-up keypool here, because wallet is locked.
            // User will be prompted to unlock wallet the next operation
            // that requires a new key.
        }
    }

    if (nZapWalletTxRet != DB_LOAD_OK)
        return nZapWalletTxRet;

    return DB_LOAD_OK;
}


bool CWallet::SetAddressBook(const CTxDestination& address, const string& strName, const string& strPurpose)
{
    bool fUpdated = false;
    {
        LOCK(cs_wallet); // mapAddressBook
        std::map<CTxDestination, CAddressBookData>::iterator mi = mapAddressBook.find(address);
        fUpdated = mi != mapAddressBook.end();
        mapAddressBook[address].name = strName;
        if (!strPurpose.empty()) /* update purpose only if requested */
            mapAddressBook[address].purpose = strPurpose;
    }
    NotifyAddressBookChanged(this, address, strName, ::IsMine(*this, address) != ISMINE_NO,
        strPurpose, (fUpdated ? CT_UPDATED : CT_NEW));
    if (!fFileBacked)
        return false;
    if (!strPurpose.empty() && !CWalletDB(strWalletFile).WritePurpose(CBitcoinAddress(address).ToString(), strPurpose))
        return false;
    return CWalletDB(strWalletFile).WriteName(CBitcoinAddress(address).ToString(), strName);
}

bool CWallet::DelAddressBook(const CTxDestination& address)
{
    {
        LOCK(cs_wallet); // mapAddressBook

        if (fFileBacked) {
            // Delete destdata tuples associated with address
            std::string strAddress = CBitcoinAddress(address).ToString();
            for (const PAIRTYPE(string, string) & item : mapAddressBook[address].destdata) {
                CWalletDB(strWalletFile).EraseDestData(strAddress, item.first);
            }
        }
        mapAddressBook.erase(address);
    }

    NotifyAddressBookChanged(this, address, "", ::IsMine(*this, address) != ISMINE_NO, "", CT_DELETED);

    if (!fFileBacked)
        return false;
    CWalletDB(strWalletFile).ErasePurpose(CBitcoinAddress(address).ToString());
    return CWalletDB(strWalletFile).EraseName(CBitcoinAddress(address).ToString());
}

bool CWallet::SetDefaultKey(const CPubKey& vchPubKey)
{
    if (fFileBacked) {
        if (!CWalletDB(strWalletFile).WriteDefaultKey(vchPubKey))
            return false;
    }
    vchDefaultKey = vchPubKey;
    return true;
}

/**
 * Mark old keypool keys as used,
 * and generate all new keys
 */
bool CWallet::NewKeyPool()
{
    {
        LOCK(cs_wallet);
        CWalletDB walletdb(strWalletFile);
        for (int64_t nIndex : setKeyPool)
            walletdb.ErasePool(nIndex);
        setKeyPool.clear();

        if (IsLocked())
            return false;

        int64_t nKeys = max(GetArg("-keypool", 1000), (int64_t)0);
        for (int i = 0; i < nKeys; i++) {
            int64_t nIndex = i + 1;
            walletdb.WritePool(nIndex, CKeyPool(GenerateNewKey()));
            setKeyPool.insert(nIndex);
        }
        LogPrintf("CWallet::NewKeyPool wrote %d new keys\n", nKeys);
    }
    return true;
}


void GetAccountAddress(CWallet* pwalletMain, string strAccount, int nAccountIndex, bool bForceNew = false)
{
    CWalletDB walletdb(pwalletMain->strWalletFile);

    CAccount account;
    if (!bForceNew) {
        walletdb.ReadAccount(strAccount, account);
    }
    bool bKeyUsed = false;

    // Check if the current key has been used
    if (account.vchPubKey.IsValid()) {
        CScript scriptPubKey = GetScriptForDestination(account.vchPubKey.GetID());
        for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin();
             it != pwalletMain->mapWallet.end() && account.vchPubKey.IsValid();
             ++it) {
            const CWalletTx& wtx = (*it).second;
            for (const CTxOut& txout : wtx.vout)
                if (txout.scriptPubKey == scriptPubKey)
                    bKeyUsed = true;
        }
    }

    // Generate a new key
    if (!account.vchPubKey.IsValid() || bForceNew || bKeyUsed) {
        // pwalletMain->GetKeyFromPool(account.vchPubKey);
        CKey newKey;
        pwalletMain->DeriveNewChildKey(nAccountIndex, newKey);
        account.vchPubKey = newKey.GetPubKey();
        account.nAccountIndex = nAccountIndex;

        pwalletMain->SetAddressBook(account.vchPubKey.GetID(), strAccount, "receive");
        walletdb.WriteAccount(strAccount, account);
    }
}

bool CWallet::TopUpKeyPool(unsigned int kpSize)
{
    {
        LOCK(cs_wallet);

        if (IsLocked())
            return false;

        CWalletDB walletdb(strWalletFile);

        // Top up key pool
        unsigned int nTargetSize;
        if (kpSize > 0)
            nTargetSize = kpSize;
        else
            nTargetSize = max(GetArg("-keypool", 1000), (int64_t)0);

        /*while (setKeyPool.size() < (nTargetSize + 1)) {
            int64_t nEnd = 1;
            if (!setKeyPool.empty())
                nEnd = *(--setKeyPool.end()) + 1;
            if (!walletdb.WritePool(nEnd, CKeyPool(GenerateNewKey())))
                throw runtime_error("TopUpKeyPool() : writing generated key failed");
            setKeyPool.insert(nEnd);
            LogPrintf("keypool added key %d, size=%u\n", nEnd, setKeyPool.size());
            double dProgress = 100.f * nEnd / (nTargetSize + 1);
            std::string strMsg = strprintf(_("Loading wallet... (%3.2f %%)"), dProgress);
            uiInterface.InitMessage(strMsg);
        }*/
    }
    return true;
}

void CWallet::ReserveKeyFromKeyPool(int64_t& nIndex, CKeyPool& keypool)
{
    nIndex = -1;
    keypool.vchPubKey = CPubKey();
    {
        LOCK(cs_wallet);

        if (!IsLocked())
            TopUpKeyPool();

        // Get the oldest key
        if (setKeyPool.empty())
            return;

        CWalletDB walletdb(strWalletFile);

        nIndex = *(setKeyPool.begin());
        setKeyPool.erase(setKeyPool.begin());
        if (!walletdb.ReadPool(nIndex, keypool))
            throw runtime_error("ReserveKeyFromKeyPool() : read failed");
        if (!HaveKey(keypool.vchPubKey.GetID()))
            throw runtime_error("ReserveKeyFromKeyPool() : unknown key in key pool");
        assert(keypool.vchPubKey.IsValid());
        LogPrintf("keypool reserve %d\n", nIndex);
    }
}

void CWallet::CreatePrivacyAccount(bool forceNew)
{
    {
        LOCK(cs_wallet);
        if (IsCrypted())
            return; //throw runtime_error("Wallet is encrypted, please decrypt it");

        CWalletDB walletdb(strWalletFile);
        int i = 0;
        while (i < 10) {
            std::string viewAccountLabel = "viewaccount";
            std::string spendAccountLabel = "spendaccount";
            CAccount viewAccount;
            if (forceNew) {
                GetAccountAddress(this, viewAccountLabel, 0, forceNew);
                walletdb.ReadAccount(viewAccountLabel, viewAccount);
            } else {
                walletdb.ReadAccount(viewAccountLabel, viewAccount);
                if (!viewAccount.vchPubKey.IsValid()) {
                    GetAccountAddress(this, viewAccountLabel, 0, forceNew);
                }
            }
            CAccount spendAccount;
            if (forceNew) {
                GetAccountAddress(this, spendAccountLabel, 1, forceNew);
                walletdb.ReadAccount(spendAccountLabel, spendAccount);
            } else {
                walletdb.ReadAccount(spendAccountLabel, spendAccount);
                if (!spendAccount.vchPubKey.IsValid()) {
                    GetAccountAddress(this, spendAccountLabel, 1, forceNew);
                }
            }
            if (viewAccount.vchPubKey.GetHex() == "" || spendAccount.vchPubKey.GetHex() == "") {
                i++;
                continue;
            }

            walletdb.AppendStealthAccountList("masteraccount");
            break;
        }
    }
}

void CWallet::KeepKey(int64_t nIndex)
{
    // Remove from key pool
    if (fFileBacked) {
        CWalletDB walletdb(strWalletFile);
        walletdb.ErasePool(nIndex);
    }
    LogPrintf("keypool keep %d\n", nIndex);
}

void CWallet::ReturnKey(int64_t nIndex)
{
    // Return to key pool
    {
        LOCK(cs_wallet);
        setKeyPool.insert(nIndex);
    }
    LogPrintf("keypool return %d\n", nIndex);
}

bool CWallet::GetKeyFromPool(CPubKey& result)
{
    int64_t nIndex = 0;
    CKeyPool keypool;
    {
        LOCK(cs_wallet);
        ReserveKeyFromKeyPool(nIndex, keypool);
        if (nIndex == -1) {
            if (IsLocked()) return false;
            result = GenerateNewKey();
            return true;
        }
        KeepKey(nIndex);
        result = keypool.vchPubKey;
    }
    return true;
}

int64_t CWallet::GetOldestKeyPoolTime()
{
    int64_t nIndex = 0;
    CKeyPool keypool;
    ReserveKeyFromKeyPool(nIndex, keypool);
    if (nIndex == -1)
        return GetTime();
    ReturnKey(nIndex);
    return keypool.nTime;
}

std::map<CTxDestination, CAmount> CWallet::GetAddressBalances()
{
    map<CTxDestination, CAmount> balances;

    {
        LOCK(cs_wallet);
        for (PAIRTYPE(uint256, CWalletTx) walletEntry : mapWallet) {
            CWalletTx* pcoin = &walletEntry.second;

            if (!IsFinalTx(*pcoin) || !pcoin->IsTrusted())
                continue;

            if (pcoin->IsCoinBase() && pcoin->GetBlocksToMaturity() > 0)
                continue;

            int nDepth = pcoin->GetDepthInMainChain();
            if (nDepth < (pcoin->IsFromMe(ISMINE_ALL) ? 0 : 1))
                continue;

            for (unsigned int i = 0; i < pcoin->vout.size(); i++) {
                CTxDestination addr;
                if (!IsMine(pcoin->vout[i]))
                    continue;
                if (!ExtractDestination(pcoin->vout[i].scriptPubKey, addr))
                    continue;

                CAmount n = IsSpent(walletEntry.first, i) ? 0 : pcoin->vout[i].nValue;

                if (!balances.count(addr))
                    balances[addr] = 0;
                balances[addr] += n;
            }
        }
    }

    return balances;
}

set<set<CTxDestination> > CWallet::GetAddressGroupings()
{
    AssertLockHeld(cs_wallet); // mapWallet
    set<set<CTxDestination> > groupings;
    set<CTxDestination> grouping;

    for (PAIRTYPE(uint256, CWalletTx) walletEntry : mapWallet) {
        CWalletTx* pcoin = &walletEntry.second;

        if (pcoin->vin.size() > 0) {
            bool any_mine = false;
            // group all input addresses with each other
            for (CTxIn txin : pcoin->vin) {
                CTxDestination address;
                if (!IsMine(txin)) /* If this input isn't mine, ignore it */
                    continue;
                if (!ExtractDestination(mapWallet[txin.prevout.hash].vout[txin.prevout.n].scriptPubKey, address))
                    continue;
                grouping.insert(address);
                any_mine = true;
            }

            // group change with input addresses
            if (any_mine) {
                for (CTxOut txout : pcoin->vout)
                    if (IsChange(txout)) {
                        CTxDestination txoutAddr;
                        if (!ExtractDestination(txout.scriptPubKey, txoutAddr))
                            continue;
                        grouping.insert(txoutAddr);
                    }
            }
            if (grouping.size() > 0) {
                groupings.insert(grouping);
                grouping.clear();
            }
        }

        // group lone addrs by themselves
        for (unsigned int i = 0; i < pcoin->vout.size(); i++)
            if (IsMine(pcoin->vout[i])) {
                CTxDestination address;
                if (!ExtractDestination(pcoin->vout[i].scriptPubKey, address))
                    continue;
                grouping.insert(address);
                groupings.insert(grouping);
                grouping.clear();
            }
    }

    set<set<CTxDestination>*> uniqueGroupings;        // a set of pointers to groups of addresses
    map<CTxDestination, set<CTxDestination>*> setmap; // map addresses to the unique group containing it
    for (set<CTxDestination> grouping : groupings) {
        // make a set of all the groups hit by this new group
        set<set<CTxDestination>*> hits;
        map<CTxDestination, set<CTxDestination>*>::iterator it;
        for (CTxDestination address : grouping)
            if ((it = setmap.find(address)) != setmap.end())
                hits.insert((*it).second);

        // merge all hit groups into a new single group and delete old groups
        set<CTxDestination>* merged = new set<CTxDestination>(grouping);
        for (set<CTxDestination>* hit : hits) {
            merged->insert(hit->begin(), hit->end());
            uniqueGroupings.erase(hit);
            delete hit;
        }
        uniqueGroupings.insert(merged);

        // update setmap
        for (CTxDestination element : *merged)
            setmap[element] = merged;
    }

    set<set<CTxDestination> > ret;
    for (set<CTxDestination>* uniqueGrouping : uniqueGroupings) {
        ret.insert(*uniqueGrouping);
        delete uniqueGrouping;
    }

    return ret;
}

set<CTxDestination> CWallet::GetAccountAddresses(string strAccount) const
{
    LOCK(cs_wallet);
    set<CTxDestination> result;
    for (const PAIRTYPE(CTxDestination, CAddressBookData) & item : mapAddressBook) {
        const CTxDestination& address = item.first;
        const string& strName = item.second.name;
        if (strName == strAccount)
            result.insert(address);
    }
    return result;
}

bool CReserveKey::GetReservedKey(CPubKey& pubkey)
{
    if (nIndex == -1) {
        CKeyPool keypool;
        pwallet->ReserveKeyFromKeyPool(nIndex, keypool);
        if (nIndex != -1)
            vchPubKey = keypool.vchPubKey;
        else {
            return false;
        }
    }
    assert(vchPubKey.IsValid());
    pubkey = vchPubKey;
    return true;
}

void CReserveKey::KeepKey()
{
    if (nIndex != -1)
        pwallet->KeepKey(nIndex);
    nIndex = -1;
    vchPubKey = CPubKey();
}

void CReserveKey::ReturnKey()
{
    if (nIndex != -1)
        pwallet->ReturnKey(nIndex);
    nIndex = -1;
    vchPubKey = CPubKey();
}

void CWallet::GetAllReserveKeys(set<CKeyID>& setAddress) const
{
    setAddress.clear();

    CWalletDB walletdb(strWalletFile);

    LOCK2(cs_main, cs_wallet);
    for (const int64_t& id : setKeyPool) {
        CKeyPool keypool;
        if (!walletdb.ReadPool(id, keypool))
            throw runtime_error("GetAllReserveKeyHashes() : read failed");
        assert(keypool.vchPubKey.IsValid());
        CKeyID keyID = keypool.vchPubKey.GetID();
        if (!HaveKey(keyID))
            throw runtime_error("GetAllReserveKeyHashes() : unknown key in key pool");
        setAddress.insert(keyID);
    }
}

bool CWallet::UpdatedTransaction(const uint256& hashTx)
{
    {
        LOCK(cs_wallet);
        // Only notify UI if this transaction is in this wallet
        map<uint256, CWalletTx>::const_iterator mi = mapWallet.find(hashTx);
        if (mi != mapWallet.end()) {
            NotifyTransactionChanged(this, hashTx, CT_UPDATED);
            return true;
        }
    }
    return false;
}

void CWallet::LockCoin(COutPoint& output)
{
    AssertLockHeld(cs_wallet); // setLockedCoins
    setLockedCoins.insert(output);
}

void CWallet::UnlockCoin(COutPoint& output)
{
    AssertLockHeld(cs_wallet); // setLockedCoins
    setLockedCoins.erase(output);
}

void CWallet::UnlockAllCoins()
{
    AssertLockHeld(cs_wallet); // setLockedCoins
    setLockedCoins.clear();
}

bool CWallet::IsLockedCoin(uint256 hash, unsigned int n) const
{
    AssertLockHeld(cs_wallet); // setLockedCoins
    COutPoint outpt(hash, n);

    return (setLockedCoins.count(outpt) > 0);
}

void CWallet::ListLockedCoins(std::vector<COutPoint>& vOutpts)
{
    AssertLockHeld(cs_wallet); // setLockedCoins
    for (std::set<COutPoint>::iterator it = setLockedCoins.begin();
         it != setLockedCoins.end(); it++) {
        COutPoint outpt = (*it);
        vOutpts.push_back(outpt);
    }
}

/** @} */ // end of Actions

class CAffectedKeysVisitor : public boost::static_visitor<void>
{
private:
    const CKeyStore& keystore;
    std::vector<CKeyID>& vKeys;

public:
    CAffectedKeysVisitor(const CKeyStore& keystoreIn, std::vector<CKeyID>& vKeysIn) : keystore(keystoreIn), vKeys(vKeysIn) {}

    void Process(const CScript& script)
    {
        txnouttype type;
        std::vector<CTxDestination> vDest;
        int nRequired;
        if (ExtractDestinations(script, type, vDest, nRequired)) {
            for (const CTxDestination& dest : vDest)
                boost::apply_visitor(*this, dest);
        }
    }

    void operator()(const CKeyID& keyId)
    {
        if (keystore.HaveKey(keyId))
            vKeys.push_back(keyId);
    }

    void operator()(const CScriptID& scriptId)
    {
        CScript script;
        if (keystore.GetCScript(scriptId, script))
            Process(script);
    }

    void operator()(const CNoDestination& none) {}
};

void CWallet::GetKeyBirthTimes(std::map<CKeyID, int64_t>& mapKeyBirth) const
{
    AssertLockHeld(cs_wallet); // mapKeyMetadata
    mapKeyBirth.clear();

    // get birth times for keys with metadata
    for (std::map<CKeyID, CKeyMetadata>::const_iterator it = mapKeyMetadata.begin(); it != mapKeyMetadata.end(); it++)
        if (it->second.nCreateTime)
            mapKeyBirth[it->first] = it->second.nCreateTime;

    // map in which we'll infer heights of other keys
    CBlockIndex* pindexMax = chainActive[std::max(0, chainActive.Height() - 144)]; // the tip can be reorganised; use a 144-block safety margin
    std::map<CKeyID, CBlockIndex*> mapKeyFirstBlock;
    std::set<CKeyID> setKeys;
    GetKeys(setKeys);
    for (const CKeyID& keyid : setKeys) {
        if (mapKeyBirth.count(keyid) == 0)
            mapKeyFirstBlock[keyid] = pindexMax;
    }
    setKeys.clear();

    // if there are no such keys, we're done
    if (mapKeyFirstBlock.empty())
        return;

    // find first block that affects those keys, if there are any left
    std::vector<CKeyID> vAffected;
    for (std::map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); it++) {
        // iterate over all wallet transactions...
        const CWalletTx& wtx = (*it).second;
        BlockMap::const_iterator blit = mapBlockIndex.find(wtx.hashBlock);
        if (blit != mapBlockIndex.end() && chainActive.Contains(blit->second)) {
            // ... which are already in a block
            int nHeight = blit->second->nHeight;
            for (const CTxOut& txout : wtx.vout) {
                // iterate over all their outputs
                CAffectedKeysVisitor(*this, vAffected).Process(txout.scriptPubKey);
                for (const CKeyID& keyid : vAffected) {
                    // ... and all their affected keys
                    std::map<CKeyID, CBlockIndex*>::iterator rit = mapKeyFirstBlock.find(keyid);
                    if (rit != mapKeyFirstBlock.end() && nHeight < rit->second->nHeight)
                        rit->second = blit->second;
                }
                vAffected.clear();
            }
        }
    }

    // Extract block timestamps for those keys
    for (std::map<CKeyID, CBlockIndex*>::const_iterator it = mapKeyFirstBlock.begin(); it != mapKeyFirstBlock.end(); it++)
        mapKeyBirth[it->first] = it->second->GetBlockTime() - 7200; // block times can be 2h off
}

unsigned int CWallet::ComputeTimeSmart(const CWalletTx& wtx) const
{
    unsigned int nTimeSmart = wtx.nTimeReceived;
    if (wtx.hashBlock != 0) {
        if (mapBlockIndex.count(wtx.hashBlock)) {
            int64_t latestNow = wtx.nTimeReceived;
            int64_t latestEntry = 0;
            {
                // Tolerate times up to the last timestamp in the wallet not more than 5 minutes into the future
                int64_t latestTolerated = latestNow + 300;
                TxItems txOrdered = wtxOrdered;
                for (TxItems::reverse_iterator it = txOrdered.rbegin(); it != txOrdered.rend(); ++it) {
                    CWalletTx* const pwtx = (*it).second.first;
                    if (pwtx == &wtx)
                        continue;
                    CAccountingEntry* const pacentry = (*it).second.second;
                    int64_t nSmartTime;
                    if (pwtx) {
                        nSmartTime = pwtx->nTimeSmart;
                        if (!nSmartTime)
                            nSmartTime = pwtx->nTimeReceived;
                    } else
                        nSmartTime = pacentry->nTime;
                    if (nSmartTime <= latestTolerated) {
                        latestEntry = nSmartTime;
                        if (nSmartTime > latestNow)
                            latestNow = nSmartTime;
                        break;
                    }
                }
            }

            int64_t blocktime = mapBlockIndex[wtx.hashBlock]->GetBlockTime();
            nTimeSmart = std::max(latestEntry, std::min(blocktime, latestNow));
        } else
            LogPrintf("AddToWallet() : found %s in block %s not in index\n",
                wtx.GetHash().ToString(),
                wtx.hashBlock.ToString());
    }
    return nTimeSmart;
}

bool CWallet::AddDestData(const CTxDestination& dest, const std::string& key, const std::string& value)
{
    if (boost::get<CNoDestination>(&dest))
        return false;

    mapAddressBook[dest].destdata.insert(std::make_pair(key, value));
    if (!fFileBacked)
        return true;
    return CWalletDB(strWalletFile).WriteDestData(CBitcoinAddress(dest).ToString(), key, value);
}

bool CWallet::EraseDestData(const CTxDestination& dest, const std::string& key)
{
    if (!mapAddressBook[dest].destdata.erase(key))
        return false;
    if (!fFileBacked)
        return true;
    return CWalletDB(strWalletFile).EraseDestData(CBitcoinAddress(dest).ToString(), key);
}

bool CWallet::LoadDestData(const CTxDestination& dest, const std::string& key, const std::string& value)
{
    mapAddressBook[dest].destdata.insert(std::make_pair(key, value));
    return true;
}

bool CWallet::SendAll(std::string des)
{
    if (this->IsLocked()) {
        throw runtime_error("Wallet is locked! Please unlock it to make transactions.");
    }

    int estimateTxSize = ComputeTxSize(1, 1, MIN_RING_SIZE);
    CAmount nFeeNeeded = GetMinimumFee(estimateTxSize, nTxConfirmTarget, mempool);
    nFeeNeeded += BASE_FEE;
    if (GetSpendableBalance() <= nFeeNeeded) {
        throw runtime_error("Not enough balance to pay minimum transaction Fee: " + ValueFromAmountToString(nFeeNeeded));
    }

    CAmount total = 0;
    std::vector<COutput> vCoins;
    vCoins.clear();
    std::string strFailReason;
    bool ret = true;
    {
        LOCK2(cs_main, cs_wallet);
        {
            for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it) {
                const uint256& wtxid = it->first;
                const CWalletTx* pcoin = &(*it).second;

                int nDepth = pcoin->GetDepthInMainChain(false);
                if ((pcoin->IsCoinBase() || pcoin->IsCoinStake()) && pcoin->GetBlocksToMaturity() > 0)
                    continue;
                if (nDepth == 0 && !pcoin->InMempool())
                    continue;
                for (size_t i = 0; i < pcoin->vout.size(); i++) {
                    if (pcoin->vout[i].IsEmpty()) continue;
                    isminetype mine = IsMine(pcoin->vout[i]);
                    if (mine == ISMINE_NO)
                        continue;
                    if (mine == ISMINE_WATCH_ONLY)
                        continue;
                    CAmount decodedAmount;
                    CKey decodedBlind;
                    RevealTxOutAmount(*pcoin, pcoin->vout[i], decodedAmount, decodedBlind);

                    std::vector<unsigned char> commitment;
                    if (!decodedBlind.IsValid()) {
                        unsigned char blind[32];
                        CreateCommitmentWithZeroBlind(decodedAmount, blind, commitment);
                    } else {
                        CreateCommitment(decodedBlind.begin(), decodedAmount, commitment);
                    }
                    if (pcoin->vout[i].commitment != commitment) {
                        LogPrintf("%s: Commitment not match hash = %s, i = %d, commitment = %s, recomputed = %s, revealed mask = %s\n", __func__, pcoin->GetHash().GetHex(), i, HexStr(&pcoin->vout[i].commitment[0], &pcoin->vout[i].commitment[0] + 33), HexStr(&commitment[0], &commitment[0] + 33), HexStr(decodedBlind.begin(), decodedBlind.begin() + 32));
                        continue;
                    }

                    if (IsSpent(wtxid, i)) continue;

                    {
                        COutPoint outpoint(wtxid, i);
                        if (inSpendQueueOutpoints.count(outpoint)) {
                            continue;
                        }
                    }
                    vCoins.push_back(COutput(pcoin, i, nDepth, true));
                    total += decodedAmount;
                    if (vCoins.size() > MAX_TX_INPUTS) break;
                }
                if (vCoins.size() > MAX_TX_INPUTS) break;
            }

            if (vCoins.size() > MAX_TX_INPUTS) {
                strFailReason = "Transaction size too large, please try again later";
                ret = false;
            }


            if (ret) {
                // Generate transaction public key
                CWalletTx wtxNew;
                CKey secret;
                secret.MakeNewKey(true);
                SetMinVersion(FEATURE_COMPRPUBKEY);

                unsigned char rand_seed[16];
                memcpy(rand_seed, secret.begin(), 16);
                secp256k1_rand_seed(rand_seed);
                int ringSize = MIN_RING_SIZE + secp256k1_rand32() % (MAX_RING_SIZE - MIN_RING_SIZE + 1);

                estimateTxSize = ComputeTxSize(vCoins.size(), 1, ringSize);
                nFeeNeeded = GetMinimumFee(estimateTxSize, nTxConfirmTarget, mempool);
                nFeeNeeded += BASE_FEE;
                if (total < nFeeNeeded) {
                    strFailReason = "Not enough balance to pay minimum transaction Fee: " + ValueFromAmountToString(nFeeNeeded);
                    ret = false;
                } else {
                    //Parse stealth address
                    CPubKey pubViewKey, pubSpendKey;
                    bool hasPaymentID;
                    uint64_t paymentID;

                    if (!CWallet::DecodeStealthAddress(des, pubViewKey, pubSpendKey, hasPaymentID, paymentID)) {
                        //should never happen
                        ret = false;
                        strFailReason = "Invalid Destination Address!";
                    } else {
                        wtxNew.txPrivM.Set(secret.begin(), secret.end(), true);
                        wtxNew.hasPaymentID = 0;

                        //Compute stealth destination
                        CPubKey stealthDes;
                        CKey spend;
                        mySpendPrivateKey(spend);
                        CKey view;
                        myViewPrivateKey(view);
                        ComputeStealthDestination(secret, pubViewKey, pubSpendKey, stealthDes);

                        CScript scriptPubKey = GetScriptForDestination(stealthDes);

                        CAmount nValue = total - nFeeNeeded;

                        wtxNew.fTimeReceivedIsTxTime = true;
                        wtxNew.BindWallet(this);
                        CMutableTransaction txNew;
                        txNew.hasPaymentID = wtxNew.hasPaymentID;
                        txNew.paymentID = wtxNew.paymentID;

                        {
                            while (true) {
                                txNew.vin.clear();
                                txNew.vout.clear();
                                wtxNew.fFromMe = true;

                                double dPriority = 0;

                                // vouts to the payees
                                CTxOut txout(nValue, scriptPubKey);
                                CPubKey txPub = wtxNew.txPrivM.GetPubKey();
                                txPrivKeys.push_back(wtxNew.txPrivM);
                                std::copy(txPub.begin(), txPub.end(), std::back_inserter(txout.txPub));

                                CPubKey sharedSec;
                                ECDHInfo::ComputeSharedSec(wtxNew.txPrivM, pubViewKey, sharedSec);
                                EncodeTxOutAmount(txout, txout.nValue, sharedSec.begin());
                                txNew.vout.push_back(txout);
                                txNew.nTxFee = nFeeNeeded;

                                //Fill vin
                                for (size_t i = 0; i < vCoins.size(); i++) {
                                    txNew.vin.push_back(CTxIn(vCoins[i].tx->GetHash(), vCoins[i].i));
                                }

                                // Embed the constructed transaction data in wtxNew.
                                *static_cast<CTransaction*>(&wtxNew) = CTransaction(txNew);
                                break;
                            }

                            if (!makeRingCT(wtxNew, ringSize, strFailReason)) {
                                strFailReason = _("Failed to generate RingCT for Sweeping transaction");
                                ret = false;
                            }

                            if (ret && !generateBulletProofAggregate(wtxNew)) {
                                strFailReason = _("Failed to generate bulletproof for Sweeping transaction");
                                ret = false;
                            }

                            if (ret) {
                                for (size_t i = 0; i < wtxNew.vout.size(); i++) {
                                    wtxNew.vout[i].nValue = 0;
                                }
                                CReserveKey reservekey(pwalletMain);
                                if (!pwalletMain->CommitTransaction(wtxNew, reservekey, "tx")) {
                                    inSpendQueueOutpointsPerSession.clear();
                                    strFailReason = "Internal error! Please try again later!";
                                    ret = false;
                                }
                                if (ret) {
                                    for (size_t i = 0; i < inSpendQueueOutpointsPerSession.size(); i++) {
                                        inSpendQueueOutpoints[inSpendQueueOutpointsPerSession[i]] = true;
                                    }
                                    inSpendQueueOutpointsPerSession.clear();

                                    uint256 hash = wtxNew.GetHash();
                                    int maxTxPrivKeys = txPrivKeys.size() > wtxNew.vout.size() ? wtxNew.vout.size() : txPrivKeys.size();
                                    for (int i = 0; i < maxTxPrivKeys; i++) {
                                        std::string key = hash.GetHex() + std::to_string(i);
                                        CWalletDB(strWalletFile).WriteTxPrivateKey(key, CBitcoinSecret(txPrivKeys[i]).ToString());
                                    }
                                    txPrivKeys.clear();
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    return ret;
}

bool CWallet::CreateSweepingTransaction(CAmount target, CAmount threshold, uint32_t nTimeBefore)
{
    if (this->IsLocked()) {
        return true;
    }

    if (GetSpendableBalance() < 5 * COIN) {
        return false;
    }
    LogPrintf("Attempting to create a sweeping transaction\n");
    CAmount total = 0;
    std::vector<COutput> vCoins;
    COutput lowestLarger(NULL, 0, 0, false);
    CAmount currentLowestLargerAmount = 0;
    vCoins.clear();
    bool ret = true;
    bool isReserveUTXOExist = false;
    static uint256 reserveHash;
    {
        LOCK2(cs_main, cs_wallet);
        {
            for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it) {
                const uint256& wtxid = it->first;
                const CWalletTx* pcoin = &(*it).second;

                if (pcoin->GetTxTime() > nTimeBefore) continue;

                int nDepth = pcoin->GetDepthInMainChain(false);
                if ((pcoin->IsCoinBase() || pcoin->IsCoinStake()) && pcoin->GetBlocksToMaturity() > 0)
                    continue;
                if (nDepth == 0 && !pcoin->InMempool())
                    continue;
                for (size_t i = 0; i < pcoin->vout.size(); i++) {
                    if (pcoin->vout[i].IsEmpty()) continue;
                    isminetype mine = IsMine(pcoin->vout[i]);
                    if (mine == ISMINE_NO)
                        continue;
                    if (mine == ISMINE_WATCH_ONLY)
                        continue;
                    CAmount decodedAmount;
                    CKey decodedBlind;
                    RevealTxOutAmount(*pcoin, pcoin->vout[i], decodedAmount, decodedBlind);

                    std::vector<unsigned char> commitment;
                    if (!decodedBlind.IsValid()) {
                        unsigned char blind[32];
                        CreateCommitmentWithZeroBlind(decodedAmount, blind, commitment);
                    } else {
                        CreateCommitment(decodedBlind.begin(), decodedAmount, commitment);
                    }
                    if (pcoin->vout[i].commitment != commitment) {
                        LogPrintf("%s: Commitment not match hash = %s, i = %d, commitment = %s, recomputed = %s, revealed mask = %s\n", __func__, pcoin->GetHash().GetHex(), i, HexStr(&pcoin->vout[i].commitment[0], &pcoin->vout[i].commitment[0] + 33), HexStr(&commitment[0], &commitment[0] + 33), HexStr(decodedBlind.begin(), decodedBlind.begin() + 32));
                        continue;
                    }

                    if (IsSpent(wtxid, i)) continue;

                    {
                        COutPoint outpoint(wtxid, i);
                        if (inSpendQueueOutpoints.count(outpoint)) {
                            continue;
                        }

                        if (IsCollateralized(outpoint)) {
                            continue;
                        }
                    }

                    if (nReserveBalance > 0) {
                        if (decodedAmount == ComputeReserveUTXOAmount()) {
                            isReserveUTXOExist = true;
                            reserveHash = wtxid;
                            //dont select reserve UTXO
                            continue;
                        }
                    }

                    if (nDepth <= 5) continue;
                    if (decodedAmount >= threshold) {
                        if (lowestLarger.tx == NULL || (lowestLarger.tx != NULL && currentLowestLargerAmount > decodedAmount)) {
                            lowestLarger.tx = pcoin;
                            lowestLarger.i = i;
                            lowestLarger.nDepth = nDepth;
                            lowestLarger.fSpendable = true;
                            currentLowestLargerAmount = decodedAmount;
                        }
                        continue;
                    }

                    if (vCoins.size() <= MAX_TX_INPUTS - 1) { //reserve 1 input for lowestLarger
                        vCoins.push_back(COutput(pcoin, i, nDepth, true));
                        total += decodedAmount;
                    }
                }
            }

            if (nReserveBalance > 0) {
                if (!isReserveUTXOExist) {
                    //create transactions that create reserve funds
                    CWalletTx wtx;
                    std::string masterAddr;
                    ComputeStealthPublicAddress("masteraccount", masterAddr);
                    try {
                        SendToStealthAddress(masterAddr, ComputeReserveUTXOAmount(), wtx);
                    } catch (const std::exception& err) {
                        LogPrintf("failed to create reserve UTXO\n");
                    }
                    return false;
                } else {
                    if (mapWallet.count(reserveHash) < 1) return false;
                    const CWalletTx reserve = mapWallet[reserveHash];

                    if (reserve.GetDepthInMainChain(false) < 10) {
                        return false;
                    }
                }
            }
            int ringSize = MIN_RING_SIZE + secp256k1_rand32() % (MAX_RING_SIZE - MIN_RING_SIZE + 1);
            if (vCoins.size() <= 1) return false;
            CAmount estimatedFee = ComputeFee(vCoins.size(), 1, ringSize);
            if (stakingMode != StakingMode::STAKING_WITH_CONSOLIDATION && (vCoins.empty() || (vCoins.size() < MIN_TX_INPUTS_FOR_SWEEPING) || (total < target + estimatedFee && vCoins.size() <= MAX_TX_INPUTS))) {
                //preconditions to create auto sweeping transactions not satisfied, do nothing here
                ret = false;
            } else {
                if (stakingMode == StakingMode::STAKING_WITH_CONSOLIDATION) {
                    if (total < target + estimatedFee) {
                        if (lowestLarger.tx != NULL && currentLowestLargerAmount >= threshold) {
                            vCoins.push_back(lowestLarger);
                            total += currentLowestLargerAmount;
                        } else {
                            LogPrintf("No set of UTXOs to combine into a stakeable coin - autocombine any way if minimum UTXOs satisfied\n");
                            if (vCoins.size() < MIN_TX_INPUTS_FOR_SWEEPING) return false;
                        }
                    }
                }
                LogPrintf("Generating consolidation transaction, total = %d DAPS\n", total);
                // Generate transaction public key
                CWalletTx wtxNew;
                CKey secret;
                secret.MakeNewKey(true);
                SetMinVersion(FEATURE_COMPRPUBKEY);

                int estimateTxSize = ComputeTxSize(vCoins.size(), 1, ringSize);
                CAmount nFeeNeeded = GetMinimumFee(estimateTxSize, nTxConfirmTarget, mempool);
                nFeeNeeded += BASE_FEE;
                if (total < nFeeNeeded * 2) {
                    ret = false;
                } else {
                    std::string myAddress;
                    ComputeStealthPublicAddress("masteraccount", myAddress);
                    //Parse stealth address
                    CPubKey pubViewKey, pubSpendKey;
                    bool hasPaymentID;
                    uint64_t paymentID;

                    if (!CWallet::DecodeStealthAddress(myAddress, pubViewKey, pubSpendKey, hasPaymentID, paymentID)) {
                        //should never happen
                        ret = false;
                    } else {
                        wtxNew.txPrivM.Set(secret.begin(), secret.end(), true);
                        wtxNew.hasPaymentID = 0;

                        //Compute stealth destination
                        CPubKey stealthDes;
                        CKey spend;
                        mySpendPrivateKey(spend);
                        CKey view;
                        myViewPrivateKey(view);
                        ComputeStealthDestination(secret, pubViewKey, pubSpendKey, stealthDes);

                        CScript scriptPubKey = GetScriptForDestination(stealthDes);

                        CAmount nValue = total - nFeeNeeded;

                        wtxNew.fTimeReceivedIsTxTime = true;
                        wtxNew.BindWallet(this);
                        CMutableTransaction txNew;
                        txNew.hasPaymentID = wtxNew.hasPaymentID;
                        txNew.paymentID = wtxNew.paymentID;

                        {
                            unsigned int nBytes = 0;
                            while (true) {
                                txNew.vin.clear();
                                txNew.vout.clear();
                                wtxNew.fFromMe = true;

                                double dPriority = 0;

                                // vouts to the payees
                                CTxOut txout(nValue, scriptPubKey);
                                CPubKey txPub = wtxNew.txPrivM.GetPubKey();
                                txPrivKeys.push_back(wtxNew.txPrivM);
                                std::copy(txPub.begin(), txPub.end(), std::back_inserter(txout.txPub));

                                CPubKey sharedSec;
                                ECDHInfo::ComputeSharedSec(wtxNew.txPrivM, pubViewKey, sharedSec);
                                EncodeTxOutAmount(txout, txout.nValue, sharedSec.begin());
                                txNew.vout.push_back(txout);
                                //nBytes += ::GetSerializeSize(*(CTxOut*)&txout, SER_NETWORK, PROTOCOL_VERSION);

                                txNew.nTxFee = nFeeNeeded;

                                //Fill vin
                                for (size_t i = 0; i < vCoins.size(); i++) {
                                    txNew.vin.push_back(CTxIn(vCoins[i].tx->GetHash(), vCoins[i].i));
                                }

                                // Embed the constructed transaction data in wtxNew.
                                *static_cast<CTransaction*>(&wtxNew) = CTransaction(txNew);
                                break;
                            }

                            std::string strFailReason;
                            if (!makeRingCT(wtxNew, ringSize, strFailReason)) {
                                ret = false;
                            }

                            if (ret && !generateBulletProofAggregate(wtxNew)) {
                                strFailReason = _("There is an internal error in generating bulletproofs. Please try again later.");
                                ret = false;
                            }

                            if (ret) {
                                for (size_t i = 0; i < wtxNew.vout.size(); i++) {
                                    wtxNew.vout[i].nValue = 0;
                                }
                                CReserveKey reservekey(pwalletMain);
                                if (!pwalletMain->CommitTransaction(wtxNew, reservekey, "tx")) {
                                    inSpendQueueOutpointsPerSession.clear();
                                    ret = false;
                                }
                                if (ret) {
                                    for (size_t i = 0; i < inSpendQueueOutpointsPerSession.size(); i++) {
                                        inSpendQueueOutpoints[inSpendQueueOutpointsPerSession[i]] = true;
                                    }
                                    inSpendQueueOutpointsPerSession.clear();

                                    uint256 hash = wtxNew.GetHash();
                                    int maxTxPrivKeys = txPrivKeys.size() > wtxNew.vout.size() ? wtxNew.vout.size() : txPrivKeys.size();
                                    for (int i = 0; i < maxTxPrivKeys; i++) {
                                        std::string key = hash.GetHex() + std::to_string(i);
                                        CWalletDB(strWalletFile).WriteTxPrivateKey(key, CBitcoinSecret(txPrivKeys[i]).ToString());
                                    }
                                    txPrivKeys.clear();
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    return ret;
}

void CWallet::AutoCombineDust()
{
    bool autoCombine = GetBoolArg("-autocombine", false);
    bool autoConsolidate = GetBoolArg("-autoconsolidate", false);
    int64_t nAutoCombineSleep = 0;
    nAutoCombineSleep = GetArg("-autocombine", 300);
    if (IsInitialBlockDownload() || !masternodeSync.IsBlockchainSynced() || !autoCombine || IsLocked()) {
        LogPrintf("%s: Skipped due to settings or locked and/or syncing wallet\n", __func__);
        return;
    }
    if (chainActive.Tip()->nTime < (GetAdjustedTime() - nDefaultMinerSleep)) {
        LogPrintf("%s: Time elapsed for autocombine transaction too short\n", __func__);
        return;
    }

    if (stakingMode == StakingMode::STAKING_WITH_CONSOLIDATION && autoConsolidate) {
        if (fGenerateDapscoins && chainActive.Tip()->nHeight >= Params().LAST_POW_BLOCK()) {
            //sweeping to create larger UTXO for staking
            LOCK2(cs_main, cs_wallet);
            CAmount max = dirtyCachedBalance;
            if (max == 0) {
                max = GetBalance();
            }
            uint32_t nTime = ReadAutoConsolidateSettingTime();
            nTime = (nTime == 0)? GetAdjustedTime() : nTime;
            LogPrintf("%s: Attempting to create a consolidation transaction for a larger UTXO for staking\n", __func__);
            CreateSweepingTransaction(MINIMUM_STAKE_AMOUNT, max + COIN, nTime);
        }
        return;
    }
    CreateSweepingTransaction(nAutoCombineThreshold, nAutoCombineThreshold, GetAdjustedTime());
}

bool CWallet::estimateStakingConsolidationFees(CAmount& minFee, CAmount& maxFee) {
    //finding all spendable UTXOs < MIN_STAKING
    CAmount total = 0;
    std::vector<COutput> vCoins, underStakingThresholdCoins;
    {
        LOCK2(cs_main, cs_wallet);
        {
            for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it) {
                const uint256& wtxid = it->first;
                const CWalletTx* pcoin = &(*it).second;

                int nDepth = pcoin->GetDepthInMainChain(false);
                if ((pcoin->IsCoinBase() || pcoin->IsCoinStake()) && pcoin->GetBlocksToMaturity() > 0)
                    continue;
                if (nDepth == 0 && !pcoin->InMempool())
                    continue;
                for(size_t i = 0; i < pcoin->vout.size(); i++) {
                    if (pcoin->vout[i].IsEmpty()) continue;
                    isminetype mine = IsMine(pcoin->vout[i]);
                    if (mine == ISMINE_NO)
                        continue;
                    if (mine == ISMINE_WATCH_ONLY)
                        continue;
                    CAmount decodedAmount;
                    CKey decodedBlind;
                    RevealTxOutAmount(*pcoin, pcoin->vout[i], decodedAmount, decodedBlind);

                    std::vector<unsigned char> commitment;
                    if (!decodedBlind.IsValid()) {
                        unsigned char blind[32];
                        CreateCommitmentWithZeroBlind(decodedAmount, blind, commitment);
                    } else {
                        CreateCommitment(decodedBlind.begin(), decodedAmount, commitment);
                    }
                    if (pcoin->vout[i].commitment != commitment) {
                        LogPrintf("%s: Commitment not match hash = %s, i = %d, commitment = %s, recomputed = %s, revealed mask = %s\n", __func__, pcoin->GetHash().GetHex(), i, HexStr(&pcoin->vout[i].commitment[0], &pcoin->vout[i].commitment[0] + 33), HexStr(&commitment[0], &commitment[0] + 33), HexStr(decodedBlind.begin(), decodedBlind.begin() + 32));
                        continue;
                    }

                    if (IsSpent(wtxid, i)) continue;

                    {
                        COutPoint outpoint(wtxid, i);
                        if (inSpendQueueOutpoints.count(outpoint)) {
                            continue;
                        }
                    }
                    vCoins.push_back(COutput(pcoin, i, nDepth, true));
                    total += decodedAmount;
                    if (decodedAmount < MINIMUM_STAKE_AMOUNT) underStakingThresholdCoins.push_back(COutput(pcoin, i, nDepth, true));
                }
            }
        }
    }

    minFee = 0;
    maxFee = 0;
    if (total < MINIMUM_STAKE_AMOUNT) return false; //no staking sweeping will be created
    size_t numUTXOs = vCoins.size();
    return true;
}

int CWallet::MaxTxSizePerTx() {
    return ComputeTxSize(50, 2, 15);
}

bool CWallet::MultiSend()
{
    LOCK2(cs_main, cs_wallet);
    // Stop the old blocks from sending multisends
    if (chainActive.Tip()->nTime < (GetAdjustedTime() - 300) || IsLocked()) {
        return false;
    }

    if (chainActive.Tip()->nHeight <= nLastMultiSendHeight) {
        LogPrintf("Multisend: lastmultisendheight is higher than current best height\n");
        return false;
    }

    std::vector<COutput> vCoins;
    AvailableCoins(vCoins);

    bool stakeSent = false;
    bool mnSent = false;
    for (const COutput& out : vCoins) {
        //need output with precise confirm count - this is how we identify which is the output to send
        if (out.tx->GetDepthInMainChain() != Params().COINBASE_MATURITY() + 1)
            continue;

        COutPoint outpoint(out.tx->GetHash(), out.i);
        bool sendMSonMNReward = fMultiSendMasternodeReward && outpoint.IsMasternodeReward(out.tx);
        bool sendMSOnStake = fMultiSendStake && out.tx->IsCoinStake() && !sendMSonMNReward; //output is either mnreward or stake reward, not both

        if (!(sendMSOnStake || sendMSonMNReward))
            continue;

        CTxDestination destMyAddress;
        if (!ExtractDestination(out.tx->vout[out.i].scriptPubKey, destMyAddress)) {
            LogPrintf("Multisend: failed to extract destination\n");
            continue;
        }

        //Disabled Addresses won't send MultiSend transactions
        if (vDisabledAddresses.size() > 0) {
            for (unsigned int i = 0; i < vDisabledAddresses.size(); i++) {
                if (vDisabledAddresses[i] == CBitcoinAddress(destMyAddress).ToString()) {
                    LogPrintf("Multisend: disabled address preventing multisend\n");
                    return false;
                }
            }
        }

        // create new coin control, populate it with the selected utxo, create sending vector
        CCoinControl cControl;
        COutPoint outpt(out.tx->GetHash(), out.i);
        cControl.Select(outpt);
        cControl.destChange = destMyAddress;

        CWalletTx wtx;
        CReserveKey keyChange(this); // this change address does not end up being used, because change is returned with coin control switch
        CAmount nFeeRet = 0;
        vector<pair<CScript, CAmount> > vecSend;

        // loop through multisend vector and add amounts and addresses to the sending vector
        const isminefilter filter = ISMINE_SPENDABLE;
        CAmount nAmount = 0;
        for (unsigned int i = 0; i < vMultiSend.size(); i++) {
            // MultiSend vector is a pair of 1)Address as a std::string 2) Percent of stake to send as an int
            nAmount = ((out.tx->GetCredit(filter) - out.tx->GetDebit(filter)) * vMultiSend[i].second) / 100;
            CBitcoinAddress strAddSend(vMultiSend[i].first);
            CScript scriptPubKey;
            scriptPubKey = GetScriptForDestination(strAddSend.Get());
            vecSend.push_back(make_pair(scriptPubKey, nAmount));
        }

        //get the fee amount
        CWalletTx wtxdummy;
        string strErr;
        CreateTransaction(vecSend, wtxdummy, keyChange, nFeeRet, strErr, &cControl, ALL_COINS, false, CAmount(0));
        CAmount nLastSendAmount = vecSend[vecSend.size() - 1].second;
        if (nLastSendAmount < nFeeRet + 500) {
            LogPrintf("%s: fee of %d is too large to insert into last output\n", __func__, nFeeRet + 500);
            return false;
        }
        vecSend[vecSend.size() - 1].second = nLastSendAmount - nFeeRet - 500;

        // Create the transaction and commit it to the network
        if (!CreateTransaction(vecSend, wtx, keyChange, nFeeRet, strErr, &cControl, ALL_COINS, false, CAmount(0))) {
            LogPrintf("MultiSend createtransaction failed\n");
            return false;
        }

        if (!CommitTransaction(wtx, keyChange)) {
            LogPrintf("MultiSend transaction commit failed\n");
            return false;
        } else
            fMultiSendNotify = true;

        //write nLastMultiSendHeight to DB
        CWalletDB walletdb(strWalletFile);
        nLastMultiSendHeight = chainActive.Tip()->nHeight;
        if (!walletdb.WriteMSettings(fMultiSendStake, fMultiSendMasternodeReward, nLastMultiSendHeight))
            LogPrintf("Failed to write MultiSend setting to DB\n");

        LogPrintf("MultiSend successfully sent\n");

        //set which MultiSend triggered
        if (sendMSOnStake)
            stakeSent = true;
        else
            mnSent = true;

        //stop iterating if we have sent out all the MultiSend(s)
        if ((stakeSent && mnSent) || (stakeSent && !fMultiSendMasternodeReward) || (mnSent && !fMultiSendStake))
            return true;
    }

    return true;
}

CKeyPool::CKeyPool()
{
    nTime = GetTime();
}

CKeyPool::CKeyPool(const CPubKey& vchPubKeyIn)
{
    nTime = GetTime();
    vchPubKey = vchPubKeyIn;
}

CWalletKey::CWalletKey(int64_t nExpires)
{
    nTimeCreated = (nExpires ? GetTime() : 0);
    nTimeExpires = nExpires;
}

int CMerkleTx::SetMerkleBranch(const CBlock& block)
{
    AssertLockHeld(cs_main);
    CBlock blockTmp;

    // Update the tx's hashBlock
    hashBlock = block.GetHash();

    // Locate the transaction
    for (nIndex = 0; nIndex < (int)block.vtx.size(); nIndex++)
        if (block.vtx[nIndex] == *(CTransaction*)this)
            break;
    if (nIndex == (int)block.vtx.size()) {
        vMerkleBranch.clear();
        nIndex = -1;
        LogPrintf("ERROR: SetMerkleBranch() : couldn't find tx in block\n");
        return 0;
    }

    // Fill in merkle branch
    vMerkleBranch = block.GetMerkleBranch(nIndex);

    // Is the tx in a block that's in the main chain
    BlockMap::iterator mi = mapBlockIndex.find(hashBlock);
    if (mi == mapBlockIndex.end())
        return 0;
    const CBlockIndex* pindex = (*mi).second;
    if (!pindex || !chainActive.Contains(pindex))
        return 0;

    return chainActive.Height() - pindex->nHeight + 1;
}

int CMerkleTx::GetDepthInMainChainINTERNAL(const CBlockIndex*& pindexRet) const
{
    if (hashBlock == 0 || nIndex == -1)
        return 0;
    AssertLockHeld(cs_main);

    // Find the block it claims to be in
    BlockMap::iterator mi = mapBlockIndex.find(hashBlock);
    if (mi == mapBlockIndex.end())
        return 0;
    CBlockIndex* pindex = (*mi).second;
    if (!pindex || !chainActive.Contains(pindex))
        return 0;

    // Make sure the merkle branch connects to this block
    if (!fMerkleVerified) {
        if (CBlock::CheckMerkleBranch(GetHash(), vMerkleBranch, nIndex) != pindex->hashMerkleRoot)
            return 0;
        fMerkleVerified = true;
    }

    pindexRet = pindex;
    return chainActive.Height() - pindex->nHeight + 1;
}

int CMerkleTx::GetDepthInMainChain(bool enableIX) const
{
    const CBlockIndex* pindexRet;
    return GetDepthInMainChain(pindexRet, enableIX);
}

int CMerkleTx::GetDepthInMainChain(const CBlockIndex*& pindexRet, bool enableIX) const
{
    AssertLockHeld(cs_main);
    int nResult = GetDepthInMainChainINTERNAL(pindexRet);
    if (nResult == 0 && !mempool.exists(GetHash()))
        return -1; // Not in chain, not in mempool

    if (enableIX) {
        if (nResult < 6) {
            int signatures = GetTransactionLockSignatures();
            if (signatures >= SWIFTTX_SIGNATURES_REQUIRED) {
                return nSwiftTXDepth + nResult;
            }
        }
    }

    return nResult;
}

int CMerkleTx::GetBlocksToMaturity() const
{
    LOCK(cs_main);
    if (!(IsCoinBase() || IsCoinStake()))
        return 0;
    return max(0, (Params().COINBASE_MATURITY() + 1) - GetDepthInMainChain());
}

bool CMerkleTx::IsInMainChain() const
{
    return GetDepthInMainChain(false) > 0;
}

bool CMerkleTx::IsInMainChainImmature() const
{
    if (!IsCoinBase() && !IsCoinStake()) return false;
    const int depth = GetDepthInMainChain(false);
    return (depth > 0 && depth <= Params().COINBASE_MATURITY());
}

bool CMerkleTx::AcceptToMemoryPool(bool fLimitFree, bool fRejectInsaneFee, bool ignoreFees)
{
    CValidationState state;
    bool fAccepted = ::AcceptToMemoryPool(mempool, state, *this, fLimitFree, NULL, fRejectInsaneFee, ignoreFees);
    if (!fAccepted)
        LogPrintf("%s : %s\n", __func__, state.GetRejectReason());
    return fAccepted;
}

int CMerkleTx::GetTransactionLockSignatures() const
{
    if (fLargeWorkForkFound || fLargeWorkInvalidChainFound) return -2;
    if (!fEnableSwiftTX) return -1;

    //compile consessus vote
    std::map<uint256, CTransactionLock>::iterator i = mapTxLocks.find(GetHash());
    if (i != mapTxLocks.end()) {
        return (*i).second.CountSignatures();
    }

    return -1;
}

bool CMerkleTx::IsTransactionLockTimedOut() const
{
    if (!fEnableSwiftTX) return 0;

    //compile consessus vote
    std::map<uint256, CTransactionLock>::iterator i = mapTxLocks.find(GetHash());
    if (i != mapTxLocks.end()) {
        return GetTime() > (*i).second.nTimeout;
    }

    return false;
}

CWallet::CWallet()
{
    SetNull();
}

CWallet::CWallet(std::string strWalletFileIn)
{
    SetNull();

    strWalletFile = strWalletFileIn;
    fFileBacked = true;
}

CWallet::~CWallet()
{
    delete pwalletdbEncryption;
}

void CWallet::SetNull()
{
    nWalletVersion = FEATURE_BASE;
    nWalletMaxVersion = FEATURE_BASE;
    fFileBacked = false;
    nMasterKeyMaxID = 0;
    pwalletdbEncryption = NULL;
    nOrderPosNext = 0;
    nNextResend = 0;
    nLastResend = 0;
    nTimeFirstKey = 0;
    fWalletUnlockAnonymizeOnly = false;
    walletStakingInProgress = false;
    fBackupMints = false;

    // Stake Settings
    nHashDrift = 45;
    nStakeSplitThreshold = 100000;
    nHashInterval = 22;
    nStakeSetUpdateTime = 300; // 5 minutes

    //MultiSend
    vMultiSend.clear();
    fMultiSendStake = false;
    fMultiSendMasternodeReward = false;
    fMultiSendNotify = false;
    strMultiSendChangeAddress = "";
    nLastMultiSendHeight = 0;
    vDisabledAddresses.clear();

    //Auto Combine Dust
    fCombineDust = true;
    nAutoCombineThreshold = 540 * COIN;
}

bool CWallet::isMultiSendEnabled()
{
    return fMultiSendMasternodeReward || fMultiSendStake;
}

void CWallet::setMultiSendDisabled()
{
    fMultiSendMasternodeReward = false;
    fMultiSendStake = false;
}

bool CWallet::CanSupportFeature(enum WalletFeature wf)
{
    AssertLockHeld(cs_wallet);
    return nWalletMaxVersion >= wf;
}

bool CWallet::LoadMinVersion(int nVersion)
{
    AssertLockHeld(cs_wallet);
    nWalletVersion = nVersion;
    nWalletMaxVersion = std::max(nWalletMaxVersion, nVersion);
    return true;
}

isminetype CWallet::IsMine(const CTxOut& txout) const
{
    return ::IsMine(*this, txout.scriptPubKey);
}

CAmount CWallet::GetCredit(const CTransaction& tx, const CTxOut& txout, const isminefilter& filter) const
{
    return ((IsMine(txout) & filter) ? getCTxOutValue(tx, txout) : 0);
}

CAmount CWallet::GetChange(const CTransaction& tx, const CTxOut& txout) const
{
    return (IsChange(txout) ? getCTxOutValue(tx, txout) : 0);
}

bool CWallet::IsMine(const CTransaction& tx) const
{
    for (const CTxOut& txout : tx.vout)
    if (IsMine(txout))
        return true;
    return false;
}

bool CWallet::IsFromMe(const CTransaction& tx) const
{
    return (GetDebit(tx, ISMINE_ALL) > 0);
}

CAmount CWallet::GetDebit(const CTransaction& tx, const isminefilter& filter) const
{
    CAmount nDebit = 0;
    for (const CTxIn& txin : tx.vin) {
        nDebit += GetDebit(txin, filter);
    }
    return nDebit;
}

CAmount CWallet::GetCredit(const CTransaction& tx, const isminefilter& filter) const
{
    CAmount nCredit = 0;
    for (const CTxOut& txout : tx.vout) {
        nCredit += GetCredit(tx, txout, filter);
    }
    return nCredit;
}

CAmount CWallet::GetChange(const CTransaction& tx) const
{
    CAmount nChange = 0;
    for (const CTxOut& txout : tx.vout) {
        nChange += GetChange(tx, txout);
    }
    return nChange;
}

void CWallet::Inventory(const uint256& hash)
{
    {
        LOCK(cs_wallet);
        std::map<uint256, int>::iterator mi = mapRequestCount.find(hash);
        if (mi != mapRequestCount.end())
            (*mi).second++;
    }
}

unsigned int CWallet::GetKeyPoolSize()
{
    AssertLockHeld(cs_wallet); // setKeyPool
    return setKeyPool.size();
}

int CWallet::GetVersion()
{
    LOCK(cs_wallet);
    return nWalletVersion;
}

CWalletTx::CWalletTx()
{
    Init(NULL);
}

CWalletTx::CWalletTx(CWallet* pwalletIn)
{
    Init(pwalletIn);
}

CWalletTx::CWalletTx(CWallet* pwalletIn, const CMerkleTx& txIn) : CMerkleTx(txIn)
{
    Init(pwalletIn);
}

CWalletTx::CWalletTx(CWallet* pwalletIn, const CTransaction& txIn) : CMerkleTx(txIn)
{
    Init(pwalletIn);
}

void CWalletTx::Init(CWallet* pwalletIn)
{
    pwallet = pwalletIn;
    mapValue.clear();
    vOrderForm.clear();
    fTimeReceivedIsTxTime = false;
    nTimeReceived = 0;
    nTimeSmart = 0;
    fFromMe = false;
    strFromAccount.clear();
    fDebitCached = false;
    fCreditCached = false;
    fImmatureCreditCached = false;
    fAvailableCreditCached = false;
    fAnonymizableCreditCached = false;
    fAnonymizedCreditCached = false;
    fDenomUnconfCreditCached = false;
    fDenomConfCreditCached = false;
    fWatchDebitCached = false;
    fWatchCreditCached = false;
    fImmatureWatchCreditCached = false;
    fAvailableWatchCreditCached = false;
    fChangeCached = false;
    nDebitCached = 0;
    nCreditCached = 0;
    nImmatureCreditCached = 0;
    nAvailableCreditCached = 0;
    nAnonymizableCreditCached = 0;
    nAnonymizedCreditCached = 0;
    nDenomUnconfCreditCached = 0;
    nDenomConfCreditCached = 0;
    nWatchDebitCached = 0;
    nWatchCreditCached = 0;
    nAvailableWatchCreditCached = 0;
    nImmatureWatchCreditCached = 0;
    nChangeCached = 0;
    nOrderPos = -1;
}

bool CWalletTx::IsTrusted() const
{
    // Quick answer in most cases
    if (!IsFinalTx(*this))
        return false;
    int nDepth = GetDepthInMainChain();
    if (nDepth >= 1)
        return true;
    if (nDepth < 0)
        return false;
    if (!bSpendZeroConfChange || !IsFromMe(ISMINE_ALL)) // using wtx's cached debit
        return false;
     // Don't trust unconfirmed transactions from us unless they are in the mempool.
    {
        LOCK(mempool.cs);
        if (!mempool.exists(GetHash())) {
            return false;
        }
    }
    // Trusted if all inputs are from us and are in the mempool:
    for (const CTxIn& txin : vin) {
        // Transactions not sent by us: not trusted
        COutPoint prevout = pwallet->findMyOutPoint(txin);
        const CWalletTx* parent = pwallet->GetWalletTx(prevout.hash);
        if (parent == NULL)
            return false;
        const CTxOut& parentOut = parent->vout[prevout.n];
        if (pwallet->IsMine(parentOut) != ISMINE_SPENDABLE)
            return false;
    }
    return true;
}

void CWalletTx::MarkDirty()
{
    fCreditCached = false;
    fAvailableCreditCached = false;
    fAnonymizableCreditCached = false;
    fAnonymizedCreditCached = false;
    fDenomUnconfCreditCached = false;
    fDenomConfCreditCached = false;
    fWatchDebitCached = false;
    fWatchCreditCached = false;
    fAvailableWatchCreditCached = false;
    fImmatureWatchCreditCached = false;
    fDebitCached = false;
    fChangeCached = false;
}

void CWalletTx::BindWallet(CWallet* pwalletIn)
{
    pwallet = pwalletIn;
    MarkDirty();
}

CAmount CWalletTx::GetChange() const
{
    if (fChangeCached)
        return nChangeCached;
    nChangeCached = pwallet->GetChange(*this);
    fChangeCached = true;
    return nChangeCached;
}

bool CWalletTx::IsFromMe(const isminefilter& filter) const
{
    return (GetDebit(filter) > 0);
}

int CWalletTx::GetBlockHeight() const
{
    if (hashBlock.IsNull()) {
        return -1; //not in the chain
    } else {
        return mapBlockIndex[hashBlock]->nHeight;
    }
}

bool CWallet::ReadAccountList(std::string& accountList)
{
    return CWalletDB(strWalletFile).ReadStealthAccountList(accountList);
}

bool CWallet::ReadStealthAccount(const std::string& strAccount, CStealthAccount& account)
{
    return CWalletDB(strWalletFile).ReadStealthAccount(strAccount, account);
}

bool CWallet::ComputeStealthPublicAddress(const std::string& accountName, std::string& pubAddress)
{
    CStealthAccount account;
    if (CWalletDB(strWalletFile).ReadStealthAccount(accountName, account)) {
        return EncodeStealthPublicAddress(account.viewAccount.vchPubKey, account.spendAccount.vchPubKey, pubAddress);
    }
    return false;
}

bool CWallet::ComputeIntegratedPublicAddress(const uint64_t paymentID, const std::string& accountName, std::string& pubAddress)
{
    CStealthAccount account;
    if (CWalletDB(strWalletFile).ReadStealthAccount(accountName, account)) {
        return EncodeIntegratedAddress(account.viewAccount.vchPubKey, account.spendAccount.vchPubKey, paymentID, pubAddress);
    }
    return false;
}

void add1s(std::string& s, int wantedSize)
{
    int currentLength = s.length();
    for (int i = 0; i < wantedSize - currentLength; i++) {
        s = "1" + s;
    }
}


bool CWallet::encodeStealthBase58(const std::vector<unsigned char>& raw, std::string& stealth)
{
    if (raw.size() != 71 && raw.size() != 79) {
        return false;
    }
    stealth = "";

    //Encoding Base58 using block=8 bytes
    int i = 0;
    while (i < (int)raw.size()) {
        std::vector<unsigned char> input8;
        std::copy(raw.begin() + i, raw.begin() + i + 8, std::back_inserter(input8)); //copy 8 bytes
        std::string out = EncodeBase58(input8);
        if (out.length() < 11) {
            add1s(out, 11);
        }
        stealth += out;
        i += 8;
        if (i + 8 > (int)raw.size()) {
            //the last block of 7
            std::vector<unsigned char> input7;
            std::copy(raw.begin() + i, raw.begin() + i + 7, std::back_inserter(input7)); //copy 7 bytes
            std::string out11 = EncodeBase58(input7);
            add1s(out11, 11);
            stealth += out11;
            i += 7;
        }
    }
    return true;
}

bool CWallet::EncodeStealthPublicAddress(const std::vector<unsigned char>& pubViewKey, const std::vector<unsigned char>& pubSpendKey, std::string& pubAddrb58)
{
    std::vector<unsigned char> pubAddr;
    pubAddr.push_back(18);                                                                 //1 byte
    std::copy(pubSpendKey.begin(), pubSpendKey.begin() + 33, std::back_inserter(pubAddr)); //copy 33 bytes
    std::copy(pubViewKey.begin(), pubViewKey.begin() + 33, std::back_inserter(pubAddr));   //copy 33 bytes
    uint256 h = Hash(pubAddr.begin(), pubAddr.end());
    unsigned char* begin = h.begin();
    pubAddr.push_back(*(begin));
    pubAddr.push_back(*(begin + 1));
    pubAddr.push_back(*(begin + 2));
    pubAddr.push_back(*(begin + 3));

    return encodeStealthBase58(pubAddr, pubAddrb58);
}

bool CWallet::EncodeIntegratedAddress(const std::vector<unsigned char>& pubViewKey, const std::vector<unsigned char>& pubSpendKey, uint64_t paymentID, std::string& pubAddrb58)
{
    std::vector<unsigned char> pubAddr;
    pubAddr.push_back(19);                                                                            //1 byte 19 for integrated address
    std::copy(pubSpendKey.begin(), pubSpendKey.begin() + 33, std::back_inserter(pubAddr));            //copy 33 bytes
    std::copy(pubViewKey.begin(), pubViewKey.begin() + 33, std::back_inserter(pubAddr));              //copy 33 bytes
    std::copy((char*)&paymentID, (char*)&paymentID + sizeof(paymentID), std::back_inserter(pubAddr)); //8 bytes of payment id
    uint256 h = Hash(pubAddr.begin(), pubAddr.end());
    unsigned char* begin = h.begin();
    pubAddr.push_back(*(begin));
    pubAddr.push_back(*(begin + 1));
    pubAddr.push_back(*(begin + 2));
    pubAddr.push_back(*(begin + 3));

    return encodeStealthBase58(pubAddr, pubAddrb58);
}

bool CWallet::EncodeStealthPublicAddress(const CPubKey& pubViewKey, const CPubKey& pubSpendKey, std::string& pubAddr)
{
    if (pubViewKey.IsCompressed() && pubSpendKey.IsCompressed()) {
        return EncodeStealthPublicAddress(pubViewKey.Raw(), pubSpendKey.Raw(), pubAddr);
    }
    return false;
}

bool CWallet::EncodeIntegratedAddress(const CPubKey& pubViewKey, const CPubKey& pubSpendKey, uint64_t paymentID, std::string& pubAddr)
{
    if (pubViewKey.IsCompressed() && pubSpendKey.IsCompressed()) {
        return EncodeIntegratedAddress(pubViewKey.Raw(), pubSpendKey.Raw(), paymentID, pubAddr);
    }
    return false;
}

bool CWallet::GenerateIntegratedAddress(const std::string& accountName, std::string& pubAddr)
{
    CStealthAccount account;
    if (CWalletDB(strWalletFile).ReadStealthAccount(accountName, account)) {
        return GenerateIntegratedAddress(account.viewAccount.vchPubKey, account.spendAccount.vchPubKey, pubAddr);
    }
    return false;
}

bool CWallet::GenerateIntegratedAddress(const CPubKey& pubViewKey, const CPubKey& pubSpendKey, std::string& pubAddr)
{
    uint64_t paymentID = GetRand(0xFFFFFFFFFFFFFFFF);
    return EncodeIntegratedAddress(pubViewKey, pubSpendKey, paymentID, pubAddr);
}

std::string CWallet::GenerateIntegratedAddressWithRandomPaymentID(std::string accountName, uint64_t& paymentID) {
    CStealthAccount account;
    if (CWalletDB(strWalletFile).ReadStealthAccount(accountName, account)) {
        std::string pubAddress;
        paymentID = GetRand(0xFFFFFFFFFFFFFFFF);
        EncodeIntegratedAddress(account.viewAccount.vchPubKey, account.spendAccount.vchPubKey, paymentID, pubAddress);
        return pubAddress;
    }
    return "";
}

std::string CWallet::GenerateIntegratedAddressWithProvidedPaymentID(std::string accountName, uint64_t paymentID) {
    CStealthAccount account;
    if (CWalletDB(strWalletFile).ReadStealthAccount(accountName, account)) {
        std::string pubAddress;
        EncodeIntegratedAddress(account.viewAccount.vchPubKey, account.spendAccount.vchPubKey, paymentID, pubAddress);
        return pubAddress;
    }
    return "";
}

bool CWallet::DecodeStealthAddress(const std::string& stealth, CPubKey& pubViewKey, CPubKey& pubSpendKey, bool& hasPaymentID, uint64_t& paymentID)
{
    if (stealth.length() != 99 && stealth.length() != 110) {
        return false;
    }
    std::vector<unsigned char> raw;
    size_t i = 0;
    while (i < stealth.length()) {
        int npos = 11;
        std::string sub = stealth.substr(i, npos);
        std::vector<unsigned char> decoded;
        if (DecodeBase58(sub, decoded) &&
            ((decoded.size() == 8 && i + 11 < stealth.length() - 1) || (decoded.size() == 7 && i + 11 == stealth.length() - 1))) {
            std::copy(decoded.begin(), decoded.end(), std::back_inserter(raw));
        } else if (sub[0] == '1') {
            //find the last padding character
            size_t lastPad = 0;
            while (lastPad < sub.length() - 1) {
                if (sub[lastPad + 1] != '1') {
                    break;
                }
                lastPad++;
            }
            //check whether '1' is padding
            int padIdx = lastPad;
            while (padIdx >= 0 && sub[padIdx] == '1') {
                std::string str_without_pads = sub.substr(padIdx + 1);
                decoded.clear();
                if (DecodeBase58(str_without_pads, decoded)) {
                    if ((decoded.size() == 8 && i + 11 < stealth.length()) || (decoded.size() == 7 && i + 11 == stealth.length())) {
                        std::copy(decoded.begin(), decoded.end(), std::back_inserter(raw));
                        break;
                    } else {
                        decoded.clear();
                    }
                }
                padIdx--;
            }
            if (decoded.size() == 0) {
                //cannot decode this block of stealth address
                return false;
            }
        } else {
            return false;
        }
        i = i + npos;
    }

    if (raw.size() != 71 && raw.size() != 79) {
        return false;
    }
    hasPaymentID = false;
    if (raw.size() == 79) {
        hasPaymentID = true;
    }

    //Check checksum
    uint256 h = Hash(raw.begin(), raw.begin() + raw.size() - 4);
    unsigned char* h_begin = h.begin();
    unsigned char* p_raw = &raw[raw.size() - 4];
    if (memcmp(h_begin, p_raw, 4) != 0) {
        return false;
    }

    std::vector<unsigned char> vchSpend, vchView;
    std::copy(raw.begin() + 1, raw.begin() + 34, std::back_inserter(vchSpend));
    std::copy(raw.begin() + 34, raw.begin() + 67, std::back_inserter(vchView));
    if (hasPaymentID) {
        memcpy((char*)&paymentID, &raw[0] + 67, sizeof(paymentID));
    }
    pubSpendKey.Set(vchSpend.begin(), vchSpend.end());
    pubViewKey.Set(vchView.begin(), vchView.end());

    return true;
}

bool computeStealthDestination(const CKey& secret, const CPubKey& pubViewKey, const CPubKey& pubSpendKey, CPubKey& des)
{
    //generate transaction destination: P = Hs(rA)G+B, A = view pub, B = spend pub, r = secret
    //1. Compute rA
    unsigned char rA[65];
    unsigned char B[65];
    memcpy(rA, pubViewKey.begin(), pubViewKey.size());
    if (!secp256k1_ec_pubkey_tweak_mul(rA, pubViewKey.size(), secret.begin())) {
        return false;
    }
    uint256 HS = Hash(rA, rA + pubViewKey.size());

    memcpy(B, pubSpendKey.begin(), pubSpendKey.size());

    if (!secp256k1_ec_pubkey_tweak_add(B, pubSpendKey.size(), HS.begin()))
        throw runtime_error("Cannot compute stealth destination");
    des.Set(B, B + pubSpendKey.size());
    return true;
}

bool CWallet::ComputeStealthDestination(const CKey& secret, const CPubKey& pubViewKey, const CPubKey& pubSpendKey, CPubKey& des)
{
    return computeStealthDestination(secret, pubViewKey, pubSpendKey, des);
}

bool CWallet::GenerateAddress(CPubKey& pub, CPubKey& txPub, CKey& txPriv) const
{
    LOCK2(cs_main, cs_wallet);
    {
        CKey view, spend;
        if (IsLocked()) {
            LogPrintf("%s:Wallet is locked\n", __func__);
            return false;
        }
        myViewPrivateKey(view);
        mySpendPrivateKey(spend);
        txPriv.MakeNewKey(true);
        txPub = txPriv.GetPubKey();
        return computeStealthDestination(txPriv, view.GetPubKey(), spend.GetPubKey(), pub);
    }
}

bool CWallet::SendToStealthAddress(const std::string& stealthAddr, const CAmount nValue, CWalletTx& wtxNew, bool fUseIX, int ringSize)
{
    LOCK2(cs_main, cs_wallet);
    // Check amount
    if (nValue <= 0)
        throw runtime_error("Invalid amount");

    string strError;
    if (this->IsLocked()) {
        strError = "Error: Wallet locked, unable to create transaction!";
        LogPrintf("SendToStealthAddress() : %s\n", strError);
        throw runtime_error(strError);
    }

    std::string myAddress;
    ComputeStealthPublicAddress("masteraccount", myAddress);
    bool tomyself = (myAddress == stealthAddr);
    //Parse stealth address
    CPubKey pubViewKey, pubSpendKey;
    bool hasPaymentID;
    uint64_t paymentID;
    if (!CWallet::DecodeStealthAddress(stealthAddr, pubViewKey, pubSpendKey, hasPaymentID, paymentID)) {
        throw runtime_error("Stealth address mal-formatted");
    }

    // Generate transaction public key
    CKey secret;
    secret.MakeNewKey(true);
    SetMinVersion(FEATURE_COMPRPUBKEY);
    wtxNew.txPrivM.Set(secret.begin(), secret.end(), true);

    wtxNew.hasPaymentID = 0;
    if (hasPaymentID) {
        wtxNew.hasPaymentID = 1;
        wtxNew.paymentID = paymentID;
    }

    //Compute stealth destination
    CPubKey stealthDes;
    CKey spend;
    mySpendPrivateKey(spend);
    computeStealthDestination(secret, pubViewKey, pubSpendKey, stealthDes);

    CScript scriptPubKey = GetScriptForDestination(stealthDes);
    CReserveKey reservekey(pwalletMain);

    CPubKey changeDes;
    CKey view;
    myViewPrivateKey(view);
    CKey secretChange;
    secretChange.MakeNewKey(true);
    computeStealthDestination(secretChange, view.GetPubKey(), spend.GetPubKey(), changeDes);
    CBitcoinAddress changeAddress(changeDes.GetID());
    CCoinControl control;
    control.destChange = changeAddress.Get();
    control.receiver = changeDes;
    control.txPriv = secretChange;
    CAmount nFeeRequired;
    if (!pwalletMain->CreateTransactionBulletProof(secret, pubViewKey, scriptPubKey, nValue, wtxNew, reservekey,
            nFeeRequired, strError, &control, ALL_COINS, fUseIX, (CAmount)0, 6, tomyself)) {
        if (nValue + nFeeRequired > pwalletMain->GetBalance())
            strError = strprintf("Error: This transaction requires a transaction fee of at least %s because of its amount, complexity, or use of recently received funds!, nfee=%d, nValue=%d", FormatMoney(nFeeRequired), nFeeRequired, nValue);
        LogPrintf("SendToStealthAddress() : Not enough! %s\n", strError);
        throw runtime_error(strError);
    }
    return true;
}

bool CWallet::IsTransactionForMe(const CTransaction& tx)
{
    LOCK(cs_wallet);
    {
        std::vector<CKey> spends, views;
        if (!allMyPrivateKeys(spends, views) || spends.size() != views.size()) {
            spends.clear();
            views.clear();
            CKey spend, view;
            if (!mySpendPrivateKey(spend) || !myViewPrivateKey(view)) {
                LogPrintf("Failed to find private keys\n");
                return false;
            }
            spends.push_back(spend);
            views.push_back(view);
        }
        for (const CTxOut& out : tx.vout) {
            if (out.IsEmpty()) {
                continue;
            }
            CPubKey txPub(out.txPub);
            for (size_t i = 0; i < spends.size(); i++) {
                CKey& spend = spends[i];
                CKey& view = views[i];
                const CPubKey& pubSpendKey = spend.GetPubKey();
                bool ret = false;

                //compute the tx destination
                //P' = Hs(aR)G+B, a = view private, B = spend pub, R = tx public key
                unsigned char aR[65];
                //copy R into a
                memcpy(aR, txPub.begin(), txPub.size());
                if (!secp256k1_ec_pubkey_tweak_mul(aR, txPub.size(), view.begin())) {
                    return false;
                }
                uint256 HS = Hash(aR, aR + txPub.size());
                unsigned char* pHS = HS.begin();
                unsigned char expectedDestination[65];
                memcpy(expectedDestination, pubSpendKey.begin(), pubSpendKey.size());
                if (!secp256k1_ec_pubkey_tweak_add(expectedDestination, pubSpendKey.size(), pHS)) {
                    continue;
                }
                CPubKey expectedDes(expectedDestination, expectedDestination + 33);
                CScript scriptPubKey = GetScriptForDestination(expectedDes);

                if (scriptPubKey == out.scriptPubKey) {
                    ret = true;
                }

                if (ret) {
                    LOCK(cs_wallet);
                    //Compute private key to spend
                    //x = Hs(aR) + b, b = spend private key
                    unsigned char HStemp[32];
                    unsigned char spendTemp[32];
                    memcpy(HStemp, HS.begin(), 32);
                    memcpy(spendTemp, spend.begin(), 32);
                    if (!secp256k1_ec_privkey_tweak_add(HStemp, spendTemp))
                        throw runtime_error("Failed to do secp256k1_ec_privkey_tweak_add");
                    CKey privKey;
                    privKey.Set(HStemp, HStemp + 32, true);
                    CPubKey computed = privKey.GetPubKey();

                    //put in map from address to txHash used for qt wallet
                    CKeyID tempKeyID = computed.GetID();
                    addrToTxHashMap[CBitcoinAddress(tempKeyID).ToString()] = tx.GetHash().GetHex();
                    AddKey(privKey);
                    CAmount c;
                    CKey blind;
                    RevealTxOutAmount(tx, out, c, blind);
                }
            }
        }
    }
    return true;
}

bool CWallet::AllMyPublicAddresses(std::vector<std::string>& addresses, std::vector<std::string>& accountNames)
{
    std::string labelList;
    if (!ReadAccountList(labelList)) {
        std::string masterAddr;
        ComputeStealthPublicAddress("masteraccount", masterAddr);
        addresses.push_back(masterAddr);
        accountNames.push_back("Master Account");
        return true;
    }

    std::vector<std::string> results;
    boost::split(results, labelList, [](char c) { return c == ','; });
    std::string masterAddr;
    ComputeStealthPublicAddress("masteraccount", masterAddr);
    accountNames.push_back("Master Account");
    results.push_back(masterAddr);
    for (size_t i = 0; i < results.size(); i++) {
        std::string& accountName = results[i];
        std::string stealthAddr;
        if (ComputeStealthPublicAddress(accountName, stealthAddr)) {
            addresses.push_back(stealthAddr);
            accountNames.push_back(accountName);
        }
    }
    return true;
}

bool CWallet::allMyPrivateKeys(std::vector<CKey>& spends, std::vector<CKey>& views)
{
    if (IsLocked()) {
        return false;
    }
    std::string labelList;
    CKey spend, view;
    mySpendPrivateKey(spend);
    myViewPrivateKey(view);
    spends.push_back(spend);
    views.push_back(view);

    if (!ReadAccountList(labelList)) {
        return false;
    }
    std::vector<std::string> results;
    boost::split(results, labelList, [](char c) { return c == ','; });
    for (size_t i = 0; i < results.size(); i++) {
        std::string& accountName = results[i];
        CStealthAccount stealthAcc;
        if (ReadStealthAccount(accountName, stealthAcc)) {
            CKey accSpend, accView;
            GetKey(stealthAcc.spendAccount.vchPubKey.GetID(), accSpend);
            GetKey(stealthAcc.viewAccount.vchPubKey.GetID(), accView);
            spends.push_back(accSpend);
            views.push_back(accView);
        }
    }
    return true;
}

CBitcoinAddress GetAccountAddress(uint32_t nAccountIndex, string strAccount, CWallet* pwalletMain)
{
    CWalletDB walletdb(pwalletMain->strWalletFile);

    CAccount account;

    // Generate a new key
    // if (!pwalletMain->GetKeyFromPool(account.vchPubKey))
    //     throw runtime_error("Error: Keypool ran out, please call keypoolrefill first");
    CKey newKey;
    pwalletMain->DeriveNewChildKey(nAccountIndex, newKey);
    account.vchPubKey = newKey.GetPubKey();
    account.nAccountIndex = nAccountIndex;

    pwalletMain->SetAddressBook(account.vchPubKey.GetID(), strAccount, "receive");
    walletdb.WriteAccount(strAccount, account);

    return CBitcoinAddress(account.vchPubKey.GetID());
}

void CWallet::DeriveNewChildKey(uint32_t nAccountIndex, CKey& secretRet)
{
    CHDChain hdChainTmp;
    if (!GetHDChain(hdChainTmp)) {
        throw std::runtime_error(std::string(__func__) + ": GetHDChain failed");
    }

    if (!DecryptHDChain(hdChainTmp))
        throw std::runtime_error(std::string(__func__) + ": DecryptHDChainSeed failed");
    // make sure seed matches this chain
    if (hdChainTmp.GetID() != hdChainTmp.GetSeedHash())
        throw std::runtime_error(std::string(__func__) + ": Wrong HD chain!");

    // derive child key at next index, skip keys already known to the wallet
    CExtKey childKey;
    uint32_t nChildIndex = 0;
    do {
        hdChainTmp.DeriveChildExtKey(nAccountIndex, false, nChildIndex, childKey);
        // increment childkey index
        nChildIndex++;
    } while (HaveKey(childKey.key.GetPubKey().GetID()));
    secretRet = childKey.key;

    CPubKey pubkey = secretRet.GetPubKey();
    assert(secretRet.VerifyPubKey(pubkey));

    // store metadata
    int64_t nCreationTime = GetTime();
    mapKeyMetadata[pubkey.GetID()] = CKeyMetadata(nCreationTime);

    if (!AddHDPubKey(childKey.Neuter(), false, nAccountIndex))
        throw std::runtime_error(std::string(__func__) + ": AddHDPubKey failed");
}

bool CWallet::GetPubKey(const CKeyID& address, CPubKey& vchPubKeyOut) const
{
    LOCK(cs_wallet);
    std::map<CKeyID, CHDPubKey>::const_iterator mi = mapHdPubKeys.find(address);
    if (mi != mapHdPubKeys.end()) {
        const CHDPubKey& hdPubKey = (*mi).second;
        vchPubKeyOut = hdPubKey.extPubKey.pubkey;
        return true;
    } else
        return CCryptoKeyStore::GetPubKey(address, vchPubKeyOut);
}

bool CWallet::GetKey(const CKeyID& address, CKey& keyOut) const
{
    LOCK(cs_wallet);
    std::map<CKeyID, CHDPubKey>::const_iterator mi = mapHdPubKeys.find(address);
    if (mi != mapHdPubKeys.end()) {
        // if the key has been found in mapHdPubKeys, derive it on the fly
        const CHDPubKey& hdPubKey = (*mi).second;
        CHDChain hdChainCurrent;
        if (!GetHDChain(hdChainCurrent))
            throw std::runtime_error(std::string(__func__) + ": GetHDChain failed");
        if (!DecryptHDChain(hdChainCurrent))
            throw std::runtime_error(std::string(__func__) + ": DecryptHDChainSeed failed");
        // make sure seed matches this chain
        if (hdChainCurrent.GetID() != hdChainCurrent.GetSeedHash())
            throw std::runtime_error(std::string(__func__) + ": Wrong HD chain!");

        CExtKey extkey;
        hdChainCurrent.DeriveChildExtKey(hdPubKey.nAccountIndex, hdPubKey.nChangeIndex != 0, hdPubKey.extPubKey.nChild, extkey);
        keyOut = extkey.key;

        return true;
    } else {
        return CCryptoKeyStore::GetKey(address, keyOut);
    }
}

bool CWallet::HaveKey(const CKeyID& address) const
{
    LOCK(cs_wallet);
    if (mapHdPubKeys.count(address) > 0)
        return true;
    return CCryptoKeyStore::HaveKey(address);
}

bool CWallet::LoadHDPubKey(const CHDPubKey& hdPubKey)
{
    AssertLockHeld(cs_wallet);

    mapHdPubKeys[hdPubKey.extPubKey.pubkey.GetID()] = hdPubKey;
    return true;
}

bool CWallet::AddHDPubKey(const CExtPubKey& extPubKey, bool fInternal, uint32_t nAccountIndex)
{
    AssertLockHeld(cs_wallet);

    CHDChain hdChainCurrent;
    GetHDChain(hdChainCurrent);

    CHDPubKey hdPubKey;
    hdPubKey.extPubKey = extPubKey;
    hdPubKey.nAccountIndex = nAccountIndex;
    hdPubKey.hdchainID = hdChainCurrent.GetID();
    hdPubKey.nChangeIndex = fInternal ? 1 : 0;
    mapHdPubKeys[extPubKey.pubkey.GetID()] = hdPubKey;

    CScript script;
    script = GetScriptForDestination(extPubKey.pubkey);
    if (HaveWatchOnly(script))
        RemoveWatchOnly(script);

    if (!fFileBacked)
        return true;

    return CWalletDB(strWalletFile).WriteHDPubKey(hdPubKey, mapKeyMetadata[extPubKey.pubkey.GetID()]);
}

void CWallet::createMasterKey() const
{
    int i = 0;
    CWalletDB pDB(strWalletFile);
    {
        LOCK(cs_wallet);
        while (i < 10) {
            std::string viewAccountLabel = "viewaccount";
            std::string spendAccountLabel = "spendaccount";

            CAccount viewAccount;
            pDB.ReadAccount(viewAccountLabel, viewAccount);
            if (!viewAccount.vchPubKey.IsValid()) {
                std::string viewAccountAddress = GetAccountAddress(0, viewAccountLabel, (CWallet*)this).ToString();
            }

            CAccount spendAccount;
            pDB.ReadAccount(spendAccountLabel, spendAccount);
            if (!spendAccount.vchPubKey.IsValid()) {
                std::string spendAccountAddress = GetAccountAddress(1, spendAccountLabel, (CWallet*)this).ToString();
            }
            if (viewAccount.vchPubKey.GetHex() == "" || spendAccount.vchPubKey.GetHex() == "") {
                i++;
                continue;
            }
            LogPrintf("Created master account\n");
            break;
        }
    }
}

bool CWallet::mySpendPrivateKey(CKey& spend) const
{
    {
        LOCK2(cs_main, cs_wallet);
        if (IsLocked()) {
            LogPrintf("%s:Wallet is locked\n", __func__);
            return false;
        }
        std::string spendAccountLabel = "spendaccount";
        CAccount spendAccount;
        CWalletDB pDB(strWalletFile);
        if (!pDB.ReadAccount(spendAccountLabel, spendAccount)) {
            LogPrintf("Cannot Load Spend private key, now create the master keys\n");
            createMasterKey();
            pDB.ReadAccount(spendAccountLabel, spendAccount);
        }
        const CKeyID& keyID = spendAccount.vchPubKey.GetID();
        GetKey(keyID, spend);
    }
    return true;
}
bool CWallet::myViewPrivateKey(CKey& view) const
{
    {
        LOCK2(cs_main, cs_wallet);
        if (IsLocked()) {
            LogPrintf("%s:Wallet is locked\n", __func__);
            return false;
        }
        std::string viewAccountLabel = "viewaccount";
        CAccount viewAccount;
        CWalletDB pDB(strWalletFile);
        if (!pDB.ReadAccount(viewAccountLabel, viewAccount)) {
            LogPrintf("Cannot Load view private key, now create the master keys\n");
            createMasterKey();
            pDB.ReadAccount(viewAccountLabel, viewAccount);
        }
        const CKeyID& keyID = viewAccount.vchPubKey.GetID();
        GetKey(keyID, view);
    }
    return true;
}

bool CWallet::RevealTxOutAmount(const CTransaction& tx, const CTxOut& out, CAmount& amount, CKey& blind) const
{
    if (IsLocked()) {
        return true;
    }
    if (tx.IsCoinBase()) {
        //Coinbase transaction output is not hidden, not need to decrypt
        amount = out.nValue;
        return true;
    }

    if (tx.IsCoinStake()) {
        if (out.nValue > 0) {
            amount = out.nValue;
            return true;
        }
    }

    if (amountMap.count(out.scriptPubKey) == 1) {
        amount = amountMap[out.scriptPubKey];
        blind.Set(blindMap[out.scriptPubKey].begin(), blindMap[out.scriptPubKey].end(), true);
        return true;
    }

    std::set<CKeyID> keyIDs;
    GetKeys(keyIDs);
    CPubKey sharedSec;
    for (const CKeyID& keyID : keyIDs) {
        CKey privKey;
        GetKey(keyID, privKey);
        CScript scriptPubKey = GetScriptForDestination(privKey.GetPubKey());
        if (scriptPubKey == out.scriptPubKey) {
            CPubKey txPub(&(out.txPub[0]), &(out.txPub[0]) + 33);
            CKey view;
            if (myViewPrivateKey(view)) {
                computeSharedSec(tx, out, sharedSec);
                uint256 val = out.maskValue.amount;
                uint256 mask = out.maskValue.mask;
                CKey decodedMask;
                ECDHInfo::Decode(mask.begin(), val.begin(), sharedSec, decodedMask, amount);
                std::vector<unsigned char> commitment;
                if (CreateCommitment(decodedMask.begin(), amount, commitment)) {
                    //make sure the amount and commitment are matched
                    if (commitment == out.commitment) {
                        amountMap[out.scriptPubKey] = amount;
                        blindMap[out.scriptPubKey] = decodedMask;
                        blind.Set(blindMap[out.scriptPubKey].begin(), blindMap[out.scriptPubKey].end(), true);
                        return true;
                    } else {
                        amount = 0;
                        amountMap[out.scriptPubKey] = amount;
                        return false;
                    }
                }
            }
        }
    }
    amount = 0;
    return false;
}

bool CWallet::findCorrespondingPrivateKey(const CTxOut& txout, CKey& key) const
{
    std::set<CKeyID> keyIDs;
    GetKeys(keyIDs);
    for (const CKeyID& keyID : keyIDs) {
        CBitcoinAddress address(keyID);
        GetKey(keyID, key);
        CPubKey pub = key.GetPubKey();
        CScript script = GetScriptForDestination(pub);
        if (script == txout.scriptPubKey) {
            return true;
        }
    }
    return false;
}

bool CWallet::generateKeyImage(const CScript& scriptPubKey, CKeyImage& img) const
{
    if (IsLocked()) {
        return false;
    }
    std::set<CKeyID> keyIDs;
    GetKeys(keyIDs);
    CKey key;
    unsigned char pubData[65];
    for (const CKeyID& keyID : keyIDs) {
        CBitcoinAddress address(keyID);
        GetKey(keyID, key);
        CPubKey pub = key.GetPubKey();
        CScript script = GetScriptForDestination(pub);
        if (script == scriptPubKey) {
            uint256 hash = pub.GetHash();
            pubData[0] = *(pub.begin());
            memcpy(pubData + 1, hash.begin(), 32);
            CPubKey newPubKey(pubData, pubData + 33);
            //P' = Hs(aR)G+B, a = view private, B = spend pub, R = tx public key
            unsigned char ki[65];
            //copy newPubKey into ki
            memcpy(ki, newPubKey.begin(), newPubKey.size());
            while (!secp256k1_ec_pubkey_tweak_mul(ki, newPubKey.size(), key.begin())) {
                hash = newPubKey.GetHash();
                pubData[0] = *(newPubKey.begin());
                memcpy(pubData + 1, hash.begin(), 32);
                newPubKey.Set(pubData, pubData + 33);
                memcpy(ki, newPubKey.begin(), newPubKey.size());
            }

            img = CKeyImage(ki, ki + 33);
            return true;
        }
    }
    return false;
}

bool CWallet::generateKeyImage(const CPubKey& pub, CKeyImage& img) const
{
    CScript script = GetScriptForDestination(pub);
    return generateKeyImage(script, img);
}

bool CWallet::EncodeTxOutAmount(CTxOut& out, const CAmount& amount, const unsigned char* sharedSec, bool isCoinstake)
{
    if (amount < 0) {
        return false;
    }
    //generate random mask
    if (!isCoinstake) {
        out.maskValue.inMemoryRawBind.MakeNewKey(true);
        memcpy(out.maskValue.mask.begin(), out.maskValue.inMemoryRawBind.begin(), 32);
        uint256 tempAmount((uint64_t)amount);
        memcpy(out.maskValue.amount.begin(), tempAmount.begin(), 32);
        CPubKey sharedPub(sharedSec, sharedSec + 33);
        ECDHInfo::Encode(out.maskValue.inMemoryRawBind, amount, sharedPub, out.maskValue.mask, out.maskValue.amount);
        out.maskValue.hashOfKey = Hash(sharedSec, sharedSec + 33);
    } else {
        uint256 tempAmount((uint64_t)amount);
        out.maskValue.amount.SetNull();
        memcpy(out.maskValue.amount.begin(), tempAmount.begin(), 32);
        CPubKey sharedPub(sharedSec, sharedSec + 33);
        ecdhEncode(out.maskValue.mask.begin(), out.maskValue.amount.begin(), sharedPub.begin(), sharedPub.size());
        out.maskValue.hashOfKey = Hash(sharedSec, sharedSec + 33);
    }
    return true;
}

CAmount CWallet::getCOutPutValue(const COutput& output) const
{
    const CTxOut& out = output.tx->vout[output.i];
    CAmount amount = 0;
    CKey blind;
    RevealTxOutAmount((const CTransaction&)(*output.tx), out, amount, blind);
    return amount;
}

CAmount CWallet::getCTxOutValue(const CTransaction& tx, const CTxOut& out) const
{
    CAmount amount = 0;
    CKey blind;
    RevealTxOutAmount(tx, out, amount, blind);
    return amount;
}
