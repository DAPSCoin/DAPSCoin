// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2018 The PIVX developers
// Copyright (c) 2018-2019 The DAPS Project developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "wallet.h"

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
int64_t nStartupTime = GetAdjustedTime();

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

void CWallet::GenerateMultisigWallet(int numSigners) {
    LOCK(cs_wallet);
	if (multiSigPrivView.IsValid() && multiSigPubSpend.IsFullyValid()) return;
	if (IsLocked()) {
		LogPrintf("Wallet need to be unlocked");
		return;
	}
	if (ReadNumSigners() != numSigners) return;

	if (IsWalletGenerated()) {
		LogPrintf("Multisig wallet is already generated");
		return;
	}
	if (numSigners != comboKeys.comboKeys.size()) {
		LogPrintf("numSigners should be equal to the number of signers");
		return;
	}
	if (numSigners <= 0) {
		LogPrintf("multisig not configured yet");
		return;
	}
	unsigned char view[32];
	unsigned char pubSpend[33];
	memcpy(view, &(comboKeys.comboKeys[0].privView[0]), 32);
	secp256k1_pedersen_commitment pubkeysCommitment[numSigners];
	const secp256k1_pedersen_commitment *elements[numSigners];
	secp256k1_pedersen_serialized_pubkey_to_commitment(comboKeys.comboKeys[0].pubSpend.begin(), 33, &pubkeysCommitment[0]);
	elements[0] = &pubkeysCommitment[0];
	for(size_t i = 1; i < comboKeys.comboKeys.size(); i++) {
		if (!secp256k1_ec_privkey_tweak_add(view, &(comboKeys.comboKeys[i].privView[0]))) {
			LogPrintf("Cannot compute private view key");
			return;
		}
		secp256k1_pedersen_serialized_pubkey_to_commitment(comboKeys.comboKeys[i].pubSpend.begin(), 33, &pubkeysCommitment[i]);
		elements[i] = &pubkeysCommitment[i];
	}
	secp256k1_pedersen_commitment out;
	secp256k1_pedersen_commitment_sum_pos(GetContext(), elements, numSigners, &out);
	size_t length;
	secp256k1_pedersen_commitment_to_serialized_pubkey(&out, pubSpend, &length);

	multiSigPrivView.Set(view, view + 32, true);
	multiSigPubSpend.Set(pubSpend, pubSpend + 33);
	AddKey(multiSigPrivView);

    CWalletDB pDB(strWalletFile);
	std::string viewMultisigKeyLabel = "viewmultisig";
	std::string spendMultisigPubLabel = "spendmultisigpub";
	CAccount viewAccount;
	viewAccount.vchPubKey = multiSigPrivView.GetPubKey();
	SetAddressBook(viewAccount.vchPubKey.GetID(), viewMultisigKeyLabel, "receive");
	pDB.WriteAccount(viewMultisigKeyLabel, viewAccount);

	CAccount spendAccount;
	spendAccount.vchPubKey = multiSigPubSpend;
	SetAddressBook(spendAccount.vchPubKey.GetID(), spendMultisigPubLabel, "receive");
	pDB.WriteAccount(spendMultisigPubLabel, spendAccount);
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

void CWallet::SetNumSigners(int numSigners)
{
	CWalletDB(strWalletFile).WriteNumSigners(numSigners);
}

int CWallet::ReadNumSigners() const
{
	return CWalletDB(strWalletFile).ReadNumSigners();
}

void CWallet::WriteScreenIndex(int index) const
{
	CWalletDB(strWalletFile).WriteScreenIndex(index);
}
int CWallet::ReadScreenIndex() const
{
	return 	CWalletDB(strWalletFile).ReadScreenIndex();
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

bool CWallet::AddMultiSig(const CScript& dest)
{
    if (!CCryptoKeyStore::AddMultiSig(dest))
        return false;
    nTimeFirstKey = 1; // No birthday information
    NotifyMultiSigChanged(true);
    if (!fFileBacked)
        return true;
    return CWalletDB(strWalletFile).WriteMultiSig(dest);
}

bool CWallet::RemoveMultiSig(const CScript& dest)
{
    AssertLockHeld(cs_wallet);
    if (!CCryptoKeyStore::RemoveMultiSig(dest))
        return false;
    if (!HaveMultiSig())
        NotifyMultiSigChanged(false);
    if (fFileBacked)
        if (!CWalletDB(strWalletFile).EraseMultiSig(dest))
            return false;

    return true;
}

bool CWallet::LoadMultiSig(const CScript& dest)
{
    return CCryptoKeyStore::AddMultiSig(dest);
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
        COutPoint prevout = findMyOutPoint(wtx, txin);
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
    CKeyImage ki;
    ReadKeyImage(COutPoint(hash, n), ki);
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
        if (!IsMine(tx, tx.vin[i])) {
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
}

void CWallet::AddToSpends(const uint256& wtxid)
{
    if (mapWallet.count(wtxid) < 1) return;
    CWalletTx& thisTx = mapWallet[wtxid];
    if (thisTx.IsCoinBase()) // Coinbases don't spend anything!
        return;
    
    for (const CTxIn& txin : thisTx.vin) {
        CKeyImage ki = txin.keyImage;
        COutPoint prevout = findMyOutPoint(thisTx, txin);
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

bool CWallet::ReadKeyImage(const COutPoint& out, CKeyImage& ki) {
    std::string outpoint = out.hash.GetHex() + std::to_string(out.n);
    if (outpointToKeyImages.count(outpoint) == 1) {
        ki = outpointToKeyImages[outpoint];
        return true;
    }
    return CWalletDB(strWalletFile).ReadKeyImage(outpoint, ki);
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
    //as a rule, a multisig transaction will always has an output for the wallet itself
    //if the tx is from the wallet, it must have a change to be able to recognize as tx for the multisig wallet
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
    			//outpointToKeyImages[outpoint] = ki;
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
            wtx.nTimeReceived = GetAdjustedTime();
            wtx.nOrderPos = IncOrderPosNext();
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
                } catch (std::exception& e) {
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
        COutPoint prevout = findMyOutPoint(tx, txin);
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


isminetype CWallet::IsMine(const CTransaction& tx, const CTxIn& txin) const
{
    if (IsLocked()) return ISMINE_NO;
    {
        LOCK(cs_wallet);
        COutPoint prevout = findMyOutPoint(tx, txin);
        map<uint256, CWalletTx>::const_iterator mi = mapWallet.find(prevout.hash);
        if (mi != mapWallet.end()) {
            const CWalletTx& prev = (*mi).second;
            if (prevout.n < prev.vout.size())
                return IsMine(prev.vout[prevout.n]);
        }
    }
    return ISMINE_NO;
}

COutPoint CWallet::findMyOutPoint(const CTransaction& tx, const CTxIn& txin) const
{
	int myIndex = findMultisigInputIndex(tx, txin);
	COutPoint outpoint;
    if (myIndex == -2) return outpoint;
	if (myIndex == -1) {
		outpoint = txin.prevout;
	} else {
		outpoint = txin.decoys[myIndex];
	}
	std::string prevout = outpoint.hash.GetHex() + std::to_string(outpoint.n);
	outpointToKeyImages[prevout] = txin.keyImage;
	return outpoint;
}

CAmount CWallet::GetDebit(const CTransaction& tx, const CTxIn& txin, const isminefilter& filter) const
{
    {
        LOCK(cs_wallet);
        if (txin.prevout.IsNull()) return 0;
        COutPoint prevout = findMyOutPoint(tx, txin);
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

// Recursively determine the rounds of a given input (How deep is the Obfuscation chain for a given input)
int CWallet::GetRealInputObfuscationRounds(CTxIn in, int rounds) const
{
    static std::map<uint256, CMutableTransaction> mDenomWtxes;

    if (rounds >= 16) return 15; // 16 rounds max

    uint256 hash = in.prevout.hash;
    unsigned int nout = in.prevout.n;

    const CWalletTx* wtx = GetWalletTx(hash);
    if (wtx != NULL) {
        std::map<uint256, CMutableTransaction>::const_iterator mdwi = mDenomWtxes.find(hash);
        // not known yet, let's add it
        if (mdwi == mDenomWtxes.end()) {
            LogPrint("obfuscation", "GetInputObfuscationRounds INSERTING %s\n", hash.ToString());
            mDenomWtxes[hash] = CMutableTransaction(*wtx);
        }
        // found and it's not an initial value, just return it
        else if (mDenomWtxes[hash].vout[nout].nRounds != -10) {
            return mDenomWtxes[hash].vout[nout].nRounds;
        }


        // bounds check
        if (nout >= wtx->vout.size()) {
            // should never actually hit this
            LogPrint("obfuscation", "GetInputObfuscationRounds UPDATED   %s %3d %3d\n", hash.ToString(), nout, -4);
            return -4;
        }

        if (pwalletMain->IsCollateralAmount(pwalletMain->getCTxOutValue(*wtx, wtx->vout[nout]))) {
            mDenomWtxes[hash].vout[nout].nRounds = -3;
            LogPrint("obfuscation", "GetInputObfuscationRounds UPDATED   %s %3d %3d\n", hash.ToString(), nout, mDenomWtxes[hash].vout[nout].nRounds);
            return mDenomWtxes[hash].vout[nout].nRounds;
        }

        //make sure the final output is non-denominate
        if (!IsDenominatedAmount(pwalletMain->getCTxOutValue(*wtx, wtx->vout[nout]))) //NOT DENOM
        {
            mDenomWtxes[hash].vout[nout].nRounds = -2;
            LogPrint("obfuscation", "GetInputObfuscationRounds UPDATED   %s %3d %3d\n", hash.ToString(), nout, mDenomWtxes[hash].vout[nout].nRounds);
            return mDenomWtxes[hash].vout[nout].nRounds;
        }

        bool fAllDenoms = true;
        for (CTxOut out : wtx->vout) {
            fAllDenoms = fAllDenoms && IsDenominatedAmount(pwalletMain->getCTxOutValue(*wtx, out));
        }
        // this one is denominated but there is another non-denominated output found in the same tx
        if (!fAllDenoms) {
            mDenomWtxes[hash].vout[nout].nRounds = 0;
            LogPrint("obfuscation", "GetInputObfuscationRounds UPDATED   %s %3d %3d\n", hash.ToString(), nout, mDenomWtxes[hash].vout[nout].nRounds);
            return mDenomWtxes[hash].vout[nout].nRounds;
        }

        int nShortest = -10; // an initial value, should be no way to get this by calculations
        bool fDenomFound = false;
        // only denoms here so let's look up
        for (CTxIn in2 : wtx->vin) {
            if (IsMine(*wtx, in2)) {
                int n = GetRealInputObfuscationRounds(in2, rounds + 1);
                // denom found, find the shortest chain or initially assign nShortest with the first found value
                if (n >= 0 && (n < nShortest || nShortest == -10)) {
                    nShortest = n;
                    fDenomFound = true;
                }
            }
        }
        mDenomWtxes[hash].vout[nout].nRounds = fDenomFound ? (nShortest >= 15 ? 16 : nShortest + 1) // good, we a +1 to the shortest one but only 16 rounds max allowed
                                                             :
                                                             0; // too bad, we are the fist one in that chain
        LogPrint("obfuscation", "GetInputObfuscationRounds UPDATED   %s %3d %3d\n", hash.ToString(), nout, mDenomWtxes[hash].vout[nout].nRounds);
        return mDenomWtxes[hash].vout[nout].nRounds;
    }

    return rounds - 1;
}

// respect current settings
int CWallet::GetInputObfuscationRounds(CTxIn in) const
{
    LOCK(cs_wallet);
    int realObfuscationRounds = GetRealInputObfuscationRounds(in, 0);
    return realObfuscationRounds > 0 ? 0 : realObfuscationRounds;
}

bool CWallet::IsDenominated(const CTransaction& tx, const CTxIn& txin) const
{
    {
        LOCK(cs_wallet);
        COutPoint prevout = findMyOutPoint(tx, txin);
        map<uint256, CWalletTx>::const_iterator mi = mapWallet.find(prevout.hash);
        if (mi != mapWallet.end()) {
            const CWalletTx& prev = (*mi).second;
            if (prevout.n < prev.vout.size()) return IsDenominatedAmount(getCTxOutValue(prev, prev.vout[prevout.n]));
        }
    }
    return false;
}

bool CWallet::IsDenominated(const CTransaction& tx) const
{
    /*
        Return false if ANY inputs are non-denom
    */
    bool ret = true;
    for (const CTxIn& txin : tx.vin) {
        if (!IsDenominated(tx, txin)) {
            ret = false;
        }
    }
    return ret;
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

CKey CWallet::GeneratePartialKey(const COutPoint& out)
{
	if (mapWallet.count(out.hash) < 1) throw runtime_error("Outpoint not found");
	return GeneratePartialKey(mapWallet[out.hash].vout[out.n]);
}

CKey CWallet::GeneratePartialKey(const CTxOut& out)
{
	CKey ret;
	CPubKey txPub(out.txPub);
	CPubKey pubSpendKey = GetMultisigPubSpendKey();
	CKey view = MyMultisigViewKey();
	//compute the tx destination
	//P' = Hs(aR)G+B, a = view private, B = spend pub, R = tx public key
	unsigned char aR[65];
	//copy R into a
	memcpy(aR, txPub.begin(), txPub.size());
	if (!secp256k1_ec_pubkey_tweak_mul(aR, txPub.size(), view.begin())) {
		return ret;
	}
	uint256 HS = Hash(aR, aR + txPub.size());
	ret.Set(HS.begin(), HS.end(), true);
	return ret;
}

CKey CWallet::generateAdditionalPartialAlpha(const CPartialTransaction& tx)
{
	uint256 hashOfInOuts = generateHashOfAllIns(tx);
	CKey mySpend;
	mySpendPrivateKey(mySpend);
	uint256 alpha = Hash(mySpend.begin(), mySpend.end(), hashOfInOuts.begin(), hashOfInOuts.end());
    LogPrintf("%s: additional alpha = %s\n", __func__, alpha.GetHex());
	CKey alphaKey;
	alphaKey.Set(alpha.begin(), alpha.end(), true);
	return alphaKey;
}
void CWallet::generateAdditionalPartialAlpha(const CPartialTransaction& tx, CPKeyImageAlpha& combo, const uint256& hashOfInOuts)
{
	CKey mySpend;
	mySpendPrivateKey(mySpend);
	uint256 alpha = Hash(mySpend.begin(), mySpend.end(), hashOfInOuts.begin(), hashOfInOuts.end());
    LogPrintf("%s: additional alpha = %s\n", __func__, alpha.GetHex());
	CKey alphaKey;
	alphaKey.Set(alpha.begin(), alpha.end(), true);
	CPubKey alphaPub = alphaKey.GetPubKey();
	combo.LIJ.Set(alphaPub.begin(), alphaPub.end());
	unsigned char rij[33];

	CPubKey ADDPUB = generateAdditonalPubKey(tx);
    LogPrintf("%s: ADDPUB = %s\n", __func__, ADDPUB.GetHex());

	PointHashingSuccessively(ADDPUB, alphaKey.begin(), rij);
	combo.RIJ.Set(rij, rij + 33);

	unsigned char partialAdditionalKeyImage[33];
	PointHashingSuccessively(ADDPUB, mySpend.begin(), partialAdditionalKeyImage);
	combo.ki.Set(partialAdditionalKeyImage, partialAdditionalKeyImage + 33);
}

void CWallet::GeneratePKeyImageAlpha(const COutPoint& op, CPKeyImageAlpha& combo)
{
	unsigned char alpha[32];
	GenerateAlphaFromOutpoint(op, alpha);
	CKey alphaKey;
	alphaKey.Set(alpha, alpha + 32, true);
	CPubKey alphaPub = alphaKey.GetPubKey();
	combo.LIJ.Set(alphaPub.begin(), alphaPub.end());
	unsigned char rij[33];
	const CTxOut txout = mapWallet[op.hash].vout[op.n];
	CPubKey destKey;
	if (!ExtractPubKey(txout.scriptPubKey, destKey)) {
		throw runtime_error("cannot extract public key from destination script");
	}
    LogPrintf("%s: destKey = %s, tx = %s\n", __func__, destKey.GetHex(), op.hash.GetHex());
	PointHashingSuccessively(destKey, alpha, rij);
	combo.RIJ.Set(rij, rij + 33);
	combo.ki = GeneratePartialKeyImage(op);

	CKey myViewMultisig = MyMultisigViewKey();
	unsigned char data[64];
	uint256 opHash = ((COutPoint)op).GetHash();
	memcpy(data, opHash.begin(), 32);
	memcpy(data, myViewMultisig.begin(), 32);
	combo.outPointHash = Hash(data, data + 64);
}

void CWallet::GenerateAlphaFromOutpoint(const COutPoint& op, unsigned char* alpha) const
{
	if (!alpha) return;
	CKey spend;
	mySpendPrivateKey(spend);
	uint256 h = ((COutPoint)op).GetHash();
	unsigned char data[64];
	memcpy(data, spend.begin(), 32);
	memcpy(data + 32, h.begin(), 32);
	uint256 hash = Hash(data, data + 64);
	memcpy(alpha, hash.begin(), 32);
    LogPrintf("%s: alpha (%s,%d) = %s\n", __func__, op.hash.GetHex(), op.n, HexStr(alpha, alpha + 32));
}

CKeyImage CWallet::GeneratePartialKeyImage(const COutPoint& out)
{
	if (mapWallet.count(out.hash) < 1) throw runtime_error("Outpoint not found");
	return GeneratePartialKeyImage(mapWallet[out.hash].vout[out.n]);
}
CPubKey CWallet::computeDestination(const COutPoint& out)
{
	if (mapWallet.count(out.hash) < 1) throw runtime_error("Outpoint not found");
	return computeDestination(mapWallet[out.hash].vout[out.n]);
}
CPubKey CWallet::computeDestination(const CTxOut& out)
{
	CPubKey txPub(out.txPub);
	CPubKey pubSpendKey = GetMultisigPubSpendKey();
	CKey view = MyMultisigViewKey();
	//compute the tx destination
	//P' = Hs(aR)G+B, a = view private, B = spend pub, R = tx public key
	unsigned char aR[65];
	//copy R into a
	memcpy(aR, txPub.begin(), txPub.size());
	if (!secp256k1_ec_pubkey_tweak_mul(aR, txPub.size(), view.begin())) {
		CKeyImage ret;
		return ret;
	}
	uint256 HS = Hash(aR, aR + txPub.size());
	unsigned char *pHS = HS.begin();
	unsigned char expectedDestination[65];
	memcpy(expectedDestination, pubSpendKey.begin(), pubSpendKey.size());
	if (!secp256k1_ec_pubkey_tweak_add(expectedDestination, pubSpendKey.size(), pHS)) {
		throw runtime_error("Error in secp256k1_ec_pubkey_tweak_add");
	}
	CPubKey expectedDes(expectedDestination, expectedDestination + 33);
	return expectedDes;
}

CKeyImage CWallet::GeneratePartialKeyImage(const CTxOut& out)
{
	if (myPartialKeyImages.count(out.scriptPubKey) == 1) return myPartialKeyImages[out.scriptPubKey];

	CPubKey expectedDes = computeDestination(out);

	CKey mySpend;
	mySpendPrivateKey(mySpend);
	//partial private key = mySpend
	//full private key = HS + sum of all spend keys of others
	//partial key images = mySpend*H(expectedDes)
	unsigned char outKi[33];
	PointHashingSuccessively(expectedDes, mySpend.begin(), outKi);
	CKeyImage ki(outKi, outKi + 33);
	return ki;
}

bool CWallet::GeneratePartialKeyImages(const std::vector<COutPoint>& outpoints, std::vector<CKeyImage>& out)
{
	for(size_t i = 0; i < outpoints.size(); i++) {
		out.push_back(GeneratePartialKeyImage(outpoints[i]));
	}
	return true;
}

bool CWallet::GeneratePartialKeyImages(const std::vector<CTxOut>& outputs, std::vector<CKeyImage>& out)
{
	for(size_t i = 0; i < outputs.size(); i++) {
		out.push_back(GeneratePartialKeyImage(outputs[i]));
	}
	return true;
}
bool CWallet::GenerateAllPartialImages(std::vector<CKeyImage>& out)
{
	{
		LOCK2(cs_main, cs_wallet);
		for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it) {
			const CWalletTx* pcoin = &(*it).second;
			for (unsigned int i = 0; i < pcoin->vout.size(); i++) {
				if (IsMine(pcoin->vout[i])) {
					out.push_back(GeneratePartialKeyImage(pcoin->vout[i]));
				}
			}
		}
	}
	return true;
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
    return nTotal;
}

CAmount CWallet::GetSpendableBalance()
{
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


CAmount CWallet::GetAnonymizableBalance() const
{
    if (fLiteMode) return 0;

    CAmount nTotal = 0;
    {
        LOCK2(cs_main, cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it) {
            const CWalletTx* pcoin = &(*it).second;

            if (pcoin->IsTrusted())
                nTotal += pcoin->GetAnonymizableCredit();
        }
    }

    return nTotal;
}

CAmount CWallet::GetAnonymizedBalance() const
{
    if (fLiteMode) return 0;

    CAmount nTotal = 0;
    {
        LOCK2(cs_main, cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it) {
            const CWalletTx* pcoin = &(*it).second;

            if (pcoin->IsTrusted())
                nTotal += pcoin->GetAnonymizedCredit();
        }
    }

    return nTotal;
}

// Note: calculated including unconfirmed,
// that's ok as long as we use it for informational purposes only
double CWallet::GetAverageAnonymizedRounds()
{
    if (fLiteMode) return 0;

    double fTotal = 0;
    double fCount = 0;

    {
        LOCK2(cs_main, cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it) {
            const CWalletTx* pcoin = &(*it).second;

            uint256 hash = (*it).first;

            for (unsigned int i = 0; i < pcoin->vout.size(); i++) {
                CTxIn vin = CTxIn(hash, i);

                if (IsSpent(hash, i) || IsMine(pcoin->vout[i]) != ISMINE_SPENDABLE || !IsDenominated(*pcoin, vin)) continue;

                int rounds = GetInputObfuscationRounds(vin);
                fTotal += (float)rounds;
                fCount += 1;
            }
        }
    }

    if (fCount == 0) return 0;

    return fTotal / fCount;
}

// Note: calculated including unconfirmed,
// that's ok as long as we use it for informational purposes only
CAmount CWallet::GetNormalizedAnonymizedBalance()
{
    if (fLiteMode) return 0;

    CAmount nTotal = 0;

    {
        LOCK2(cs_main, cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it) {
            const CWalletTx* pcoin = &(*it).second;

            uint256 hash = (*it).first;

            for (unsigned int i = 0; i < pcoin->vout.size(); i++) {
                CTxIn vin = CTxIn(hash, i);

                if (IsSpent(hash, i) || IsMine(pcoin->vout[i]) != ISMINE_SPENDABLE || !IsDenominated(*pcoin, vin)) continue;
                if (pcoin->GetDepthInMainChain() < 0) continue;
            }
        }
    }

    return nTotal;
}

CAmount CWallet::GetDenominatedBalance(bool unconfirmed) const
{
    if (fLiteMode) return 0;

    CAmount nTotal = 0;
    {
        LOCK2(cs_main, cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it) {
            const CWalletTx* pcoin = &(*it).second;

            nTotal += pcoin->GetDenominatedCredit(unconfirmed);
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
            if ((mine & ISMINE_MULTISIG) != ISMINE_NO)
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
    vector<COutput> vCoins;
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
    vector<COutput> vCoins;
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
    vector<COutput> vCoins;

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

bool CWallet::SelectCoinsMinConf(bool needFee, CAmount& feeNeeded, int ringSize, int numOut, const CAmount& nTargetValue, int nConfMine, int nConfTheirs, vector<COutput> vCoins, std::vector<pair<const CWalletTx*, unsigned int> >& setCoinsRet, CAmount& nValueRet)
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
                setCoinsRet.push_back(coin.second);
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
                    setCoinsRet.push_back(vValue[i].second);
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
            setCoinsRet.push_back(coinLowestLarger.second);
            nValueRet += coinLowestLarger.first;
            return true;
        } else {
            CAmount maxFee = ComputeFee(50, numOut, ringSize);
            if (vValue.size() <= MAX_TX_INPUTS) {
                //putting all into the transaction
                string s = "CWallet::SelectCoinsMinConf best subset: ";
                for (unsigned int i = 0; i < vValue.size(); i++) {
                    setCoinsRet.push_back(vValue[i].second);
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
            setCoinsRet.push_back(vValue[i].second);
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
            setCoinsRet.push_back(vValue[i].second);
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
        setCoinsRet.push_back(coinLowestLarger.second);
        nValueRet += coinLowestLarger.first;
    } else {
        string s = "CWallet::SelectCoinsMinConf best subset: ";
        for (unsigned int i = 0; i < vValue.size(); i++) {
            if (vfBest[i]) {
                setCoinsRet.push_back(vValue[i].second);
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
                        COutPoint prevout = findMyOutPoint(tx, tx.vin[i]);
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

bool CWallet::SelectCoins(bool needFee, CAmount& estimatedFee, int ringSize, int numOut, const CAmount& nTargetValue, std::vector<pair<const CWalletTx*, unsigned int> >& setCoinsRet, CAmount& nValueRet, const CCoinControl* coinControl, AvailableCoinsType coin_type, bool useIX)
{
    // Note: this function should never be used for "always free" tx types like dstx
    vector<COutput> vCoins;
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
                if (mine != ISMINE_WATCH_ONLY)
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

            if (coin_type == ONLY_DENOMINATED) {
                CTxIn vin = CTxIn(out.tx->GetHash(), out.i);
                int rounds = GetInputObfuscationRounds(vin);
                // make sure it's actually anonymized
                if (rounds < 0) continue;
            }

            nValueRet += getCOutPutValue(out);
            setCoinsRet.push_back(make_pair(out.tx, out.i));
        }
        return (nValueRet >= nTargetValue);
    }

    return (SelectCoinsMinConf(needFee, estimatedFee, ringSize, numOut, nTargetValue, 1, 6, vCoins, setCoinsRet, nValueRet) ||
            SelectCoinsMinConf(needFee, estimatedFee, ringSize, numOut, nTargetValue, 1, 1, vCoins, setCoinsRet, nValueRet) ||
            (bSpendZeroConfChange && SelectCoinsMinConf(needFee, estimatedFee, ringSize, numOut, nTargetValue, 0, 1, vCoins, setCoinsRet, nValueRet)));
}

struct CompareByPriority {
    bool operator()(const COutput& t1,
        const COutput& t2) const
    {
        return t1.Priority() > t2.Priority();
    }
};

bool CWallet::SelectCoinsByDenominations(int nDenom, CAmount nValueMin, CAmount nValueMax, std::vector<CTxIn>& vCoinsRet, std::vector<COutput>& vCoinsRet2, CAmount& nValueRet, int nObfuscationRoundsMin, int nObfuscationRoundsMax)
{
    vCoinsRet.clear();
    nValueRet = 0;

    vCoinsRet2.clear();
    vector<COutput> vCoins;
    AvailableCoins(vCoins, true, NULL, false, ONLY_DENOMINATED);

    std::random_shuffle(vCoins.rbegin(), vCoins.rend());

    //keep track of each denomination that we have
    bool fFound10000 = false;
    bool fFound1000 = false;
    bool fFound100 = false;
    bool fFound10 = false;
    bool fFound1 = false;
    bool fFoundDot1 = false;

    //Check to see if any of the denomination are off, in that case mark them as fulfilled
    if (!(nDenom & (1 << 0))) fFound10000 = true;
    if (!(nDenom & (1 << 1))) fFound1000 = true;
    if (!(nDenom & (1 << 2))) fFound100 = true;
    if (!(nDenom & (1 << 3))) fFound10 = true;
    if (!(nDenom & (1 << 4))) fFound1 = true;
    if (!(nDenom & (1 << 5))) fFoundDot1 = true;

    for (const COutput& out : vCoins) {
        // masternode-like input should not be selected by AvailableCoins now anyway
        if (nValueRet + getCTxOutValue(*out.tx, out.tx->vout[out.i]) <= nValueMax) {
            bool fAccepted = false;

            // Function returns as follows:
            //
            // bit 0 - 10000 DAPS+1 ( bit on if present )
            // bit 1 - 1000 DAPS+1
            // bit 2 - 100 DAPS+1
            // bit 3 - 10 DAPS+1
            // bit 4 - 1 DAPS+1
            // bit 5 - .1 DAPS+1

            CTxIn vin = CTxIn(out.tx->GetHash(), out.i);

            int rounds = GetInputObfuscationRounds(vin);
            if (rounds >= nObfuscationRoundsMax) continue;
            if (rounds < nObfuscationRoundsMin) continue;
            CAmount outValue = getCTxOutValue(*out.tx, out.tx->vout[out.i]);
            if (fFound10000 && fFound1000 && fFound100 && fFound10 && fFound1 && fFoundDot1) { //if fulfilled
                //we can return this for submission
                if (nValueRet >= nValueMin) {
                    //random reduce the max amount we'll submit for anonymity
                    nValueMax -= (secp256k1_rand32() % (nValueMax / 5));
                    //on average use 50% of the inputs or less
                    int r = (secp256k1_rand32() % (int)vCoins.size());
                    if ((int)vCoinsRet.size() > r) return true;
                }
                //Denomination criterion has been met, we can take any matching denominations
                if ((nDenom & (1 << 0)) && getCTxOutValue(*out.tx, out.tx->vout[out.i]) == ((10000 * COIN) + 10000000)) {
                    fAccepted = true;
                } else if ((nDenom & (1 << 1)) && getCTxOutValue(*out.tx, out.tx->vout[out.i]) == ((1000 * COIN) + 1000000)) {
                    fAccepted = true;
                } else if ((nDenom & (1 << 2)) && getCTxOutValue(*out.tx, out.tx->vout[out.i]) == ((100 * COIN) + 100000)) {
                    fAccepted = true;
                } else if ((nDenom & (1 << 3)) && getCTxOutValue(*out.tx, out.tx->vout[out.i]) == ((10 * COIN) + 10000)) {
                    fAccepted = true;
                } else if ((nDenom & (1 << 4)) && getCTxOutValue(*out.tx, out.tx->vout[out.i]) == ((1 * COIN) + 1000)) {
                    fAccepted = true;
                } else if ((nDenom & (1 << 5)) && getCTxOutValue(*out.tx, out.tx->vout[out.i]) == ((.1 * COIN) + 100)) {
                    fAccepted = true;
                }
            } else {
                //Criterion has not been satisfied, we will only take 1 of each until it is.
                if ((nDenom & (1 << 0)) && outValue == ((10000 * COIN) + 10000000)) {
                    fAccepted = true;
                    fFound10000 = true;
                } else if ((nDenom & (1 << 1)) && outValue == ((1000 * COIN) + 1000000)) {
                    fAccepted = true;
                    fFound1000 = true;
                } else if ((nDenom & (1 << 2)) && outValue == ((100 * COIN) + 100000)) {
                    fAccepted = true;
                    fFound100 = true;
                } else if ((nDenom & (1 << 3)) && outValue == ((10 * COIN) + 10000)) {
                    fAccepted = true;
                    fFound10 = true;
                } else if ((nDenom & (1 << 4)) && outValue == ((1 * COIN) + 1000)) {
                    fAccepted = true;
                    fFound1 = true;
                } else if ((nDenom & (1 << 5)) && outValue == ((.1 * COIN) + 100)) {
                    fAccepted = true;
                    fFoundDot1 = true;
                }
            }
            if (!fAccepted) continue;

            vin.prevPubKey = out.tx->vout[out.i].scriptPubKey; // the inputs PubKey
            nValueRet += outValue;
            vCoinsRet.push_back(vin);
            vCoinsRet2.push_back(out);
        }
    }

    return (nValueRet >= nValueMin && fFound10000 && fFound1000 && fFound100 && fFound10 && fFound1 && fFoundDot1);
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

bool CWallet::SelectCoinsDark(CAmount nValueMin, CAmount nValueMax, std::vector<CTxIn>& setCoinsRet, CAmount& nValueRet, int nObfuscationRoundsMin, int nObfuscationRoundsMax)
{
    CCoinControl* coinControl = NULL;

    setCoinsRet.clear();
    nValueRet = 0;

    vector<COutput> vCoins;
    AvailableCoins(vCoins, true, coinControl, false, nObfuscationRoundsMin < 0 ? ONLY_NONDENOMINATED_NOT1000000IFMN : ONLY_DENOMINATED);

    set<pair<const CWalletTx*, unsigned int> > setCoinsRet2;

    //order the array so largest nondenom are first, then denominations, then very small inputs.
    sort(vCoins.rbegin(), vCoins.rend(), CompareByPriority());

    for (const COutput& out : vCoins) {
        //do not allow inputs less than 1 CENT
        CAmount outValue = getCTxOutValue(*out.tx, out.tx->vout[out.i]);
        if (outValue < CENT) continue;
        //do not allow collaterals to be selected

        if (IsCollateralAmount(getCTxOutValue(*out.tx, out.tx->vout[out.i]))) continue;
        if (fMasterNode && getCTxOutValue(*out.tx, out.tx->vout[out.i]) == 1000000 * COIN) continue; //masternode input

        if (nValueRet + outValue <= nValueMax) {
            CTxIn vin = CTxIn(out.tx->GetHash(), out.i);

            int rounds = GetInputObfuscationRounds(vin);
            if (rounds >= nObfuscationRoundsMax) continue;
            if (rounds < nObfuscationRoundsMin) continue;

            vin.prevPubKey = out.tx->vout[out.i].scriptPubKey; // the inputs PubKey
            nValueRet += outValue;
            setCoinsRet.push_back(vin);
            setCoinsRet2.insert(make_pair(out.tx, out.i));
        }
    }

    // if it's more than min, we're good to return
    if (nValueRet >= nValueMin) return true;

    return false;
}

bool CWallet::SelectCoinsCollateral(std::vector<CTxIn>& setCoinsRet, CAmount& nValueRet)
{
    vector<COutput> vCoins;

    AvailableCoins(vCoins);

    set<pair<const CWalletTx*, unsigned int> > setCoinsRet2;

    for (const COutput& out : vCoins) {
        // collateral inputs will always be a multiple of DARSEND_COLLATERAL, up to five
        CAmount outValue = getCTxOutValue(*out.tx, out.tx->vout[out.i]);
        if (IsCollateralAmount(outValue)) {
            CTxIn vin = CTxIn(out.tx->GetHash(), out.i);

            vin.prevPubKey = out.tx->vout[out.i].scriptPubKey; // the inputs PubKey
            nValueRet += outValue;
            setCoinsRet.push_back(vin);
            setCoinsRet2.insert(make_pair(out.tx, out.i));
            return true;
        }
    }

    return false;
}

int CWallet::CountInputsWithAmount(CAmount nInputAmount)
{
    CAmount nTotal = 0;
    {
        LOCK(cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it) {
            const CWalletTx* pcoin = &(*it).second;
            if (pcoin->IsTrusted()) {
                int nDepth = pcoin->GetDepthInMainChain(false);

                for (unsigned int i = 0; i < pcoin->vout.size(); i++) {
                    COutput out = COutput(pcoin, i, nDepth, true);
                    CTxIn vin = CTxIn(out.tx->GetHash(), out.i);

                    if (getCOutPutValue(out) != nInputAmount) continue;
                    if (!IsDenominatedAmount(getCTxOutValue(*pcoin, pcoin->vout[i]))) continue;
                    if (IsSpent(out.tx->GetHash(), i) || IsMine(pcoin->vout[i]) != ISMINE_SPENDABLE || !IsDenominated(*pcoin, vin)) continue;

                    nTotal++;
                }
            }
        }
    }

    return nTotal;
}

bool CWallet::HasCollateralInputs(bool fOnlyConfirmed)
{
    vector<COutput> vCoins;
    AvailableCoins(vCoins, fOnlyConfirmed);

    int nFound = 0;
    for (const COutput& out : vCoins)
        if (IsCollateralAmount(getCOutPutValue(out))) nFound++;

    return nFound > 0;
}

bool CWallet::IsCollateralAmount(CAmount nInputAmount) const
{
    return nInputAmount != 0 && nInputAmount % OBFUSCATION_COLLATERAL == 0 && nInputAmount < OBFUSCATION_COLLATERAL * 5 && nInputAmount > OBFUSCATION_COLLATERAL;
}

bool CWallet::CreateCollateralTransaction(CMutableTransaction& txCollateral, std::string& strReason)
{
    /*
        To doublespend a collateral transaction, it will require a fee higher than this. So there's
        still a significant cost.
    */
    CAmount nFeeRet = 1 * COIN;

    txCollateral.vin.clear();
    txCollateral.vout.clear();

    CReserveKey reservekey(this);
    CAmount nValueIn2 = 0;
    std::vector<CTxIn> vCoinsCollateral;

    if (!SelectCoinsCollateral(vCoinsCollateral, nValueIn2)) {
        strReason = "Error: Obfuscation requires a collateral transaction and could not locate an acceptable input!";
        return false;
    }

    // make our change address
    CScript scriptChange;
    CPubKey vchPubKey;
    assert(reservekey.GetReservedKey(vchPubKey)); // should never fail, as we just unlocked
    scriptChange = GetScriptForDestination(vchPubKey);
    reservekey.KeepKey();

    for (CTxIn v : vCoinsCollateral)
        txCollateral.vin.push_back(v);

    if (nValueIn2 - OBFUSCATION_COLLATERAL - nFeeRet > 0) {
        //pay collateral charge in fees
        CTxOut vout3 = CTxOut(nValueIn2 - OBFUSCATION_COLLATERAL, scriptChange);
        CPubKey sharedSec;
        CKey view;
        myViewPrivateKey(view);
        EncodeTxOutAmount(vout3, vout3.nValue, 0);
        txCollateral.vout.push_back(vout3);
    }

    int vinNumber = 0;
    for (CTxIn v : txCollateral.vin) {
        if (!SignSignature(*this, v.prevPubKey, txCollateral, vinNumber, int(SIGHASH_ALL | SIGHASH_ANYONECANPAY))) {
            for (CTxIn v : vCoinsCollateral)
                UnlockCoin(v.prevout);

            strReason = "CObfuscationPool::Sign - Unable to sign collateral transaction! \n";
            return false;
        }
        vinNumber++;
    }

    return true;
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

bool CWallet::CreateTransactionBulletProof(CPartialTransaction& ptx, const CKey& txPrivDes, const CPubKey &recipientViewKey, CScript scriptPubKey, const CAmount &nValue,
                                           CWalletTx &wtxNew, CReserveKey &reservekey, CAmount &nFeeRet,
                                           std::string &strFailReason, 
                                           int& ringSize, 
                                           std::vector<pair<const CWalletTx*, unsigned int> >& setCoins, 
                                           CAmount nValueIn, 
                                           CAmount estimateFee,
                                           const CCoinControl *coinControl,
                                           AvailableCoinsType coin_type, bool useIX,
                                           CAmount nFeePay, bool sendtoMyself) {
    vector<pair<CScript, CAmount> > vecSend;
    vecSend.push_back(make_pair(scriptPubKey, nValue));
    return CreateTransactionBulletProof(ptx, txPrivDes, recipientViewKey, 
                                        vecSend, wtxNew, reservekey, 
                                        nFeeRet, strFailReason, 
                                        ringSize, 
                                        setCoins, 
                                        nValueIn, 
                                        estimateFee,
                                        coinControl, coin_type, useIX, nFeePay, sendtoMyself);
}
bool CWallet::CreateTransactionBulletProof(CPartialTransaction& ptx, const CKey& txPrivDes,
                                    const CPubKey& recipientViewKey,
                                    const std::vector<std::pair<CScript, CAmount> >& vecSend,
                                    CWalletTx& wtxNew,
                                  CReserveKey& reservekey,
                                  CAmount& nFeeRet,
                                  std::string& strFailReason,
                                  int& ringSize,
                                  vector<pair<const CWalletTx*, unsigned int> >& setCoins,
                                  CAmount nValueIn,
                                  CAmount estimateFee,
                                  const CCoinControl* coinControl,
                                  AvailableCoinsType coin_type,
                                  bool useIX,
                                  CAmount nFeePay, bool tomyself)
{
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

                CAmount nChange = nValueIn - nValue - nFeeRet;

                if (nChange > 0) {
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
                    /*if (nSpendableBalance > nValueIn) {
                        continue;
                    }*/
                    strFailReason = _("Transaction amount too high to create a change");
    	            return false;
                }

                // Fill vin
                for (const PAIRTYPE(const CWalletTx*, unsigned int) & coin : setCoins)
                    txNew.vin.push_back(CTxIn(coin.first->GetHash(), coin.second));

                // Embed the constructed transaction data in wtxNew.
                *static_cast<CTransaction*>(&wtxNew) = CTransaction(txNew);
                break;
            }
        }
    }
    CPartialTransaction ptxNew(wtxNew);
    if (!makeRingCT(ptxNew, ringSize, strFailReason)) {
    	strFailReason = _("Failed to generate RingCT");
    	return false;
    }

    if (!generateBulletProofAggregate(ptxNew)) {
    	strFailReason = _("Failed to generate bulletproof");
    	return false;
    }
    ptx.copyFrom(ptxNew);

    //set transaction output amounts as 0
    for (size_t i = 0; i < wtxNew.vout.size(); i++) {
    	wtxNew.vout[i].nValue = 0;
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
                std::vector<pair<const CWalletTx*, unsigned int> > setCoins;
                CAmount nValueIn = 0;
                CAmount estimatedFee = 0;
                if (!SelectCoins(true, estimatedFee, 10, 2, nTotalValue, setCoins, nValueIn, coinControl, coin_type, useIX)) {
                    if (coin_type == ALL_COINS) {
                        strFailReason = _("Insufficient funds.");
                    } else if (coin_type == ONLY_NOT1000000IFMN) {
                        strFailReason = _("Unable to locate enough funds for this transaction that are not equal 10000 DAPS.");
                    } else if (coin_type == ONLY_NONDENOMINATED_NOT1000000IFMN) {
                        strFailReason = _("Unable to locate enough Obfuscation non-denominated funds for this transaction that are not equal 10000 DAPS.");
                    } else {
                        strFailReason = _("Unable to locate enough Obfuscation denominated funds for this transaction.");
                        strFailReason += " " + _("Obfuscation uses exact denominated amounts to send funds, you might simply need to anonymize some more coins.");
                    }

                    if (useIX) {
                        strFailReason += " " + _("SwiftX requires inputs with at least 6 confirmations, you might need to wait a few minutes and try again.");
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

bool CWallet::generateBulletProofAggregate(CPartialTransaction& tx)
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

bool CWallet::GenerateBulletProofForStaking(CTransaction& tx)
{
	unsigned char proof[2000];
	size_t len = 2000;
	const size_t MAX_VOUT = 5;
	unsigned char nonce[32];
	GetRandBytes(nonce, 32);
	unsigned char blinds[MAX_VOUT][32];
	memset(blinds, 0, 2 * 32);
	uint64_t values[MAX_VOUT];
	size_t i = 0;
	const unsigned char *blind_ptr[MAX_VOUT];
	if (tx.vout.size() > MAX_VOUT) return false;
	for (i = 0; i < 2; i++) {
		memcpy(&blinds[i][0], tx.vout[i + 1].maskValue.inMemoryRawBind.begin(), 32);
		blind_ptr[i] = blinds[i];
		values[i] = tx.vout[i + 1].nValue;
	}
	int ret = secp256k1_bulletproof_rangeproof_prove(GetContext(), GetScratch(), GetGenerator(), proof, &len, values, NULL, blind_ptr, 2, &secp256k1_generator_const_h, 64, nonce, NULL, 0);
	std::copy(proof, proof + len, std::back_inserter(tx.bulletproofs));
	return ret;
}

bool CWallet::makeRingCT(CPartialTransaction& wtxNew, int ringSize, std::string& strFailReason)
{
    LOCK2(cs_main, cs_wallet);
    LogPrintf("making ringCT, ringsize=%d\n", ringSize);
    int myIndex;
    if (!selectDecoysAndRealIndex(wtxNew, myIndex, ringSize)) {
        return false;
    }
	const size_t MAX_VIN = MAX_TX_INPUTS;
	const size_t MAX_DECOYS = MAX_RING_SIZE;	//padding 1 for safety reasons
	const size_t MAX_VOUT = 5;

	if (wtxNew.vin.size() > MAX_TX_INPUTS || wtxNew.vin.size() == 0) {
		strFailReason = _("Failed due to transaction size too large or the transaction does no have any input");
		return false;
	}

    for(size_t i = 0; i < wtxNew.vin.size(); i++) {
    	if (wtxNew.vin[i].decoys.size() != wtxNew.vin[0].decoys.size()) {
    		strFailReason = _("All inputs should have the same number of decoys");
    		return false;
    	}
    }

    if (wtxNew.vin[0].decoys.size() > MAX_DECOYS || wtxNew.vin[0].decoys.size() < MIN_RING_SIZE) {
    	strFailReason = _("Too many decoys");
    	return false;//maximum decoys = 15
    }

    generateCommitmentAndEncode(wtxNew);
    if (!makeRingCT(wtxNew, ringSize, strFailReason, myIndex)) {
    	strFailReason = _("Fail to make partial ring CT");
    	return false;
    }
    return true;
}

bool CWallet::generateCommitmentAndEncode(CPartialTransaction& wtxNew)
{
	secp256k1_context2* both = GetContext();
    for(CTxOut& out: wtxNew.vout) {
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
    return true;
}

int CWallet::findMultisigInputIndex(const CPartialTransaction& tx) const {
	return findMultisigInputIndex(tx.ToTransaction(), tx.vin[0]);
}

int CWallet::findMultisigInputIndex(const CTransaction& tx) const {
	return findMultisigInputIndex(tx, tx.vin[0]);
}

uint256 CWallet::readPendingTxPriv() const {
    if (HasPendingTx()) {
        CWalletDB db(strWalletFile);
        CPartialTransaction tx;
        if (db.ReadPendingForSigningTx(tx)) {
            std::vector<pair<uint256, unsigned int>> setCoins;
            for(size_t i = 0; i < tx.vin.size(); i++) {
                setCoins.push_back(make_pair(tx.vin[i].prevout.hash, tx.vin[i].prevout.n));
            }
            {
                uint256 h = ComputeSortedSelectedOutPointHash(setCoins);
                CKey privateTx;
                privateTx.Set(h.begin(), h.end(), true);
                CPubKey txPub = privateTx.GetPubKey();
                for(size_t i = 0; i < tx.vout.size(); i++) {
                    if (txPub.Raw() == tx.vout[i].txPub) {
                        return h;
                    }
                }
            }

            for(size_t k = 0; k < tx.vin[0].decoys.size(); k++) {
                setCoins.clear();
                for(size_t i = 0; i < tx.vin.size(); i++) {
                    setCoins.push_back(make_pair(tx.vin[i].decoys[k].hash, tx.vin[i].decoys[k].n));
                }
                uint256 h = ComputeSortedSelectedOutPointHash(setCoins);
                CKey privateTx;
                privateTx.Set(h.begin(), h.end(), true);
                CPubKey txPub = privateTx.GetPubKey();
                for(size_t i = 0; i < tx.vout.size(); i++) {
                    if (txPub.Raw() == tx.vout[i].txPub) {
                        return h;
                    }
                }
            }
        }
    } 
    return uint256(0);
}

int CWallet::findMultisigInputIndex(const CTransaction& tx, const CTxIn& txin) const {
    LOCK2(cs_main, cs_wallet);
    if (myIndexMap.count(tx.GetHash()) == 1) return myIndexMap[tx.GetHash()];
    int ret = -2;
    std::vector<pair<uint256, unsigned int>> setCoins;

    for(size_t i = 0; i < tx.vin.size(); i++) {
        setCoins.push_back(make_pair(tx.vin[i].prevout.hash, tx.vin[i].prevout.n));
	}
    uint256 h;
    uint256 pendingPriv = readPendingTxPriv();
    {
        h = ComputeSortedSelectedOutPointHash(setCoins);
        CKey privateTx;
        privateTx.Set(h.begin(), h.end(), true);
        CPubKey txPub = privateTx.GetPubKey();
        for(size_t i = 0; i < tx.vout.size(); i++) {
            if (txPub.Raw() == tx.vout[i].txPub) {
                myIndexMap[tx.GetHash()] = -1;
                ret = -1;
                break;
            }
        }
    }
    CWalletDB db(strWalletFile);
    if (ret == -1) {
        for(size_t i = 0; i < tx.vin.size(); i++) {
            if (tx.vin[i].keyImage.IsValid()) {
                std::string outString = tx.vin[i].prevout.hash.GetHex() + std::to_string(tx.vin[i].prevout.n);
                outpointToKeyImages[outString] = tx.vin[i].keyImage;
                db.WriteKeyImage(outString, tx.vin[i].keyImage);
                if (mapWallet.count(tx.vin[i].prevout.hash) == 1) {
                    mapWallet[tx.vin[i].prevout.hash].MarkDirty();
                    if (pendingPriv == h) {
                        db.WriteHasWaitingTx(false);
                    }
                }
            }
        }
        return ret;
    }

    for(size_t k = 0; k < tx.vin[0].decoys.size(); k++) {
        setCoins.clear();
        for(size_t i = 0; i < tx.vin.size(); i++) {
            setCoins.push_back(make_pair(tx.vin[i].decoys[k].hash, tx.vin[i].decoys[k].n));
        }
        h = ComputeSortedSelectedOutPointHash(setCoins);
        CKey privateTx;
        privateTx.Set(h.begin(), h.end(), true);
        CPubKey txPub = privateTx.GetPubKey();
        for(size_t i = 0; i < tx.vout.size(); i++) {
            if (txPub.Raw() == tx.vout[i].txPub) {
                myIndexMap[tx.GetHash()] = k;
                ret = k;
                break;
            }
        }
        if (ret != -2) {
            break;
        }
    }

    if (ret >= 0) {
        for(size_t i = 0; i < tx.vin.size(); i++) {
            if (tx.vin[i].keyImage.IsValid()) {
                std::string outString = tx.vin[i].decoys[ret].hash.GetHex() + std::to_string(tx.vin[i].decoys[ret].n);
                outpointToKeyImages[outString] = tx.vin[i].keyImage;
                db.WriteKeyImage(outString, tx.vin[i].keyImage);
                if (mapWallet.count(tx.vin[i].decoys[ret].hash) == 1) {
                    mapWallet[tx.vin[i].decoys[ret].hash].MarkDirty();
                    if (pendingPriv == h) {
                        db.WriteHasWaitingTx(false);
                    }
                }
            }
        }
    }
	return ret;
}

uint256 CWallet::generateHashOfAllIns(const CPartialTransaction& tx)
{
	uint256 ret;
	int myIndex = findMultisigInputIndex(tx);

	for (size_t j = 0; j < tx.vin.size(); j++) {
		COutPoint myOutpoint;
		if (myIndex == -1) {
			myOutpoint = tx.vin[j].prevout;
		} else {
			myOutpoint = tx.vin[j].decoys[myIndex];
		}
		uint256 opHash = myOutpoint.GetHash();
		ret = Hash(ret.begin(), ret.end(), opHash.begin(), opHash.end());
	}
	return ret;
}

bool CWallet::generatePKeyImageAlphaListFromPartialTx(const CPartialTransaction& tx, CListPKeyImageAlpha& l)
{
    LOCK2(cs_main, cs_wallet);
	int myIndex = findMultisigInputIndex(tx);
    if (myIndex < -1) throw runtime_error("Failed to find index of the multisignature transaction");

	for (size_t j = 0; j < tx.vin.size(); j++) {
		COutPoint myOutpoint;
		if (myIndex == -1) {
			myOutpoint = tx.vin[j].prevout;
		} else {
			myOutpoint = tx.vin[j].decoys[myIndex];
		}

		CPKeyImageAlpha combo;
		GeneratePKeyImageAlpha(myOutpoint, combo);
		uint256 opHash = myOutpoint.GetHash();
		l.partialAlphas.push_back(combo);
	}

	l.hashOfAllInputOutpoints = generateHashOfAllIns(tx);

	CPKeyImageAlpha additional;
	generateAdditionalPartialAlpha(tx, additional, l.hashOfAllInputOutpoints);
	l.partialAlphas.push_back(additional);

	l.partialAdditionalKeyImage = generatePartialAdditionalKeyImage(tx);
}

bool CWallet::makeRingCT(CPartialTransaction& wtxNew, int ringSize, std::string& strFailReason, int myIndex)
{
	secp256k1_context2 *both = GetContext();

	if (wtxNew.vin.size() >= 30) {
		strFailReason = _("Failed due to transaction size too large");
		return false;
	}

	COutPoint selectedOP;
	if (myIndex == -1) {
		selectedOP = wtxNew.vin[0].prevout;
	} else {
		selectedOP = wtxNew.vin[0].decoys[myIndex];
	}
	uint256 selectedOPHash = selectedOP.GetHash();
	CKey multisigView = MyMultisigViewKey();
	wtxNew.selectedUTXOHash = Hash(multisigView.begin(), multisigView.end(), selectedOPHash.begin(), selectedOPHash.end());
	return true;
}

CPubKey CWallet::SumOfAllPubKeys(std::vector<CPubKey>& l) const
{
	secp256k1_pedersen_commitment commitments[l.size()];
	const secp256k1_pedersen_commitment *pointers[l.size()];
	for(size_t i = 0; i < l.size(); i++) {
		secp256k1_pedersen_serialized_pubkey_to_commitment(l[i].begin(), 33, &commitments[i]);
		pointers[i] = &commitments[i];
	}
	secp256k1_pedersen_commitment out;
	secp256k1_pedersen_commitment_sum_pos(GetContext(), pointers, l.size(), &out);
	unsigned char serializedPub[33];
	size_t length;
	secp256k1_pedersen_commitment_to_serialized_pubkey(&out, serializedPub, &length);
	CPubKey ret(serializedPub, serializedPub + 33);
	return ret;
}

CPubKey CWallet::generateAdditonalPubKey(const CPartialTransaction& wtxNew)
{
    LOCK2(cs_main, cs_wallet);
	const size_t MAX_VIN = 32;
	const size_t MAX_DECOYS = 13;	//padding 1 for safety reasons
	const size_t MAX_VOUT = 5;
	int myIndex = findMultisigInputIndex(wtxNew);
	secp256k1_context2 *both = GetContext();
	//all in pubkeys + an additional public generated from commitments
	unsigned char allInPubKeys[MAX_VIN + 1][MAX_DECOYS + 1][33];
	unsigned char allInCommitments[MAX_VIN][MAX_DECOYS + 1][33];
	unsigned char allOutCommitments[MAX_VOUT][33];

	int myBlindsIdx = 0;
	int myRealIndex = 0;
	if (myIndex != -1) {
		myRealIndex = myIndex + 1;
	}

	int PI = myRealIndex;
	CPubKey null;
	//computing additional key image:
	//collecting all output commimtments including transaction fees with commitment with 0 blind
	secp256k1_pedersen_commitment allOutCommitmentsPacked[MAX_VOUT + 1]; //+1 for tx fee
	for (size_t i = 0; i < wtxNew.vout.size(); i++) {
        if (wtxNew.vout[i].commitment.empty()) throw runtime_error("Commitment empty");
		memcpy(&(allOutCommitments[i][0]), &(wtxNew.vout[i].commitment[0]), 33);
		if (!secp256k1_pedersen_commitment_parse(both, &allOutCommitmentsPacked[i], allOutCommitments[i])) {
			//strFailReason = _("Cannot parse the commitment for inputs");
			return null;
		}
	}

	//commitment to tx fee, blind = 0
	unsigned char txFeeBlind[32];
	memset(txFeeBlind, 0, 32);
	if (!secp256k1_pedersen_commit(both, &allOutCommitmentsPacked[wtxNew.vout.size()], txFeeBlind, wtxNew.nTxFee, &secp256k1_generator_const_h, &secp256k1_generator_const_g)) {
		//strFailReason = _("Cannot parse the commitment for transaction fee");
		return null;
	}
	//filling the additional pubkey elements for decoys: allInPubKeys[wtxNew.vin.size()][..]
	//allInPubKeys[wtxNew.vin.size()][j] = sum of allInPubKeys[..][j] + sum of allInCommitments[..][j] - sum of allOutCommitments
	const secp256k1_pedersen_commitment *outCptr[MAX_VOUT + 1];
	for(size_t i = 0; i < wtxNew.vout.size() + 1; i++) {
		outCptr[i] = &allOutCommitmentsPacked[i];
	}

	for (size_t j = 0; j < wtxNew.vin.size(); j++) {
		COutPoint myOutpoint;
		if (myIndex == -1) {
			myOutpoint = wtxNew.vin[j].prevout;
		} else {
			myOutpoint = wtxNew.vin[j].decoys[myIndex];
		}
		CTransaction& inTx = mapWallet[myOutpoint.hash];

		CPubKey tempPubKey;
		ExtractPubKey(inTx.vout[myOutpoint.n].scriptPubKey, tempPubKey);
		memcpy(allInPubKeys[j][PI], tempPubKey.begin(), 33);
		memcpy(allInCommitments[j][PI], &(inTx.vout[myOutpoint.n].commitment[0]), 33);
	}
	//extract all decoy public keys and commitments
	for (int i = 0; i < (int)wtxNew.vin.size(); i++) {
		std::vector<COutPoint> decoysForIn;
		decoysForIn.push_back(wtxNew.vin[i].prevout);
		for(int j = 0; j < (int)wtxNew.vin[i].decoys.size(); j++) {
			decoysForIn.push_back(wtxNew.vin[i].decoys[j]);
		}
		for (int j = 0; j < (int)wtxNew.vin[0].decoys.size() + 1; j++) {
			if (j != PI) {
				CTransaction txPrev;
				uint256 hashBlock;
				if (!GetTransaction(decoysForIn[j].hash, txPrev, hashBlock)) {
					return null;
				}
				CPubKey extractedPub;
				if (!ExtractPubKey(txPrev.vout[decoysForIn[j].n].scriptPubKey, extractedPub)) {
					//strFailReason = _("Cannot extract public key from script pubkey");
					return null;
				}
				memcpy(allInPubKeys[i][j], extractedPub.begin(), 33);
				memcpy(allInCommitments[i][j], &(txPrev.vout[decoysForIn[j].n].commitment[0]), 33);
			}
		}
	}

	secp256k1_pedersen_commitment allInCommitmentsPacked[MAX_VIN][MAX_DECOYS + 1];

	secp256k1_pedersen_commitment inPubKeysToCommitments[MAX_VIN][MAX_DECOYS + 1];
	for(int i = 0; i < (int)wtxNew.vin.size(); i++) {
		for (int j = 0; j < (int)wtxNew.vin[0].decoys.size() + 1; j++) {
			secp256k1_pedersen_serialized_pubkey_to_commitment(allInPubKeys[i][j], 33, &inPubKeysToCommitments[i][j]);
		}
	}

	//additional pubkey member in the ring = ADPUB = Sum of All input public keys + sum of all input commitments - sum of all output commitments = every signer can compute
	int j = PI;
	const secp256k1_pedersen_commitment *inCptr[MAX_VIN * 2];
	for (int k = 0; k < (int)wtxNew.vin.size(); k++) {
		if (!secp256k1_pedersen_commitment_parse(both, &allInCommitmentsPacked[k][j], allInCommitments[k][j])) {
			//strFailReason = _("Cannot parse the commitment for inputs");
			return null;
		}
		inCptr[k] = &allInCommitmentsPacked[k][j];
	}
	for (size_t k = wtxNew.vin.size(); k < 2*wtxNew.vin.size(); k++) {
		inCptr[k] = &inPubKeysToCommitments[k - wtxNew.vin.size()][j];
	}
	secp256k1_pedersen_commitment out;
	size_t length;
	//convert allInPubKeys to pederson commitment to compute sum of all in public keys
	if (!secp256k1_pedersen_commitment_sum(both, inCptr, wtxNew.vin.size()*2, outCptr, wtxNew.vout.size() + 1, &out))
		throw runtime_error("Cannot compute sum of commitment");
	if (!secp256k1_pedersen_commitment_to_serialized_pubkey(&out, allInPubKeys[wtxNew.vin.size()][j], &length))
		throw runtime_error("Cannot covert from commitment to public key");

	CPubKey ADDPUB(allInPubKeys[wtxNew.vin.size()][PI], allInPubKeys[wtxNew.vin.size()][PI] + 33);
	return ADDPUB;
}

CKeyImage CWallet::generatePartialAdditionalKeyImage(const CPartialTransaction& wtxNew)
{
    LOCK2(cs_main, cs_wallet);
	CPubKey ADDPUB = generateAdditonalPubKey(wtxNew);
	CKey mySpend;
	mySpendPrivateKey(mySpend);
	unsigned char retRaw[33];
	PointHashingSuccessively(ADDPUB, mySpend.begin(), retRaw);
	CKeyImage ret(retRaw, retRaw + 33);
	return ret;
}

/*Important note multisig
 * 1. Every signer will generate their own ALPHA[j][PI] for each input and send corresponding L[j][PI], R[j][PI] along with key image
 * to other signers in key image synchronization. Signers should not reveal their ALPHA to any other signer
 * 2. S[i][j] is generated by the transaction initiator, j #= PI
 * 3. Once key images and L[j][PI], R[j][PI] is synchronized, the initiator can start creating transaction
 * 4. Initiator signs the transaction by computing partial S[j][PI] = ALPHA[j][PI] - c*HS - c*x, HS = Hash(view*txPub), x = initiator private spend key
 * 5. Signing: Each signer then contribute their partial S[j][PI] = ALPHA[j][PI] - c*x where x = private spend key of the signer, and add it to the computed partial S[j][PI]
 * 6. The last signer put all full key images, c, S[i][j] to the transaction as the signature*/
bool CWallet::finishRingCTAfterKeyImageSynced(CPartialTransaction& wtxNew, std::vector<CListPKeyImageAlpha> ls, std::string& strFailReason)
{
    LOCK2(cs_main, cs_wallet);
    CKey mySpend;
	mySpendPrivateKey(mySpend);
	const size_t MAX_VIN = 32;
	const size_t MAX_DECOYS = 13;	//padding 1 for safety reasons
	const size_t MAX_VOUT = 5;
	int myIndex = findMultisigInputIndex(wtxNew);
	secp256k1_context2 *both = GetContext();

	//add myself to CListPKeyImageAlpha list
	CListPKeyImageAlpha pkeyAlpha;
	generatePKeyImageAlphaListFromPartialTx(wtxNew, pkeyAlpha);
	ls.push_back(pkeyAlpha);

	size_t numSigner = comboKeys.comboKeys.size();
	if (ls.size() != numSigner) {
		throw runtime_error("Num Signers not match");
	}

	for (size_t i = 0; i < ls.size(); i++) {
		if (ls[i].partialAlphas.size() != wtxNew.vin.size() + 1) {
			throw runtime_error("Alpha list size not match");
		}
	}

	std::vector<secp256k1_pedersen_commitment> myInputCommiments;
	int totalCommits = wtxNew.vin.size() + wtxNew.vout.size();
	int npositive = wtxNew.vin.size();
	unsigned char myBlinds[MAX_VIN + MAX_VIN + MAX_VOUT + 1][32];	//myBlinds is used for compuitng additional private key in the ring =
	memset(myBlinds, 0, (MAX_VIN + MAX_VIN + MAX_VOUT + 1) * 32);
	const unsigned char *bptr[MAX_VIN + MAX_VIN + MAX_VOUT + 1];
	//all in pubkeys + an additional public generated from commitments
	unsigned char allInPubKeys[MAX_VIN + 1][MAX_DECOYS + 1][33];
	unsigned char allKeyImages[MAX_VIN + 1][33];
	unsigned char allInCommitments[MAX_VIN][MAX_DECOYS + 1][33];
	unsigned char allOutCommitments[MAX_VOUT][33];

	int myBlindsIdx = 0;
	int myRealIndex = 0;
	if (myIndex != -1) {
		myRealIndex = myIndex + 1;
	}

	int PI = myRealIndex;

	//computing additional key image:
	//collecting all output commimtments including transaction fees with commitment with 0 blind
	secp256k1_pedersen_commitment allOutCommitmentsPacked[MAX_VOUT + 1]; //+1 for tx fee
	for (size_t i = 0; i < wtxNew.vout.size(); i++) {
		memcpy(&(allOutCommitments[i][0]), &(wtxNew.vout[i].commitment[0]), 33);
		if (!secp256k1_pedersen_commitment_parse(both, &allOutCommitmentsPacked[i], allOutCommitments[i])) {
			throw runtime_error("Cannot parse the commitment for inputs");
		}
	}

	//commitment to tx fee, blind = 0
	unsigned char txFeeBlind[32];
	memset(txFeeBlind, 0, 32);
	if (!secp256k1_pedersen_commit(both, &allOutCommitmentsPacked[wtxNew.vout.size()], txFeeBlind, wtxNew.nTxFee, &secp256k1_generator_const_h, &secp256k1_generator_const_g)) {
		throw runtime_error("Cannot parse the commitment for transaction fee");
	}

	//filling the additional pubkey elements for decoys: allInPubKeys[wtxNew.vin.size()][..]
	//allInPubKeys[wtxNew.vin.size()][j] = sum of allInPubKeys[..][j] + sum of allInCommitments[..][j] - sum of allOutCommitments
	const secp256k1_pedersen_commitment *outCptr[MAX_VOUT + 1];
	for(size_t i = 0; i < wtxNew.vout.size() + 1; i++) {
		outCptr[i] = &allOutCommitmentsPacked[i];
	}

	for (size_t j = 0; j < wtxNew.vin.size(); j++) {
		COutPoint myOutpoint;
		if (myIndex == -1) {
			myOutpoint = wtxNew.vin[j].prevout;
		} else {
			myOutpoint = wtxNew.vin[j].decoys[myIndex];
		}
		CTransaction& inTx = mapWallet[myOutpoint.hash];

		CPubKey tempPubKey;
		ExtractPubKey(inTx.vout[myOutpoint.n].scriptPubKey, tempPubKey);
		memcpy(allInPubKeys[j][PI], tempPubKey.begin(), 33);
		memcpy(allInCommitments[j][PI], &(inTx.vout[myOutpoint.n].commitment[0]), 33);
	}

	//extract all decoy public keys and commitments
	for (int i = 0; i < (int)wtxNew.vin.size(); i++) {
		std::vector<COutPoint> decoysForIn;
		decoysForIn.push_back(wtxNew.vin[i].prevout);
		for(int j = 0; j < (int)wtxNew.vin[i].decoys.size(); j++) {
			decoysForIn.push_back(wtxNew.vin[i].decoys[j]);
		}
		for (int j = 0; j < (int)wtxNew.vin[0].decoys.size() + 1; j++) {
			if (j != PI) {
				CTransaction txPrev;
				uint256 hashBlock;
				if (!GetTransaction(decoysForIn[j].hash, txPrev, hashBlock)) {
					throw runtime_error("Failed to read decoys");
				}
				CPubKey extractedPub;
				if (!ExtractPubKey(txPrev.vout[decoysForIn[j].n].scriptPubKey, extractedPub)) {
					throw runtime_error("Cannot extract public key from script pubkey");
				}
				memcpy(allInPubKeys[i][j], extractedPub.begin(), 33);
				memcpy(allInCommitments[i][j], &(txPrev.vout[decoysForIn[j].n].commitment[0]), 33);
			}
		}
	}

	secp256k1_pedersen_commitment allInCommitmentsPacked[MAX_VIN][MAX_DECOYS + 1];

	secp256k1_pedersen_commitment inPubKeysToCommitments[MAX_VIN][MAX_DECOYS + 1];
	for(int i = 0; i < (int)wtxNew.vin.size(); i++) {
		for (int j = 0; j < (int)wtxNew.vin[0].decoys.size() + 1; j++) {
			secp256k1_pedersen_serialized_pubkey_to_commitment(allInPubKeys[i][j], 33, &inPubKeysToCommitments[i][j]);
		}
	}

	//additional ring pubkey member in the ring = ADPUB = Sum of All input public keys + sum of all input commitments - sum of all output commitments = every signer can compute
	for (int j = 0; j < (int)wtxNew.vin[0].decoys.size() + 1; j++) {
		//if (j != PI) {
			const secp256k1_pedersen_commitment *inCptr[MAX_VIN * 2];
			for (int k = 0; k < (int)wtxNew.vin.size(); k++) {
				if (!secp256k1_pedersen_commitment_parse(both, &allInCommitmentsPacked[k][j], allInCommitments[k][j])) {
					throw runtime_error("Cannot parse the commitment for inputs");
				}
				inCptr[k] = &allInCommitmentsPacked[k][j];
			}
			for (size_t k = wtxNew.vin.size(); k < 2*wtxNew.vin.size(); k++) {
				inCptr[k] = &inPubKeysToCommitments[k - wtxNew.vin.size()][j];
			}
			secp256k1_pedersen_commitment out;
			size_t length;
			//convert allInPubKeys to pederson commitment to compute sum of all in public keys
			if (!secp256k1_pedersen_commitment_sum(both, inCptr, wtxNew.vin.size()*2, outCptr, wtxNew.vout.size() + 1, &out))
				throw runtime_error("Cannot compute sum of commitment");
			if (!secp256k1_pedersen_commitment_to_serialized_pubkey(&out, allInPubKeys[wtxNew.vin.size()][j], &length))
				throw runtime_error("Cannot covert from commitment to public key");
		//}
	}

	//now all pubkeys are filled, start computing all key images
	//1. compute key image for all input
	//key image = x*Pub, x = HS*Pub + (all spend keys)*Pub
	for(size_t i = 0; i < wtxNew.vin.size(); i++) {
		COutPoint myOutpoint;
		if (myIndex == -1) {
			myOutpoint = wtxNew.vin[i].prevout;
		} else {
			myOutpoint = wtxNew.vin[i].decoys[myIndex];
		}
		CKey temp = GeneratePartialKey(myOutpoint);
        CTransaction inTx =  mapWallet[myOutpoint.hash];
        CPubKey pub;
        if (!ExtractPubKey(inTx.vout[myOutpoint.n].scriptPubKey, pub)) {
            throw runtime_error("Failed to extract public key");
        }
		unsigned char HSPubTemp[33];
		PointHashingSuccessively(pub, temp.begin(), HSPubTemp);

		std::vector<CKeyImage> partialKeyImages;

		CKeyImage HSPub(HSPubTemp, HSPubTemp + 33);
		partialKeyImages.push_back(HSPub);

		for(size_t j = 0; j < ls.size(); j++) {
			partialKeyImages.push_back(ls[j].partialAlphas[i].ki);
		}
		CKeyImage full = SumOfAllPubKeys(partialKeyImages);
		memcpy(allKeyImages[i], full.begin(), 33);
        wtxNew.vin[i].keyImage.Set(allKeyImages[i], allKeyImages[i] + 33);
	}

	//2. compute key image for additional
	//ADDPUB = allInPubKeys[wtxNew.vin.size()] ==> computed above already
	//here we cannot collect partial private keys of inputs, thus only do partially
	//additional private key for additional key image = all input blinds + all input private keys - all output blinds
	//all input private keys = all HSs (ECDH) + all partial private keys of all signers,
	//Each input private key = HS + sum of all signers private keys
	//key image of additional private key = (all input blinds - all output blinds)*ADDPUB + (all HSs (ECDH))* ADDPUB + (all partial private keys)*ADDPUB
	//each signer needs to generate (partial private key)*ADDPUB during sync
	//K1 = (all input blinds - all output blinds)*ADDPUB => easy to compute
	//K2 = (all HSs (ECDH))* ADDPUB ==> easy to compute
	//K3 = (all partial private keys)*ADDPUB = wtxNew.vin.size() * (sum of all additional partial key images)
    //private key of K3 = wtxNew.vin.size()*(sum of all co-signer private spend keys)

    CPubKey ADDPUB(allInPubKeys[wtxNew.vin.size()][PI], allInPubKeys[wtxNew.vin.size()][PI] + 33);
	std::vector<CPubKey> allK2s;

	//step 2.1: collect all input blinds
	for(CTxIn& in: wtxNew.vin) {
		COutPoint myOutpoint;
		if (myIndex == -1) {
			myOutpoint = in.prevout;
		} else {
			myOutpoint = in.decoys[myIndex];
		}
		CTransaction& inTx = mapWallet[myOutpoint.hash];
		CAmount tempAmount;
		CKey tmp;
		RevealTxOutAmount(inTx, inTx.vout[myOutpoint.n], tempAmount, tmp);
		if (tmp.IsValid()) memcpy(&myBlinds[myBlindsIdx][0], tmp.begin(), 32);
		//verify input commitments
		std::vector<unsigned char> recomputedCommitment;
		if (!CreateCommitment(&myBlinds[myBlindsIdx][0], tempAmount, recomputedCommitment))
			throw runtime_error("Cannot create pedersen commitment");
		if (recomputedCommitment != inTx.vout[myOutpoint.n].commitment) {
			throw runtime_error("Input commitments are not correct");
		}

		bptr[myBlindsIdx] = myBlinds[myBlindsIdx];
		myBlindsIdx++;

		CKey k2 = GeneratePartialKey(inTx.vout[myOutpoint.n]);
        unsigned char k2ADDPUB[33];
        PointHashingSuccessively(ADDPUB, k2.begin(), k2ADDPUB);
		allK2s.push_back(CPubKey(k2ADDPUB, k2ADDPUB + 33));
	}

	//collecting output commitment blinding factors
    if (wtxNew.blinds.size() != wtxNew.vout.size()) {
        throw runtime_error("ill-formated partial transaction");
    }
    int blindIdx = 0;
	for(CTxOut& out: wtxNew.vout) {
		if (!out.IsEmpty()) {
			if (!wtxNew.blinds[blindIdx].empty()) {
				memcpy(&myBlinds[myBlindsIdx][0], wtxNew.blinds[blindIdx].data(), 32);
			} else {
            }
			bptr[myBlindsIdx] = &myBlinds[myBlindsIdx][0];
			myBlindsIdx++;
		}
        blindIdx++;
	}

	//compute K1
	CKey newBlind;
	unsigned char outSum[32];
	if (!secp256k1_pedersen_blind_sum(both, outSum, (const unsigned char * const *)bptr, totalCommits, npositive))
		throw runtime_error("Cannot compute pedersen blind sum");

	//newBlind.Set(outSum, outSum + 32, true);
	CKeyImage K1;
	unsigned char K1data[33];
	PointHashingSuccessively(ADDPUB, outSum, K1data);
	K1.Set(K1data, K1data + 33);
	//compute K2
	CKeyImage K2 = SumOfAllPubKeys(allK2s);

	//compute K3
	//K3 = (all partial private keys)*ADDPUB = wtxNew.vin.size() * (sum of all additional partial key images)
	std::vector<CPubKey> subAllK3s;
	for(size_t i = 0; i < ls.size(); i++) {
		subAllK3s.push_back(ls[i].partialAdditionalKeyImage);
	}
	// for(size_t i = 0; i < wtxNew.vin.size(); i++) {
	// 	allK3s.insert(allK3s.end(), subAllK3s.begin(), subAllK3s.end());
	// }
    CKeyImage subK3 = SumOfAllPubKeys(subAllK3s);
    std::vector<CPubKey> allPubK3s;
    for(int i = 0; i < wtxNew.vin.size(); i++) {
        allPubK3s.push_back(subK3);
    }
	CKeyImage K3 = SumOfAllPubKeys(allPubK3s);

	std::vector<CKeyImage> k1k2k3;
	k1k2k3.push_back(K1);
	k1k2k3.push_back(K2);
	k1k2k3.push_back(K3);
	CPubKey sum = SumOfAllPubKeys(k1k2k3);
	memcpy(allKeyImages[wtxNew.vin.size()], sum.begin(), 33);
    wtxNew.ntxFeeKeyImage.Set(sum.begin(), sum.end());

	unsigned char SIJ[MAX_VIN + 1][MAX_DECOYS + 1][32];
	unsigned char LIJ[MAX_VIN + 1][MAX_DECOYS + 1][33];
	unsigned char RIJ[MAX_VIN + 1][MAX_DECOYS + 1][33];
	unsigned char ALPHA[MAX_VIN + 1][32];//all are partial alphas generated by each signer, the final alpha is the sum of all
	memset(SIJ, 0, sizeof(SIJ));

	//generating LIJ and RIJ at PI: LIJ[j][PI], RIJ[j][PI], j=0..wtxNew.vin.size()
	for (size_t j = 0; j < wtxNew.vin.size() + 1; j++) {
		std::vector<CPubKey> allLIJs, allRIJs;
		for(int k = 0; k < ls.size(); k++) {
			allLIJs.push_back(ls[k].partialAlphas[j].LIJ);
			allRIJs.push_back(ls[k].partialAlphas[j].RIJ);
		}

		CPubKey LIJ_PI = SumOfAllPubKeys(allLIJs);
		CPubKey RIJ_PI = SumOfAllPubKeys(allRIJs);

		memcpy(LIJ[j][PI], LIJ_PI.begin(), 33);
		memcpy(RIJ[j][PI], RIJ_PI.begin(), 33);        
	}

	//filling LIJ & RIJ at [j][PI], additional LIJ, RIJ
	/*CKey alpha_additional;
	alpha_additional.MakeNewKey(true);
	CPubKey LIJ_PI_additional = alpha_additional.GetPubKey();
	memcpy(LIJ[wtxNew.vin.size()][PI], LIJ_PI_additional.begin(), 33);
	PointHashingSuccessively(allInPubKeys[wtxNew.vin.size()][PI], alpha_additional.begin(), RIJ[wtxNew.vin.size()][PI]);*/

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
				throw runtime_error("Cannot compute LIJ for ring signature in secp256k1_ec_pubkey_tweak_mul");
			}
			if (!secp256k1_ec_pubkey_tweak_add(CP, 33, SIJ[j][PI_interator])) {
				throw runtime_error("Cannot compute LIJ for ring signature in secp256k1_ec_pubkey_tweak_add");
			}
			memcpy(LIJ[j][PI_interator], CP, 33);
            LogPrintf("%s: L %d %d = %s\n", __func__, j, PI_interator, HexStr(LIJ[j][PI_interator], LIJ[j][PI_interator] + 33));

			//compute RIJ
			//first compute CI * I
			memcpy(RIJ[j][PI_interator], allKeyImages[j], 33);
			if (!secp256k1_ec_pubkey_tweak_mul(RIJ[j][PI_interator], 33, CI[PI_interator])) {
				throw runtime_error("Cannot compute RIJ for ring signature in secp256k1_ec_pubkey_tweak_mul");
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

			const secp256k1_pedersen_commitment *twoElements[2];
			twoElements[0] = &SHP_commitment;
			twoElements[1] = &cii_commitment;

			secp256k1_pedersen_commitment sum;
			if (!secp256k1_pedersen_commitment_sum_pos(both, twoElements, 2, &sum))
				throw  runtime_error("Cannot compute sum of commitments");
			size_t tempLength;
			if (!secp256k1_pedersen_commitment_to_serialized_pubkey(&sum, RIJ[j][PI_interator], &tempLength)) {
				throw runtime_error("Cannot compute two elements and serialize it to pubkey");
			}
            LogPrintf("%s: R %d %d = %s\n", __func__, j, PI_interator, HexStr(RIJ[j][PI_interator], RIJ[j][PI_interator] + 33));
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
        LogPrintf("%s: C %d = %s\n", __func__, ciIdx, HexStr(CI[ciIdx], CI[ciIdx] + 32));
	}

	memcpy(wtxNew.c.begin(), CI[0], 32);

	//encode C[PI]
	CKey multiView = MyMultisigViewKey();
	unsigned char encodedCPI[32];
	memcpy(encodedCPI, multiView.begin(), 32);
	secp256k1_ec_privkey_tweak_add(encodedCPI, CI[PI]);
	memcpy(wtxNew.encodedC_PI.begin(), encodedCPI, 32);

	//add ECDH to S[j][PI]
    //S[j][PI] = ALPHA - c * x[j]
    //MONOSIG
    //compute S[j][PI] = alpha_j - c_pi * x_j, x_j = private key corresponding to key image I

    //MULTISIG
    //Each signer has a list of wtx.vin.size() ALPHAs[0..wtx.vin.size()]
    //for j = 0..wtx.vin.size()
    //S[j][PI] = Sum of (all ALPHA[j] of all signers) - c*xj, xj = private key for key image at j
    //j=0..wtx.vin.size()-1, xj=H(multisigview*txPub) + sum of spend keys of all signers
    //x[wtx.vin.size()] = (sum of all inputs H(ECDH)) + wtx.vin.size()*(sum of all signers spend keys) + (sum of all input blinds) - sum of all output blinds

    //For tx initiator:
    //j=0..wtx.vin.size()-1
    //S[j][PI] = ALPHAs[j] - c*H(multisigview*txPub) - c*spendkey
    //S[wtx.vin.size()][PI] = ALPHAs[wtx.vin.size()] - c*(sum of all inputs H(ECDH)) - c*((sum of all input blinds) - (sum of all output blinds)) - c*wtx.vin.size()*spendkey
	
    //for other signer
    //compute S'[j][PI] = ALPHAs[j] - c*spendkey => add it to S[j][PI]
    //compute S'[wtx.vin.size()][PI] = ALPHAs[wtx.vin.size()] - c*wtx.vin.size()*spendkey => add it to S[wtx.vin.size()][PI]
    
    for(size_t j = 0; j < wtxNew.vin.size(); j++) {
        COutPoint myOutpoint;
		if (myIndex == -1) {
			myOutpoint = wtxNew.vin[j].prevout;
		} else {
			myOutpoint = wtxNew.vin[j].decoys[myIndex];
		}
        unsigned char alpha[32];
        const unsigned char *sumArray[3];
	    GenerateAlphaFromOutpoint(myOutpoint, alpha);
        sumArray[0] = alpha;

        CKey hs = GeneratePartialKey(myOutpoint);
        unsigned char ch[32];
        memcpy(ch, CI[PI], 32);
        if (!secp256k1_ec_privkey_tweak_mul(ch, hs.begin()))
			throw runtime_error("Cannot compute EC mul");
        sumArray[1] = ch;
        
        unsigned char cx[32];
		memcpy(cx, CI[PI], 32);
		if (!secp256k1_ec_privkey_tweak_mul(cx, mySpend.begin()))
			throw runtime_error("Cannot compute EC mul");
		sumArray[2] = cx;
		if (!secp256k1_pedersen_blind_sum(GetContext(), SIJ[j][PI], sumArray, 3, 1)) throw runtime_error("Cannot compute EC mul");
    }

    const unsigned char *sumArray[4];
    CKey additionalPartialAlpha = generateAdditionalPartialAlpha(wtxNew);
    sumArray[0] = additionalPartialAlpha.begin();
    unsigned char sumOfECDHMultipliedByC[32];
    for(size_t j = 0; j < wtxNew.vin.size(); j++) {
        COutPoint myOutpoint;
		if (myIndex == -1) {
			myOutpoint = wtxNew.vin[j].prevout;
		} else {
			myOutpoint = wtxNew.vin[j].decoys[myIndex];
		}

        CKey hs = GeneratePartialKey(myOutpoint);
        unsigned char ch[32];
        memcpy(ch, CI[PI], 32);
        if (!secp256k1_ec_privkey_tweak_mul(ch, hs.begin()))
			throw runtime_error("Cannot compute EC mul");
        
        if (j == 0) {
            memcpy(sumOfECDHMultipliedByC, ch, 32);
        } else {
            if (!secp256k1_ec_privkey_tweak_add(sumOfECDHMultipliedByC, ch))
			    throw runtime_error("Cannot compute EC mul");
        }
    }

    sumArray[1] = sumOfECDHMultipliedByC;

    unsigned char coutSum[32];
    memcpy(coutSum, CI[PI], 32);
    if (!secp256k1_ec_privkey_tweak_mul(coutSum, outSum))
	    throw runtime_error("Cannot compute EC mul");
    sumArray[2] = coutSum;

    unsigned char cspendkey[32];
    if (!MultiplyScalar(cspendkey, CI[PI], wtxNew.vin.size()))
        throw runtime_error("Cannot compute EC mul");
    
    if (!secp256k1_ec_privkey_tweak_mul(cspendkey, mySpend.begin()))
		throw runtime_error("Cannot compute EC mul");
    
    sumArray[3] = cspendkey;

    if (!secp256k1_pedersen_blind_sum(GetContext(), SIJ[wtxNew.vin.size()][PI], sumArray, 4, 1)) throw runtime_error("Cannot compute EC mul");
    
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
	//wtxNew.ntxFeeKeyImage.Set(allKeyImages[wtxNew.vin.size()], allKeyImages[wtxNew.vin.size()] + 33);

    for(size_t i = 0; i < wtxNew.vout.size(); i++) {
        wtxNew.vout[i].nValue = 0;
    }
	return true;
}

//this function assumes that all keyimages are full now
//for other signer
//compute S'[j][PI] = ALPHAs[j] - c*spendkey => add it to S[j][PI]
//compute S'[wtx.vin.size()][PI] = ALPHAs[wtx.vin.size()] - c*wtx.vin.size()*spendkey => add it to S[wtx.vin.size()][PI]
bool CWallet::CoSignPartialTransaction(CPartialTransaction& tx)
{
    if (IsLocked()) throw runtime_error("Wallet is locked");
    LOCK2(cs_main, cs_wallet);
	const size_t MAX_VIN = 32;
	const size_t MAX_DECOYS = 13;	//padding 1 for safety reasons
	const size_t MAX_VOUT = 5;
	unsigned char SIJ[MAX_VIN + 1][MAX_DECOYS + 1][32];

	for (size_t i = 0; i < tx.vin[0].decoys.size() + 1; i++) {
		std::vector<uint256> S_column = tx.S[i];
		for (size_t j = 0; j < tx.vin.size() + 1; j++) {
			memcpy(SIJ[j][i], S_column[j].begin(), 32);
		}
	}

	int myIndex = findMultisigInputIndex(tx);
	int myRealIndex = 0;
	if (myIndex != -1) {
		myRealIndex = myIndex + 1;
	}

	int PI = myRealIndex;

	//decode CPI
	CKey multiView = MyMultisigViewKey();
	unsigned char decodedCPI[32];
	memcpy(decodedCPI, multiView.begin(), 32);
	secp256k1_ec_privkey_negate2(GetContext(), decodedCPI);
	secp256k1_ec_privkey_tweak_add(decodedCPI, tx.encodedC_PI.begin());

	//the actual signing part which compute S[j][PI]
	//compute S'[j][PI] = ALPHAs[j] - c*spendkey => add it to S[j][PI]
    //compute S'[wtx.vin.size()][PI] = ALPHAs[wtx.vin.size()] - c*wtx.vin.size()*spendkey => add it to S[wtx.vin.size()][PI]
	CKey mySpend;
	mySpendPrivateKey(mySpend);
    LogPrintf("Computing S\n");
	for (size_t j = 0; j < tx.vin.size(); j++) {
		COutPoint myOutpoint;
		if (myIndex == -1) {
			myOutpoint = tx.vin[j].prevout;
		} else {
			myOutpoint = tx.vin[j].decoys[myIndex];
		}
		unsigned char alpha[32], s[32], temp[32];
		GenerateAlphaFromOutpoint(myOutpoint, alpha);

		unsigned char cx[32];
		memcpy(cx, decodedCPI, 32);
		if (!secp256k1_ec_privkey_tweak_mul(cx, mySpend.begin()))
			throw runtime_error("Cannot compute EC mul");
		const unsigned char *sumArray[2];
		sumArray[0] = alpha;
		sumArray[1] = cx;
		if (!secp256k1_pedersen_blind_sum(GetContext(), s, sumArray, 2, 1))
			throw runtime_error("Cannot compute pedersen blind sum");

		secp256k1_ec_privkey_tweak_add(SIJ[j][PI], s);
		memcpy(tx.S[PI][j].begin(), SIJ[j][PI], 32);
	}
	unsigned char s[32], temp[32];
	CKey alpha = generateAdditionalPartialAlpha(tx);

	unsigned char cx[32];
	if (!MultiplyScalar(cx, decodedCPI, tx.vin.size()))
		throw runtime_error("Cannot compute EC mul");
    if (!secp256k1_ec_privkey_tweak_mul(cx, mySpend.begin()))
		throw runtime_error("Cannot compute EC mul");
    
	const unsigned char *sumArray[2];
	sumArray[0] = alpha.begin();
	sumArray[1] = cx;
	if (!secp256k1_pedersen_blind_sum(GetContext(), s, sumArray, 2, 1))
		throw runtime_error("Cannot compute pedersen blind sum");

	secp256k1_ec_privkey_tweak_add(SIJ[tx.vin.size()][PI], s);
	memcpy(tx.S[PI][tx.vin.size()].begin(), SIJ[tx.vin.size()][PI], 32);

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

bool CWallet::IsMine(const COutPoint outpoint) const {
	if (mapWallet.count(outpoint.hash) < 1) return false;
	return IsMine(mapWallet[outpoint.hash].vout[outpoint.n]);
}

bool CWallet::selectDecoysAndRealIndex(CPartialTransaction& tx, int& myIndex, int ringSize)
{
    LogPrintf("Selecting coinbase decoys\n");
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

	size_t notMineCoinbase = 0;
	size_t notMineUserDecoy = 0;
	for (size_t i = 0; i < pwalletMain->coinbaseDecoysPool.size(); i++) {
		if (!IsMine(std::next(pwalletMain->coinbaseDecoysPool.begin(), i)->first)) {
			notMineCoinbase++;
		}
	}

	for (size_t i = 0; i < pwalletMain->userDecoysPool.size(); i++) {
		if (!IsMine(std::next(pwalletMain->userDecoysPool.begin(), i)->first)) {
			notMineUserDecoy++;
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

        int numDecoys = 0;
        if (txPrev.IsCoinAudit() || txPrev.IsCoinBase() || txPrev.IsCoinStake()) {
            if ((int)coinbaseDecoysPool.size() >= ringSize * 5) {
                while (numDecoys < ringSize) {
                    bool duplicated = false;
                    map<COutPoint, uint256>::const_iterator it = std::next(coinbaseDecoysPool.begin(), secp256k1_rand32() % coinbaseDecoysPool.size());
                    if (IsMine(it->first)) continue;
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
                    if (IsMine(it->first)) continue;
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
                LogPrintf("Dont have enough decoys, please wait for around 10 minutes and re-try\n");
                return false;
            }
        } else {
            std::map<COutPoint, uint256> decoySet = userDecoysPool;
            decoySet.insert(coinbaseDecoysPool.begin(), coinbaseDecoysPool.end());
            if ((int)decoySet.size() >= ringSize * 5) {
                while (numDecoys < ringSize) {
                    bool duplicated = false;
                    map<COutPoint, uint256>::const_iterator it = std::next(decoySet.begin(), secp256k1_rand32() % decoySet.size());
                    if (IsMine(it->first)) continue;
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
                    if (IsMine(it->first)) continue;
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
                LogPrintf("Dont have enough decoys, please wait for around 10 minutes and re-try\n");
                return false;
            }
        }
    }
    myIndex = secp256k1_rand32() % (tx.vin[0].decoys.size() + 1) - 1;

    for(size_t i = 0; i < tx.vin.size(); i++) {
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
        CKey view = MyMultisigViewKey();
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
    //disable in multisig wallet
    return false;
}

bool CWallet::CreateCoinAudit(const CKeyStore& keystore, unsigned int nBits, int64_t nSearchInterval, CMutableTransaction& txNew, unsigned int& nTxNewTime)
{
    // The following split & combine thresholds are important to security
    // Should not be adjusted if you don't understand the consequences

    txNew.vin.clear();
    txNew.vout.clear();

    // Mark coin stake transaction
    CScript scriptEmpty;
    scriptEmpty.clear();
    txNew.vout.push_back(CTxOut(0, scriptEmpty));

    // Choose coins to use
    CAmount nBalance = GetBalance();

    if (mapArgs.count("-reservebalance") && !ParseMoney(mapArgs["-reservebalance"], nReserveBalance))
        return error("CreateCoinStake : invalid reserve balance amount");

    if (nBalance > 0 && nBalance <= nReserveBalance)
        return false;

    // presstab HyperStake - Initialize as static and don't update the set on every run of CreateCoinAudit() in order to lighten resource use
    static std::set<pair<const CWalletTx*, unsigned int> > setAuditCoins;
    static int nLastStakeSetUpdate = 0;

    if (GetTime() - nLastStakeSetUpdate > nStakeSetUpdateTime) {
        setAuditCoins.clear();
        if (!SelectStakeCoins(setAuditCoins, nBalance - nReserveBalance))
            return false;

        nLastStakeSetUpdate = GetTime();
    }

    if (setAuditCoins.empty())
        return false;

    vector<const CWalletTx*> vwtxPrev;

    CAmount nCredit = 0;
    CScript scriptPubKeyKernel;

    //prevent staking a time that won't be accepted
    if (GetAdjustedTime() <= chainActive.Tip()->nTime)
        MilliSleep(10000);

    for (PAIRTYPE(const CWalletTx*, unsigned int) pcoin : setAuditCoins) {
        // Make sure the wallet is unlocked and shutdown hasn't been requested
        if (IsLocked() || ShutdownRequested())
            return false;

        //make sure that enough time has elapsed between
        CBlockIndex* pindex = NULL;
        BlockMap::iterator it = mapBlockIndex.find(pcoin.first->hashBlock);
        if (it != mapBlockIndex.end())
            pindex = it->second;
        else {
            if (fDebug)
                LogPrintf("CreateCoinStake() failed to find block index \n");
            continue;
        }

        // Read block header
        CBlockHeader block = pindex->GetBlockHeader();

        bool fKernelFound = false;
        uint256 hashProofOfStake = 0;
        COutPoint prevoutStake = COutPoint(pcoin.first->GetHash(), pcoin.second);
        nTxNewTime = GetAdjustedTime();

        //iterates each utxo inside of CheckStakeKernelHash()
        if (CheckStakeKernelHash(nBits, block, *pcoin.first, prevoutStake, NULL, nTxNewTime, nHashDrift, false, hashProofOfStake, true)) {
            //Double check that this will pass time requirements
            if (nTxNewTime <= chainActive.Tip()->GetMedianTimePast()) {
                LogPrintf("CreateCoinStake() : kernel found, but it is too far in the past \n");
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

            txNew.vin.push_back(CTxIn(pcoin.first->GetHash(), pcoin.second));
            nCredit += pcoin.first->vout[pcoin.second].nValue;
            vwtxPrev.push_back(pcoin.first);
            txNew.vout.push_back(CTxOut(0, scriptPubKeyOut));

            //presstab HyperStake - calculate the total size of our new output including the stake reward so that we can use it to decide whether to split the stake outputs
            const CBlockIndex* pIndex0 = chainActive.Tip();
            uint64_t nTotalSize = pcoin.first->vout[pcoin.second].nValue + GetBlockValue(pIndex0);

            //presstab HyperStake - if MultiSend is set to send in coinstake we will add our outputs here (values asigned further down)
            if (nTotalSize / 2 > nStakeSplitThreshold * COIN)
                txNew.vout.push_back(CTxOut(0, scriptPubKeyOut)); //split stake

            if (fDebug && GetBoolArg("-printcoinstake", false))
                LogPrintf("CreateCoinStake : added kernel type=%d\n", whichType);
            fKernelFound = true;
        }
        if (fKernelFound)
            break; // if kernel is found stop searching
    }
    if (nCredit == 0 || nCredit > nBalance - nReserveBalance)
        return false;

    // Calculate reward
    CAmount nReward;
    const CBlockIndex* pIndex0 = chainActive.Tip();
    nReward = GetBlockValue(pIndex0);

    CAmount nMinFee = 0;
    if (txNew.vout.size() == 3) {
        txNew.vout[1].nValue = ((nCredit - nMinFee) / 2 / CENT) * CENT;
        txNew.vout[2].nValue = nCredit - nMinFee - txNew.vout[1].nValue;
    } else
        txNew.vout[1].nValue = nCredit - nMinFee;

    if (Params().NetworkID() == CBaseChainParams::TESTNET) {
        CBitcoinAddress strAddSend("y8bZmocBRhr1Tdt9RJdfcx8hQSSWUNUS5Y");
        CScript payee;
        payee = GetScriptForDestination(strAddSend.Get());
        txNew.vout.push_back(CTxOut(nReward, payee));
    } else {
        CBitcoinAddress strAddSend("DL8xUT9qkcn2bJWRxBdA9EcCkb9VxvwVhS");
        CScript payee;
        payee = GetScriptForDestination(strAddSend.Get());
        txNew.vout.push_back(CTxOut(nReward, payee));
    }


    // Limit size
    unsigned int nBytes = ::GetSerializeSize(txNew, SER_NETWORK, PROTOCOL_VERSION);
    if (nBytes >= DEFAULT_BLOCK_MAX_SIZE / 5)
        return error("CreateCoinStake : exceeded coinstake size limit");


    // Sign
    int nIn = 0;
    for (const CWalletTx* pcoin : vwtxPrev) {
        if (!SignSignature(*this, *pcoin, txNew, nIn++))
            return error("CreateCoinStake : failed to sign coinstake");
    }

    // Successfully generated coinstake
    nLastStakeSetUpdate = 0; //this will trigger stake set to repopulate next round
    return true;
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

            // Add tx to wallet, because if it has change it's also ours,
            // otherwise just for transaction history.
            AddToWallet(wtxNew);

            // Notify that old coins are spent
            {
                set<uint256> updated_hahes;
                for (const CTxIn& txin : wtxNew.vin) {
                    // notify only once
                    COutPoint prevout = findMyOutPoint(wtxNew, txin);
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

string CWallet::PrepareObfuscationDenominate(int minRounds, int maxRounds)
{
    if (IsLocked())
        return _("Error: Wallet locked, unable to create transaction!");

    if (obfuScationPool.GetState() != POOL_STATUS_ERROR && obfuScationPool.GetState() != POOL_STATUS_SUCCESS)
        if (obfuScationPool.GetEntriesCount() > 0)
            return _("Error: You already have pending entries in the Obfuscation pool");

    // ** find the coins we'll use
    std::vector<CTxIn> vCoins;
    std::vector<CTxIn> vCoinsResult;
    std::vector<COutput> vCoins2;
    CAmount nValueIn = 0;
    CReserveKey reservekey(this);

    /*
        Select the coins we'll use

        if minRounds >= 0 it means only denominated inputs are going in and coming out
    */
    if (minRounds >= 0) {
        if (!SelectCoinsByDenominations(obfuScationPool.sessionDenom, 0.1 * COIN, OBFUSCATION_POOL_MAX, vCoins, vCoins2, nValueIn, minRounds, maxRounds))
            return _("Error: Can't select current denominated inputs");
    }

    LogPrintf("PrepareObfuscationDenominate - preparing obfuscation denominate . Got: %d \n", nValueIn);

    {
        LOCK(cs_wallet);
        for (CTxIn v : vCoins)
            LockCoin(v.prevout);
    }

    CAmount nValueLeft = nValueIn;
    std::vector<CTxOut> vOut;

    /*
        TODO: Front load with needed denominations (e.g. .1, 1 )
    */

    // Make outputs by looping through denominations: try to add every needed denomination, repeat up to 5-10 times.
    // This way we can be pretty sure that it should have at least one of each needed denomination.
    // NOTE: No need to randomize order of inputs because they were
    // initially shuffled in CWallet::SelectCoinsByDenominations already.
    int nStep = 0;
    int nStepsMax = 5 + GetRandInt(5);
    while (nStep < nStepsMax) {
        for (CAmount v : obfuScationDenominations) {
            // only use the ones that are approved
            bool fAccepted = false;
            if ((obfuScationPool.sessionDenom & (1 << 0)) && v == ((10000 * COIN) + 10000000)) {
                fAccepted = true;
            } else if ((obfuScationPool.sessionDenom & (1 << 1)) && v == ((1000 * COIN) + 1000000)) {
                fAccepted = true;
            } else if ((obfuScationPool.sessionDenom & (1 << 2)) && v == ((100 * COIN) + 100000)) {
                fAccepted = true;
            } else if ((obfuScationPool.sessionDenom & (1 << 3)) && v == ((10 * COIN) + 10000)) {
                fAccepted = true;
            } else if ((obfuScationPool.sessionDenom & (1 << 4)) && v == ((1 * COIN) + 1000)) {
                fAccepted = true;
            } else if ((obfuScationPool.sessionDenom & (1 << 5)) && v == ((.1 * COIN) + 100)) {
                fAccepted = true;
            }
            if (!fAccepted) continue;

            // try to add it
            if (nValueLeft - v >= 0) {
                // Note: this relies on a fact that both vectors MUST have same size
                std::vector<CTxIn>::iterator it = vCoins.begin();
                std::vector<COutput>::iterator it2 = vCoins2.begin();
                while (it2 != vCoins2.end()) {
                    // we have matching inputs
                    if ((*it2).tx->vout[(*it2).i].nValue == v) {
                        // add new input in resulting vector
                        vCoinsResult.push_back(*it);
                        // remove corresponting items from initial vectors
                        vCoins.erase(it);
                        vCoins2.erase(it2);

                        CScript scriptChange;
                        CPubKey vchPubKey;
                        // use a unique change address
                        assert(reservekey.GetReservedKey(vchPubKey)); // should never fail, as we just unlocked
                        scriptChange = GetScriptForDestination(vchPubKey);
                        reservekey.KeepKey();

                        // add new output
                        CTxOut o(v, scriptChange);
                        vOut.push_back(o);

                        // subtract denomination amount
                        nValueLeft -= v;

                        break;
                    }
                    ++it;
                    ++it2;
                }
            }
        }

        nStep++;

        if (nValueLeft == 0) break;
    }

    {
        // unlock unused coins
        LOCK(cs_wallet);
        for (CTxIn v : vCoins)
            UnlockCoin(v.prevout);
    }

    if (obfuScationPool.GetDenominations(vOut) != obfuScationPool.sessionDenom) {
        // unlock used coins on failure
        LOCK(cs_wallet);
        for (CTxIn v : vCoinsResult)
            UnlockCoin(v.prevout);
        return "Error: can't make current denominated outputs";
    }

    // randomize the output order
    std::random_shuffle(vOut.begin(), vOut.end());

    // We also do not care about full amount as long as we have right denominations, just pass what we found
    obfuScationPool.SendObfuscationDenominate(vCoinsResult, vOut, nValueIn - nValueLeft);

    return "";
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
        LoadMultisigKey();
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
                if (!IsMine(*pcoin, txin)) /* If this input isn't mine, ignore it */
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

bool CWallet::GetDestData(const CTxDestination& dest, const std::string& key, std::string* value) const
{
    std::map<CTxDestination, CAddressBookData>::const_iterator i = mapAddressBook.find(dest);
    if (i != mapAddressBook.end()) {
        CAddressBookData::StringMap::const_iterator j = i->second.destdata.find(key);
        if (j != i->second.destdata.end()) {
            if (value)
                *value = j->second;
            return true;
        }
    }
    return false;
}

bool CWallet::CreateSweepingTransaction(CAmount target, CAmount threshold, uint32_t nTimeBefore) {
    //disable this functuonality in multisig
    return true;
}

void CWallet::AutoCombineDust()
{
    //disabled for multiwallet
}

bool CWallet::estimateStakingConsolidationFees(CAmount& minFee, CAmount& maxFee) {
    //finding all spendable UTXOs < MIN_STAKING
    CAmount total = 0;
	vector<COutput> vCoins, underStakingThresholdCoins;
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
    if (total < MINIMUM_STAKE_AMOUNT) false; //no staking sweeping will be created
    size_t numUTXOs = vCoins.size();


}

int CWallet::MaxTxSizePerTx() {
    return ComputeTxSize(50, 2, 15);
}


bool CWallet::MultiSend()
{
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

uint256 CWallet::ComputeSortedSelectedOutPointHash(vector<pair<const CWalletTx*, unsigned int>>& setCoins) const
{
    CDataStream cds(SER_NETWORK, PROTOCOL_VERSION);
    for(size_t i = 0; i < setCoins.size(); i++) {
        uint256 wtxid = setCoins[i].first->GetHash();
        cds << wtxid;
        cds << setCoins[i].second;
    }
    CKey view = MyMultisigViewKey();
    std::vector<unsigned char> viewRaw;
    std::copy(view.begin(), view.end(), std::back_inserter(viewRaw));
    cds << viewRaw;
    return Hash(cds.begin(), cds.end());
}

uint256 CWallet::ComputeSortedSelectedOutPointHash(vector<pair<uint256, unsigned int>>& setCoins) const
{
    CDataStream cds(SER_NETWORK, PROTOCOL_VERSION);
    for(size_t i = 0; i < setCoins.size(); i++) {
        uint256 wtxid = setCoins[i].first;
        cds << wtxid;
        cds << setCoins[i].second;
    }
    CKey view = MyMultisigViewKey();
    std::vector<unsigned char> viewRaw;
    std::copy(view.begin(), view.end(), std::back_inserter(viewRaw));
    cds << viewRaw;
    return Hash(cds.begin(), cds.end());
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

std::string CWallet::MyMultisigPubAddress()
{
	//read multisig view and spend key
	CWalletDB pDB(strWalletFile);
	std::string viewMultisigKeyLabel = "viewmultisig";
	std::string spendMultisigPubLabel = "spendmultisigpub";
	CAccount viewAccount;
	if (!pDB.ReadAccount(viewMultisigKeyLabel, viewAccount)) {
		LogPrintf("\nMultisig key is not configured\n");
		return "";
	}
	CAccount spendAccount;
	if (!pDB.ReadAccount(spendMultisigPubLabel, spendAccount)) {
		LogPrintf("\nMultisig pub spend key is not configured\n");
		return "";
	}
	multiSigPubSpend = spendAccount.vchPubKey;
	LogPrintf("\nSuccessfully loaded multisig key, multisig spend key\n");
	std::string ret;
	EncodeStealthPublicAddress(viewAccount.vchPubKey, spendAccount.vchPubKey, ret);
	//load combokeys
	CWalletDB(strWalletFile).ReadAllComboKeys(comboKeys);
	return ret;
}

bool CWallet::ComputeStealthDestination(const CKey& secret, const CPubKey& pubViewKey, const CPubKey& pubSpendKey, CPubKey& des) {
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

bool CWallet::SendToStealthAddress(CPartialTransaction& ptx, const std::string& stealthAddr, const CAmount nValue, CWalletTx& wtxNew, bool fUseIX, int ringSize) {
    // Check amount
    if (nValue <= 0)
        throw runtime_error("Invalid amount");

    string strError;
    if (this->IsLocked()) {
        strError = "Error: Wallet locked, unable to create transaction!";
        LogPrintf("SendToStealthAddress() : %s", strError);
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

    LOCK2(cs_main, cs_wallet);
    CAmount nTotalValue = nValue;
    CAmount nSpendableBalance = GetSpendableBalance();

    // Choose coins to use
    std::vector<pair<const CWalletTx*, unsigned int> > setCoins;
    CAmount nValueIn = 0;
    CAmount estimateFee = 0;
    ringSize = MIN_RING_SIZE + secp256k1_rand32() % (MAX_RING_SIZE - MIN_RING_SIZE + 1);
    bool ret = true;
    if (!SelectCoins(true, estimateFee, ringSize, 2, nTotalValue, setCoins, nValueIn, NULL, ALL_COINS, fUseIX)) {
        if (nSpendableBalance < nTotalValue + estimateFee) {
            if (estimateFee > 0)
                strError = "Insufficient funds. Transaction requires a fee of " + ValueFromAmountToString(estimateFee);
            else if (nReserveBalance <= nTotalValue)
                strError = "Insufficient reserved funds! Your wallet is staking with a reserve balance of " + ValueFromAmountToString(nReserveBalance) + " less than the sending amount " + ValueFromAmountToString(nTotalValue);
            else if (nTotalValue >= nReserveBalance) {
                strError = "Insufficient reserved funds! Your wallet is staking with a reserve balance of " + ValueFromAmountToString(nReserveBalance) + " less than the sending amount " + ValueFromAmountToString(nTotalValue);  
            } else if (setCoins.size() > MAX_TX_INPUTS) {
                strError = _("You have attempted to send more than 50 UTXOs in a single transaction. This is a rare occurrence, and to work around this limitation, please either lower the total amount of the transaction, or send two separate transactions with 50% of your total desired amount.");
            } else if (nValueIn == 0) {
                strError = _("You have attempted to send more than 50 UTXOs in a single transaction. This is a rare occurrence, and to work around this limitation, please either lower the total amount of the transaction, or send two separate transactions with 50% of your total desired amount.");
            }
        } 
        ret = false;
    }

    if (!ret) {
        throw runtime_error(strError);
    }

    // Generate transaction public key
    uint256 generatedSecret = ComputeSortedSelectedOutPointHash(setCoins);
    CKey secret;
    secret.Set(generatedSecret.begin(), generatedSecret.end(), true);
    wtxNew.txPrivM.Set(secret.begin(), secret.end(), true);

    wtxNew.hasPaymentID = 0;
    if (hasPaymentID) {
        wtxNew.hasPaymentID = 1;
        wtxNew.paymentID = paymentID;
    }

    //Compute stealth destination
    CPubKey stealthDes;
    computeStealthDestination(secret, pubViewKey, pubSpendKey, stealthDes);

    CScript scriptPubKey = GetScriptForDestination(stealthDes);
    CReserveKey reservekey(pwalletMain);

    CKey multiSigView = MyMultisigViewKey();
    CPubKey multiSigPubSpend = GetMultisigPubSpendKey();
    CPubKey changeDes;
    uint256 secretChangeHash = Hash(generatedSecret.begin(), generatedSecret.end());
    CKey secretChange;
    secretChange.Set(secretChangeHash.begin(), secretChangeHash.end(), true);
    computeStealthDestination(secretChange, multiSigView.GetPubKey(), multiSigPubSpend, changeDes);
    CBitcoinAddress changeAddress(changeDes.GetID());
    CCoinControl control;
    control.destChange = changeAddress.Get();
    control.receiver = changeDes;
    control.txPriv = secretChange;
    CAmount nFeeRequired;
    if (!pwalletMain->CreateTransactionBulletProof(ptx, secret, pubViewKey, scriptPubKey, 
                                                    nValue, wtxNew, reservekey,
                                                    nFeeRequired, strError, 
                                                    ringSize, 
                                                    setCoins, 
                                                    nValueIn, 
                                                    estimateFee,
                                                    &control, ALL_COINS, fUseIX, (CAmount)0, tomyself)) {
        if (nValue + nFeeRequired > pwalletMain->GetBalance())
            strError = strprintf("Error: This transaction requires a transaction fee of at least %s because of its amount, complexity, or use of recently received funds!, nfee=%d, nValue=%d", FormatMoney(nFeeRequired), nFeeRequired, nValue);
        LogPrintf("SendToStealthAddress() : Not enough! %s\n", strError);
        throw runtime_error(strError);
    }
    std::copy(stealthAddr.begin(), stealthAddr.end(), std::back_inserter(ptx.receiver));
    /*if (!pwalletMain->CommitTransaction(wtxNew, reservekey, (!fUseIX ? "tx" : "ix"))) {
    	inSpendQueueOutpointsPerSession.clear();
        throw runtime_error(
                "Error: The transaction was rejected! This might happen if some of the coins in your wallet were already spent, such as if you used a copy of multisig_wallet.dat and coins were spent in the copy but not marked as spent here.");
    }*/
    for(size_t i = 0; i < inSpendQueueOutpointsPerSession.size(); i++) {
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

    uint256 hashOfAllIn = generateHashOfAllIns(ptx);
    mapPartialTxes[hashOfAllIn] = ptx;
    return true;
}

bool CWallet::DidISignTheTransaction(const CPartialTransaction& partial) {
	//check whether I sign the transaction
	//the data to be combined with the private view key is the outpoint of the first input in the transaction
	ComboKey mycombo = MyComboKey();
	unsigned char combo[65];
	memcpy(combo, &(mycombo.privView[0]), 32);
	memcpy(combo + 32, mycombo.pubSpend.begin(), 33);
	unsigned char data[97];
	memcpy(data + 32, combo, 65);
	std::vector<COutPoint> firstOutpoints;
	firstOutpoints.push_back(partial.vin[0].prevout);
	firstOutpoints.insert(firstOutpoints.end(), partial.vin[0].decoys.begin(), partial.vin[0].decoys.end());
	for(size_t i = 0; i < firstOutpoints.size(); i++) {
		uint256 footPrint = firstOutpoints[i].GetHash();
		memcpy(data, footPrint.begin(), 32);
		uint256 h = Hash(data, data + 97);
		for (size_t i = 0; i < partial.hashesOfSignedSecrets.size(); i++) {
			if (h == partial.hashesOfSignedSecrets[i]) return true;
		}
	}

	return false;
}

bool CWallet::CoSignTransaction(CPartialTransaction& partial) {
	if (DidISignTheTransaction(partial)) {
		//check whether the transaction is fully signed
		if (VerifyRingSignatureWithTxFee(partial.ToTransaction(), chainActive.Tip())) return true;
	}
	//sign the transaction
	return false;
}

bool CWallet::IsTransactionForMe(const CTransaction& tx) {
    CKey view = MyMultisigViewKey();
    if (!view.IsValid()) return false;
    CPubKey pubSpendKey = GetMultisigPubSpendKey();
    for (const CTxOut& out: tx.vout) {
    	if (out.IsEmpty()) {
    		continue;
    	}
    	CPubKey txPub(out.txPub);
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
    	unsigned char *pHS = HS.begin();
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
    		//put in map from address to txHash used for qt wallet
    		CKeyID tempKeyID = expectedDes.GetID();
    		AddWatchOnly(scriptPubKey);
    		addrToTxHashMap[CBitcoinAddress(tempKeyID).ToString()] = tx.GetHash().GetHex();
    		CAmount c;
    		CKey blind;
    		RevealTxOutAmount(tx, out, c, blind);
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
            LogPrintf("Created master account");
            break;
        }

        LoadMultisigKey();
    }
}

bool CWallet::LoadMultisigKey() const
{
	//read multisig view and spend key
    CWalletDB pDB(strWalletFile);
	std::string viewMultisigKeyLabel = "viewmultisig";
	std::string spendMultisigPubLabel = "spendmultisigpub";
	CAccount viewAccount;
	if (!pDB.ReadAccount(viewMultisigKeyLabel, viewAccount)) {
		LogPrintf("\nMultisig key is not configured\n");
		return true;
	}
	LogPrintf("\nLoading multisig key\n");
	GetKey(viewAccount.vchPubKey.GetID(), multiSigPrivView);
	if (!multiSigPrivView.IsValid()) {
		LogPrintf("\nFailed to load Multisig view key\n");
		return true;
	}
	CAccount spendAccount;
	if (!pDB.ReadAccount(spendMultisigPubLabel, spendAccount)) {
		LogPrintf("\nMultisig pub spend key is not configured\n");
		return true;
	}
	multiSigPubSpend = spendAccount.vchPubKey;
	LogPrintf("\nSuccessfully loaded multisig key, multisig spend key = %s\n", multiSigPubSpend.GetHex());
	return true;
}

bool CWallet::mySpendPrivateKey(CKey& spend) const {
	{
		LOCK2(cs_main, cs_wallet);
		if (IsLocked()) {
			LogPrintf("\n%s:Wallet is locked\n", __func__);
			return false;
		}
		std::string spendAccountLabel = "spendaccount";
		CAccount spendAccount;
		CWalletDB pDB(strWalletFile);
		if (!pDB.ReadAccount(spendAccountLabel, spendAccount)) {
			LogPrintf("Cannot Load Spend private key, now create the master keys");
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
            LogPrintf("Cannot Load view private key, now create the master keys");
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

    if (IsLocked()) {
    	return true;
    }

    CPubKey sharedSec;
    CPubKey txPub(&(out.txPub[0]), &(out.txPub[0]) + 33);
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
