// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2013 The Bitcoin developers
// Copyright (c) 2015-2018 The PIVX developers
// Copyright (c) 2018-2019 The DAPS Project developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLETDB_H
#define BITCOIN_WALLETDB_H

#include "amount.h"
#include "db.h"
#include "key.h"
#include "keystore.h"

#include <list>
#include <stdint.h>
#include <string>
#include <utility>
#include <vector>
#include "bignum.h"

class CAccount;
class CStealthAccount;
class CAccountingEntry;
struct CBlockLocator;
class CKeyPool;
class CMasterKey;
class CScript;
class CWallet;
class CWalletTx;
struct CPartialTransaction;
class uint160;
class uint256;

/** Error statuses for the wallet database */
enum DBErrors {
    DB_LOAD_OK,
    DB_CORRUPT,
    DB_NONCRITICAL_ERROR,
    DB_TOO_NEW,
    DB_LOAD_FAIL,
    DB_NEED_REWRITE
};

class CKeyMetadata
{
public:
    static const int CURRENT_VERSION = 1;
    int nVersion;
    int64_t nCreateTime; // 0 means unknown

    CKeyMetadata()
    {
        SetNull();
    }
    CKeyMetadata(int64_t nCreateTime_)
    {
        nVersion = CKeyMetadata::CURRENT_VERSION;
        nCreateTime = nCreateTime_;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        READWRITE(this->nVersion);
        nVersion = this->nVersion;
        READWRITE(nCreateTime);
    }

    void SetNull()
    {
        nVersion = CKeyMetadata::CURRENT_VERSION;
        nCreateTime = 0;
    }
};

/** Access to the wallet database (multisig_wallet.dat) */
class CWalletDB : public CDB
{
public:
    CWalletDB(const std::string& strFilename, const char* pszMode = "r+") : CDB(strFilename, pszMode)
    {
    }

    bool WriteName(const std::string& strAddress, const std::string& strName);
    bool EraseName(const std::string& strAddress);

    bool WritePurpose(const std::string& strAddress, const std::string& purpose);
    bool ErasePurpose(const std::string& strAddress);

    bool WriteTx(uint256 hash, const CWalletTx& wtx);
    bool EraseTx(uint256 hash);

    bool WriteStakingStatus(bool status);
    bool ReadStakingStatus();

    bool WriteNumSigners(int numSigners);

    int ReadNumSigners();
    void WriteScreenIndex(int index);

    int ReadScreenIndex();
    
    bool Write2FA(bool status);
    bool Read2FA();

    bool Write2FASecret(std::string secret);
    std::string Read2FASecret();

    bool Write2FAPeriod(int period);
    int Read2FAPeriod();
    
    bool Write2FALastTime(uint64_t lastTime);
    uint64_t Read2FALastTime();

    bool WriteScannedBlockHeight(int height);
    bool ReadScannedBlockHeight(int& height);

    bool WriteReserveAmount(const double &amount);
    bool ReadReserveAmount(double &amount);

    bool WriteTxPrivateKey(const std::string& outpointKey, const std::string& k);
    bool ReadTxPrivateKey(const std::string& outpointKey, std::string& k);

    bool WriteKeyImage(const std::string& outpointKey, const CKeyImage& k);
    bool ReadKeyImage(const std::string& outpointKey, CKeyImage& k);

    bool WriteHasWaitingTx(const bool hasWaitingTx);
    bool ReadHasWaitingTx();
    bool WritePendingForSigningTx(const CPartialTransaction& ptx);
    bool ReadPendingForSigningTx(CPartialTransaction& ptx);

    bool WriteKey(const CPubKey& vchPubKey, const CPrivKey& vchPrivKey, const CKeyMetadata& keyMeta);
    bool WriteCryptedKey(const CPubKey& vchPubKey, const std::vector<unsigned char>& vchCryptedSecret, const CKeyMetadata& keyMeta);
    bool WriteMasterKey(unsigned int nID, const CMasterKey& kMasterKey);

    bool WriteCScript(const uint160& hash, const CScript& redeemScript);

    bool WriteWatchOnly(const CScript& script);
    bool EraseWatchOnly(const CScript& script);

    bool WriteMultiSig(const CScript& script);
    bool EraseMultiSig(const CScript& script);

    bool WriteBestBlock(const CBlockLocator& locator);
    bool ReadBestBlock(CBlockLocator& locator);
    bool WriteComboKeys(const ComboKeyList& combo);
    bool ReadAllComboKeys(ComboKeyList& comboData);

    bool WriteOrderPosNext(int64_t nOrderPosNext);

    // presstab
    bool WriteStakeSplitThreshold(uint64_t nStakeSplitThreshold);
    bool WriteMultiSend(std::vector<std::pair<std::string, int> > vMultiSend);
    bool EraseMultiSend(std::vector<std::pair<std::string, int> > vMultiSend);
    bool WriteMSettings(bool fMultiSendStake, bool fMultiSendMasternode, int nLastMultiSendHeight);
    bool WriteMSDisabledAddresses(std::vector<std::string> vDisabledAddresses);
    bool EraseMSDisabledAddresses(std::vector<std::string> vDisabledAddresses);
    bool WriteAutoCombineSettings(bool fEnable, CAmount nCombineThreshold);

    bool WriteDefaultKey(const CPubKey& vchPubKey);

    bool ReadPool(int64_t nPool, CKeyPool& keypool);
    bool WritePool(int64_t nPool, const CKeyPool& keypool);
    bool ErasePool(int64_t nPool);

    bool WriteMinVersion(int nVersion);

    /// This writes directly to the database, and will not update the CWallet's cached accounting entries!
    /// Use wallet.AddAccountingEntry instead, to write *and* update its caches.
    bool WriteAccountingEntry_Backend(const CAccountingEntry& acentry);

    bool ReadAccount(const std::string& strAccount, CAccount& account);
    bool WriteAccount(const std::string& strAccount, const CAccount& account);

    bool WriteAutoConsolidateSettingTime(uint32_t settingTime);
    uint32_t ReadAutoConsolidateSettingTime();

    bool ReadStealthAccount(const std::string& strAccount, CStealthAccount& account);
    bool WriteStealthAccount(const std::string& strAccount, const CStealthAccount& account);

    /// Write destination data key,value tuple to database
    bool WriteDestData(const std::string& address, const std::string& key, const std::string& value);
    /// Erase destination data tuple from wallet database
    bool EraseDestData(const std::string& address, const std::string& key);
    bool WriteHDChain(const CHDChain& chain);
    bool WriteCryptedHDChain(const CHDChain& chain);
    bool WriteHDPubKey(const CHDPubKey& hdPubKey, const CKeyMetadata& keyMeta);

    CAmount GetAccountCreditDebit(const std::string& strAccount);
    void ListAccountCreditDebit(const std::string& strAccount, std::list<CAccountingEntry>& acentries);

    DBErrors ReorderTransactions(CWallet* pwallet);
    DBErrors LoadWallet(CWallet* pwallet);
    DBErrors FindWalletTx(CWallet* pwallet, std::vector<uint256>& vTxHash, std::vector<CWalletTx>& vWtx);
    DBErrors ZapWalletTx(CWallet* pwallet, std::vector<CWalletTx>& vWtx);
    static bool Recover(CDBEnv& dbenv, std::string filename, bool fOnlyKeys);
    static bool Recover(CDBEnv& dbenv, std::string filename);
    std::list<CBigNum> ListMintedCoinsSerial();
    std::list<CBigNum> ListSpentCoinsSerial();

    bool AppendStealthAccountList(const std::string& accountName);
    bool ReadStealthAccountList(std::string& accountList);
private:
    CWalletDB(const CWalletDB&);
    void operator=(const CWalletDB&);

    bool WriteAccountingEntry(const uint64_t nAccEntryNum, const CAccountingEntry& acentry);
};

bool BackupWallet(const CWallet& wallet, const std::string& strDest);

#endif // BITCOIN_WALLETDB_H
