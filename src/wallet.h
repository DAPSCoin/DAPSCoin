// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2018 The PIVX developers
// Copyright (c) 2018-2019 The DAPS Project developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_H
#define BITCOIN_WALLET_H

#include "amount.h"
#include "base58.h"
#include "crypter.h"
#include "kernel.h"
#include "key.h"
#include "keystore.h"
#include "main.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "ui_interface.h"
#include "util.h"
#include "validationinterface.h"
#include "wallet_ismine.h"
#include "walletdb.h"

#include <algorithm>
#include <map>
#include <set>
#include <stdexcept>
#include <stdint.h>
#include <string>
#include <utility>
#include <vector>


#include <memory>

#include <boost/program_options/options_description.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/serialization/list.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/serialization/deque.hpp>
#include <atomic>



/**
 * Settings
 */
extern CFeeRate payTxFee;
extern CAmount maxTxFee;
extern unsigned int nTxConfirmTarget;
extern bool bSpendZeroConfChange;
extern bool bdisableSystemnotifications;
extern bool fSendFreeTransactions;
extern bool fPayAtLeastCustomFee;

//! -paytxfee default
static const CAmount DEFAULT_TRANSACTION_FEE = 0.1 * COIN;//
//! -paytxfee will warn if called with a higher fee than this amount (in satoshis) per KB
static const CAmount nHighTransactionFeeWarning = 0.1 * COIN;
//! -maxtxfee default
static const CAmount DEFAULT_TRANSACTION_MAXFEE = 1 * COIN;
//! -maxtxfee will warn if called with a higher fee than this amount (in satoshis)
static const CAmount nHighTransactionMaxFeeWarning = 100 * nHighTransactionFeeWarning;
//! Largest (in bytes) free transaction we're willing to create
static const unsigned int MAX_FREE_TRANSACTION_CREATE_SIZE = 1000;

// 6666 = 1*5000 + 1*1000 + 1*500 + 1*100 + 1*50 + 1*10 + 1*5 + 1
static const int ZQ_6666 = 6666;

class CAccountingEntry;
class CCoinControl;
class COutput;
class CReserveKey;
class CScript;
class CWalletTx;

/** (client) version numbers for particular wallet features */
enum WalletFeature {
    FEATURE_BASE = 10500, // the earliest version new wallets supports (only useful for getinfo's clientversion output)

    FEATURE_WALLETCRYPT = 40000, // wallet encryption
    FEATURE_COMPRPUBKEY = 60000, // compressed public keys

    FEATURE_LATEST = 61000
};

enum AvailableCoinsType {
    ALL_COINS = 1,
    ONLY_DENOMINATED = 2,
    ONLY_NOT1000000IFMN = 3,
    ONLY_NONDENOMINATED_NOT1000000IFMN = 4, // ONLY_NONDENOMINATED and not 1000000 DAPS at the same time
    ONLY_1000000 = 5,                        // find masternode outputs including locked ones (use with caution)
    STAKABLE_COINS = 6                          // UTXO's that are valid for staking
};

struct CompactTallyItem {
    CBitcoinAddress address;
    CAmount nAmount;
    std::vector<CTxIn> vecTxIn;
    CompactTallyItem()
    {
        nAmount = 0;
    }
};

/** A key pool entry */
class CKeyPool
{
public:
    int64_t nTime;
    CPubKey vchPubKey;

    CKeyPool();
    CKeyPool(const CPubKey& vchPubKeyIn);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        if (!(nType & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(nTime);
        READWRITE(vchPubKey);
    }
};

/** Address book data */
class CAddressBookData
{
public:
    std::string name;
    std::string purpose;

    CAddressBookData()
    {
        purpose = "unknown";
    }

    typedef std::map<std::string, std::string> StringMap;
    StringMap destdata;
};

/**
 * Account information.
 * Stored in wallet with key "acc"+string account name.
 */
class CAccount
{
public:
    CPubKey vchPubKey;
    uint32_t nAccountIndex;

    CAccount()
    {
        SetNull();
    }

    void SetNull()
    {
        vchPubKey = CPubKey();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        if (!(nType & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(vchPubKey);
        READWRITE(nAccountIndex);
    }
};

class CStealthAccount
{
public:
    CAccount spendAccount;
    CAccount viewAccount;

    CStealthAccount()
    {
        SetNull();
    }

    void SetNull()
    {
        spendAccount.SetNull();
        viewAccount.SetNull();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        READWRITE(spendAccount);
        READWRITE(viewAccount);
    }
};

typedef enum MultiSigType {
	FULL_N_N = 0,
	PARTIAL_N_1_N
};

class MultisigWallet {
public:
	static CKey computePrivateViewKey(std::vector<CKey> privView);
};

struct CPKeyImageAlpha {
	uint256 outPointHash;
	CPubKey LIJ;
	CPubKey RIJ;
	CKeyImage ki;
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        READWRITE(outPointHash);
        READWRITE(LIJ);
        READWRITE(RIJ);
        READWRITE(ki);
    }
};

enum StakingStatusError
{
    STAKING_OK, //use case B, C, D, no consolidation needed, 
    UNSTAKABLE_BALANCE_TOO_LOW, //coin is not mature yet (balance > 400k)
    UNSTAKABLE_BALANCE_TOO_LOW_CONSOLIDATION_FAILED, //coin is not mature yet (balance > 400k)
    UNSTAKABLE_BALANCE_RESERVE_TOO_HIGH,
    UNSTAKABLE_BALANCE_RESERVE_TOO_HIGH_CONSOLIDATION_FAILED, //even consolidation does not help
    STAKABLE_NEED_CONSOLIDATION,   //stable and consolidation, needs to estimate fees
    STAKABLE_NEED_CONSOLIDATION_WITH_RESERVE_BALANCE  //stable and consolidation, needs to estimate fees
};

enum StakingMode {
	STOPPED, //staking disabled or balance < 400k
	STAKING_WITHOUT_CONSOLIDATION,
	STAKING_WITH_CONSOLIDATION,
	STAKING_WITH_CONSOLIDATION_WITH_STAKING_NEWW_FUNDS
};

//each signer after receive transaction from the initiator, will need to create this and send it back to the initiator
struct CListPKeyImageAlpha {
	std::vector<CPKeyImageAlpha> partialAlphas;
	CKeyImage partialAdditionalKeyImage;
	uint256 hashOfAllInputOutpoints;
	ADD_SERIALIZE_METHODS;
	template <typename Stream, typename Operation>
	inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
	{
		READWRITE(partialAlphas);
		READWRITE(partialAdditionalKeyImage);
		READWRITE(hashOfAllInputOutpoints);
	}

	CListPKeyImageAlpha() {
		hashOfAllInputOutpoints.SetNull();
	}
};

/**
 * A CWallet is an extension of a keystore, which also maintains a set of transactions and balances,
 * and provides the ability to create new transactions.
 */
class CWallet : public CCryptoKeyStore, public CValidationInterface
{
private:
    bool SelectCoins(bool needFee, CAmount& estimatedFee, int ringSize, int numOut, const CAmount& nTargetValue, std::vector<std::pair<const CWalletTx*, unsigned int> >& setCoinsRet, CAmount& nValueRet, const CCoinControl* coinControl = NULL, AvailableCoinsType coin_type = ALL_COINS, bool useIX = true) ;
    //it was public bool SelectCoins(int64_t nTargetValue, std::set<std::pair<const CWalletTx*,unsigned int> >& setCoinsRet, int64_t& nValueRet, const CCoinControl *coinControl = NULL, AvailableCoinsType coin_type=ALL_COINS, bool useIX = true) const;

    CWalletDB* pwalletdbEncryption;

    //! the current wallet version: clients below this version are not able to load the wallet
    int nWalletVersion;

    //! the maximum wallet format version: memory-only variable that specifies to what version this wallet may be upgraded
    int nWalletMaxVersion;

    int64_t nNextResend;
    int64_t nLastResend;

    /**
     * Used to keep track of spent outpoints, and
     * detect and report conflicts (double-spends or
     * mutated transactions where the mutant gets mined).
     */
    typedef std::multimap<COutPoint, uint256> TxSpends;
    TxSpends mapTxSpends;
    void AddToSpends(const COutPoint& outpoint, const uint256& wtxid);
    void AddToSpends(const uint256& wtxid);

    void SyncMetaData(std::pair<TxSpends::iterator, TxSpends::iterator>);
    void GenerateAlphaFromOutpoint(const COutPoint& op, unsigned char*) const;

public:
    static const CAmount MINIMUM_STAKE_AMOUNT = 400000 * COIN;
    static const int32_t MAX_DECOY_POOL = 500;
    static const int32_t PROBABILITY_NEW_COIN_SELECTED = 70;
    bool RescanAfterUnlock(int fromHeight);
    bool MintableCoins();
    bool SelectStakeCoins(std::set<std::pair<const CWalletTx*, unsigned int> >& setCoins, CAmount nTargetAmount) ;
    bool SelectCoinsDark(CAmount nValueMin, CAmount nValueMax, std::vector<CTxIn>& setCoinsRet, CAmount& nValueRet, int nObfuscationRoundsMin, int nObfuscationRoundsMax) ;
    bool SelectCoinsByDenominations(int nDenom, CAmount nValueMin, CAmount nValueMax, std::vector<CTxIn>& vCoinsRet, std::vector<COutput>& vCoinsRet2, CAmount& nValueRet, int nObfuscationRoundsMin, int nObfuscationRoundsMax);
    bool SelectCoinsDarkDenominated(CAmount nTargetValue, std::vector<CTxIn>& setCoinsRet, CAmount& nValueRet) ;
    bool HasCollateralInputs(bool fOnlyConfirmed = true);
    bool IsCollateralAmount(CAmount nInputAmount) const;
    bool IsMasternodeController();
    int CountInputsWithAmount(CAmount nInputAmount);
    bool checkPassPhraseRule(const char *pass);
    COutPoint findMyOutPoint(const CTransaction& tx, const CTxIn& txin) const;
    bool SelectCoinsCollateral(std::vector<CTxIn>& setCoinsRet, CAmount& nValueRet);
    static int ComputeTxSize(size_t numIn, size_t numOut, size_t ringSize);
    void resetPendingOutPoints();
    bool estimateStakingConsolidationFees(CAmount& min, CAmount& max);
    static int MaxTxSizePerTx();
    std::string GetTransactionType(const CTransaction& tx);
    bool WriteAutoConsolidateSettingTime(uint32_t settingTime);
    uint32_t ReadAutoConsolidateSettingTime();
    bool IsAutoConsolidateOn();
    /*
     * Main wallet lock.
     * This lock protects all the fields added by CWallet
     *   except for:
     *      fFileBacked (immutable after instantiation)
     *      strWalletFile (immutable after instantiation)
     */
    mutable CCriticalSection cs_wallet;

    bool fFileBacked;
    bool fWalletUnlockAnonymizeOnly;
    std::string strWalletFile;
    bool fBackupMints;

    std::set<int64_t> setKeyPool;
    std::map<CKeyID, CKeyMetadata> mapKeyMetadata;

    typedef std::map<unsigned int, CMasterKey> MasterKeyMap;
    MasterKeyMap mapMasterKeys;
    unsigned int nMasterKeyMaxID;

    // Stake Settings
    unsigned int nHashDrift;
    unsigned int nHashInterval;
    uint64_t nStakeSplitThreshold;
    int nStakeSetUpdateTime;
    int walletUnlockCountStatus = 0;

    //MultiSend
    std::vector<std::pair<std::string, int> > vMultiSend;
    bool fMultiSendStake;
    bool fMultiSendMasternodeReward;
    bool fMultiSendNotify;
    std::string strMultiSendChangeAddress;
    int nLastMultiSendHeight;
    std::vector<std::string> vDisabledAddresses;

    //Auto Combine Inputs
    bool fCombineDust;
    CAmount nAutoCombineThreshold;
    bool CreateSweepingTransaction(CAmount target, CAmount threshold, uint32_t nTimeBefore);
    bool SendAll(std::string des);
    CWallet()
    {
        SetNull();
    }

    CWallet(std::string strWalletFileIn)
    {
        SetNull();

        strWalletFile = strWalletFileIn;
        fFileBacked = true;
    }

    ~CWallet()
    {
        delete pwalletdbEncryption;
    }

    void SetNull()
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
        fCombineDust = false;
        nAutoCombineThreshold = 540 * COIN;
    }

    bool isMultiSendEnabled()
    {
        return fMultiSendMasternodeReward || fMultiSendStake;
    }

    void setMultiSendDisabled()
    {
        fMultiSendMasternodeReward = false;
        fMultiSendStake = false;
    }

    mutable std::map<uint256, CWalletTx> mapWallet;
    mutable std::map<uint256, int> myIndexMap;  //-1 => prevout, -2 means tx not from me
    mutable std::map<uint256, CPartialTransaction> mapPartialTxes;
    std::list<CAccountingEntry> laccentries;

    typedef std::pair<CWalletTx*, CAccountingEntry*> TxPair;
    typedef std::multimap<int64_t, TxPair > TxItems;
    TxItems wtxOrdered;

    int64_t nOrderPosNext;
    std::map<uint256, int> mapRequestCount;

    std::map<CTxDestination, CAddressBookData> mapAddressBook;
    std::map<std::string, std::string> addrToTxHashMap;
    std::vector<CKey> txPrivKeys;	//only for temporary storing tx private keys for user transactions, dont care staking transactions

    CPubKey vchDefaultKey;

    std::set<COutPoint> setLockedCoins;
    bool walletStakingInProgress;
    std::map<CKeyID, CHDPubKey> mapHdPubKeys; //<! memory map of HD extended pubkeys

    mutable ComboKeyList comboKeys;
    mutable CKey multiSigPrivView;
    mutable CPubKey multiSigPubSpend;
    mutable std::map<CScript, CKeyImage> myPartialKeyImages;
    mutable std::map<CScript, std::vector<CKeyImage>> otherPartialKeyImages;
    bool isMultisigSetupFinished = false;

    int64_t nTimeFirstKey;

    StakingMode stakingMode = STOPPED;
    int64_t DecoyConfirmationMinimum = 15;

    mutable std::map<std::string, CKeyImage> outpointToKeyImages;
    std::map<std::string, bool> keyImagesSpends;
    std::map<std::string, std::string> keyImageMap;//mapping from: txhashHex-n to key image str, n = index
    std::list<std::string> pendingKeyImages;
    std::map<COutPoint, bool> inSpendQueueOutpoints;
    std::vector<COutPoint> inSpendQueueOutpointsPerSession;
    mutable std::map<CScript, CAmount> amountMap;
    mutable std::map<CScript, CKey> blindMap;
    mutable std::map<COutPoint, uint256> userDecoysPool;	//used in transaction spending user transaction
    mutable std::map<COutPoint, uint256> coinbaseDecoysPool; //used in transction spending coinbase

    CAmount dirtyCachedBalance = 0;

    const CWalletTx* GetWalletTx(const uint256& hash) const;

    //! check whether we are allowed to upgrade (or already support) to the named feature
    bool CanSupportFeature(enum WalletFeature wf)
    {
        AssertLockHeld(cs_wallet);
        return nWalletMaxVersion >= wf;
    }

    bool generateKeyImage(const CPubKey& pub, CKeyImage& img) const;
    bool generateKeyImage(const CScript& scriptKey, CKeyImage& img) const;

    void AvailableCoins(std::vector<COutput>& vCoins, bool fOnlyConfirmed = true, const CCoinControl* coinControl = NULL, bool fIncludeZeroValue = false, AvailableCoinsType nCoinType = ALL_COINS, bool fUseIX = false);
    std::map<CBitcoinAddress, std::vector<COutput> > AvailableCoinsByAddress(bool fConfirmed = true, CAmount maxCoinValue = 0);
    bool SelectCoinsMinConf(bool needFee, CAmount& estimatedFee, int ringSize, int numOut, const CAmount& nTargetValue, int nConfMine, int nConfTheirs, std::vector<COutput> vCoins, std::vector<std::pair<const CWalletTx*, unsigned int> >& setCoinsRet, CAmount& nValueRet);

    /// Get 1000DASH output and keys which can be used for the Masternode
    bool GetMasternodeVinAndKeys(CTxIn& txinRet, CPubKey& pubKeyRet, CKey& keyRet, std::string strTxHash = "", std::string strOutputIndex = "");
    /// Extract txin information and keys from output
    bool GetVinAndKeysFromOutput(COutput out, CTxIn& txinRet, CPubKey& pubKeyRet, CKey& keyRet);

    bool IsSpent(const uint256& hash, unsigned int n);

    bool IsLockedCoin(uint256 hash, unsigned int n) const;
    void LockCoin(COutPoint& output);
    void UnlockCoin(COutPoint& output);
    void UnlockAllCoins();
    void ListLockedCoins(std::vector<COutPoint>& vOutpts);

    //  keystore implementation
    // Generate a new key
    CPubKey GenerateNewKey();
    void DeriveNewChildKey(uint32_t nAccountIndex, CKey& secretRet);
    void GenerateNewHDChain(std::string* phrase = NULL);
     /* Set the HD chain model (chain child index counters) */
    bool SetHDChain(const CHDChain& chain, bool memonly);
    bool SetCryptedHDChain(const CHDChain& chain, bool memonly);
    bool GetDecryptedHDChain(CHDChain& hdChainRet);
    bool IsHDEnabled();
    bool HaveKey(const CKeyID &address) const;
    //! GetPubKey implementation that also checks the mapHdPubKeys
    bool GetPubKey(const CKeyID &address, CPubKey& vchPubKeyOut) const;
    //! GetKey implementation that can derive a HD private key on the fly
    bool GetKey(const CKeyID &address, CKey& keyOut) const;
    //! Adds a HDPubKey into the wallet(database)
    bool AddHDPubKey(const CExtPubKey &extPubKey, bool fInternal, uint32_t nAccountIndex);
    //! loads a HDPubKey into the wallets memory
    bool LoadHDPubKey(const CHDPubKey &hdPubKey);
    //! Adds a key to the store, and saves it to disk.
    bool AddKeyPubKey(const CKey& key, const CPubKey& pubkey);
    //! Adds a key to the store, without saving it to disk (used by LoadWallet)
    bool LoadKey(const CKey& key, const CPubKey& pubkey) { return CCryptoKeyStore::AddKeyPubKey(key, pubkey); }
    //! Load metadata (used by LoadWallet)
    bool LoadKeyMetadata(const CPubKey& pubkey, const CKeyMetadata& metadata);

    bool LoadMinVersion(int nVersion)
    {
        AssertLockHeld(cs_wallet);
        nWalletVersion = nVersion;
        nWalletMaxVersion = std::max(nWalletMaxVersion, nVersion);
        return true;
    }

    //! Adds an encrypted key to the store, and saves it to disk.
    bool AddCryptedKey(const CPubKey& vchPubKey, const std::vector<unsigned char>& vchCryptedSecret);
    //! Adds an encrypted key to the store, without saving it to disk (used by LoadWallet)
    bool LoadCryptedKey(const CPubKey& vchPubKey, const std::vector<unsigned char>& vchCryptedSecret);
    bool AddCScript(const CScript& redeemScript);
    bool LoadCScript(const CScript& redeemScript);

    //! Adds a destination data tuple to the store, and saves it to disk
    bool AddDestData(const CTxDestination& dest, const std::string& key, const std::string& value);
    //! Erases a destination data tuple in the store and on disk
    bool EraseDestData(const CTxDestination& dest, const std::string& key);
    //! Adds a destination data tuple to the store, without saving it to disk
    bool LoadDestData(const CTxDestination& dest, const std::string& key, const std::string& value);
    //! Look up a destination data tuple in the store, return true if found false otherwise
    bool GetDestData(const CTxDestination& dest, const std::string& key, std::string* value) const;

    //! Adds a watch-only address to the store, and saves it to disk.
    bool AddWatchOnly(const CScript& dest);
    bool RemoveWatchOnly(const CScript& dest);
    //! Adds a watch-only address to the store, without saving it to disk (used by LoadWallet)
    bool LoadWatchOnly(const CScript& dest);

    //! Adds a MultiSig address to the store, and saves it to disk.
    bool AddMultiSig(const CScript& dest);
    bool RemoveMultiSig(const CScript& dest);
    //! Adds a MultiSig address to the store, without saving it to disk (used by LoadWallet)
    bool LoadMultiSig(const CScript& dest);

    bool Unlock(const SecureString& strWalletPassphrase, bool anonimizeOnly = false);
    bool ChangeWalletPassphrase(const SecureString& strOldWalletPassphrase, const SecureString& strNewWalletPassphrase);
    bool EncryptWallet(const SecureString& strWalletPassphrase);

    void GetKeyBirthTimes(std::map<CKeyID, int64_t>& mapKeyBirth) const;
    unsigned int ComputeTimeSmart(const CWalletTx& wtx) const;

    /**
     * Increment the next transaction order id
     * @return next transaction order id
     */
    int64_t IncOrderPosNext(CWalletDB* pwalletdb = NULL);


    void MarkDirty();
    bool AddToWallet(const CWalletTx& wtxIn, bool fFromLoadWallet = false);
    void SyncTransaction(const CTransaction& tx, const CBlock* pblock);
    bool AddToWalletIfInvolvingMe(const CTransaction& tx, const CBlock* pblock, bool fUpdate);
    void EraseFromWallet(const uint256& hash);
    int ScanForWalletTransactions(CBlockIndex* pindexStart, bool fUpdate = false, bool fromStartup = false, int height = -1);
    void ReacceptWalletTransactions();
    void ResendWalletTransactions();
    CAmount GetBalance();
    bool ReadKeyImage(const COutPoint& out, CKeyImage& ki);
    CAmount GetSpendableBalance();
    CAmount GetLockedCoins() const;
    CAmount GetUnlockedCoins() const;
    CAmount GetUnconfirmedBalance() const;
    CAmount GetImmatureBalance() const;
    CAmount GetAnonymizableBalance() const;
    CAmount GetAnonymizedBalance() const;
    double GetAverageAnonymizedRounds();
    CAmount GetNormalizedAnonymizedBalance();
    CAmount GetDenominatedBalance(bool unconfirmed = false) const;
    CAmount GetWatchOnlyBalance() const;
    CAmount GetUnconfirmedWatchOnlyBalance() const;
    CAmount GetImmatureWatchOnlyBalance() const;
    bool CreateTransaction(CScript scriptPubKey, int64_t nValue, CWalletTx& wtxNew, CReserveKey& reservekey, int64_t& nFeeRet, std::string& strFailReason, const CCoinControl* coinControl);
    bool CreateTransaction(const std::vector<std::pair<CScript, CAmount> >& vecSend,
                           CWalletTx& wtxNew,
                           CReserveKey& reservekey,
                           CAmount& nFeeRet,
                           std::string& strFailReason,
                           const CCoinControl* coinControl = NULL,
                           AvailableCoinsType coin_type = ALL_COINS,
                           bool useIX = false,
                           CAmount nFeePay = 0);
    bool CreateTransactionBulletProof(CPartialTransaction& ptx, const CKey& txPrivDes,
                           const CPubKey& recipientViewKey,
                           const std::vector<std::pair<CScript, CAmount> >& vecSend,
                           CWalletTx& wtxNew,
                           CReserveKey& reservekey,
                           CAmount& nFeeRet,
                           std::string& strFailReason,
                           int& ringSize,
                           std::vector<pair<const CWalletTx*, unsigned int> >& setCoins,
                           CAmount nValueIn,
                           CAmount estimateFee,
                           const CCoinControl* coinControl = NULL,
                           AvailableCoinsType coin_type = ALL_COINS,
                           bool useIX = false,
                           CAmount nFeePay = 0, bool tomyself = false);

    bool CreateTransactionBulletProof(CPartialTransaction& ptx, const CKey& txPrivDes, const CPubKey &recipientViewKey, CScript scriptPubKey, const CAmount &nValue,
                                      CWalletTx &wtxNew, CReserveKey &reservekey, CAmount &nFeeRet,
                                      std::string &strFailReason,
                                      int& ringSize, 
                                      std::vector<pair<const CWalletTx*, unsigned int> >& setCoins,
                                      CAmount nValueIn,
                                      CAmount estimateFee,
                                      const CCoinControl *coinControl = NULL,
                                      AvailableCoinsType coin_type = ALL_COINS, bool useIX = false,
                                      CAmount nFeePay = 0, bool tomyself = false);

    uint256 ComputeSortedSelectedOutPointHash(vector<pair<const CWalletTx*, unsigned int>>& setCoins) const;
    uint256 ComputeSortedSelectedOutPointHash(vector<pair<uint256, unsigned int>>& setCoins) const;
    
    int ComputeFee(size_t numIn, size_t numOut, size_t ringSize);
    CAmount ComputeReserveUTXOAmount();
    bool CreateTransaction(CScript scriptPubKey, const CAmount &nValue, CWalletTx &wtxNew, CReserveKey &reservekey,
                           CAmount &nFeeRet, std::string &strFailReason, const CCoinControl *coinControl = NULL,
                           AvailableCoinsType coin_type = ALL_COINS, bool useIX = false, CAmount nFeePay = 0);
    bool CommitTransaction(CWalletTx& wtxNew, CReserveKey& reservekey, std::string strCommand = "tx");
    bool AddAccountingEntry(const CAccountingEntry&, CWalletDB & pwalletdb);
    std::string PrepareObfuscationDenominate(int minRounds, int maxRounds);
    int GenerateObfuscationOutputs(int nTotalValue, std::vector<CTxOut>& vout);
    bool CreateCollateralTransaction(CMutableTransaction& txCollateral, std::string& strReason);
    bool CreateCoinStake(const CKeyStore& keystore, unsigned int nBits, int64_t nSearchInterval, CMutableTransaction& txNew, unsigned int& nTxNewTime);
    bool CreateCoinAudit(const CKeyStore& keystore, unsigned int nBits, int64_t nSearchInterval, CMutableTransaction& txNew, unsigned int& nTxNewTime);
    bool MultiSend();
    void AutoCombineDust();

    static CFeeRate minTxFee;
    static CAmount GetMinimumFee(unsigned int nTxBytes, unsigned int nConfirmTarget, const CTxMemPool& pool);

    bool NewKeyPool();
    bool TopUpKeyPool(unsigned int kpSize = 0);
    void ReserveKeyFromKeyPool(int64_t& nIndex, CKeyPool& keypool);
    void KeepKey(int64_t nIndex);
    void ReturnKey(int64_t nIndex);
    bool GetKeyFromPool(CPubKey& key);
    int64_t GetOldestKeyPoolTime();
    void GetAllReserveKeys(std::set<CKeyID>& setAddress) const;

    std::set<std::set<CTxDestination> > GetAddressGroupings();
    std::map<CTxDestination, CAmount> GetAddressBalances();

    std::set<CTxDestination> GetAccountAddresses(std::string strAccount) const;

    bool GetBudgetSystemCollateralTX(CTransaction& tx, uint256 hash, bool useIX);
    bool GetBudgetSystemCollateralTX(CWalletTx& tx, uint256 hash, bool useIX);

    // get the Obfuscation chain depth for a given input
    int GetRealInputObfuscationRounds(CTxIn in, int rounds) const;
    // respect current settings
    int GetInputObfuscationRounds(CTxIn in) const;

    bool IsDenominated(const CTransaction& tx, const CTxIn& txin) const;
    bool IsDenominated(const CTransaction& tx) const;

    bool IsDenominatedAmount(CAmount nInputAmount) const;

    isminetype IsMine(const CTransaction& tx, const CTxIn& txin) const;
    CAmount GetDebit(const CTransaction& tx, const CTxIn& txin, const isminefilter& filter) const;
    isminetype IsMine(const CTxOut& txout) const
    {
        return ::IsMine(*this, txout.scriptPubKey);
    }
    CAmount GetCredit(const CTransaction& tx, const CTxOut& txout, const isminefilter& filter) const
    {
        return ((IsMine(txout) & filter) ? getCTxOutValue(tx, txout) : 0);
    }
    bool IsChange(const CTxOut& txout) const;
    CAmount GetChange(const CTransaction& tx, const CTxOut& txout) const
    {
        return (IsChange(txout) ? getCTxOutValue(tx, txout) : 0);
    }
    bool IsMine(const CTransaction& tx) const
    {
        for (const CTxOut& txout : tx.vout)
        if (IsMine(txout))
            return true;
        return false;
    }
    /** should probably be renamed to IsRelevantToMe */
    bool IsFromMe(const CTransaction& tx) const
    {
        return (GetDebit(tx, ISMINE_ALL) > 0);
    }
    CAmount GetDebit(const CTransaction& tx, const isminefilter& filter) const
    {
        CAmount nDebit = 0;
        for (const CTxIn& txin : tx.vin) {
            nDebit += GetDebit(tx, txin, filter);
        }
        return nDebit;
    }
    CAmount GetCredit(const CTransaction& tx, const isminefilter& filter) const
    {
        CAmount nCredit = 0;
        for (const CTxOut& txout : tx.vout) {
            nCredit += GetCredit(tx, txout, filter);
        }
        return nCredit;
    }
    CAmount GetChange(const CTransaction& tx) const
    {
        CAmount nChange = 0;
        for (const CTxOut& txout : tx.vout) {
            nChange += GetChange(tx, txout);
        }
        return nChange;
    }
    void SetBestChain(const CBlockLocator& loc);

    DBErrors LoadWallet(bool& fFirstRunRet);
    DBErrors ZapWalletTx(std::vector<CWalletTx>& vWtx);

    bool SetAddressBook(const CTxDestination& address, const std::string& strName, const std::string& purpose);

    bool DelAddressBook(const CTxDestination& address);

    bool UpdatedTransaction(const uint256& hashTx);

    void Inventory(const uint256& hash)
    {
        {
            LOCK(cs_wallet);
            std::map<uint256, int>::iterator mi = mapRequestCount.find(hash);
            if (mi != mapRequestCount.end())
                (*mi).second++;
        }
    }

    unsigned int GetKeyPoolSize()
    {
        AssertLockHeld(cs_wallet); // setKeyPool
        return setKeyPool.size();
    }

    bool SetDefaultKey(const CPubKey& vchPubKey);

    //! signify that a particular wallet feature is now used. this may change nWalletVersion and nWalletMaxVersion if those are lower
    bool SetMinVersion(enum WalletFeature, CWalletDB* pwalletdbIn = NULL, bool fExplicit = false);

    //! change which version we're allowed to upgrade to (note that this does not immediately imply upgrading to that format)
    bool SetMaxVersion(int nVersion);

    //! get the current wallet format (the oldest client version guaranteed to understand this wallet)
    int GetVersion()
    {
        LOCK(cs_wallet);
        return nWalletVersion;
    }

    //! Get wallet transactions that conflict with given transaction (spend same outputs)
    std::set<uint256> GetConflicts(const uint256& txid) const;

    /**
     * Address book entry changed.
     * @note called with lock cs_wallet held.
     */
    boost::signals2::signal<void(CWallet* wallet, const CTxDestination& address, const std::string& label, bool isMine, const std::string& purpose, ChangeType status)> NotifyAddressBookChanged;

    /**
     * Wallet transaction added, removed or updated.
     * @note called with lock cs_wallet held.
     */
    boost::signals2::signal<void(CWallet* wallet, const uint256& hashTx, ChangeType status)> NotifyTransactionChanged;

    /** Show progress e.g. for rescan */
    boost::signals2::signal<void(const std::string& title, int nProgress)> ShowProgress;

    /** Watch-only address added */
    boost::signals2::signal<void(bool fHaveWatchOnly)> NotifyWatchonlyChanged;

    /** MultiSig address added */
    boost::signals2::signal<void(bool fHaveMultiSig)> NotifyMultiSigChanged;

    bool ComputeStealthPublicAddress(const std::string& accountName, std::string& pubAddress);
    bool ComputeIntegratedPublicAddress(const uint64_t paymentID, const std::string& accountName, std::string& pubAddress);
    bool EncodeStealthPublicAddress(const std::vector<unsigned char>& pubViewKey, const std::vector<unsigned char>& pubSpendKey, std::string& pubAddr);
    bool EncodeStealthPublicAddress(const CPubKey& pubViewKey, const CPubKey& pubSpendKey, std::string& pubAddr);
    static bool DecodeStealthAddress(const std::string& stealth, CPubKey& pubViewKey, CPubKey& pubSpendKey, bool& hasPaymentID, uint64_t& paymentID);
    static bool ComputeStealthDestination(const CKey& secret, const CPubKey& pubViewKey, const CPubKey& pubSpendKey, CPubKey& des);
    bool SendToStealthAddress(CPartialTransaction& ptx, const std::string& stealthAddr, CAmount nValue, CWalletTx& wtxNew, bool fUseIX = false, int ringSize = 5);
    bool GenerateAddress(CPubKey& pub, CPubKey& txPub, CKey& txPriv) const;
    bool IsTransactionForMe(const CTransaction& tx);
    bool ReadAccountList(std::string& accountList);
    bool ReadStealthAccount(const std::string& strAccount, CStealthAccount& account);
    bool EncodeIntegratedAddress(const CPubKey& pubViewKey, const CPubKey& pubSpendKey, uint64_t paymentID, std::string& pubAddr);
    bool EncodeIntegratedAddress(const std::vector<unsigned char>& pubViewKey, const std::vector<unsigned char>& pubSpendKey, uint64_t paymentID, std::string& pubAddrb58);
    bool GenerateIntegratedAddress(const std::string& accountName, std::string& pubAddr);
    std::string GenerateIntegratedAddressWithRandomPaymentID(std::string accountName, uint64_t& paymentID);
    std::string GenerateIntegratedAddressWithProvidedPaymentID(std::string accountName, uint64_t paymentID);
    bool GenerateIntegratedAddress(const CPubKey& pubViewKey, const CPubKey& pubSpendKey, std::string& pubAddr);
    bool AllMyPublicAddresses(std::vector<std::string>& addresses, std::vector<std::string>& accountNames);
    bool RevealTxOutAmount(const CTransaction &tx, const CTxOut &out, CAmount &amount, CKey&) const;
    bool EncodeTxOutAmount(CTxOut& out, const CAmount& amount, const unsigned char * sharedSec, bool isCoinstake = false);
    CAmount getCOutPutValue(const COutput& output) const;
    CAmount getCTxOutValue(const CTransaction &tx, const CTxOut &out) const;
    bool findCorrespondingPrivateKey(const CTxOut &txout, CKey &key) const;
    bool AvailableCoins(const uint256 wtxid, const CWalletTx* pcoin, vector<COutput>& vCoins, int cannotSpend, bool fOnlyConfirmed = true, const CCoinControl* coinControl = NULL, bool fIncludeZeroValue = false, AvailableCoinsType nCoinType = ALL_COINS, bool fUseIX = false);
    void CreatePrivacyAccount(bool force = false);
    bool mySpendPrivateKey(CKey& spend) const;
    bool myViewPrivateKey(CKey& view) const;
    static bool CreateCommitment(const CAmount val, CKey& blind, std::vector<unsigned char>& commitment);
    static bool CreateCommitment(const unsigned char* blind, CAmount val, std::vector<unsigned char>& commitment);
    static bool CreateCommitmentWithZeroBlind(const CAmount val, unsigned char* pBlind, std::vector<unsigned char>& commitment);
    bool WriteStakingStatus(bool status);
    bool ReadStakingStatus();
    bool Write2FA(bool status);
    bool Read2FA();
    bool Write2FASecret(std::string secret);
    std::string Read2FASecret();
    bool Write2FAPeriod(int period);
    int Read2FAPeriod();
    bool Write2FALastTime(uint64_t lastTime);
    uint64_t Read2FALastTime();
    bool MakeShnorrSignature(CTransaction&);
    bool MakeShnorrSignatureTxIn(CTxIn& txin, uint256);
    bool computeSharedSec(const CTransaction& tx, const CTxOut& out, CPubKey& sharedSec) const;
    bool GenerateBulletProofForStaking(CTransaction& tx);
    CKeyImage GeneratePartialKeyImage(const CTxOut& out);
    CKeyImage GeneratePartialKeyImage(const COutPoint& out);
    CPubKey computeDestination(const COutPoint& out);
    CPubKey computeDestination(const CTxOut& out);
    bool GeneratePartialKeyImages(const std::vector<CTxOut>& outputs, std::vector<CKeyImage>& out);
    bool GeneratePartialKeyImages(const std::vector<COutPoint>& outpoints, std::vector<CKeyImage>& out);
    bool GenerateAllPartialImages(std::vector<CKeyImage>& out);
    bool IsWalletGenerated() const {
    	ComboKeyList combos;
    	CWalletDB(strWalletFile).ReadAllComboKeys(combos);
    	return multiSigPrivView.IsValid() && comboKeys.comboKeys.size() == ReadNumSigners();
    }
    ComboKey MyComboKey() const {
    	if (IsLocked()) throw runtime_error("Wallet need to be unlocked");
    	CKey view, spend;
    	myViewPrivateKey(view);
    	mySpendPrivateKey(spend);
    	CPubKey pubSpend = spend.GetPubKey();
    	ComboKey combo;
    	combo.pubSpend = pubSpend;
    	std::copy(view.begin(), view.end(), std::back_inserter(combo.privView));
    	return combo;
    }
    void AddCoSignerKey(ComboKey combo)
    {
    	if (IsWalletGenerated()) throw runtime_error("Multisig wallet is already generated");
    	comboKeys.AddKey(MyComboKey());
    	comboKeys.AddKey(combo);
		CWalletDB(strWalletFile).WriteComboKeys(comboKeys);
    }

    void AddCosignerKeyAtIndex(ComboKey combo, int idx) {
    	if (IsWalletGenerated()) throw runtime_error("Multisig wallet is already generated");
    	if (idx >= comboKeys.comboKeys.size()) {
    		AddCoSignerKey(combo);
    	} else {
    		comboKeys.comboKeys[idx] = combo;
    		CWalletDB(strWalletFile).WriteComboKeys(comboKeys);
    	}
    }

    void GenerateMultisigWallet(int numSigners);

    CPubKey GetMultisigPubSpendKey()
    {
    	GenerateMultisigWallet(comboKeys.comboKeys.size());
    	return multiSigPubSpend;
    }

    CKey MyMultisigViewKey() const
    {
    	if (multiSigPrivView.IsValid()) return multiSigPrivView;
    	{
    		LOCK(cs_wallet);
    		LoadMultisigKey();
    	}
    	return multiSigPrivView;
    }
    bool DidISignTheTransaction(const CPartialTransaction& partial);
    //return true if the transaction is fully signed
    bool CoSignTransaction(CPartialTransaction& partial);
    bool CoSignPartialTransaction(CPartialTransaction& tx);
    bool generatePKeyImageAlphaListFromPartialTx(const CPartialTransaction& tx, CListPKeyImageAlpha& l);
    bool HasPendingTx() const
    {
        return CWalletDB(strWalletFile).ReadHasWaitingTx();
    }
    uint256 readPendingTxPriv() const;
    void AddComputedPrivateKey(const CTxOut& out);
    bool IsMultisigSetup() const {
    	MyMultisigViewKey();
    	return multiSigPrivView.IsValid();
    }

    void SetNumSigners(int numSigners);
    int ReadNumSigners() const;
    std::string MyMultisigPubAddress();
    void WriteScreenIndex(int index) const;
    int ReadScreenIndex() const;
    bool IsCollateralized(const COutPoint& outpoint);
    bool finishRingCTAfterKeyImageSynced(CPartialTransaction& wtxNew, std::vector<CListPKeyImageAlpha> ls, std::string& failReason);
private:
    void GeneratePKeyImageAlpha(const COutPoint& op, CPKeyImageAlpha&) ;
    bool encodeStealthBase58(const std::vector<unsigned char>& raw, std::string& stealth);
    bool allMyPrivateKeys(std::vector<CKey>& spends, std::vector<CKey>& views);
    void createMasterKey() const;
    bool LoadMultisigKey() const;
    bool generateBulletProofAggregate(CPartialTransaction& tx);
    bool selectDecoysAndRealIndex(CPartialTransaction& tx, int& myIndex, int ringSize);
    bool IsMine(const COutPoint outpoint) const;
    bool makeRingCT(CPartialTransaction& wtxNew, int ringSize, std::string& strFailReason);
    CKeyImage generatePartialAdditionalKeyImage(const CPartialTransaction& wtxNew);
    CPubKey SumOfAllPubKeys(std::vector<CPubKey>& l) const;
    int findMultisigInputIndex(const CPartialTransaction& tx) const;
    int findMultisigInputIndex(const CTransaction& tx) const;
    int findMultisigInputIndex(const CTransaction& tx, const CTxIn& txin) const;
    int walletIdxCache = 0;
    bool isMatchMyKeyImage(const CKeyImage& ki, const COutPoint& out);
    void ScanWalletKeyImages();
    bool generateCommitmentAndEncode(CPartialTransaction& wtxNew);
    bool makeRingCT(CPartialTransaction& wtxNew, int ringSize, std::string& strFailReason, int myIndex);
    CKey GeneratePartialKey(const COutPoint& out);
    CKey GeneratePartialKey(const CTxOut& out);
    void generateAdditionalPartialAlpha(const CPartialTransaction& tx, CPKeyImageAlpha& combo, const uint256& hashOfInOuts);
    CPubKey generateAdditonalPubKey(const CPartialTransaction& wtxNew);
    CKey generateAdditionalPartialAlpha(const CPartialTransaction& tx);
    uint256 generateHashOfAllIns(const CPartialTransaction& tx);
};


/** A key allocated from the key pool. */
class CReserveKey
{
protected:
    CWallet* pwallet;
    int64_t nIndex;
    CPubKey vchPubKey;

public:
    CReserveKey(CWallet* pwalletIn)
    {
        nIndex = -1;
        pwallet = pwalletIn;
    }

    ~CReserveKey()
    {
        ReturnKey();
    }

    void ReturnKey();
    bool GetReservedKey(CPubKey& pubkey);
    void KeepKey();
};


typedef std::map<std::string, std::string> mapValue_t;


static void ReadOrderPos(int64_t& nOrderPos, mapValue_t& mapValue)
{
    if (!mapValue.count("n")) {
        nOrderPos = -1; // TODO: calculate elsewhere
        return;
    }
    nOrderPos = atoi64(mapValue["n"].c_str());
}


static void WriteOrderPos(const int64_t& nOrderPos, mapValue_t& mapValue)
{
    if (nOrderPos == -1)
        return;
    mapValue["n"] = i64tostr(nOrderPos);
}

struct COutputEntry {
    CTxDestination destination;
    CAmount amount;
    int vout;
};

/** A transaction with a merkle branch linking it to the block chain. */
class CMerkleTx : public CTransaction
{
private:
    int GetDepthInMainChainINTERNAL(const CBlockIndex*& pindexRet) const;

public:
    uint256 hashBlock;
    std::vector<uint256> vMerkleBranch;
    int nIndex;

    // memory only
    mutable bool fMerkleVerified;


    CMerkleTx()
    {
        Init();
    }

    CMerkleTx(const CTransaction& txIn) : CTransaction(txIn)
    {
        Init();
    }

    void Init()
    {
        hashBlock = 0;
        nIndex = -1;
        fMerkleVerified = false;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        READWRITE(*(CTransaction*)this);
        nVersion = this->nVersion;
        READWRITE(hashBlock);
        READWRITE(vMerkleBranch);
        READWRITE(nIndex);
    }

    int SetMerkleBranch(const CBlock& block);


    /**
     * Return depth of transaction in blockchain:
     * -1  : not in blockchain, and not in memory pool (conflicted transaction)
     *  0  : in memory pool, waiting to be included in a block
     * >=1 : this many blocks deep in the main chain
     */
    int GetDepthInMainChain(const CBlockIndex*& pindexRet, bool enableIX = true) const;
    int GetDepthInMainChain(bool enableIX = true) const
    {
        const CBlockIndex* pindexRet;
        return GetDepthInMainChain(pindexRet, enableIX);
    }
    bool IsInMainChain() const
    {
        const CBlockIndex* pindexRet;
        return GetDepthInMainChainINTERNAL(pindexRet) > 0;
    }
    int GetBlocksToMaturity() const;
    bool AcceptToMemoryPool(bool fLimitFree = true, bool fRejectInsaneFee = true, bool ignoreFees = false);
    int GetTransactionLockSignatures() const;
    bool IsTransactionLockTimedOut() const;
};

/**
 * A transaction with a bunch of additional info that only the owner cares about.
 * It includes any unrecorded transactions needed to link it back to the block chain.
 */
class CWalletTx : public CMerkleTx
{
private:
    CWallet* pwallet;

public:
    mapValue_t mapValue;
    std::vector<std::pair<std::string, std::string> > vOrderForm;
    unsigned int fTimeReceivedIsTxTime;
    unsigned int nTimeReceived; //! time received by this node
    unsigned int nTimeSmart;
    char fFromMe;
    std::string strFromAccount;
    int64_t nOrderPos; //! position in ordered transaction list
    char fSpent = false;

    // memory only
    mutable bool fDebitCached;
    mutable bool fCreditCached;
    mutable bool fImmatureCreditCached;
    mutable bool fAvailableCreditCached;
    mutable bool fAnonymizableCreditCached;
    mutable bool fAnonymizedCreditCached;
    mutable bool fDenomUnconfCreditCached;
    mutable bool fDenomConfCreditCached;
    mutable bool fWatchDebitCached;
    mutable bool fWatchCreditCached;
    mutable bool fImmatureWatchCreditCached;
    mutable bool fAvailableWatchCreditCached;
    mutable bool fChangeCached;

    mutable CAmount nDebitCached;
    mutable CAmount nCreditCached;
    mutable CAmount nImmatureCreditCached;
    mutable CAmount nAvailableCreditCached;
    mutable CAmount nAnonymizableCreditCached;
    mutable CAmount nAnonymizedCreditCached;
    mutable CAmount nDenomUnconfCreditCached;
    mutable CAmount nDenomConfCreditCached;
    mutable CAmount nWatchDebitCached;
    mutable CAmount nWatchCreditCached;
    mutable CAmount nImmatureWatchCreditCached;
    mutable CAmount nAvailableWatchCreditCached;
    mutable CAmount nChangeCached;


    CWalletTx()
    {
        Init(NULL);
    }

    CWalletTx(CWallet* pwalletIn)
    {
        Init(pwalletIn);
    }

    CWalletTx(CWallet* pwalletIn, const CMerkleTx& txIn) : CMerkleTx(txIn)
    {
        Init(pwalletIn);
    }

    CWalletTx(CWallet* pwalletIn, const CTransaction& txIn) : CMerkleTx(txIn)
    {
        Init(pwalletIn);
    }

    void Init(CWallet* pwalletIn)
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

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        if (ser_action.ForRead())
            Init(NULL);
        if (!ser_action.ForRead()) {
            mapValue["fromaccount"] = strFromAccount;

            WriteOrderPos(nOrderPos, mapValue);

            if (nTimeSmart)
                mapValue["timesmart"] = strprintf("%u", nTimeSmart);
        }

        READWRITE(*(CMerkleTx*)this);
        std::vector<CMerkleTx> vUnused; //! Used to be vtxPrev
        READWRITE(vUnused);
        READWRITE(mapValue);
        READWRITE(vOrderForm);
        READWRITE(fTimeReceivedIsTxTime);
        READWRITE(nTimeReceived);
        READWRITE(fFromMe);
        READWRITE(fSpent);

        if (ser_action.ForRead()) {
            strFromAccount = mapValue["fromaccount"];

            ReadOrderPos(nOrderPos, mapValue);

            nTimeSmart = mapValue.count("timesmart") ? (unsigned int)atoi64(mapValue["timesmart"]) : 0;
        }

        mapValue.erase("fromaccount");
        mapValue.erase("version");
        mapValue.erase("spent");
        mapValue.erase("n");
        mapValue.erase("timesmart");
    }

    //! make sure balances are recalculated
    void MarkDirty()
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

    void BindWallet(CWallet* pwalletIn)
    {
        pwallet = pwalletIn;
        MarkDirty();
    }

    //! filter decides which addresses will count towards the debit
    CAmount GetDebit(const isminefilter& filter) const
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

    CAmount GetCredit(const isminefilter& filter) const
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

    CAmount GetImmatureCredit(bool fUseCache = true) const
    {
        LOCK(cs_main);
        if ((IsCoinBase() || IsCoinStake()) && GetBlocksToMaturity() > 0 && IsInMainChain()) {
            if (fUseCache && fImmatureCreditCached)
                return nImmatureCreditCached;
            nImmatureCreditCached = pwallet->GetCredit(*this, ISMINE_SPENDABLE);
            fImmatureCreditCached = true;
            return nImmatureCreditCached;
        }
        return 0;
    }

    CAmount GetAvailableCredit(bool fUseCache = true) const
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
                CAmount cre = pwallet->GetCredit(*this, txout, ISMINE_ALL);
                if (cre == 0 && fCreditCached) {
                    fCreditCached = false;
                    cre = pwallet->GetCredit(*this, txout, ISMINE_ALL);
                }
                nCredit += cre;
            }
        }

        nAvailableCreditCached = nCredit;
        fAvailableCreditCached = true;
        return nCredit;
    }

    CAmount GetAnonymizableCredit(bool fUseCache = true) const
    {
        if (pwallet == 0)
            return 0;

        // Must wait until coinbase is safely deep enough in the chain before valuing it
        if (IsCoinBase() && GetBlocksToMaturity() > 0)
            return 0;

        if (fUseCache && fAnonymizableCreditCached)
            return nAnonymizableCreditCached;

        CAmount nCredit = 0;
        uint256 hashTx = GetHash();
        for (unsigned int i = 0; i < vout.size(); i++) {
            const CTxIn vin = CTxIn(hashTx, i);

            if (pwallet->IsSpent(hashTx, i) || pwallet->IsLockedCoin(hashTx, i)) continue;
            if (fMasterNode && pwallet->getCTxOutValue(*this, vout[i]) == 1000000 * COIN) continue; // do not count MN-like outputs
        }

        nAnonymizableCreditCached = nCredit;
        fAnonymizableCreditCached = true;
        return nCredit;
    }

    CAmount GetAnonymizedCredit(bool fUseCache = true) const
    {
        if (pwallet == 0)
            return 0;

        // Must wait until coinbase is safely deep enough in the chain before valuing it
        if (IsCoinBase() && GetBlocksToMaturity() > 0)
            return 0;

        if (fUseCache && fAnonymizedCreditCached)
            return nAnonymizedCreditCached;

        CAmount nCredit = 0;
        uint256 hashTx = GetHash();
        for (unsigned int i = 0; i < vout.size(); i++) {
            const CTxIn vin = CTxIn(hashTx, i);
            if (pwallet->IsSpent(hashTx, i) || !pwallet->IsDenominated(*this, vin)) continue;
        }

        nAnonymizedCreditCached = nCredit;
        fAnonymizedCreditCached = true;
        return nCredit;
    }

    // Return sum of unlocked coins
    CAmount GetUnlockedCredit() const
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
    CAmount GetLockedCredit() const
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

    CAmount GetDenominatedCredit(bool unconfirmed, bool fUseCache = true) const
    {
        if (pwallet == 0)
            return 0;

        // Must wait until coinbase is safely deep enough in the chain before valuing it
        if (IsCoinBase() && GetBlocksToMaturity() > 0)
            return 0;

        int nDepth = GetDepthInMainChain(false);
        if (nDepth < 0) return 0;

        bool isUnconfirmed = !IsFinalTx(*this) || (!IsTrusted() && nDepth == 0);
        if (unconfirmed != isUnconfirmed) return 0;

        if (fUseCache) {
            if (unconfirmed && fDenomUnconfCreditCached)
                return nDenomUnconfCreditCached;
            else if (!unconfirmed && fDenomConfCreditCached)
                return nDenomConfCreditCached;
        }

        CAmount nCredit = 0;
        uint256 hashTx = GetHash();
        for (unsigned int i = 0; i < vout.size(); i++) {
            const CTxOut& txout = vout[i];

            if (pwallet->IsSpent(hashTx, i) || !pwallet->IsDenominatedAmount(pwallet->getCTxOutValue(*this, txout))) continue;

            nCredit += pwallet->GetCredit(*this, txout, ISMINE_SPENDABLE);
        }

        if (unconfirmed) {
            nDenomUnconfCreditCached = nCredit;
            fDenomUnconfCreditCached = true;
        } else {
            nDenomConfCreditCached = nCredit;
            fDenomConfCreditCached = true;
        }
        return nCredit;
    }

    CAmount GetImmatureWatchOnlyCredit(const bool& fUseCache = true) const
    {
        LOCK(cs_main);
        if (IsCoinBase() && GetBlocksToMaturity() > 0 && IsInMainChain()) {
            if (fUseCache && fImmatureWatchCreditCached)
                return nImmatureWatchCreditCached;
            nImmatureWatchCreditCached = pwallet->GetCredit(*this, ISMINE_WATCH_ONLY);
            fImmatureWatchCreditCached = true;
            return nImmatureWatchCreditCached;
        }

        return 0;
    }

    CAmount GetAvailableWatchOnlyCredit(const bool& fUseCache = true) const
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

    CAmount GetChange() const
    {
        if (fChangeCached)
            return nChangeCached;
        nChangeCached = pwallet->GetChange(*this);
        fChangeCached = true;
        return nChangeCached;
    }

    void GetAmounts(std::list<COutputEntry>& listReceived,
                    std::list<COutputEntry>& listSent,
                    CAmount& nFee,
                    std::string& strSentAccount,
                    const isminefilter& filter) const;

    void GetAccountAmounts(const std::string& strAccount, CAmount& nReceived, CAmount& nSent, CAmount& nFee, const isminefilter& filter) const;

    bool IsFromMe(const isminefilter& filter) const
    {
        return (GetDebit(filter) > 0);
    }

    bool InMempool() const;

    bool IsTrusted() const
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
        	COutPoint prevout = pwallet->findMyOutPoint(*this, txin);
            const CWalletTx* parent = pwallet->GetWalletTx(prevout.hash);
            if (parent == NULL)
                return false;
            const CTxOut& parentOut = parent->vout[prevout.n];
            if (pwallet->IsMine(parentOut) != ISMINE_SPENDABLE)
                return false;
        }
        return true;
    }

    int GetBlockHeight() const {
        if (hashBlock.IsNull()) {
            return -1; //not in the chain
        } else {
            return mapBlockIndex[hashBlock]->nHeight;
        }
    }

    bool WriteToDisk();

    int64_t GetTxTime() const;
    int64_t GetComputedTxTime() const;
    int GetRequestCount() const;
    void RelayWalletTransaction(std::string strCommand = "tx");

    std::set<uint256> GetConflicts() const;
};


class COutput
{
public:
    const CWalletTx* tx;
    int i;
    int nDepth;
    bool fSpendable;

    COutput(const CWalletTx* txIn, int iIn, int nDepthIn, bool fSpendableIn)
    {
        tx = txIn;
        i = iIn;
        nDepth = nDepthIn;
        fSpendable = fSpendableIn;
    }

    //Used with Obfuscation. Will return largest nondenom, then denominations, then very small inputs
    int Priority() const
    {
        for (CAmount d : obfuScationDenominations)
        if (tx->vout[i].nValue == d) return 10000;
        if (tx->vout[i].nValue < 1 * COIN) return 20000;

        //nondenom return largest first
        return -(tx->vout[i].nValue / COIN);
    }

    CAmount Value() const
    {
        return tx->vout[i].nValue;
    }

    std::string ToString() const;
};


/** Private key that includes an expiration date in case it never gets used. */
class CWalletKey
{
public:
    CPrivKey vchPrivKey;
    int64_t nTimeCreated;
    int64_t nTimeExpires;
    std::string strComment;
    //! todo: add something to note what created it (user, getnewaddress, change)
    //!   maybe should have a map<string, string> property map

    CWalletKey(int64_t nExpires = 0);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        if (!(nType & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(vchPrivKey);
        READWRITE(nTimeCreated);
        READWRITE(nTimeExpires);
        READWRITE(LIMITED_STRING(strComment, 65536));
    }
};





/**
 * Internal transfers.
 * Database key is acentry<account><counter>.
 */
class CAccountingEntry
{
public:
    std::string strAccount;
    CAmount nCreditDebit;
    int64_t nTime;
    std::string strOtherAccount;
    std::string strComment;
    mapValue_t mapValue;
    int64_t nOrderPos; //! position in ordered transaction list
    uint64_t nEntryNo;

    CAccountingEntry()
    {
        SetNull();
    }

    void SetNull()
    {
        nCreditDebit = 0;
        nTime = 0;
        strAccount.clear();
        strOtherAccount.clear();
        strComment.clear();
        nOrderPos = -1;
        nEntryNo = 0;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        if (!(nType & SER_GETHASH))
            READWRITE(nVersion);
        //! Note: strAccount is serialized as part of the key, not here.
        READWRITE(nCreditDebit);
        READWRITE(nTime);
        READWRITE(LIMITED_STRING(strOtherAccount, 65536));

        if (!ser_action.ForRead()) {
            WriteOrderPos(nOrderPos, mapValue);

            if (!(mapValue.empty() && _ssExtra.empty())) {
                CDataStream ss(nType, nVersion);
                ss.insert(ss.begin(), '\0');
                ss << mapValue;
                ss.insert(ss.end(), _ssExtra.begin(), _ssExtra.end());
                strComment.append(ss.str());
            }
        }

        READWRITE(LIMITED_STRING(strComment, 65536));

        size_t nSepPos = strComment.find("\0", 0, 1);
        if (ser_action.ForRead()) {
            mapValue.clear();
            if (std::string::npos != nSepPos) {
                CDataStream ss(std::vector<char>(strComment.begin() + nSepPos + 1, strComment.end()), nType, nVersion);
                ss >> mapValue;
                _ssExtra = std::vector<char>(ss.begin(), ss.end());
            }
            ReadOrderPos(nOrderPos, mapValue);
        }
        if (std::string::npos != nSepPos)
            strComment.erase(nSepPos);

        mapValue.erase("n");
    }

private:
    std::vector<char> _ssExtra;
};



#endif // BITCOIN_WALLET_H
