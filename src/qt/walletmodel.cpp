// Copyright (c) 2011-2014 The Bitcoin developers
// Copyright (c) 2015-2018 The PIVX developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2018-2019 The DAPS Project developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "walletmodel.h"

#include "addresstablemodel.h"
#include "bitcoinunits.h"
#include "guiconstants.h"
#include "guiutil.h"
#include "recentrequeststablemodel.h"
#include "transactionrecord.h"
#include "transactiontablemodel.h"


#include "base58.h"
#include "db.h"
#include "keystore.h"
#include "main.h"
#include "miner.h"
#include "sync.h"
#include "ui_interface.h"
#include "wallet.h"
#include "walletdb.h" // for BackupWallet
#include <stdint.h>
#include <regex>
#include <QDebug>
#include <QLocale>
#include <QSet>
#include <QTimer>
#include <QtCore>
#include <QtMath>
#include <stdint.h>
#include <QTextStream>

using namespace std;

WalletModel::WalletModel(CWallet* wallet, OptionsModel* optionsModel, QObject* parent) : QObject(parent), wallet(wallet), optionsModel(optionsModel), addressTableModel(0),
                                                                                         transactionTableModel(0),
                                                                                         recentRequestsTableModel(0),
                                                                                         cachedBalance(0), cachedUnconfirmedBalance(0), spendableBalance(0), cachedImmatureBalance(0), cachedWatchOnlyBalance(0),
                                                                                         cachedWatchUnconfBalance(0), cachedWatchImmatureBalance(0),
                                                                                         cachedEncryptionStatus(Unencrypted),
                                                                                         cachedNumBlocks(0), cachedTxLocks(0),
                                                                                         txTableModel(0)

{
    fHaveWatchOnly = wallet->HaveWatchOnly();
    fHaveMultiSig = wallet->HaveMultiSig();
    fForceCheckBalanceChanged = false;

    addressTableModel = new AddressTableModel(wallet, this);
    transactionTableModel = new TransactionTableModel(wallet, this);
    recentRequestsTableModel = new RecentRequestsTableModel(wallet, this);

    // This timer will be fired repeatedly to update the balance
    pollTimer = new QTimer(this);
    connect(pollTimer, SIGNAL(timeout()), this, SLOT(pollBalanceChanged()));
    pollTimer->start(MODEL_UPDATE_DELAY);

    subscribeToCoreSignals();
}

WalletModel::~WalletModel()
{
    unsubscribeFromCoreSignals();
}

CAmount WalletModel::getBalance(const CCoinControl* coinControl) const
{
    if (coinControl) {

        {   
            return wallet->GetBalance();
        }
    }

    return wallet->GetBalance();
}

CAmount WalletModel::getUnconfirmedBalance() const
{
    return wallet->GetUnconfirmedBalance();
}

CAmount WalletModel::getSpendableBalance() const 
{
    return wallet->GetSpendableBalance();
}

CAmount WalletModel::getImmatureBalance() const
{
    return wallet->GetImmatureBalance();
}

CAmount WalletModel::getLockedBalance() const
{
    return wallet->GetLockedCoins();
}

bool WalletModel::haveWatchOnly() const
{
    return fHaveWatchOnly;
}

CAmount WalletModel::getWatchBalance() const
{
    return wallet->GetWatchOnlyBalance();
}

CAmount WalletModel::getWatchUnconfirmedBalance() const
{
    return wallet->GetUnconfirmedWatchOnlyBalance();
}

CAmount WalletModel::getWatchImmatureBalance() const
{
    return wallet->GetImmatureWatchOnlyBalance();
}

void WalletModel::updateStatus()
{
    EncryptionStatus newEncryptionStatus = getEncryptionStatus();

    if (cachedEncryptionStatus != newEncryptionStatus)
        emit encryptionStatusChanged(newEncryptionStatus);
}

void WalletModel::pollBalanceChanged()
{
	if (wallet->walletUnlockCountStatus == 1) {
		emit WalletUnlocked();
		wallet->walletUnlockCountStatus++;
	}
    // Get required locks upfront. This avoids the GUI from getting stuck on
    // periodical polls if the core is holding the locks for a longer time -
    // for example, during a wallet rescan.
    TRY_LOCK(cs_main, lockMain);
    if (!lockMain)
        return;
    TRY_LOCK(wallet->cs_wallet, lockWallet);
    if (!lockWallet)
        return;

    if (fForceCheckBalanceChanged || chainActive.Height() != cachedNumBlocks || cachedTxLocks != nCompleteTXLocks) {
        fForceCheckBalanceChanged = false;

        // Balance and number of transactions might have changed
        cachedNumBlocks = chainActive.Height();

        checkBalanceChanged();
        if (transactionTableModel) {
            transactionTableModel->updateConfirmations();
        }
    } else {
        checkBalanceChanged();
    }
}

void WalletModel::emitBalanceChanged()
{
    // Force update of UI elements even when no values have changed
    if (cachedBalance == 0 && !checkBalanceChanged())
        return;
    
    emit balanceChanged(cachedBalance, cachedUnconfirmedBalance, cachedImmatureBalance,
        cachedWatchOnlyBalance, cachedWatchUnconfBalance, cachedWatchImmatureBalance);
}

bool WalletModel::checkBalanceChanged()
{
    TRY_LOCK(cs_main, lockMain);
    if (!lockMain) return false;
    TRY_LOCK(pwalletMain->cs_wallet, lockWallet);
    if (!lockWallet) return false;
    CAmount newBalance = getBalance();
    CAmount newUnconfirmedBalance = getUnconfirmedBalance();
    CAmount newImmatureBalance = getImmatureBalance();
    CAmount newSpendableBalance = newBalance - newImmatureBalance;
    static bool stkEnabled = false;
    static bool walletLocked = pwalletMain->IsLocked();
    CAmount newWatchOnlyBalance = 0;
    CAmount newWatchUnconfBalance = 0;
    CAmount newWatchImmatureBalance = 0;
    if (haveWatchOnly()) {
        newWatchOnlyBalance = getWatchBalance();
        newWatchUnconfBalance = getWatchUnconfirmedBalance();
        newWatchImmatureBalance = getWatchImmatureBalance();
    }

    if (walletLocked != pwalletMain->IsLocked() || 
        (stkEnabled != (nLastCoinStakeSearchInterval > 0)) || 
        newSpendableBalance != spendableBalance || 
        cachedBalance != newBalance || 
        cachedUnconfirmedBalance != newUnconfirmedBalance || 
        cachedImmatureBalance != newImmatureBalance ||
        cachedWatchOnlyBalance != newWatchOnlyBalance || 
        cachedWatchUnconfBalance != newWatchUnconfBalance || 
        cachedWatchImmatureBalance != newWatchImmatureBalance ||
        cachedTxLocks != nCompleteTXLocks) {
        cachedBalance = newBalance;
        cachedUnconfirmedBalance = newUnconfirmedBalance;
        cachedImmatureBalance = newImmatureBalance;
        spendableBalance = newSpendableBalance;
        cachedTxLocks = nCompleteTXLocks;
        cachedWatchOnlyBalance = newWatchOnlyBalance;
        cachedWatchUnconfBalance = newWatchUnconfBalance;
        cachedWatchImmatureBalance = newWatchImmatureBalance;
        stkEnabled = (nLastCoinStakeSearchInterval > 0);
        walletLocked = pwalletMain->IsLocked();
        emit balanceChanged(newBalance, newUnconfirmedBalance, newImmatureBalance,
            newWatchOnlyBalance, newWatchUnconfBalance, newWatchImmatureBalance);
        return true;
    }

    return false;
}

void WalletModel::updateTransaction()
{
    // Balance and number of transactions might have changed
    fForceCheckBalanceChanged = true;
}

void WalletModel::updateAddressBook(const QString& address, const QString& label, bool isMine, const QString& purpose, int status)
{
    if (addressTableModel)
        addressTableModel->updateEntry(address, label, isMine, purpose, status);
}
void WalletModel::updateAddressBook(const QString& pubCoin, const QString& isUsed, int status)
{
    if (addressTableModel)
        addressTableModel->updateEntry(pubCoin, isUsed, status);
}


void WalletModel::updateWatchOnlyFlag(bool fHaveWatchonly)
{
    fHaveWatchOnly = fHaveWatchonly;
    emit notifyWatchonlyChanged(fHaveWatchonly);
}

void WalletModel::updateMultiSigFlag(bool fHaveMultiSig)
{
    this->fHaveMultiSig = fHaveMultiSig;
    emit notifyMultiSigChanged(fHaveMultiSig);
}

bool WalletModel::validateAddress(const QString& address)
{
    CBitcoinAddress addressParsed(address.toStdString());
    bool valid = (regex_match(address.toStdString(), regex("[a-zA-z0-9]+")))&&(address.length()==99||address.length()==110);
    return valid||addressParsed.IsValid();
}

WalletModel::SendCoinsReturn WalletModel::prepareTransaction(WalletModelTransaction& transaction, const CCoinControl* coinControl)
{
    CAmount total = 0;
    QList<SendCoinsRecipient> recipients = transaction.getRecipients();
    std::vector<std::pair<CScript, CAmount> > vecSend;

    if (recipients.empty()) {
        return OK;
    }

    if (isAnonymizeOnlyUnlocked()) {
        return AnonymizeOnlyUnlocked;
    }

    QSet<QString> setAddress; // Used to detect duplicates
    int nAddresses = 0;

    // Pre-check input data for validity
    foreach (const SendCoinsRecipient& rcp, recipients) {
        if (rcp.paymentRequest.IsInitialized()) { // PaymentRequest...
            CAmount subtotal = 0;
            const payments::PaymentDetails& details = rcp.paymentRequest.getDetails();
            for (int i = 0; i < details.outputs_size(); i++) {
                const payments::Output& out = details.outputs(i);
                if (out.amount() <= 0) continue;
                subtotal += out.amount();
                const unsigned char* scriptStr = (const unsigned char*)out.script().data();
                CScript scriptPubKey(scriptStr, scriptStr + out.script().size());
                vecSend.push_back(std::pair<CScript, CAmount>(scriptPubKey, out.amount()));
            }
            if (subtotal <= 0) {
                return InvalidAmount;
            }
            total += subtotal;
        } else { // User-entered dapscoin address / amount:
            if (!validateAddress(rcp.address)) {
                return InvalidAddress;
            }
            if (rcp.amount <= 0) {
                return InvalidAmount;
            }
            setAddress.insert(rcp.address);
            ++nAddresses;

            CScript scriptPubKey = GetScriptForDestination(CBitcoinAddress(rcp.address.toStdString()).Get());
            vecSend.push_back(std::pair<CScript, CAmount>(scriptPubKey, rcp.amount));

            total += rcp.amount;
        }
    }
    if (setAddress.size() != nAddresses) {
        return DuplicateAddress;
    }

    CAmount nBalance = getBalance(coinControl);

    if (total > nBalance) {
        return AmountExceedsBalance;
    }

    {
        LOCK2(cs_main, wallet->cs_wallet);

        transaction.newPossibleKeyChange(wallet);
        CAmount nFeeRequired = 0;
        std::string strFailReason;

        CWalletTx* newTx = transaction.getTransaction();
        CReserveKey* keyChange = transaction.getPossibleKeyChange();

        bool fCreated = wallet->CreateTransaction(vecSend, *newTx, *keyChange, nFeeRequired, strFailReason, coinControl, recipients[0].inputType, recipients[0].useSwiftTX);
        transaction.setTransactionFee(nFeeRequired);

        if (!fCreated) {
            if ((total + nFeeRequired) > nBalance) {
                return SendCoinsReturn(AmountWithFeeExceedsBalance);
            }
            emit message(tr("Send Coins"), QString::fromStdString(strFailReason),
                CClientUIInterface::MSG_ERROR);
            return TransactionCreationFailed;
        }

        // reject insane fee
        if (nFeeRequired > ::minRelayTxFee.GetFee(transaction.getTransactionSize()) * 10000)
            return InsaneFee;
    }

    return SendCoinsReturn(OK);
}

WalletModel::SendCoinsReturn WalletModel::sendCoins(WalletModelTransaction& transaction)
{
    QByteArray transaction_array; /* store serialized transaction */

    std::string stealthAddr = transaction.getRecipients()[0].address.toStdString();
    CAmount nValue = transaction.getRecipients()[0].amount;
    CWalletTx wtxNew;
    CPartialTransaction ptx;

    if (wallet->SendToStealthAddress(ptx, stealthAddr, nValue, wtxNew,false))
        return SendCoinsReturn(OK);

    return SendCoinsReturn(TransactionCommitFailed);
}

OptionsModel* WalletModel::getOptionsModel()
{
    return optionsModel;
}

AddressTableModel* WalletModel::getAddressTableModel()
{
    return addressTableModel;
}

TransactionTableModel* WalletModel::getTransactionTableModel()
{
    return transactionTableModel;
}

RecentRequestsTableModel* WalletModel::getRecentRequestsTableModel()
{
    return recentRequestsTableModel;
}

WalletModel::EncryptionStatus WalletModel::getEncryptionStatus() const
{
    if (!wallet->IsLocked()) {
        return Unencrypted;
    } else if (wallet->fWalletUnlockAnonymizeOnly) {
        return UnlockedForAnonymizationOnly;
    } else if (wallet->IsLocked()) {
        return Locked;
    } else {
        return Unlocked;
    }
}

bool WalletModel::isMultiSigSetup() const
{
	return wallet->IsMultisigSetup();
}

bool WalletModel::setWalletEncrypted(bool encrypted, const SecureString& passphrase)
{
    if (encrypted) {
        // Encrypt
        return wallet->EncryptWallet(passphrase);
    } else {
        // Decrypt -- TODO; not supported yet
        return false;
    }
}

bool WalletModel::setWalletLocked(bool locked, const SecureString& passPhrase, bool anonymizeOnly)
{
    if (locked) {
        // Lock
        wallet->fWalletUnlockAnonymizeOnly = false;
        return wallet->Lock();
    } else {
        // Unlock
        return wallet->Unlock(passPhrase, anonymizeOnly);
    }
}

bool WalletModel::isAnonymizeOnlyUnlocked()
{
    return wallet->fWalletUnlockAnonymizeOnly;
}

bool WalletModel::changePassphrase(const SecureString& oldPass, const SecureString& newPass)
{
    bool retval;
    {
        LOCK(wallet->cs_wallet);
        wallet->Lock(); // Make sure wallet is locked before attempting pass change
        retval = wallet->ChangeWalletPassphrase(oldPass, newPass);
    }
    return retval;
}

bool WalletModel::backupWallet(const QString& filename)
{
    return BackupWallet(*wallet, filename.toLocal8Bit().data());
}

// Handlers for core signals
static void NotifyKeyStoreStatusChanged(WalletModel* walletmodel, CCryptoKeyStore* wallet)
{
    qDebug() << "NotifyKeyStoreStatusChanged";
    QMetaObject::invokeMethod(walletmodel, "updateStatus", Qt::QueuedConnection);
}

static void NotifyAddressBookChanged(WalletModel* walletmodel, CWallet* wallet, const CTxDestination& address, const std::string& label, bool isMine, const std::string& purpose, ChangeType status)
{
    QString strAddress = QString::fromStdString(CBitcoinAddress(address).ToString());
    QString strLabel = QString::fromStdString(label);
    QString strPurpose = QString::fromStdString(purpose);

    qDebug() << "NotifyAddressBookChanged : " + strAddress + " " + strLabel + " isMine=" + QString::number(isMine) + " purpose=" + strPurpose + " status=" + QString::number(status);
    QMetaObject::invokeMethod(walletmodel, "updateAddressBook", Qt::QueuedConnection,
        Q_ARG(QString, strAddress),
        Q_ARG(QString, strLabel),
        Q_ARG(bool, isMine),
        Q_ARG(QString, strPurpose),
        Q_ARG(int, status));
}

// queue notifications to show a non freezing progress dialog e.g. for rescan
static bool fQueueNotifications = false;
static std::vector<std::pair<uint256, ChangeType> > vQueueNotifications;
static void NotifyTransactionChanged(WalletModel* walletmodel, CWallet* wallet, const uint256& hash, ChangeType status)
{
    if (fQueueNotifications) {
        vQueueNotifications.push_back(make_pair(hash, status));
        return;
    }

    QString strHash = QString::fromStdString(hash.GetHex());

    qDebug() << "NotifyTransactionChanged : " + strHash + " status= " + QString::number(status);
    QMetaObject::invokeMethod(walletmodel, "updateTransaction", Qt::QueuedConnection
    );
}

static void ShowProgress(WalletModel* walletmodel, const std::string& title, int nProgress)
{
    // emits signal "showProgress"
    QMetaObject::invokeMethod(walletmodel, "showProgress", Qt::QueuedConnection,
        Q_ARG(QString, QString::fromStdString(title)),
        Q_ARG(int, nProgress));
}

static void NotifyWatchonlyChanged(WalletModel* walletmodel, bool fHaveWatchonly)
{
    QMetaObject::invokeMethod(walletmodel, "updateWatchOnlyFlag", Qt::QueuedConnection,
        Q_ARG(bool, fHaveWatchonly));
}

static void NotifyMultiSigChanged(WalletModel* walletmodel, bool fHaveMultiSig)
{
    QMetaObject::invokeMethod(walletmodel, "updateMultiSigFlag", Qt::QueuedConnection,
        Q_ARG(bool, fHaveMultiSig));
}

void WalletModel::subscribeToCoreSignals()
{
    // Connect signals to wallet
    wallet->NotifyStatusChanged.connect(boost::bind(&NotifyKeyStoreStatusChanged, this, _1));
    wallet->NotifyAddressBookChanged.connect(boost::bind(NotifyAddressBookChanged, this, _1, _2, _3, _4, _5, _6));
    wallet->NotifyTransactionChanged.connect(boost::bind(NotifyTransactionChanged, this, _1, _2, _3));
    wallet->ShowProgress.connect(boost::bind(ShowProgress, this, _1, _2));
    wallet->NotifyWatchonlyChanged.connect(boost::bind(NotifyWatchonlyChanged, this, _1));
    wallet->NotifyMultiSigChanged.connect(boost::bind(NotifyMultiSigChanged, this, _1));
}

void WalletModel::unsubscribeFromCoreSignals()
{
    // Disconnect signals from wallet
    wallet->NotifyStatusChanged.disconnect(boost::bind(&NotifyKeyStoreStatusChanged, this, _1));
    wallet->NotifyAddressBookChanged.disconnect(boost::bind(NotifyAddressBookChanged, this, _1, _2, _3, _4, _5, _6));
    wallet->NotifyTransactionChanged.disconnect(boost::bind(NotifyTransactionChanged, this, _1, _2, _3));
    wallet->ShowProgress.disconnect(boost::bind(ShowProgress, this, _1, _2));
    wallet->NotifyWatchonlyChanged.disconnect(boost::bind(NotifyWatchonlyChanged, this, _1));
    wallet->NotifyMultiSigChanged.disconnect(boost::bind(NotifyMultiSigChanged, this, _1));
}

// WalletModel::UnlockContext implementation
WalletModel::UnlockContext WalletModel::requestUnlock(bool relock)
{
    bool was_locked = getEncryptionStatus() == Locked;

    if (!was_locked && isAnonymizeOnlyUnlocked()) {
        setWalletLocked(true);
        wallet->fWalletUnlockAnonymizeOnly = false;
        was_locked = getEncryptionStatus() == Locked;
    }

    if (was_locked) {
        // Request UI to unlock wallet
        emit requireUnlock();
    }
    // If wallet is still locked, unlock was failed or cancelled, mark context as invalid
    bool valid = getEncryptionStatus() != Locked;

    return UnlockContext(valid, relock);
}

WalletModel::UnlockContext::UnlockContext(bool valid, bool relock) : valid(valid), relock(relock)
{
}

WalletModel::UnlockContext::~UnlockContext()
{
}

CWallet* WalletModel::getCWallet()
{
    return this->wallet;
}

void WalletModel::UnlockContext::CopyFrom(const UnlockContext& rhs)
{
    // Transfer context; old object no longer relocks wallet
    *this = rhs;
    rhs.relock = false;
}

bool WalletModel::getPubKey(const CKeyID& address, CPubKey& vchPubKeyOut) const
{
    return wallet->GetPubKey(address, vchPubKeyOut);
}

// returns a list of COutputs from COutPoints
void WalletModel::getOutputs(const std::vector<COutPoint>& vOutpoints, std::vector<COutput>& vOutputs)
{
    LOCK2(cs_main, wallet->cs_wallet);
    for (const COutPoint& outpoint : vOutpoints) {
        if (!wallet->mapWallet.count(outpoint.hash)) continue;
        int nDepth = wallet->mapWallet[outpoint.hash].GetDepthInMainChain();
        if (nDepth < 0) continue;
        COutput out(&wallet->mapWallet[outpoint.hash], outpoint.n, nDepth, true);
        vOutputs.push_back(out);
    }
}

bool WalletModel::isSpent(const COutPoint& outpoint) const
{
    LOCK2(cs_main, wallet->cs_wallet);
    return wallet->IsSpent(outpoint.hash, outpoint.n);
}

// AvailableCoins + LockedCoins grouped by wallet address (put change in one group with wallet address)
void WalletModel::listCoins(std::map<QString, std::vector<COutput> >& mapCoins) const
{
    std::vector<COutput> vCoins;
    wallet->AvailableCoins(vCoins);

    LOCK2(cs_main, wallet->cs_wallet); // ListLockedCoins, mapWallet
    std::vector<COutPoint> vLockedCoins;
    wallet->ListLockedCoins(vLockedCoins);

    // add locked coins
    for (const COutPoint& outpoint : vLockedCoins) {
        if (!wallet->mapWallet.count(outpoint.hash)) continue;
        int nDepth = wallet->mapWallet[outpoint.hash].GetDepthInMainChain();
        if (nDepth < 0) continue;
        COutput out(&wallet->mapWallet[outpoint.hash], outpoint.n, nDepth, true);
        if (outpoint.n < out.tx->vout.size() && wallet->IsMine(out.tx->vout[outpoint.n]) == ISMINE_SPENDABLE)
            vCoins.push_back(out);
    }

    for (const COutput& out : vCoins) {
        COutput cout = out;

        while (wallet->IsChange(cout.tx->vout[cout.i]) && cout.tx->vin.size() > 0 && wallet->IsMine(*cout.tx, cout.tx->vin[0])) {
            if (!wallet->mapWallet.count(wallet->findMyOutPoint(*cout.tx, cout.tx->vin[0]).hash)) break;
            cout = COutput(&wallet->mapWallet[wallet->findMyOutPoint(*cout.tx, cout.tx->vin[0]).hash], wallet->findMyOutPoint(*cout.tx, cout.tx->vin[0]).n, 0, true);
        }

        CTxDestination address;
        if (!out.fSpendable || !ExtractDestination(cout.tx->vout[cout.i].scriptPubKey, address))
            continue;
        mapCoins[QString::fromStdString(CBitcoinAddress(address).ToString())].push_back(out);
    }
}

bool WalletModel::isLockedCoin(uint256 hash, unsigned int n) const
{
    LOCK2(cs_main, wallet->cs_wallet);   
    return wallet->IsLockedCoin(hash, n);
}

void WalletModel::lockCoin(COutPoint& output)
{   
    LOCK2(cs_main, wallet->cs_wallet);
    wallet->LockCoin(output);
}

void WalletModel::unlockCoin(COutPoint& output)
{
    LOCK2(cs_main, wallet->cs_wallet);
    wallet->UnlockCoin(output);
}

void WalletModel::listLockedCoins(std::vector<COutPoint>& vOutpts)
{
    LOCK2(cs_main, wallet->cs_wallet);
    wallet->ListLockedCoins(vOutpts);
}

void WalletModel::loadReceiveRequests(std::vector<std::string>& vReceiveRequests)
{
    LOCK(wallet->cs_wallet);
    for (const PAIRTYPE(CTxDestination, CAddressBookData) & item : wallet->mapAddressBook)
        for (const PAIRTYPE(std::string, std::string) & item2 : item.second.destdata)
            if (item2.first.size() > 2 && item2.first.substr(0, 2) == "rr") // receive request
                vReceiveRequests.push_back(item2.second);
}

bool WalletModel::saveReceiveRequest(const std::string& sAddress, const int64_t nId, const std::string& sRequest)
{
    CTxDestination dest = CBitcoinAddress(sAddress).Get();

    std::stringstream ss;
    ss << nId;
    std::string key = "rr" + ss.str(); // "rr" prefix = "receive request" in destdata

    LOCK(wallet->cs_wallet);
    if (sRequest.empty())
        return wallet->EraseDestData(dest, key);
    else
        return wallet->AddDestData(dest, key, sRequest);
}

bool WalletModel::isMine(CBitcoinAddress address)
{
    return IsMine(*wallet, address.Get());
}

StakingStatusError WalletModel::getStakingStatusError(QString& error)
{
    /* {
    	bool fMintable = pwalletMain->MintableCoins();
    	CAmount balance = pwalletMain->GetSpendableBalance();
    	if (!fMintable || nReserveBalance > balance) {
    		if (balance < CWallet::MINIMUM_STAKE_AMOUNT) {
    			error = "\nBalance is under the minimum 400,000 staking threshold.\nPlease send more DAPS to this wallet.\n";
    			return StakingStatusError::STAKING_OK;
    		}
    		if (nReserveBalance > balance || (balance > nReserveBalance && balance - nReserveBalance < CWallet::MINIMUM_STAKE_AMOUNT)) {
    			error = "Reserve balance is too high.\nPlease lower it in order to turn staking on.";
    			return StakingStatusError::RESERVE_TOO_HIGH;
    		}
			if (!fMintable) {
				if (balance > CWallet::MINIMUM_STAKE_AMOUNT) {
					//10 is to cover transaction fees
					if (balance >= CWallet::MINIMUM_STAKE_AMOUNT + 10*COIN) {
						error = "Not enough mintable coins.\nDo you want to merge & make a sent-to-yourself transaction to make the wallet stakable?";
						return StakingStatusError::UTXO_UNDER_THRESHOLD;
					}
				}
			}
		}
    }*/
    return StakingStatusError::STAKING_OK;
}

void WalletModel::generateCoins(bool fGenerate, int nGenProcLimit)
{
    GenerateDapscoins(fGenerate, pwalletMain, nGenProcLimit);
    if (false /*if regtest*/ && fGenerate) {
        //regtest generate
    } else {
        GenerateDapscoins(fGenerate, pwalletMain, nGenProcLimit);
    }
}

QAbstractTableModel* WalletModel::getTxTableModel()
{
    if (!txTableModel) {
        return NULL;
    } else
        return txTableModel;
}

namespace WalletUtil
{
std::map<QString, QString> getTx(CWallet* wallet, uint256 hash)
{
    return getTx(wallet, *wallet->GetWalletTx(hash));
}

vector<std::map<QString, QString> > getTXs(CWallet* wallet)
{
	vector<std::map<QString, QString> > txs;
	if (!wallet || wallet->IsLocked()) return txs;
	std::map<uint256, CWalletTx> txMap = wallet->mapWallet;
	{
		LOCK2(cs_main, wallet->cs_wallet);
		for (std::map<uint256, CWalletTx>::iterator tx = txMap.begin(); tx != txMap.end(); ++tx) {
			if (tx->second.GetDepthInMainChain() > 0) {
				txs.push_back(getTx(wallet, tx->second));
			}
		}
	}

    return txs;
}

std::map<QString, QString> getTx(CWallet* wallet, CWalletTx tx)
{

    // get stx amount
    CAmount totalamount = CAmount(0);
    CAmount totalIn = 0;
    if (wallet && !wallet->IsLocked()) {
    	for (CTxIn in: tx.vin) {
    		COutPoint prevout = wallet->findMyOutPoint(tx, in);
    		map<uint256, CWalletTx>::const_iterator mi = wallet->mapWallet.find(prevout.hash);
    		if (mi != wallet->mapWallet.end()) {
    			const CWalletTx& prev = (*mi).second;
    			if (prevout.n < prev.vout.size()) {
    				if (wallet->IsMine(prev.vout[prevout.n])) {
    					CAmount decodedAmount = 0;
    					CKey blind;
    					pwalletMain->RevealTxOutAmount(prev, prev.vout[prevout.n], decodedAmount, blind);
    					totalIn += decodedAmount;
    				}
    			}
    		}
    	}
    }
    CAmount firstOut = 0;
    if (wallet && !wallet->IsLocked()) {
		for (CTxOut out: tx.vout){
			CAmount vamount;
			CKey blind;
			if (wallet->IsMine(out) && wallet->RevealTxOutAmount(tx,out,vamount, blind)) {
				if (vamount != 0 && firstOut == 0) {
					firstOut = vamount;
				}
				totalamount+=vamount;   //this is the total output
			}
		}
    }
    QList<TransactionRecord> decomposedTx = TransactionRecord::decomposeTransaction(wallet, tx);
    std::string txHash = tx.GetHash().GetHex();
    QList<QString> addressBook = getAddressBookData(wallet);
    std::map<QString, QString> txData;
    
    if (tx.hashBlock != 0) {
        BlockMap::iterator mi = mapBlockIndex.find(tx.hashBlock);
        if (mi != mapBlockIndex.end() && (*mi).second) {
            CBlockIndex* pindex = (*mi).second;
            if (chainActive.Contains(pindex))
                txData["confirmations"] = QString::number(1 + chainActive.Height() - pindex->nHeight);
            else
                txData["confirmations"] = QString::number(0);
        }
    }

    for (TransactionRecord TxRecord : decomposedTx) {
        txData["date"] = QString(GUIUtil::dateTimeStr(TxRecord.time));
        // if address is in book, use data from book, else use data from transaction
        txData["address"]=""; 
//        for (QString addressBookEntry : addressBook)
//            if (addressBookEntry.contains(TxRecord.address.c_str())) {
//                txData["address"] = addressBookEntry;
//                wallet->addrToTxHashMap[addressBookEntry.toStdString()] = txHash;
//            }
        if (!txData["address"].length()) {
            txData["address"] = QString(TxRecord.address.c_str());
            wallet->addrToTxHashMap[TxRecord.address] = txHash;
        }

        txData["amount"] = BitcoinUnits::format(0, totalamount); //absolute value of total amount
        txData["id"] = QString(TxRecord.hash.GetHex().c_str());
        // parse transaction type
        switch (TxRecord.type) {
        case 1:
            txData["type"] = QString("Mined");
            txData["amount"] = BitcoinUnits::format(0, totalamount - totalIn); //absolute value of total amount
            return txData;
            break;
        case TransactionRecord::SendToSelf:
        	txData["type"] = QString("Payment to yourself");
        	txData["amount"] = BitcoinUnits::format(0, TxRecord.debit); //absolute value of total amount
        	return txData;
        	break;
        case TransactionRecord::SendToAddress:
        case TransactionRecord::SendToOther:
            txData["type"] = QString("Sent");
            txData["amount"] = BitcoinUnits::format(0, totalIn - totalamount - tx.nTxFee); //absolute value of total amount
            return txData;
            break;
        case 0:
        case TransactionRecord::RecvWithAddress:
        case TransactionRecord::RecvFromOther:
        case TransactionRecord::RecvWithObfuscation:
            txData["type"] = QString("Received");
            break;
        case 2:
            txData["type"] = QString("Minted");
            txData["amount"] = BitcoinUnits::format(0,  totalamount - totalIn); //absolute value of total amount
            break;
        case TransactionRecord::MNReward:
            txData["type"] = QString("Masternode");
            txData["amount"] = BitcoinUnits::format(0,  TxRecord.credit); //absolute value of total amount
            break;     
        default:
            txData["type"] = QString("Unknown");
        }
    }
    return txData;
}

QList<QString> getAddressBookData(CWallet* wallet)
{
    std::map<CTxDestination, CAddressBookData> mapAddressBook = pwalletMain->mapAddressBook;
    QList<QString> AddressBookData;
    for (std::map<CTxDestination, CAddressBookData>::iterator address = mapAddressBook.begin(); address != mapAddressBook.end(); ++address) {
        QString desc = address->second.name.c_str();
        QString addressHash = CBitcoinAddress(address->first).ToString().c_str();
        if (desc.length())
            AddressBookData.push_front(desc + " | " + addressHash);
        else
            AddressBookData.push_front(addressHash);
       
    }
    return AddressBookData;
}

} // namespace WalletUtil
