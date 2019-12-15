// Copyright (c) 2011-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2018 The PIVX developers
// Copyright (c) 2018-2019 The DAPS Project developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "overviewpage.h"
#include "ui_overviewpage.h"
#include "unlockdialog.h"
#include "lockdialog.h"
#include "bitcoinunits.h"
#include "clientmodel.h"
#include "guiconstants.h"
#include "guiutil.h"
#include "init.h"
#include "obfuscation.h"
#include "optionsmodel.h"
#include "transactionfilterproxy.h"
#include "transactiontablemodel.h"
#include "txentry.h"
#include "walletmodel.h"

#include <QAbstractItemDelegate>
#include <QPainter>
#include <QSettings>
#include <QTimer>
#include <QtMath>

#define DECORATION_SIZE 48
#define ICON_OFFSET 16
#define NUM_ITEMS 5

extern CWallet* pwalletMain;

class TxViewDelegate : public QAbstractItemDelegate
{
    Q_OBJECT
public:
    TxViewDelegate() : QAbstractItemDelegate(), unit(BitcoinUnits::DAPS)
    {
    }

    inline void paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& index) const
    {
        painter->save();

        QIcon icon = qvariant_cast<QIcon>(index.data(Qt::DecorationRole));
        QRect mainRect = option.rect;
        mainRect.moveLeft(ICON_OFFSET);
        QRect decorationRect(mainRect.topLeft(), QSize(DECORATION_SIZE, DECORATION_SIZE));
        int xspace = DECORATION_SIZE + 8;
        int ypad = 6;
        int halfheight = (mainRect.height() - 2 * ypad) / 2;
        QRect amountRect(mainRect.left() + xspace, mainRect.top() + ypad, mainRect.width() - xspace - ICON_OFFSET, halfheight);
        QRect addressRect(mainRect.left() + xspace, mainRect.top() + ypad + halfheight, mainRect.width() - xspace, halfheight);
        icon.paint(painter, decorationRect);

        QDateTime date = index.data(TransactionTableModel::DateRole).toDateTime();
        QString address = index.data(Qt::DisplayRole).toString();
        qint64 amount = index.data(TransactionTableModel::AmountRole).toLongLong();
        bool confirmed = index.data(TransactionTableModel::ConfirmedRole).toBool();
        QVariant value = index.data(Qt::ForegroundRole);
        QColor foreground = COLOR_BLACK;
        if (value.canConvert<QBrush>()) {
            QBrush brush = qvariant_cast<QBrush>(value);
            foreground = brush.color();
        }

        painter->setPen(foreground);
        QRect boundingRect;
        painter->drawText(addressRect, Qt::AlignLeft | Qt::AlignVCenter, address, &boundingRect);

        if (index.data(TransactionTableModel::WatchonlyRole).toBool()) {
            QIcon iconWatchonly = qvariant_cast<QIcon>(index.data(TransactionTableModel::WatchonlyDecorationRole));
            QRect watchonlyRect(boundingRect.right() + 5, mainRect.top() + ypad + halfheight, 16, halfheight);
            iconWatchonly.paint(painter, watchonlyRect);
        }

        if (amount < 0) {
            foreground = COLOR_NEGATIVE;
        } else if (!confirmed) {
            foreground = COLOR_UNCONFIRMED;
        } else {
            foreground = COLOR_BLACK;
        }
        painter->setPen(foreground);
        QString amountText = BitcoinUnits::formatWithUnit(unit, amount, true, BitcoinUnits::separatorAlways);
        if (!confirmed) {
            amountText = QString("[") + amountText + QString("]");
        }
        painter->drawText(amountRect, Qt::AlignRight | Qt::AlignVCenter, amountText);

        painter->setPen(COLOR_BLACK);
        painter->drawText(amountRect, Qt::AlignLeft | Qt::AlignVCenter, GUIUtil::dateTimeStr(date));

        painter->restore();
    }

    inline QSize sizeHint(const QStyleOptionViewItem& option, const QModelIndex& index) const
    {
        return QSize(DECORATION_SIZE, DECORATION_SIZE);
    }

    int unit;
};
#include "overviewpage.moc"

OverviewPage::OverviewPage(QWidget* parent) : QDialog(parent, Qt::WindowSystemMenuHint | Qt::WindowTitleHint | Qt::WindowCloseButtonHint),
                                              ui(new Ui::OverviewPage),
                                              clientModel(0),
                                              walletModel(0),
                                              currentBalance(-1),
                                              currentUnconfirmedBalance(-1),
                                              currentImmatureBalance(-1),
                                              currentWatchOnlyBalance(-1),
                                              currentWatchUnconfBalance(-1),
                                              currentWatchImmatureBalance(-1),
                                              txdelegate(new TxViewDelegate()),
                                              // m_SizeGrip(this),
                                              filter(0)
{
    nDisplayUnit = 0; // just make sure it's not unitialized
    ui->setupUi(this);

    pingNetworkInterval = new QTimer(this);
    connect(pingNetworkInterval, SIGNAL(timeout()), this, SLOT(tryNetworkBlockCount()));
    pingNetworkInterval->setInterval(3000); pingNetworkInterval->start(); 
    
    pingNetworkInterval = new QTimer();

    initSyncCircle(.8);

    timerBlockHeightLabel = new QTimer(this);
    connect(timerBlockHeightLabel, SIGNAL(timeout()), this, SLOT(showBlockCurrentHeight()));
    timerBlockHeightLabel->start(45000);

    connect(ui->btnLockUnlock, SIGNAL(clicked()), this, SLOT(on_lockUnlock()));
}

void OverviewPage::handleTransactionClicked(const QModelIndex& index)
{
    if (filter)
        emit transactionClicked(filter->mapToSource(index));
}

OverviewPage::~OverviewPage()
{
    if (animClock)
        delete animClock;
    delete ui;
}

void OverviewPage::getPercentage(CAmount nUnlockedBalance, QString& sDAPSPercentage)
{
    int nPrecision = 2;
    double dPercentage = 100.0;
    sDAPSPercentage = "(" + QLocale(QLocale::system()).toString(dPercentage, 'f', nPrecision) + " %)";
}
void OverviewPage::setBalance(const CAmount& balance, const CAmount& unconfirmedBalance, const CAmount& immatureBalance, 
                              const CAmount& watchOnlyBalance, const CAmount& watchUnconfBalance, const CAmount& watchImmatureBalance)
{
    int walletStatus = walletModel->getEncryptionStatus();
    bool stkStatus = pwalletMain->ReadStakingStatus();

    currentBalance = balance;
    currentUnconfirmedBalance = unconfirmedBalance;
    currentImmatureBalance = immatureBalance;
    currentWatchOnlyBalance = watchOnlyBalance;
    currentWatchUnconfBalance = watchUnconfBalance;
    currentWatchImmatureBalance = watchImmatureBalance;
    CAmount nSpendableBalance = balance - immatureBalance;
    if (nSpendableBalance < 0) {
    	nSpendableBalance = pwalletMain->GetSpendableBalance();
    }
    CAmount nSpendableDisplayed = nSpendableBalance; //if it is not staking
    if (nLastCoinStakeSearchInterval) {
        //if staking enabled
        nSpendableDisplayed = nSpendableDisplayed > nReserveBalance ? nReserveBalance:nSpendableDisplayed;
    }
    // DAPS labels
    //TODO-NOTE: Remove immatureBalance from showing on qt wallet (as requested)
    if (walletStatus == WalletModel::Locked || walletStatus == WalletModel::UnlockedForAnonymizationOnly) {
        ui->labelBalance_2->setText("Locked; Hidden");
        ui->labelBalance->setText("Locked; Hidden");
        ui->labelUnconfirmed->setText("Locked; Hidden");
        ui->btnLockUnlock->setStyleSheet("border-image: url(:/images/lock) 0 0 0 0 stretch stretch; width: 20px;");
    } else {
        if (stkStatus && !nLastCoinStakeSearchInterval) {
            ui->labelBalance_2->setText("Enabling Staking...");
            ui->labelBalance_2->setToolTip("Enabling Staking... Please wait up to 1.5 hours for it to be properly enabled after consolidation.");
            ui->labelBalance->setText("Enabling Staking...");
        } else {
            ui->labelBalance_2->setText(BitcoinUnits::floorHtmlWithUnit(nDisplayUnit, balance, false, BitcoinUnits::separatorAlways));
            ui->labelBalance_2->setToolTip("Your current balance");
            ui->labelBalance->setText(BitcoinUnits::floorHtmlWithUnit(nDisplayUnit, nSpendableDisplayed, false, BitcoinUnits::separatorAlways));
        }
        ui->labelUnconfirmed->setText(BitcoinUnits::floorHtmlWithUnit(nDisplayUnit, unconfirmedBalance, false, BitcoinUnits::separatorAlways));
        ui->btnLockUnlock->setStyleSheet("border-image: url(:/images/unlock) 0 0 0 0 stretch stretch; width: 30px;");
    }
    QFont font = ui->labelBalance_2->font();
    font.setPointSize(15);
    font.setBold(true);
    ui->labelBalance_2->setFont(font);   

    refreshRecentTransactions();
}

// show/hide watch-only labels
void OverviewPage::updateWatchOnlyLabels(bool showWatchOnly)
{
        ui->labelBalance->setIndent(20);
        ui->labelUnconfirmed->setIndent(20);
}

void OverviewPage::setClientModel(ClientModel* model)
{
    this->clientModel = model;
    if (model) {
        // Show warning if this is a prerelease version
        connect(model, SIGNAL(alertsChanged(QString)), this, SLOT(updateAlerts(QString)));
        updateAlerts(model->getStatusBarWarnings());
    }
}

void OverviewPage::setSpendableBalance(bool isStaking) {
    TRY_LOCK(cs_main, lockMain);
    if (!lockMain)
        return;
    TRY_LOCK(pwalletMain->cs_wallet, lockWallet);
    if (!lockWallet)
        return;
    {
        CAmount nSpendableDisplayed = this->walletModel->getSpendableBalance();
        if (isStaking) {
            //if staking enabled
            nSpendableDisplayed = nSpendableDisplayed > nReserveBalance ? nReserveBalance:nSpendableDisplayed;
        }
        ui->labelBalance->setText(BitcoinUnits::floorHtmlWithUnit(nDisplayUnit, nSpendableDisplayed, false, BitcoinUnits::separatorAlways));
    }
}

void OverviewPage::setWalletModel(WalletModel* model)
{
    this->walletModel = model;
    if (model && model->getOptionsModel()) {
        // Set up transaction list
        LogPrintf("%s:setWalletModel\n", __func__);
        filter = new TransactionFilterProxy(this);
        filter->setSourceModel(model->getTransactionTableModel());
        filter->setLimit(NUM_ITEMS);
        filter->setDynamicSortFilter(true);
        filter->setSortRole(Qt::EditRole);
        filter->setShowInactive(false);
        filter->sort(TransactionTableModel::Date, Qt::DescendingOrder);

        // Keep up to date with wallet
        setBalance(model->getBalance(), model->getUnconfirmedBalance(), model->getImmatureBalance(),
                   model->getWatchBalance(), model->getWatchUnconfirmedBalance(), model->getWatchImmatureBalance());
        connect(model, SIGNAL(balanceChanged(CAmount, CAmount, CAmount, CAmount, CAmount, CAmount)), this, 
                         SLOT(setBalance(CAmount, CAmount, CAmount, CAmount, CAmount, CAmount)));
        connect(model, SIGNAL(stakingStatusChanged(bool)), this, 
                         SLOT(setSpendableBalance(bool)));
        connect(model, SIGNAL(WalletUnlocked()), this,
                                         SLOT(updateBalance()));
        connect(model, SIGNAL(encryptionStatusChanged(int)), this,
                                         SLOT(updateLockStatus(int)));
        
        connect(model->getOptionsModel(), SIGNAL(displayUnitChanged(int)), this, SLOT(updateDisplayUnit()));
        connect(model->getOptionsModel(), SIGNAL(hideOrphansChanged(bool)), this, SLOT(hideOrphans(bool)));

        updateWatchOnlyLabels(model->haveWatchOnly());
        connect(model, SIGNAL(notifyWatchonlyChanged(bool)), this, SLOT(updateWatchOnlyLabels(bool)));
        updateLockStatus(walletModel->getEncryptionStatus());
    }
    // update the display unit, to not use the default ("DAPS")
    updateDisplayUnit();

    // Hide orphans
    QSettings settings;
    hideOrphans(settings.value("fHideOrphans", false).toBool());
}

void OverviewPage::updateBalance()
{
	WalletModel* model = this->walletModel;
	setBalance(model->getBalance(), model->getUnconfirmedBalance(), model->getImmatureBalance(),
			model->getWatchBalance(), model->getWatchUnconfirmedBalance(), model->getWatchImmatureBalance());
}

void OverviewPage::updateDisplayUnit()
{
    if (walletModel && walletModel->getOptionsModel()) {
        nDisplayUnit = walletModel->getOptionsModel()->getDisplayUnit();
        if (currentBalance != -1)
            setBalance(currentBalance, currentUnconfirmedBalance, currentImmatureBalance,
                currentWatchOnlyBalance, currentWatchUnconfBalance, currentWatchImmatureBalance);

        // Update txdelegate->unit with the current unit
        txdelegate->unit = nDisplayUnit;
    }
}

void OverviewPage::hideOrphans(bool fHide)
{
    filter->setHideOrphans(fHide);
}

void OverviewPage::updateAlerts(const QString& warnings)
{
    this->ui->labelAlerts->setVisible(!warnings.isEmpty());
    this->ui->labelAlerts->setText(warnings);
}

void OverviewPage::showBalanceSync(bool fShow){
        ui->labelWalletStatus->setVisible(fShow);
        ui->labelPendingText->setVisible(true);
        ui->labelUnconfirmed->setVisible(true);
        ui->labelBalanceText->setVisible(true);
        isSyncingBalance = fShow;
}

void OverviewPage::showBlockSync(bool fShow)
{
    ui->labelBlockStatus->setVisible(true);
    ui->labelBlockOf->setVisible(fShow);
    ui->labelBlocksTotal->setVisible(fShow);

    isSyncingBlocks = fShow;

    ui->labelBlockCurrent->setText(QString::number(clientModel->getNumBlocks()));
    if (isSyncingBlocks){
        ui->labelBlockStatus->setText("(syncing)");
        ui->labelBlockCurrent->setAlignment((Qt::AlignRight|Qt::AlignVCenter));
    } else {
        ui->labelBlockStatus->setText("(synced)");
        ui->labelBlockCurrent->setAlignment((Qt::AlignHCenter|Qt::AlignVCenter));
    }
}

void OverviewPage::showBlockCurrentHeight()
{
    TRY_LOCK(cs_main, lockMain);
    if (!lockMain)
        return;
	ui->labelBlockCurrent->setText(QString::number(chainActive.Height()));
}

void OverviewPage::initSyncCircle(float ratioToParent)
{
    animTicker = new QTimer(this);
    animTicker->setInterval(17); //17 mSecs or ~60 fps
    animClock = new QElapsedTimer();
    connect(animTicker, SIGNAL(timeout()), this, SLOT(onAnimTick()));
    animTicker->start(); animClock->start();

    blockAnimSyncCircle = new QWidget(ui->widgetSyncBlocks);
    blockAnimSyncCircle->setStyleSheet("image:url(':/images/syncb')");//"background-image: ./image.png");
    blockAnimSyncCircle->setGeometry(getCircleGeometry(ui->widgetSyncBlocks, ratioToParent));
    blockAnimSyncCircle->show();

    blockSyncCircle = new QWidget(ui->widgetSyncBlocks);
    blockSyncCircle->setStyleSheet("image:url(':/images/syncp')");//"background-image: ./image.png");
    blockSyncCircle->setGeometry(getCircleGeometry(ui->widgetSyncBlocks, ratioToParent));
    blockSyncCircle->show();

    balanceAnimSyncCircle = new QWidget(ui->widgetSyncBalance);
    balanceAnimSyncCircle->setStyleSheet("image:url(':/images/syncb')");//"background-image: ./image.png");
    balanceAnimSyncCircle->setGeometry(getCircleGeometry(ui->widgetSyncBalance, ratioToParent));
    balanceAnimSyncCircle->show();

    balanceSyncCircle = new QWidget(ui->widgetSyncBalance);
    balanceSyncCircle->setStyleSheet("image:url(':/images/syncp')");//"background-image: ./image.png");
    balanceSyncCircle->setGeometry(getCircleGeometry(ui->widgetSyncBalance, ratioToParent));
    balanceSyncCircle->show();
}

void OverviewPage::onAnimTick()
{
    if (isSyncingBlocks){
        moveSyncCircle(blockSyncCircle, blockAnimSyncCircle, 3, 120);
        blockSyncCircle->setStyleSheet("image:url(':/images/syncp')");
        blockAnimSyncCircle->setVisible(true);
    } else {
        blockSyncCircle->setStyleSheet("image:url(':/images/syncb')");
        blockAnimSyncCircle->setVisible(false);
        ui->lblHelp->setVisible(false);
    }
    if (isSyncingBalance){
        moveSyncCircle(balanceSyncCircle, balanceAnimSyncCircle, 3, -100, 130);
        balanceSyncCircle->setStyleSheet("image:url(':/images/syncp')");
        balanceAnimSyncCircle->setVisible(true);
    } else {
        balanceSyncCircle->setStyleSheet("image:url(':/images/syncb')");
        balanceAnimSyncCircle->setVisible(false);
    }
    showBalanceSync(currentUnconfirmedBalance>0);
}

void OverviewPage::moveSyncCircle(QWidget* anchor, QWidget* animated, int deltaRadius, float degreesPerSecond, float angleOffset) //deltaRad in px
{
    auto centerX = anchor->parentWidget()->width()/10;  //center of anchor
    auto centerY = anchor->parentWidget()->height()/10;
    auto angle = float(animClock->elapsed()/*%3600*/)*degreesPerSecond/1000;
    angle = qDegreesToRadians(angle+angleOffset); //rotation angle from time elapsed
    auto newX = centerX+deltaRadius*qCos(angle); //delta position plus anchor position
    auto newY = centerY+deltaRadius*qSin(angle);

    animated->setGeometry(newX, newY, anchor->width(), anchor->height());
}

QRect OverviewPage::getCircleGeometry(QWidget* parent, float ratioToParent)
{
    auto width = parent->width()*ratioToParent;
    auto height = parent->height()*ratioToParent;
    auto x = (parent->width()-width)/2;
    auto y = (parent->height()-height)/2;
    return QRect(x,y,width,height);
}

void OverviewPage::updateTotalBlocksLabel(){
    ui->labelBlocksTotal->setText(QString::number(networkBlockCount));
}

int OverviewPage::tryNetworkBlockCount(){
    try{
        LOCK(cs_vNodes);
        if (vNodes.size()>=1){
            int highestCount = 0;
            for (CNode* node : vNodes)
                if (node->nStartingHeight>highestCount)
                    highestCount = node->nStartingHeight;
            if (highestCount>550){
                networkBlockCount = highestCount; 
                updateTotalBlocksLabel();
                return highestCount;
            }
        }
    }catch(int err_code)
    {
    }
    return -1;
}

void OverviewPage::updateRecentTransactions(){
    if (!pwalletMain) return;
    {
        LOCK2(cs_main, pwalletMain->cs_wallet);
        QLayoutItem* item;
        QSettings settings;
        QVariant theme = settings.value("theme");
        QString themeName = QString(theme.toString());

        while ( ( item = ui->verticalLayoutRecent->takeAt( 0 ) ) != NULL )
        {
            delete item->widget();
            delete item;
        }
        if (pwalletMain) {
            {
                vector<std::map<QString, QString>> txs;// = WalletUtil::getTXs(pwalletMain);

                std::map<uint256, CWalletTx> txMap = pwalletMain->mapWallet;
                std::vector<CWalletTx> latestTxes;
                for (std::map<uint256, CWalletTx>::iterator tx = txMap.begin(); tx != txMap.end(); ++tx) {
                    if (tx->second.GetDepthInMainChain() > 0) {
                        int64_t txTime = tx->second.GetComputedTxTime();
                        int idx = -1;
                        for (int i = 0; i < (int)latestTxes.size(); i++) {
                            if (txTime >= latestTxes[i].GetComputedTxTime()) {
                                idx = i;
                                break;
                            }
                        }
                        if (idx == -1) {
                            latestTxes.push_back(tx->second);
                        } else {
                            latestTxes.insert(latestTxes.begin() + idx, tx->second);
                        }
                    }
                }

                for (int i = 0; i < (int)latestTxes.size(); i++) {
                    txs.push_back(WalletUtil::getTx(pwalletMain, latestTxes[i]));
                    if (txs.size() >= 5) break;
                }

                int length = (txs.size()>5)? 5:txs.size();
                for (int i = 0; i< length; i++){
                    uint256 txHash;
                    txHash.SetHex(txs[i]["id"].toStdString());
                    TxEntry* entry = new TxEntry(this);
                    ui->verticalLayoutRecent->addWidget(entry);
                    CWalletTx wtx = pwalletMain->mapWallet[txHash];
                    int64_t txTime = wtx.GetComputedTxTime();
                    if (pwalletMain->IsLocked()) {
                        entry->setData(txTime, "Locked; Hidden", "Locked; Hidden", "Locked; Hidden", "Locked; Hidden");
                    } else {
                        entry->setData(txTime, txs[i]["address"] , txs[i]["amount"], txs[i]["id"], txs[i]["type"]);
                    }

                    if (i % 2 == 0) {
                        entry->setObjectName("secondaryTxEntry");
                    }
                }

                ui->lblRecentTransaction->setVisible(true);
            }
        } else {
            LogPrintf("pwalletMain has not been initialized\n");
        }
    }
}

void OverviewPage::refreshRecentTransactions() {
	updateRecentTransactions();
}

void OverviewPage::on_lockUnlock() {
    if (walletModel->getEncryptionStatus() == WalletModel::Locked || walletModel->getEncryptionStatus() == WalletModel::UnlockedForAnonymizationOnly) {
        UnlockDialog unlockdlg;
        unlockdlg.setWindowTitle("Unlock Keychain Wallet");
        unlockdlg.setModel(walletModel);
        unlockdlg.setStyleSheet(GUIUtil::loadStyleSheet());
        connect(&unlockdlg, SIGNAL(finished (int)), this, SLOT(unlockDialogIsFinished(int)));
        unlockdlg.exec();
    }
    else {
        LockDialog lockdlg;
        lockdlg.setWindowTitle("Lock Keychain Wallet");
        lockdlg.setModel(walletModel);
        lockdlg.setStyleSheet(GUIUtil::loadStyleSheet());
        connect(&lockdlg, SIGNAL(finished (int)), this, SLOT(lockDialogIsFinished(int)));
        lockdlg.exec();   
    }
}


void OverviewPage::unlockDialogIsFinished(int result) {
    if(result == QDialog::Accepted){
        ui->btnLockUnlock->setStyleSheet("border-image: url(:/images/unlock) 0 0 0 0 stretch stretch; width: 30px;");
        ui->labelBalance_2->setText(BitcoinUnits::floorHtmlWithUnit(nDisplayUnit, walletModel->getBalance(), false, BitcoinUnits::separatorAlways));
        ui->labelBalance->setText(BitcoinUnits::floorHtmlWithUnit(nDisplayUnit, walletModel->getSpendableBalance(), false, BitcoinUnits::separatorAlways));
        ui->labelUnconfirmed->setText(BitcoinUnits::floorHtmlWithUnit(nDisplayUnit, walletModel->getUnconfirmedBalance(), false, BitcoinUnits::separatorAlways));
        pwalletMain->stakingMode = StakingMode::STAKING_WITH_CONSOLIDATION;
    }
}

void OverviewPage::lockDialogIsFinished(int result) {
    if(result == QDialog::Accepted){
        ui->btnLockUnlock->setStyleSheet("border-image: url(:/images/lock) 0 0 0 0 stretch stretch; width: 20px;");
        ui->labelBalance_2->setText("Locked; Hidden");
        ui->labelBalance->setText("Locked; Hidden");
        ui->labelUnconfirmed->setText("Locked; Hidden");
        pwalletMain->stakingMode = StakingMode::STOPPED;
    }
}

void OverviewPage::updateLockStatus(int status) {
    if (!walletModel)
        return;

    // update wallet state
    if (status == WalletModel::Locked || status == WalletModel::UnlockedForAnonymizationOnly)
        ui->btnLockUnlock->setStyleSheet("border-image: url(:/images/lock) 0 0 0 0 stretch stretch; width: 20px;");
    else
        ui->btnLockUnlock->setStyleSheet("border-image: url(:/images/unlock) 0 0 0 0 stretch stretch; width: 30px;");
}
