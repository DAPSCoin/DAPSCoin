// Copyright (c) 2011-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2018 The PIVX developers
// Copyright (c) 2018-2020 The DAPS Project developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "bitcoingui.h"

#include "bitcoinunits.h"
#include "clientmodel.h"
#include "guiconstants.h"
#include "guiutil.h"
#include "miner.h"
#include "networkstyle.h"
#include "notificator.h"
#include "openuridialog.h"
#include "optionsdialog.h"
#include "optionsmodel.h"
#include "overviewpage.h"
#include "rpcconsole.h"
#include "utilitydialog.h"
#include "masternode-sync.h"

#ifdef ENABLE_WALLET
#include "blockexplorer.h"
#include "walletframe.h"
#include "walletmodel.h"
#endif // ENABLE_WALLET

#ifdef Q_OS_MAC
#include "macdockiconhandler.h"
#endif

#include "init.h"
#include "masternodelist.h"
#include "guiinterface.h"
#include "util.h"

#include <iostream>

#include <QAction>
#include <QApplication>
#include <QDateTime>
#include <QDesktopWidget>
#include <QDragEnterEvent>
#include <QIcon>
#include <QListWidget>
#include <QMenuBar>
#include <QMessageBox>
#include <QMimeData>
#include <QMouseEvent>
#include <QCursor>
#include <QSettings>
#include <QStackedWidget>
#include <QStyle>
#include <QTimer>
#include <QTextEdit>
#include <QToolBar>
#include <QVBoxLayout>
#include <QPushButton>
#include <QDesktopServices>
#include <QNetworkAccessManager>

#if QT_VERSION < 0x050000
#include <QTextDocument>
#include <QUrl>
#else
#include <QUrlQuery>
#endif

#define BASE_WINDOW_WIDTH 800
#define BASE_WINDOW_HEIGHT 768
#define BASE_WINDOW_MIN_HEIGHT 600

const QString BitcoinGUI::DEFAULT_WALLET = "~Default";

BitcoinGUI::BitcoinGUI(const NetworkStyle* networkStyle, QWidget* parent) : QMainWindow(parent),
                                                                            clientModel(0),
                                                                            walletFrame(0),
                                                                            unitDisplayControl(0),
                                                                            labelStakingIcon(0),
                                                                            labelEncryptionIcon(0),
                                                                            labelConnectionsIcon(0),
                                                                            labelBlocksIcon(0),
                                                                            appMenuBar(0),
                                                                            overviewAction(0),
                                                                            historyAction(0),
                                                                            masternodeAction(0),
                                                                            quitAction(0),
                                                                            sendCoinsAction(0),
                                                                            usedSendingAddressesAction(0),
                                                                            usedReceivingAddressesAction(0),
                                                                            multisigCreateAction(0),
                                                                            multisigSpendAction(0),
                                                                            multisigSignAction(0),
                                                                            aboutAction(0),
                                                                            receiveCoinsAction(0),
                                                                            //                                                                            privacyAction(0),
                                                                            optionsAction(0),
                                                                            toggleHideAction(0),
                                                                            encryptWalletAction(0),
                                                                            backupWalletAction(0),
                                                                            changePassphraseAction(0),
                                                                            aboutQtAction(0),
                                                                            openRPCConsoleAction(0),
                                                                            openAction(0),
                                                                            showHelpMessageAction(0),
                                                                            multiSendAction(0),
                                                                            trayIcon(0),
                                                                            trayIconMenu(0),
                                                                            notificator(0),
                                                                            rpcConsole(0),
                                                                            explorerWindow(0),
                                                                            prevBlocks(0),
                                                                            spinnerFrame(0),
                                                                            m_previousPos(0,0),
                                                                            m_fMousePress(0)
{
    /* Open CSS when configured */
    this->setStyleSheet(GUIUtil::loadStyleSheet());

    this->setMinimumSize(BASE_WINDOW_WIDTH, BASE_WINDOW_MIN_HEIGHT);
    GUIUtil::restoreWindowGeometry("nWindow", QSize(BASE_WINDOW_WIDTH, BASE_WINDOW_HEIGHT), this);

    QString windowTitle = tr("DAPS Coin") + " ";
    fLiteMode = GetBoolArg("-litemode", false);
#ifdef ENABLE_WALLET
    /* if compiled with wallet support, -disablewallet can still disable the wallet */
    enableWallet = !GetBoolArg("-disablewallet", false);
#else
    enableWallet = false;
#endif // ENABLE_WALLET
    if (enableWallet) {
        windowTitle += tr("Keychain Wallet");
    } else {
        windowTitle += tr("Node");
    }
    if (fLiteMode) {
        windowTitle += tr(" - Lite Mode");
    }
    QString userWindowTitle = QString::fromStdString(GetArg("-windowtitle", ""));
    if (!userWindowTitle.isEmpty()) windowTitle += " - " + userWindowTitle;
    windowTitle += " " + networkStyle->getTitleAddText();
#ifndef Q_OS_MAC
    QApplication::setWindowIcon(networkStyle->getAppIcon());
    setWindowIcon(networkStyle->getAppIcon());
#else
    MacDockIconHandler::instance()->setIcon(networkStyle->getAppIcon());
#endif
    setWindowTitle(windowTitle);

#if defined(Q_OS_MAC) && QT_VERSION < 0x050000
    // This property is not implemented in Qt 5. Setting it has no effect.
    // A replacement API (QtMacUnifiedToolBar) is available in QtMacExtras.
    setUnifiedTitleAndToolBarOnMac(true);
#endif

    rpcConsole = new RPCConsole(enableWallet ? this : 0);
#ifdef ENABLE_WALLET
    if (enableWallet) {
        /** Create wallet frame*/
        walletFrame = new WalletFrame(this);
        explorerWindow = new BlockExplorer(this);
    } else
#endif // ENABLE_WALLET
    {
        /* When compiled without wallet or -disablewallet is provided,
         * the central widget is the rpc console.
         */
        setCentralWidget(rpcConsole);
    }

    // Accept D&D of URIs
    setAcceptDrops(true);

    // Create actions for the toolbar, menu bar and tray/dock icon
    // Needs walletFrame to be initialized
    createActions(networkStyle);

    // Create application menu bar
    createMenuBar();

    // Create the toolbars
    createToolBars();

    // Create system tray icon and notification
    createTrayIcon(networkStyle);

    // Status bar notification icons
    frameBlocks = new QFrame();
    frameBlocks->setContentsMargins(0, 0, 0, 0);
    frameBlocks->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Preferred);
    QHBoxLayout* frameBlocksLayout = new QHBoxLayout(frameBlocks);
    frameBlocksLayout->setContentsMargins(3, 0, 3, 0);
    frameBlocksLayout->setSpacing(3);
    unitDisplayControl = new UnitDisplayStatusBarControl();
    labelStakingIcon = new QLabel();
    labelEncryptionIcon = new QPushButton(this);
    labelEncryptionIcon->setFlat(true); // Make the button look like a label, but clickable
    labelEncryptionIcon->setStyleSheet(".QPushButton { background-color: rgba(255, 255, 255, 0);}");
    labelEncryptionIcon->setMaximumSize(STATUSBAR_ICONSIZE, STATUSBAR_ICONSIZE);
    labelConnectionsIcon = new QPushButton();
    labelConnectionsIcon->setFlat(true); // Make the button look like a label, but clickable
    labelConnectionsIcon->setStyleSheet(".QPushButton { background-color: rgba(255, 255, 255, 0);}");
    labelConnectionsIcon->setMaximumSize(STATUSBAR_ICONSIZE, STATUSBAR_ICONSIZE);
    labelBlocksIcon = new QLabel();

    if (enableWallet) {
        frameBlocksLayout->addStretch();
        frameBlocksLayout->addWidget(unitDisplayControl);
        frameBlocksLayout->addStretch();
        frameBlocksLayout->addWidget(labelEncryptionIcon);
    }
    frameBlocksLayout->addStretch();
    frameBlocksLayout->addWidget(labelStakingIcon);
    frameBlocksLayout->addStretch();
    frameBlocksLayout->addWidget(labelConnectionsIcon);
    frameBlocksLayout->addStretch();
    frameBlocksLayout->addWidget(labelBlocksIcon);
    frameBlocksLayout->addStretch();

    // Jump directly to tabs in RPC-console
    connect(openInfoAction, SIGNAL(triggered()), rpcConsole, SLOT(showInfo()));
    connect(openRPCConsoleAction, SIGNAL(triggered()), rpcConsole, SLOT(showConsole()));
    connect(openNetworkAction, SIGNAL(triggered()), rpcConsole, SLOT(showNetwork()));
    connect(openPeersAction, SIGNAL(triggered()), rpcConsole, SLOT(showPeers()));
    connect(openRepairAction, SIGNAL(triggered()), rpcConsole, SLOT(showRepair()));
    connect(openConfEditorAction, SIGNAL(triggered()), rpcConsole, SLOT(showConfEditor()));
    connect(openMNConfEditorAction, SIGNAL(triggered()), rpcConsole, SLOT(showMNConfEditor()));
    connect(showDataDirAction, SIGNAL(triggered()), rpcConsole, SLOT(showDataDir()));
    connect(showBackupsAction, SIGNAL(triggered()), rpcConsole, SLOT(showBackups()));
    connect(labelConnectionsIcon, SIGNAL(clicked()), rpcConsole, SLOT(showPeers()));
    connect(labelEncryptionIcon, SIGNAL(clicked()), walletFrame, SLOT(toggleLockWallet()));

    // Get restart command-line parameters and handle restart
    connect(rpcConsole, SIGNAL(handleRestart(QStringList)), this, SLOT(handleRestart(QStringList)));

    // prevents an open debug window from becoming stuck/unusable on client shutdown
    connect(quitAction, SIGNAL(triggered()), rpcConsole, SLOT(hide()));

    connect(openBlockExplorerAction, SIGNAL(triggered()), explorerWindow, SLOT(show()));

    // prevents an open debug window from becoming stuck/unusable on client shutdown
    connect(quitAction, SIGNAL(triggered()), explorerWindow, SLOT(hide()));

    // Install event filter to be able to catch status tip events (QEvent::StatusTip)
    this->installEventFilter(this);



    // Initially wallet actions should be disabled
    setWalletActionsEnabled(false);

    // Subscribe to notifications from core
    subscribeToCoreSignals();

    if (!fLiteMode) {
        QTimer* timerStakingIcon = new QTimer(labelStakingIcon);
        connect(timerStakingIcon, SIGNAL(timeout()), this, SLOT(setStakingStatus()));
        timerStakingIcon->start(10000);
        setStakingStatus();
    }
}

BitcoinGUI::~BitcoinGUI()
{
    // Unsubscribe from notifications from core
    unsubscribeFromCoreSignals();

    GUIUtil::saveWindowGeometry("nWindow", this);
    if (trayIcon) // Hide tray icon, as deleting will let it linger until quit (on Ubuntu)
        trayIcon->hide();

    delete unitDisplayControl;
    delete frameBlocks;
#ifdef Q_OS_MAC
    delete appMenuBar;
    MacDockIconHandler::cleanup();
#endif
}

void BitcoinGUI::createActions(const NetworkStyle* networkStyle)
{
    QActionGroup* tabGroup = new QActionGroup(this);

    overviewAction = new QAction(QIcon(":/icons/overview"), tr("&Overview"), this);
    overviewAction->setIconText("    &Overview");
    overviewAction->setStatusTip(QString());
    overviewAction->setToolTip(QString());
    overviewAction->setCheckable(true);
#ifdef Q_OS_MAC
    overviewAction->setShortcut(QKeySequence(Qt::CTRL + Qt::Key_1));
#else
    overviewAction->setShortcut(QKeySequence(Qt::ALT + Qt::Key_1));
#endif
    tabGroup->addAction(overviewAction);

    sendCoinsAction = new QAction(QIcon(":/icons/send"), tr("&Send"), this);
    sendCoinsAction->setIconText("    &Send");
    sendCoinsAction->setToolTip(QString());
    sendCoinsAction->setCheckable(true);
#ifdef Q_OS_MAC
    sendCoinsAction->setShortcut(QKeySequence(Qt::CTRL + Qt::Key_2));
#else
    sendCoinsAction->setShortcut(QKeySequence(Qt::ALT + Qt::Key_2));
#endif
    tabGroup->addAction(sendCoinsAction);

    receiveCoinsAction = new QAction(QIcon(":/icons/receiving_addresses"), tr("&Receive"), this);
    receiveCoinsAction->setIconText("    &Receive");
    receiveCoinsAction->setToolTip(QString());
    receiveCoinsAction->setCheckable(true);
#ifdef Q_OS_MAC
    receiveCoinsAction->setShortcut(QKeySequence(Qt::CTRL + Qt::Key_3));
#else
    receiveCoinsAction->setShortcut(QKeySequence(Qt::ALT + Qt::Key_3));
#endif
    tabGroup->addAction(receiveCoinsAction);

    historyAction = new QAction(QIcon(":/icons/history"), tr("&History"), this);
    historyAction->setIconText("    &History");
    historyAction->setToolTip(QString());
    historyAction->setCheckable(true);
#ifdef Q_OS_MAC
    historyAction->setShortcut(QKeySequence(Qt::CTRL + Qt::Key_4));
#else
    historyAction->setShortcut(QKeySequence(Qt::ALT + Qt::Key_4));
#endif
    tabGroup->addAction(historyAction);

#ifdef ENABLE_WALLET
        masternodeAction = new QAction(QIcon(":/icons/masternodes"), tr("&Masternodes"), this);
        masternodeAction->setIconText("    &Masternodes");
        masternodeAction->setStatusTip(tr("Masternodes"));
        masternodeAction->setToolTip(masternodeAction->statusTip());
        masternodeAction->setCheckable(true);
#ifdef Q_OS_MAC
        masternodeAction->setShortcut(QKeySequence(Qt::CTRL + Qt::Key_5));
#else
        masternodeAction->setShortcut(QKeySequence(Qt::ALT + Qt::Key_5));
#endif
        if (!fLiteMode) {
            tabGroup->addAction(masternodeAction);
        }
        connect(masternodeAction, SIGNAL(triggered()), this, SLOT(showNormalIfMinimized()));
        connect(masternodeAction, SIGNAL(triggered()), this, SLOT(gotoMasternodePage()));

    // These showNormalIfMinimized are needed because Send Coins and Receive Coins
    // can be triggered from the tray menu, and need to show the GUI to be useful.
    connect(overviewAction, SIGNAL(triggered()), this, SLOT(showNormalIfMinimized()));
    connect(overviewAction, SIGNAL(triggered()), this, SLOT(gotoOverviewPage()));
    connect(sendCoinsAction, SIGNAL(triggered()), this, SLOT(showNormalIfMinimized()));
    connect(sendCoinsAction, SIGNAL(triggered()), this, SLOT(gotoSendCoinsPage()));
    connect(receiveCoinsAction, SIGNAL(triggered()), this, SLOT(showNormalIfMinimized()));
    connect(receiveCoinsAction, SIGNAL(triggered()), this, SLOT(gotoReceiveCoinsPage()));
    connect(historyAction, SIGNAL(triggered()), this, SLOT(showNormalIfMinimized()));
    connect(historyAction, SIGNAL(triggered()), this, SLOT(gotoHistoryPage()));
#endif // ENABLE_WALLET

    quitAction = new QAction(QIcon(":/icons/quit"), tr("E&xit"), this);
    quitAction->setStatusTip(tr("Quit application"));
    quitAction->setShortcut(QKeySequence(Qt::CTRL + Qt::Key_Q));
    quitAction->setMenuRole(QAction::QuitRole);
    aboutAction = new QAction(networkStyle->getAppIcon(), tr("&About DAPS"), this);
    aboutAction->setStatusTip(tr("Show information about DAPS"));
    aboutAction->setMenuRole(QAction::AboutRole);
#if QT_VERSION < 0x050000
    aboutQtAction = new QAction(QIcon(":/trolltech/qmessagebox/images/qtlogo-64.png"), tr("About &Qt"), this);
#else
    aboutQtAction = new QAction(QIcon(":/qt-project.org/qmessagebox/images/qtlogo-64.png"), tr("About &Qt"), this);
#endif
    aboutQtAction->setStatusTip(tr("Show information about Qt"));
    aboutQtAction->setMenuRole(QAction::AboutQtRole);
    optionsAction = new QAction(QIcon(":/icons/options"), tr("&Settings"), this);
    optionsAction->setIconText("   Settings");
    optionsAction->setStatusTip(tr("Modify settings"));
    optionsAction->setMenuRole(QAction::PreferencesRole);
    optionsAction->setToolTip(optionsAction->statusTip());
    optionsAction->setCheckable(true);
    tabGroup->addAction(optionsAction);

    stakingAction = new QAction(QIcon(":/icons/options"), tr("&Staking"), this);
    stakingAction->setText(tr("Staking Status"));
    stakingAction->setIconText("   Staking Status");
    stakingAction->setMenuRole(QAction::NoRole);
    stakingState = new QLabel(this);
    stakingState->setObjectName("stakingState");
    networkAction = new QAction(QIcon(":/icons/options"), tr("&Network"), this);
    networkAction->setMenuRole(QAction::NoRole);
    networkAction->setText("Network Status");
    networkAction->setIconText("   Network Status");
    connectionCount = new QLabel(this);
    connectionCount->setObjectName("connectionCount");

    toggleHideAction = new QAction(networkStyle->getAppIcon(), tr("&Show / Hide"), this);
    toggleHideAction->setStatusTip(tr("Show or hide the main Window"));

    encryptWalletAction = new QAction(QIcon(":/icons/lock_closed"), tr("&Encrypt Wallet..."), this);
    encryptWalletAction->setStatusTip(tr("Encrypt the private keys that belong to your wallet"));
    encryptWalletAction->setCheckable(true);
    backupWalletAction = new QAction(QIcon(":/icons/filesave"), tr("&Backup Wallet..."), this);
    backupWalletAction->setStatusTip(tr("Backup wallet to another location"));
    changePassphraseAction = new QAction(QIcon(":/icons/key"), tr("&Change Passphrase..."), this);
    changePassphraseAction->setStatusTip(tr("Change the passphrase used for wallet encryption"));
    unlockWalletAction = new QAction(tr("&Unlock Wallet..."), this);
    unlockWalletAction->setToolTip(tr("Unlock wallet"));
    lockWalletAction = new QAction(tr("&Lock Wallet"), this);
    multiSendAction = new QAction(QIcon(":/icons/edit"), tr("&MultiSend"), this);
    multiSendAction->setToolTip(tr("MultiSend Settings"));
    multiSendAction->setCheckable(true);

    openInfoAction = new QAction(QApplication::style()->standardIcon(QStyle::SP_MessageBoxInformation), tr("&Information"), this);
    openInfoAction->setStatusTip(tr("Show diagnostic information"));
    openRPCConsoleAction = new QAction(QIcon(":/icons/debugwindow"), tr("&Debug Console"), this);
    openRPCConsoleAction->setStatusTip(tr("Open debugging console"));
    openRPCConsoleAction->setShortcut(Qt::Key_F1);
    openNetworkAction = new QAction(QIcon(":/icons/connect_4"), tr("&Network Monitor"), this);
    openNetworkAction->setStatusTip(tr("Show network monitor"));
    openPeersAction = new QAction(QIcon(":/icons/connect_4"), tr("&Peers List"), this);
    openPeersAction->setStatusTip(tr("Show peers info"));
    openRepairAction = new QAction(QIcon(":/icons/options"), tr("Wallet &Repair"), this);
    openRepairAction->setStatusTip(tr("Show wallet repair options"));
    openConfEditorAction = new QAction(QIcon(":/icons/edit"), tr("Open Wallet &Configuration File"), this);
    openConfEditorAction->setStatusTip(tr("Open configuration file"));
    openConfEditorAction->setShortcut(QKeySequence(Qt::CTRL + Qt::Key_D));
    openMNConfEditorAction = new QAction(QIcon(":/icons/edit"), tr("Open &Masternode Configuration File"), this);
    openMNConfEditorAction->setStatusTip(tr("Open Masternode configuration file"));
    openMNConfEditorAction->setShortcut(QKeySequence(Qt::CTRL + Qt::Key_M));
    showDataDirAction = new QAction(QIcon(":/icons/browse"), tr("Show &DAPScoin Folder"), this);
    showDataDirAction->setStatusTip(tr("Show the DAPScoin folder"));
    showDataDirAction->setShortcut(Qt::Key_F2);
    showBackupsAction = new QAction(QIcon(":/icons/browse"), tr("Show Automatic &Backups"), this);
    showBackupsAction->setStatusTip(tr("Show automatically created wallet backups"));

    usedSendingAddressesAction = new QAction(QIcon(":/icons/address-book"), tr("&Sending addresses..."), this);
    usedSendingAddressesAction->setStatusTip(tr("Show the list of used sending addresses and labels"));
    usedReceivingAddressesAction = new QAction(QIcon(":/icons/address-book"), tr("&Receiving addresses..."), this);
    usedReceivingAddressesAction->setStatusTip(tr("Show the list of used receiving addresses and labels"));

    multisigCreateAction = new QAction(QIcon(":/icons/address-book"), tr("&Multisignature creation..."), this);
    multisigCreateAction->setStatusTip(tr("Create a new multisignature address and add it to this wallet"));
    multisigSpendAction = new QAction(QIcon(":/icons/send"), tr("&Multisignature spending..."), this);
    multisigSpendAction->setStatusTip(tr("Spend from a multisignature address"));
    multisigSignAction = new QAction(QIcon(":/icons/editpaste"), tr("&Multisignature signing..."), this);
    multisigSignAction->setStatusTip(tr("Sign with a multisignature address"));

    openAction = new QAction(QApplication::style()->standardIcon(QStyle::SP_FileIcon), tr("Open &URI..."), this);
    openAction->setStatusTip(tr("Open a DAPS: URI or payment request"));
    openBlockExplorerAction = new QAction(QIcon(":/icons/explorer"), tr("&Blockchain Explorer"), this);
    openBlockExplorerAction->setStatusTip(tr("Block explorer window"));

    facebookAction = new QAction(QIcon(":/icons/facebook"), tr("Facebook"), this);
    facebookAction->setStatusTip(tr("DAPS Facebook"));
    twitterAction = new QAction(QIcon(":/icons/twitter"), tr("Twitter"), this);
    twitterAction->setStatusTip(tr("DAPS Twitter"));
    discordAction = new QAction(QIcon(":/icons/discord"), tr("Discord"), this);
    discordAction->setStatusTip(tr("DAPS Discord"));
    telegramOfficialAction = new QAction(QIcon(":/icons/telegram"), tr("Telegram - Main"), this);
    telegramOfficialAction->setStatusTip(tr("DAPS Telegram - Main"));
    telegramLoungeAction = new QAction(QIcon(":/icons/telegram"), tr("Telegram - Lounge"), this);
    telegramLoungeAction->setStatusTip(tr("DAPS Telegram - Lounge"));
    mediumAction = new QAction(QIcon(":/icons/medium"), tr("Medium"), this);
    mediumAction->setStatusTip(tr("DAPS Medium"));
    steemitAction = new QAction(QIcon(":/icons/steemit"), tr("Steemit"), this);
    steemitAction->setStatusTip(tr("DAPS Steemit"));
    instagramAction = new QAction(QIcon(":/icons/instagram"), tr("Instagram"), this);
    instagramAction->setStatusTip(tr("DAPS Instagram"));
    redditAction = new QAction(QIcon(":/icons/reddit"), tr("Reddit"), this);
    redditAction->setStatusTip(tr("DAPS Reddit"));

    showHelpMessageAction = new QAction(QApplication::style()->standardIcon(QStyle::SP_MessageBoxInformation), tr("&Command-line Options"), this);
    showHelpMessageAction->setMenuRole(QAction::NoRole);
    showHelpMessageAction->setStatusTip(tr("Show the DAPS help message to get a list with possible DAPS command-line options"));

    // Help Links
    openFAQAction = new QAction(QApplication::style()->standardIcon(QStyle::SP_MessageBoxInformation), tr("&Frequently Asked Questions"), this);
    openFAQAction->setStatusTip(tr("Frequently Asked Questions"));
    openBlockExplorerAPIAction = new QAction(QApplication::style()->standardIcon(QStyle::SP_MessageBoxInformation), tr("&Blockhain Explorer API"), this);
    openBlockExplorerAPIAction->setStatusTip(tr("Blockhain Explorer API"));
    openBootStrapAction = new QAction(QApplication::style()->standardIcon(QStyle::SP_MessageBoxInformation), tr("&BootStrap"), this);
    openBootStrapAction->setStatusTip(tr("BootStrap Link"));
    openTGTechSupportAction = new QAction(QIcon(":/icons/telegram"), tr("&Telegram Tech Support"), this);
    openTGTechSupportAction->setStatusTip(tr("Telegram Tech Support"));
    openTGMNSupportAction = new QAction(QIcon(":/icons/telegram"), tr("&Telegram Masternode Support"), this);
    openTGMNSupportAction->setStatusTip(tr("Telegram Masternode Support"));
    openDiscordSupportAction = new QAction(QIcon(":/icons/discord"), tr("&Discord Tech Support"), this);
    openDiscordSupportAction->setStatusTip(tr("Discord Tech Support"));
    checkForUpdatesAction = new QAction(QApplication::style()->standardIcon(QStyle::SP_MessageBoxInformation), tr("&Check For Updates"), this);
    checkForUpdatesAction->setStatusTip(tr("Check For Updates"));

    connect(quitAction, SIGNAL(triggered()), qApp, SLOT(quit()));
    connect(aboutAction, SIGNAL(triggered()), this, SLOT(aboutClicked()));
    connect(aboutQtAction, SIGNAL(triggered()), qApp, SLOT(aboutQt()));
    connect(optionsAction, SIGNAL(triggered()), this, SLOT(gotoOptionsPage()));
    connect(toggleHideAction, SIGNAL(triggered()), this, SLOT(toggleHidden()));
    connect(showHelpMessageAction, SIGNAL(triggered()), this, SLOT(showHelpMessageClicked()));
    connect(openFAQAction, SIGNAL(triggered()), this, SLOT(openFAQClicked()));
    connect(openBlockExplorerAPIAction, SIGNAL(triggered()), this, SLOT(openBlockExplorerAPIClicked()));
    connect(openBootStrapAction, SIGNAL(triggered()), this, SLOT(openBootStrapClicked()));
    connect(openTGTechSupportAction, SIGNAL(triggered()), this, SLOT(openTGTechSupportClicked()));
    connect(openTGMNSupportAction, SIGNAL(triggered()), this, SLOT(openTGMNSupportClicked()));
    connect(openDiscordSupportAction, SIGNAL(triggered()), this, SLOT(openDiscordSupportClicked()));
    connect(checkForUpdatesAction, SIGNAL(triggered()), this, SLOT(checkForUpdatesClicked()));
#ifdef ENABLE_WALLET
    if (walletFrame) {
        connect(encryptWalletAction, SIGNAL(triggered(bool)), walletFrame, SLOT(encryptWallet(bool)));
        connect(backupWalletAction, SIGNAL(triggered()), walletFrame, SLOT(backupWallet()));
        connect(changePassphraseAction, SIGNAL(triggered()), walletFrame, SLOT(changePassphrase()));
        connect(unlockWalletAction, SIGNAL(triggered()), walletFrame, SLOT(unlockWallet()));
        connect(lockWalletAction, SIGNAL(triggered()), walletFrame, SLOT(lockWallet()));
        connect(usedSendingAddressesAction, SIGNAL(triggered()), walletFrame, SLOT(usedSendingAddresses()));
        connect(usedReceivingAddressesAction, SIGNAL(triggered()), walletFrame, SLOT(usedReceivingAddresses()));
        connect(openAction, SIGNAL(triggered()), this, SLOT(openClicked()));
        connect(multiSendAction, SIGNAL(triggered()), this, SLOT(gotoMultiSendDialog()));
        connect(multisigCreateAction, SIGNAL(triggered()), this, SLOT(gotoMultisigCreate()));
        connect(multisigSpendAction, SIGNAL(triggered()), this, SLOT(gotoMultisigSpend()));
        connect(multisigSignAction, SIGNAL(triggered()), this, SLOT(gotoMultisigSign()));
    }
#endif // ENABLE_WALLET
    connect(facebookAction, SIGNAL(triggered()), this, SLOT(facebookActionClicked()));
    connect(twitterAction, SIGNAL(triggered()), this, SLOT(twitterActionClicked()));
    connect(discordAction, SIGNAL(triggered()), this, SLOT(discordActionClicked()));
    connect(telegramOfficialAction, SIGNAL(triggered()), this, SLOT(telegramOfficialActionClicked()));
    connect(telegramLoungeAction, SIGNAL(triggered()), this, SLOT(telegramLoungeActionClicked()));
    connect(mediumAction, SIGNAL(triggered()), this, SLOT(mediumActionClicked()));
    connect(steemitAction, SIGNAL(triggered()), this, SLOT(steemitActionClicked()));
    connect(instagramAction, SIGNAL(triggered()), this, SLOT(instagramActionClicked()));
    connect(redditAction, SIGNAL(triggered()), this, SLOT(redditActionClicked()));
}

void BitcoinGUI::createMenuBar()
{
#ifdef Q_OS_MAC
    // Create a decoupled menu bar on Mac which stays even if the window is closed
    appMenuBar = new QMenuBar();
#else
    // Get the main window's menu bar on other platforms
    appMenuBar = menuBar();
#endif

    // Configure the menus
    QMenu* file = appMenuBar->addMenu(tr("&File"));
    if (walletFrame) {
        //file->addAction(openAction);
        file->addAction(backupWalletAction);
        file->addSeparator();
        //file->addAction(usedSendingAddressesAction);
        //file->addAction(usedReceivingAddressesAction);
        //file->addSeparator();
        //file->addAction(multisigCreateAction);
        //file->addAction(multisigSpendAction);
        //file->addAction(multisigSignAction);
        //file->addSeparator();
    }
    file->addAction(quitAction);

    //QMenu* settings = appMenuBar->addMenu(tr("&Settings"));
    //if (walletFrame) {
        //settings->addAction(encryptWalletAction);
        //settings->addAction(changePassphraseAction);
        //settings->addAction(unlockWalletAction);
        //settings->addAction(lockWalletAction);
        //settings->addAction(multiSendAction);
        //settings->addSeparator();
    //}

    if (walletFrame) {
        walletFrame->addAction(openRPCConsoleAction);
        QMenu* tools = appMenuBar->addMenu(tr("&Tools"));
        tools->addAction(openInfoAction);
        tools->addAction(openRPCConsoleAction);
        tools->addAction(openNetworkAction);
        tools->addAction(openPeersAction);
        tools->addAction(openRepairAction);
        tools->addSeparator();
        tools->addAction(openConfEditorAction);
        tools->addAction(openMNConfEditorAction);
        tools->addAction(showDataDirAction);
        tools->addAction(showBackupsAction);
        tools->addAction(openBlockExplorerAction);
    }

    QMenu* socials = appMenuBar->addMenu(tr("Social"));
    socials->addAction(facebookAction);
    socials->addAction(twitterAction);
    socials->addAction(discordAction);
    socials->addAction(telegramOfficialAction);
    socials->addAction(telegramLoungeAction);
    socials->addAction(mediumAction);
    socials->addAction(steemitAction);
    socials->addAction(instagramAction);
    socials->addAction(redditAction);

    QMenu* help = appMenuBar->addMenu(tr("&Help"));
    help->addAction(showHelpMessageAction);
    help->addSeparator();
    help->addAction(openFAQAction);
    help->addSeparator();
    help->addAction(openBlockExplorerAPIAction);
    help->addAction(openBootStrapAction);
    help->addSeparator();
    help->addAction(openTGTechSupportAction);
    help->addAction(openTGMNSupportAction);
    help->addSeparator();
    help->addAction(openDiscordSupportAction);
    help->addSeparator();
    help->addAction(checkForUpdatesAction);
    help->addSeparator();
    help->addAction(aboutAction);
    help->addAction(aboutQtAction);
    appMenuBar->setVisible(true);
}

void BitcoinGUI::createToolBars()
{
    if (walletFrame) {
        QToolBar* toolbar = new QToolBar(this);
        toolbar->setOrientation(Qt::Vertical);
        toolbar->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);

        toolbar->addAction(overviewAction);
        toolbar->addAction(sendCoinsAction);
        toolbar->addAction(receiveCoinsAction);
        toolbar->addAction(historyAction);
        if (!fLiteMode) {
            toolbar->addAction(masternodeAction);
        }
        toolbar->setMovable(false); // remove unused icon in upper left corner
        overviewAction->setChecked(true);
        toolbar->setStyleSheet("QToolBar{spacing:25px;}");

        // Create NavBar
        QToolBar* bottomToolbar = new QToolBar(this);

        bottomToolbar->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
        bottomToolbar->setOrientation(Qt::Vertical);
        bottomToolbar->addAction(optionsAction);
        bottomToolbar->addSeparator();
        bottomToolbar->addAction(stakingAction);
        bottomToolbar->addWidget(stakingState);
        bottomToolbar->addAction(networkAction);
        bottomToolbar->addWidget(connectionCount);
        bottomToolbar->setStyleSheet("QToolBar{spacing:5px;}");
        bottomToolbar->setObjectName("bottomToolbar");
        if (fLiteMode) {
            stakingAction->setVisible(false);
            stakingState->setVisible(false);
        }

        QHBoxLayout* layout = new QHBoxLayout();
        QVBoxLayout* navLayout = new QVBoxLayout();
        QWidget* navWidget = new QWidget(this);
        navWidget->setObjectName("navLayout");

        bottomToolbar->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Minimum);
        toolbar->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Expanding);
        QLabel* dapsico = new QLabel;
        dapsico->setPixmap(QIcon(":icons/bitcoin").pixmap(130, 107));
        dapsico->setObjectName("dapsico");

        navLayout->addWidget(dapsico);
        navLayout->addWidget(toolbar);
        navLayout->addWidget(bottomToolbar);
        navWidget->setLayout(navLayout);

        layout->addWidget(navWidget);
        layout->addWidget(walletFrame);
        layout->setSpacing(0);
        layout->setContentsMargins(QMargins());
        QWidget* containerWidget = new QWidget();
        containerWidget->setLayout(layout);
        setCentralWidget(containerWidget);

        auto toolLayout = toolbar->layout();
        for (int i = 0; i < toolLayout->count(); i++)
            toolLayout->itemAt(i)->setAlignment(Qt::AlignLeft);
    }
}

void BitcoinGUI::setClientModel(ClientModel* clientModel)
{
    this->clientModel = clientModel;
    if (clientModel) {
        // Create system tray menu (or setup the dock menu) that late to prevent users from calling actions,
        // while the client has not yet fully loaded
        createTrayIconMenu();

        // Keep up to date with client
        setNumConnections(clientModel->getNumConnections());
        connect(clientModel, SIGNAL(numConnectionsChanged(int)), this, SLOT(setNumConnections(int)));

        setNumBlocks(clientModel->getNumBlocks());
        connect(clientModel, SIGNAL(numBlocksChanged(int)), this, SLOT(setNumBlocks(int)));

        // Receive and report messages from client model
        connect(clientModel, SIGNAL(message(QString, QString, unsigned int)), this, SLOT(message(QString, QString, unsigned int)));

        rpcConsole->setClientModel(clientModel);
#ifdef ENABLE_WALLET
        if (walletFrame) {
            walletFrame->setClientModel(clientModel);
        }
#endif // ENABLE_WALLET
        unitDisplayControl->setOptionsModel(clientModel->getOptionsModel());
    } else {
        // Disable possibility to show main window via action
        toggleHideAction->setEnabled(false);
        if (trayIconMenu) {
            // Disable context menu on tray icon
            trayIconMenu->clear();
        }
    }
}

void BitcoinGUI::showProgress(const QString &title, int nProgress)
{
    if (nProgress == 0) {
        progressDialog = new QProgressDialog(title, QString(), 0, 100);
        progressDialog->setWindowModality(Qt::ApplicationModal);
        progressDialog->setMinimumDuration(0);
        progressDialog->setAutoClose(false);
        progressDialog->setValue(0);
    } else if (nProgress == 100) {
        if (progressDialog) {
            progressDialog->close();
            progressDialog->deleteLater();
        }
    } else if (progressDialog) {
        progressDialog->setValue(nProgress);
    }
}

#ifdef ENABLE_WALLET
bool BitcoinGUI::addWallet(const QString& name, WalletModel* walletModel)
{
    if (!walletFrame)
        return false;
    setWalletActionsEnabled(true);
    return walletFrame->addWallet(name, walletModel);
}

bool BitcoinGUI::setCurrentWallet(const QString& name)
{
    if (!walletFrame)
        return false;
    return walletFrame->setCurrentWallet(name);
}

void BitcoinGUI::removeAllWallets()
{
    if (!walletFrame)
        return;
    setWalletActionsEnabled(false);
    walletFrame->removeAllWallets();
}
#endif // ENABLE_WALLET

void BitcoinGUI::setWalletActionsEnabled(bool enabled)
{
    overviewAction->setEnabled(enabled);
    sendCoinsAction->setEnabled(enabled);
    receiveCoinsAction->setEnabled(enabled);
    historyAction->setEnabled(enabled);
    masternodeAction->setEnabled(enabled);
    encryptWalletAction->setEnabled(enabled);
    backupWalletAction->setEnabled(enabled);
    changePassphraseAction->setEnabled(enabled);
    multisigCreateAction->setEnabled(enabled);
    multisigSpendAction->setEnabled(enabled);
    multisigSignAction->setEnabled(enabled);
    usedSendingAddressesAction->setEnabled(enabled);
    usedReceivingAddressesAction->setEnabled(enabled);
    openAction->setEnabled(enabled);
}

void BitcoinGUI::createTrayIcon(const NetworkStyle* networkStyle)
{
#ifndef Q_OS_MAC
    trayIcon = new QSystemTrayIcon(this);
    QString toolTip = tr("DAPS client") + " " + networkStyle->getTitleAddText();
    trayIcon->setToolTip(toolTip);
    trayIcon->setIcon(networkStyle->getAppIcon());
    trayIcon->show();
#endif

    notificator = new Notificator(QApplication::applicationName(), trayIcon, this);
}

void BitcoinGUI::createTrayIconMenu()
{
#ifndef Q_OS_MAC
    // return if trayIcon is unset (only on non-Mac OSes)
    if (!trayIcon)
        return;

    trayIconMenu = new QMenu(this);
    trayIcon->setContextMenu(trayIconMenu);

    connect(trayIcon, SIGNAL(activated(QSystemTrayIcon::ActivationReason)),
        this, SLOT(trayIconActivated(QSystemTrayIcon::ActivationReason)));
#else
    // Note: On Mac, the dock icon is used to provide the tray's functionality.
    MacDockIconHandler* dockIconHandler = MacDockIconHandler::instance();
    dockIconHandler->setMainWindow((QMainWindow*)this);
    trayIconMenu = dockIconHandler->dockMenu();
#endif

    // Configuration of the tray icon (or dock icon) icon menu
    trayIconMenu->addAction(toggleHideAction);
    trayIconMenu->addSeparator();
    trayIconMenu->addAction(sendCoinsAction);
    trayIconMenu->addAction(receiveCoinsAction);
    trayIconMenu->addAction(historyAction);
    if (!fLiteMode) {
        trayIconMenu->addAction(masternodeAction);
    }
    trayIconMenu->addSeparator();
    trayIconMenu->addAction(optionsAction);
    trayIconMenu->addSeparator();
    trayIconMenu->addAction(openInfoAction);
    trayIconMenu->addAction(openRPCConsoleAction);
    trayIconMenu->addAction(openNetworkAction);
    trayIconMenu->addAction(openPeersAction);
    trayIconMenu->addAction(openRepairAction);
    trayIconMenu->addSeparator();
    trayIconMenu->addAction(openConfEditorAction);
    trayIconMenu->addAction(openMNConfEditorAction);
    trayIconMenu->addAction(showDataDirAction);
    trayIconMenu->addAction(showBackupsAction);
    trayIconMenu->addAction(openBlockExplorerAction);
#ifndef Q_OS_MAC // This is built-in on Mac
    trayIconMenu->addSeparator();
    trayIconMenu->addAction(quitAction);
#endif
}

#ifndef Q_OS_MAC
void BitcoinGUI::trayIconActivated(QSystemTrayIcon::ActivationReason reason)
{
    if (reason == QSystemTrayIcon::Trigger) {
        // Click on system tray icon triggers show/hide of the main window
        toggleHidden();
    }
}
#endif

void BitcoinGUI::optionsClicked()
{
    if (!clientModel || !clientModel->getOptionsModel())
        return;

    OptionsDialog dlg(this, enableWallet);
    dlg.setModel(clientModel->getOptionsModel());
    dlg.exec();
}

void BitcoinGUI::facebookActionClicked()
{
    QDesktopServices::openUrl(QUrl("https://www.facebook.com/officialdapscoin/"));
}
void BitcoinGUI::twitterActionClicked()
{
    QDesktopServices::openUrl(QUrl("https://twitter.com/DAPScoin"));
}
void BitcoinGUI::discordActionClicked()
{
    QDesktopServices::openUrl(QUrl("https://officialdapscoin.com/discord"));
}
void BitcoinGUI::telegramOfficialActionClicked()
{
    QDesktopServices::openUrl(QUrl("https://t.me/dapscoin"));
}
void BitcoinGUI::telegramLoungeActionClicked()
{
    QDesktopServices::openUrl(QUrl("https://t.me/DAPS_LOUNGE"));
}
void BitcoinGUI::mediumActionClicked()
{
    QDesktopServices::openUrl(QUrl("https://medium.com/DAPScoin"));
}
void BitcoinGUI::instagramActionClicked()
{
    QDesktopServices::openUrl(QUrl("https://www.instagram.com/DAPSCoin/"));
}
void BitcoinGUI::redditActionClicked()
{
    QDesktopServices::openUrl(QUrl("https://www.reddit.com/r/DAPSCoin/"));
}
void BitcoinGUI::steemitActionClicked()
{
    QDesktopServices::openUrl(QUrl("https://steemit.com/@DAPSCoin/"));
}

void BitcoinGUI::aboutClicked()
{
    if (!clientModel)
        return;

    HelpMessageDialog dlg(this, true);
    dlg.exec();
}

void BitcoinGUI::showHelpMessageClicked()
{
    HelpMessageDialog* help = new HelpMessageDialog(this, false);
    help->setAttribute(Qt::WA_DeleteOnClose);
    help->show();
}

void BitcoinGUI::openFAQClicked()
{
    QDesktopServices::openUrl(QUrl("https://officialdapscoin.com/faq"));
}

void BitcoinGUI::openBlockExplorerAPIClicked()
{
    QDesktopServices::openUrl(QUrl("https://explorer.dapscoin.com/api/getblockcount"));
}

void BitcoinGUI::openBootStrapClicked()
{
    QDesktopServices::openUrl(QUrl("https://github.com/DAPSCoin/BootStrap/releases/tag/latest"));
}

void BitcoinGUI::openTGTechSupportClicked()
{
    QDesktopServices::openUrl(QUrl("https://t.me/DAPSTechSupport"));
}

void BitcoinGUI::openTGMNSupportClicked()
{
    QDesktopServices::openUrl(QUrl("https://t.me/DAPS_MN_Support"));
}

void BitcoinGUI::openDiscordSupportClicked()
{
    QDesktopServices::openUrl(QUrl("https://discord.gg/8vbXJMf"));
}

void BitcoinGUI::checkForUpdatesClicked()
{
    QUrl serviceUrl = QUrl("https://raw.githubusercontent.com/DAPSCoin/DAPSCoin/master/version.txt");
    QNetworkAccessManager *manager = new QNetworkAccessManager(this);
    connect(manager, SIGNAL(finished(QNetworkReply*)), this, SLOT(serviceRequestFinished(QNetworkReply*)));
    QNetworkRequest request;
    request.setUrl(serviceUrl);
    QNetworkReply* reply = manager->get(request);
}

void BitcoinGUI::serviceRequestFinished(QNetworkReply* reply)
{
    QString currentVersion = QString::number(CLIENT_VERSION_MAJOR) + "." + QString::number(CLIENT_VERSION_MINOR)+ "." + QString::number(CLIENT_VERSION_REVISION)+ "." + QString::number(CLIENT_VERSION_BUILD);
    reply->deleteLater();
    if(reply->error() == QNetworkReply::NoError) {
        QByteArray data = reply->readAll();
        if (data != currentVersion) {
            QMessageBox::StandardButton msgReply;
            msgReply = QMessageBox::question(this, "Wallet Update Available!", "Wallet update available.\n\nWould you like to go to the GitHub Releases page to download v" + data.trimmed() + "?", QMessageBox::Yes|QMessageBox::No);
            if (msgReply == QMessageBox::Yes) {
                QDesktopServices::openUrl(QUrl("https://github.com/DAPSCoin/DAPSCoin/releases/latest"));
            } else {
                return;
            }
        } else {
            QMessageBox msgBox;
            msgBox.setWindowTitle("No Update Available");
            msgBox.setText("No update available.\n\nYour wallet is up to date.");
            msgBox.setStyleSheet(GUIUtil::loadStyleSheet());
            msgBox.setIcon(QMessageBox::Information);
            msgBox.exec();
        }
    } else {
        QByteArray error = reply->readAll();
        QMessageBox msgBox;
        msgBox.setWindowTitle("Error");
        msgBox.setText("Error checking for updates.\n\n" + error);
        msgBox.setStyleSheet(GUIUtil::loadStyleSheet());
        msgBox.setIcon(QMessageBox::Critical);
        msgBox.exec();
    }
}

#ifdef ENABLE_WALLET
void BitcoinGUI::openClicked()
{
    OpenURIDialog dlg(this);
    if (dlg.exec()) {
        emit receivedURI(dlg.getURI());
    }
}

void BitcoinGUI::gotoOverviewPage()
{
    overviewAction->setChecked(true);
    if (walletFrame) walletFrame->gotoOverviewPage();
}

void BitcoinGUI::gotoHistoryPage()
{
    historyAction->setChecked(true);
    if (walletFrame) walletFrame->gotoHistoryPage();
}

void BitcoinGUI::gotoMasternodePage()
{
    masternodeAction->setChecked(true);
    if (walletFrame) walletFrame->gotoMasternodePage();

}

void BitcoinGUI::gotoReceiveCoinsPage()
{
    receiveCoinsAction->setChecked(true);
    if (walletFrame) walletFrame->gotoReceiveCoinsPage();
}

void BitcoinGUI::gotoOptionsPage()
{
    optionsAction->setChecked(true);
    if (walletFrame) walletFrame->gotoOptionsPage();
}

void BitcoinGUI::gotoSendCoinsPage(QString addr)
{
    sendCoinsAction->setChecked(true);
    if (walletFrame) walletFrame->gotoSendCoinsPage(addr);
}

void BitcoinGUI::gotoMultisigCreate()
{
    if (walletFrame) walletFrame->gotoMultisigDialog(0);
}

void BitcoinGUI::gotoMultisigSpend()
{
    if (walletFrame) walletFrame->gotoMultisigDialog(1);
}

void BitcoinGUI::gotoMultisigSign()
{
    if (walletFrame) walletFrame->gotoMultisigDialog(2);
}

void BitcoinGUI::gotoMultiSendDialog()
{
    multiSendAction->setChecked(true);
    if (walletFrame)
        walletFrame->gotoMultiSendDialog();
}
void BitcoinGUI::gotoBlockExplorerPage()
{
    if (walletFrame) walletFrame->gotoBlockExplorerPage();
}

#endif // ENABLE_WALLET

void BitcoinGUI::setNumConnections(int count)
{
    QString icon;
    switch (count) {
    case 0:
        icon = ":/icons/connect_0";
        break;
    case 1:
    case 2:
    case 3:
        icon = ":/icons/connect_1";
        break;
    case 4:
    case 5:
    case 6:
        icon = ":/icons/connect_2";
        break;
    case 7:
    case 8:
    case 9:
        icon = ":/icons/connect_3";
        break;
    default:
        icon = ":/icons/connect_4";
        break;
    }

    connectionCount->setText(tr("%n Active Connections", "", count));
    if (count < 1)
        networkAction->setIcon(QIcon(":icons/staking_disabled"));
    else
        networkAction->setIcon(QIcon(":icons/staking_active"));
}

void BitcoinGUI::setNumBlocks(int count)
{
    if (!clientModel)
        return;

    QString tooltip;

    QDateTime lastBlockDate = clientModel->getLastBlockDate();
    QDateTime currentDate = QDateTime::currentDateTime();
    int secs = lastBlockDate.secsTo(currentDate);

    tooltip = tr("Processed %n blocks of transaction history.", "", count);

    // Set icon state: spinning if catching up, tick otherwise
    //    if(secs < 25*60) // 90*60 for bitcoin but we are 4x times faster
    if (masternodeSync.IsBlockchainSynced()) {
        QString strSyncStatus;
        tooltip = tr("Up to date") + QString(".<br>") + tooltip;

        if (masternodeSync.IsSynced()) {
            labelBlocksIcon->setPixmap(QIcon(":/icons/synced").pixmap(STATUSBAR_ICONSIZE, STATUSBAR_ICONSIZE));
        } else {
            // int nAttempt;
            // int progress = 0;

            labelBlocksIcon->setPixmap(QIcon(QString(
                                                 ":/movies/spinner-%1")
                                                 .arg(spinnerFrame, 3, 10, QChar('0')))
                                           .pixmap(STATUSBAR_ICONSIZE, STATUSBAR_ICONSIZE));
            spinnerFrame = (spinnerFrame + 1) % SPINNER_FRAMES;

#ifdef ENABLE_WALLET
            if (walletFrame)
                walletFrame->showSyncStatus(false);
#endif // ENABLE_WALLET
        }

        strSyncStatus = QString(masternodeSync.GetSyncStatus().c_str());
        tooltip = strSyncStatus + QString("<br>") + tooltip;
    } else {
        // Represent time from last generated block in human readable text
        QString timeBehindText;
        const int HOUR_IN_SECONDS = 60 * 60;
        const int DAY_IN_SECONDS = 24 * 60 * 60;
        const int WEEK_IN_SECONDS = 7 * 24 * 60 * 60;
        const int YEAR_IN_SECONDS = 31556952; // Average length of year in Gregorian calendar
        if (secs < 2 * DAY_IN_SECONDS) {
            timeBehindText = tr("%n hour(s)", "", secs / HOUR_IN_SECONDS);
        } else if (secs < 2 * WEEK_IN_SECONDS) {
            timeBehindText = tr("%n day(s)", "", secs / DAY_IN_SECONDS);
        } else if (secs < YEAR_IN_SECONDS) {
            timeBehindText = tr("%n week(s)", "", secs / WEEK_IN_SECONDS);
        } else {
            int years = secs / YEAR_IN_SECONDS;
            int remainder = secs % YEAR_IN_SECONDS;
            timeBehindText = tr("%1 and %2").arg(tr("%n year(s)", "", years)).arg(tr("%n week(s)", "", remainder / WEEK_IN_SECONDS));
        }

        tooltip = tr("Catching up...") + QString("<br>") + tooltip;
        if (count != prevBlocks) {
            labelBlocksIcon->setPixmap(QIcon(QString(
                                                 ":/movies/spinner-%1")
                                                 .arg(spinnerFrame, 3, 10, QChar('0')))
                                           .pixmap(STATUSBAR_ICONSIZE, STATUSBAR_ICONSIZE));
            spinnerFrame = (spinnerFrame + 1) % SPINNER_FRAMES;
        }
        prevBlocks = count;

#ifdef ENABLE_WALLET
        if (walletFrame)
            walletFrame->showSyncStatus(true);
#endif // ENABLE_WALLET

        tooltip += QString("<br>");
        tooltip += tr("Last received block was generated %1 ago.").arg(timeBehindText);
        tooltip += QString("<br>");
        tooltip += tr("Transactions after this will not yet be visible.");
    }
}

void BitcoinGUI::message(const QString& title, const QString& message, unsigned int style, bool* ret)
{
    QString strTitle = tr("DAPS"); // default title
    // Default to information icon
    int nMBoxIcon = QMessageBox::Information;
    int nNotifyIcon = Notificator::Information;

    QString msgType;

    // Prefer supplied title over style based title
    if (!title.isEmpty()) {
        msgType = title;
    } else {
        switch (style) {
        case CClientUIInterface::MSG_ERROR:
            msgType = tr("Error");
            break;
        case CClientUIInterface::MSG_WARNING:
            msgType = tr("Warning");
            break;
        case CClientUIInterface::MSG_INFORMATION:
            msgType = tr("Information");
            break;
        default:
            break;
        }
    }
    // Append title to "DAPS - "
    if (!msgType.isEmpty())
        strTitle += " - " + msgType;

    // Check for error/warning icon
    if (style & CClientUIInterface::ICON_ERROR) {
        nMBoxIcon = QMessageBox::Critical;
        nNotifyIcon = Notificator::Critical;
    } else if (style & CClientUIInterface::ICON_WARNING) {
        nMBoxIcon = QMessageBox::Warning;
        nNotifyIcon = Notificator::Warning;
    }

    // Display message
    if (style & CClientUIInterface::MODAL) {
        // Check for buttons, use OK as default, if none was supplied
        QMessageBox::StandardButton buttons;
        if (!(buttons = (QMessageBox::StandardButton)(style & CClientUIInterface::BTN_MASK)))
            buttons = QMessageBox::Ok;

        showNormalIfMinimized();
        QMessageBox mBox((QMessageBox::Icon)nMBoxIcon, strTitle, message, buttons, this);
        int r = mBox.exec();
        if (ret != NULL)
            *ret = r == QMessageBox::Ok;
    } else
        notificator->notify((Notificator::Class)nNotifyIcon, strTitle, message);
}

void BitcoinGUI::changeEvent(QEvent* e)
{
    QMainWindow::changeEvent(e);
#ifndef Q_OS_MAC // Ignored on Mac
    if (e->type() == QEvent::WindowStateChange) {
        if (clientModel && clientModel->getOptionsModel() && clientModel->getOptionsModel()->getMinimizeToTray()) {
            QWindowStateChangeEvent* wsevt = static_cast<QWindowStateChangeEvent*>(e);
            if (!(wsevt->oldState() & Qt::WindowMinimized) && isMinimized()) {
                QTimer::singleShot(0, this, SLOT(hide()));
                e->ignore();
            }
        }
    }
#endif
}

void BitcoinGUI::closeEvent(QCloseEvent* event)
{
#ifndef Q_OS_MAC // Ignored on Mac
    if (clientModel && clientModel->getOptionsModel()) {
        if (!clientModel->getOptionsModel()->getMinimizeOnClose()) {
            QApplication::quit();
        }
    }
#endif
    QMainWindow::closeEvent(event);
}

#ifdef ENABLE_WALLET
void BitcoinGUI::incomingTransaction(const QString& date, int unit, const CAmount& amount, const QString& type, const QString& address, const QString &confirmations)
{
    // Only send notifications when not disabled
    if (!bdisableSystemnotifications) {
        // On new transaction, make an info balloon
        message((amount) < 0 ? (pwalletMain->fMultiSendNotify == true ? tr("Sent MultiSend transaction") : tr("Sent transaction")) : tr("Incoming transaction"),
            tr("Date: %1\n"
               "Amount: %2\n"
               "Type: %3\n"
               "Address: %4\n"
               "Confirmations: %5\n")
                .arg(date)
                .arg(BitcoinUnits::formatWithUnit(unit, amount, true))
                .arg(type)
                .arg(address)
                .arg(confirmations),
            CClientUIInterface::MSG_INFORMATION);

        pwalletMain->fMultiSendNotify = false;
    }
}
#endif // ENABLE_WALLET

void BitcoinGUI::dragEnterEvent(QDragEnterEvent* event)
{
    // Accept only URIs
    if (event->mimeData()->hasUrls())
        event->acceptProposedAction();
}

bool BitcoinGUI::eventFilter(QObject *obj, QEvent *event)
{
    return false;
}

void BitcoinGUI::dropEvent(QDropEvent* event)
{
    if (event->mimeData()->hasUrls()) {
        foreach (const QUrl& uri, event->mimeData()->urls()) {
            emit receivedURI(uri.toString());
        }
    }
    event->acceptProposedAction();
}

void BitcoinGUI::setStakingStatus()
{
    bool stkStatus = false;
    if (pwalletMain) {
        fMultiSend = pwalletMain->isMultiSendEnabled();
        stkStatus = pwalletMain->ReadStakingStatus();
    }
    if (!stkStatus || pwalletMain->stakingMode == StakingMode::STOPPED || pwalletMain->IsLocked()) {
        LogPrint("staking","Checking Staking Status: Disabled.\n");
        stakingState->setText(tr("Staking Disabled"));
        stakingState->setToolTip("Staking Disabled");
        stakingAction->setIcon(QIcon(":/icons/staking_inactive"));
        return;
    }
    if (vNodes.empty()) {
        LogPrint("staking","Checking Staking Status: No Active Peers...\n");
        stakingState->setText(tr("No Active Peers"));
        stakingState->setToolTip("No Active Peers");
        stakingAction->setIcon(QIcon(":/icons/staking_inactive"));
        return;
    }
    if (IsInitialBlockDownload()) {
        LogPrint("staking","Checking Staking Status: Syncing...\n");
        stakingState->setText(tr("Syncing Blocks..."));
        stakingState->setToolTip("Syncing Blocks");
        stakingAction->setIcon(QIcon(":/icons/staking_waiting"));
        return;
    }
    if (!masternodeSync.IsSynced()) {
        LogPrint("staking","Checking Staking Status: Syncing MN List...\n");
        stakingState->setText(tr("Syncing MN List..."));
        stakingState->setToolTip("Syncing Masternode List");
        stakingAction->setIcon(QIcon(":/icons/staking_waiting"));
        return;
    }
    if (stakingState->text().contains("Enabling")) {
        if (!nLastCoinStakeSearchInterval) return;
    }
    if (nLastCoinStakeSearchInterval) {
        LogPrint("staking","Checking Staking Status: Enabled.\n");
        stakingState->setText(tr("Staking Enabled"));
        stakingState->setToolTip("Staking Enabled");
        stakingAction->setIcon(QIcon(":/icons/staking_active"));
    /*} else if (nConsolidationTime > 0) {
        nConsolidationTime --;
        stakingState->setText(tr("Consolidating Transactions…"));
        stakingState->setToolTip("Consolidating Transactions… Please wait few minutes for it to be consolidated.");
        stakingAction->setIcon(QIcon(":/icons/staking_active"));*/
    } else {
        LogPrint("staking","Checking Staking Status: Enabling...\n");
        stakingState->setText(tr("Enabling Staking..."));
        stakingState->setToolTip("Enabling Staking... Please wait up to 1.5 hours for it to be properly enabled after consolidation.");
        stakingAction->setIcon(QIcon(":/icons/staking_active"));
    }
}
void BitcoinGUI::setStakingInProgress(bool inProgress)
{
	if (inProgress) {
        stakingState->setText(tr("Enabling Staking..."));
        stakingState->setToolTip("Enabling Staking... Please wait up to 1.5 hours for it to be properly enabled after consolidation.");
        stakingAction->setIcon(QIcon(":/icons/staking_active"));
	} else {
        stakingState->setText(tr("Disabling Staking..."));
        stakingState->setToolTip("Disabling Staking...");
        stakingAction->setIcon(QIcon(":/icons/staking_inactive"));
	}
}

#ifdef ENABLE_WALLET

void BitcoinGUI::setEncryptionStatus(int status)
{
    switch (status) {
    case WalletModel::Unencrypted:
        labelEncryptionIcon->hide();
        encryptWalletAction->setChecked(false);
        changePassphraseAction->setEnabled(false);
        unlockWalletAction->setVisible(false);
        lockWalletAction->setVisible(false);
        encryptWalletAction->setEnabled(true);
        break;
    case WalletModel::Unlocked:
        labelEncryptionIcon->show();
        labelEncryptionIcon->setIcon(QIcon(":/icons/lock_open").pixmap(STATUSBAR_ICONSIZE, STATUSBAR_ICONSIZE));
        labelEncryptionIcon->setToolTip(tr("Wallet is <b>encrypted</b> and currently <b>unlocked</b>"));
        encryptWalletAction->setChecked(true);
        changePassphraseAction->setEnabled(true);
        unlockWalletAction->setVisible(false);
        lockWalletAction->setVisible(true);
        encryptWalletAction->setEnabled(false); // TODO: decrypt currently not supported
        break;
    case WalletModel::UnlockedForAnonymizationOnly:
        labelEncryptionIcon->show();
        labelEncryptionIcon->setIcon(QIcon(":/icons/lock_open").pixmap(STATUSBAR_ICONSIZE, STATUSBAR_ICONSIZE));
        labelEncryptionIcon->setToolTip(tr("Wallet is <b>encrypted</b> and currently <b>unlocked</b> for anonimization and staking only"));
        encryptWalletAction->setChecked(true);
        changePassphraseAction->setEnabled(true);
        unlockWalletAction->setVisible(true);
        lockWalletAction->setVisible(true);
        encryptWalletAction->setEnabled(false); // TODO: decrypt currently not supported
        break;
    case WalletModel::Locked:
        labelEncryptionIcon->show();
        labelEncryptionIcon->setIcon(QIcon(":/icons/lock_closed").pixmap(STATUSBAR_ICONSIZE, STATUSBAR_ICONSIZE));
        labelEncryptionIcon->setToolTip(tr("Wallet is <b>encrypted</b> and currently <b>locked</b>"));
        encryptWalletAction->setChecked(true);
        changePassphraseAction->setEnabled(true);
        unlockWalletAction->setVisible(true);
        lockWalletAction->setVisible(false);
        encryptWalletAction->setEnabled(false); // TODO: decrypt currently not supported
        break;
    }
}
#endif // ENABLE_WALLET

void BitcoinGUI::showNormalIfMinimized(bool fToggleHidden)
{
    if (!clientModel)
        return;

    // activateWindow() (sometimes) helps with keyboard focus on Windows
    if (isHidden()) {
        show();
        activateWindow();
    } else if (isMinimized()) {
        showNormal();
        activateWindow();
    } else if (GUIUtil::isObscured(this)) {
        raise();
        activateWindow();
    } else if (fToggleHidden)
        hide();
}

void BitcoinGUI::toggleHidden()
{
    showNormalIfMinimized(true);
}

void BitcoinGUI::detectShutdown()
{
    if (ShutdownRequested()) {
        if (rpcConsole)
            rpcConsole->hide();
        qApp->quit();
    }
}


static bool ThreadSafeMessageBox(BitcoinGUI* gui, const std::string& message, const std::string& caption, unsigned int style)
{
    bool modal = (style & CClientUIInterface::MODAL);
    style &= ~CClientUIInterface::SECURE;
    bool ret = false;
    // In case of modal message, use blocking connection to wait for user to click a button
    QMetaObject::invokeMethod(gui, "message",
        modal ? GUIUtil::blockingGUIThreadConnection() : Qt::QueuedConnection,
        Q_ARG(QString, QString::fromStdString(caption)),
        Q_ARG(QString, QString::fromStdString(message)),
        Q_ARG(unsigned int, style),
        Q_ARG(bool*, &ret));
    return ret;
}

void BitcoinGUI::exitApp(){
    QApplication::quit();
}

void BitcoinGUI::subscribeToCoreSignals()
{
    // Connect signals to client
    uiInterface.ThreadSafeMessageBox.connect(boost::bind(ThreadSafeMessageBox, this, _1, _2, _3));
}

void BitcoinGUI::unsubscribeFromCoreSignals()
{
    // Disconnect signals from client
    uiInterface.ThreadSafeMessageBox.disconnect(boost::bind(ThreadSafeMessageBox, this, _1, _2, _3));
}

/** Get restart command-line parameters and request restart */
void BitcoinGUI::handleRestart(QStringList args)
{
    if (!ShutdownRequested())
        emit requestedRestart(args);
}

UnitDisplayStatusBarControl::UnitDisplayStatusBarControl() : optionsModel(0),
                                                             menu(0)
{
    createContextMenu();
    setToolTip(tr("Unit to show amounts in. Click to select another unit."));
}

/** So that it responds to button clicks */
void UnitDisplayStatusBarControl::mousePressEvent(QMouseEvent* event)
{
    onDisplayUnitsClicked(event->pos());
}

/** Creates context menu, its actions, and wires up all the relevant signals for mouse events. */
void UnitDisplayStatusBarControl::createContextMenu()
{
    menu = new QMenu(this);
    menu->setAttribute(Qt::WA_DeleteOnClose);
    foreach (BitcoinUnits::Unit u, BitcoinUnits::availableUnits()) {
        QAction* menuAction = new QAction(QString(BitcoinUnits::name(u)), this);
        menuAction->setData(QVariant(u));
        menu->addAction(menuAction);
    }
    connect(menu, SIGNAL(triggered(QAction*)), this, SLOT(onMenuSelection(QAction*)));
}

/** Lets the control know about the Options Model (and its signals) */
void UnitDisplayStatusBarControl::setOptionsModel(OptionsModel* optionsModel)
{
    if (optionsModel) {
        this->optionsModel = optionsModel;

        // be aware of a display unit change reported by the OptionsModel object.
        connect(optionsModel, SIGNAL(displayUnitChanged(int)), this, SLOT(updateDisplayUnit(int)));

        // initialize the display units label with the current value in the model.
        updateDisplayUnit(optionsModel->getDisplayUnit());
    }
}

/** When Display Units are changed on OptionsModel it will refresh the display text of the control on the status bar */
void UnitDisplayStatusBarControl::updateDisplayUnit(int newUnits)
{
    if (Params().NetworkID() == CBaseChainParams::MAIN) {
        setPixmap(QIcon(":/icons/unit_" + BitcoinUnits::id(newUnits)).pixmap(39, STATUSBAR_ICONSIZE));
    } else {
        setPixmap(QIcon(":/icons/unit_t" + BitcoinUnits::id(newUnits)).pixmap(39, STATUSBAR_ICONSIZE));
    }
}

/** Shows context menu with Display Unit options by the mouse coordinates */
void UnitDisplayStatusBarControl::onDisplayUnitsClicked(const QPoint& point)
{
    QPoint globalPos = mapToGlobal(point);
    menu->exec(globalPos);
}

/** Tells underlying optionsModel to update its current display unit. */
void UnitDisplayStatusBarControl::onMenuSelection(QAction* action)
{
    if (action) {
        optionsModel->setDisplayUnit(action->data());
    }
}
