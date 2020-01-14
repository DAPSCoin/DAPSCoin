// Copyright (c) 2011-2014 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "optionspage.h"
#include "ui_optionspage.h"

#include "addressbookpage.h"
#include "addresstablemodel.h"
#include "bitcoinunits.h"
#include "guiutil.h"
#include "guiconstants.h"
#include "bitcoingui.h"
#include "optionsmodel.h"
#include "receiverequestdialog.h"
#include "recentrequeststablemodel.h"
#include "walletmodel.h"
#include "2faqrdialog.h"
#include "2fadialog.h"
#include "2faconfirmdialog.h"
#include "zxcvbn.h"
#include "utilmoneystr.h"
#include "timedata.h"

#include <QAction>
#include <QCursor>
#include <QItemSelection>
#include <QMessageBox>
#include <QScrollBar>
#include <QTextDocument>
#include <QDataWidgetMapper>
#include <QDoubleValidator>
#include <QFile>
#include <QTextStream>

using namespace std;

OptionsPage::OptionsPage(QWidget* parent) : QDialog(parent, Qt::WindowSystemMenuHint | Qt::WindowTitleHint | Qt::WindowCloseButtonHint),
                                                          ui(new Ui::OptionsPage),
                                                          model(0),
                                                          // m_SizeGrip(this),
                                                          mapper(0)
{
    ui->setupUi(this);

    mapper = new QDataWidgetMapper(this);
    mapper->setSubmitPolicy(QDataWidgetMapper::ManualSubmit);

    ui->toggleTheme->setState(settings.value("theme")!="light");
    connect(ui->toggleTheme, SIGNAL(stateChanged(ToggleButton*)), this, SLOT(changeTheme(ToggleButton*)));

    connect(ui->lineEditNewPass, SIGNAL(textChanged(const QString &)), this, SLOT(validateNewPass()));
    connect(ui->lineEditNewPassRepeat, SIGNAL(textChanged(const QString &)), this, SLOT(validateNewPassRepeat()));
    connect(ui->lineEditOldPass, SIGNAL(textChanged(const QString &)), this, SLOT(onOldPassChanged()));

    QLocale lo(QLocale::C);
    lo.setNumberOptions(QLocale::RejectGroupSeparator);
    QDoubleValidator *dblVal = new QDoubleValidator(0, 250000000, 0, ui->lineEditWithhold);
    dblVal->setNotation(QDoubleValidator::StandardNotation);
    dblVal->setLocale(lo);
    ui->lineEditWithhold->setValidator(dblVal);
    ui->lineEditWithhold->setPlaceholderText("DAPS Amount");
    if (nReserveBalance > 0)
        ui->lineEditWithhold->setText(BitcoinUnits::format(0, nReserveBalance).toUtf8());

    bool stkStatus = pwalletMain->ReadStakingStatus();
    fLiteMode = GetBoolArg("-litemode", false);
    if (stkStatus && !fLiteMode){
        if (chainActive.Height() < Params().LAST_POW_BLOCK()) {
            stkStatus = false;
            pwalletMain->walletStakingInProgress = false;
            pwalletMain->WriteStakingStatus(false);
            //emit model->stakingStatusChanged(false);
        } else {
            QString error;
            StakingStatusError stt = model->getStakingStatusError(error);
            if (error.length()) {
                stkStatus = false;
                pwalletMain->walletStakingInProgress = false;
                pwalletMain->WriteStakingStatus(false);
                //emit model->stakingStatusChanged(false);
            }
        }
    }

    if (!fLiteMode) {
        //Staking related items and functions
        ui->toggleStaking->setState(nLastCoinStakeSearchInterval | stkStatus);
        connect(ui->toggleStaking, SIGNAL(stateChanged(ToggleButton*)), this, SLOT(on_EnableStaking(ToggleButton*)));
        timerStakingToggleSync = new QTimer();
        connect(timerStakingToggleSync, SIGNAL(timeout()), this, SLOT(setStakingToggle()));
        timerStakingToggleSync->start(10000);
        ui->labelStaking->show();
        ui->toggleStaking->show();
        ui->quantityLabel->show();
        ui->lineEditWithhold->show();
        ui->addNewFunds->show();
        ui->pushButtonSave->show();
        ui->pushButtonDisable->show();
        ui->line_3->show();
    } else {
        //Staking related items and functions hidden/removed in litemode
        ui->labelStaking->hide();
        ui->toggleStaking->hide();
        ui->quantityLabel->hide();
        ui->lineEditWithhold->hide();
        ui->addNewFunds->hide();
        ui->pushButtonSave->hide();
        ui->pushButtonDisable->hide();
        ui->line_3->hide();
    }


    connect(ui->pushButtonRecovery, SIGNAL(clicked()), this, SLOT(onShowMnemonic()));

    bool twoFAStatus = pwalletMain->Read2FA();
    if (twoFAStatus)
        enable2FA();
    else
        disable2FA();

    ui->toggle2FA->setState(twoFAStatus);
    connect(ui->toggle2FA, SIGNAL(stateChanged(ToggleButton*)), this, SLOT(on_Enable2FA(ToggleButton*)));

    connect(ui->btn_day, SIGNAL(clicked()), this, SLOT(on_day()));
    connect(ui->btn_week, SIGNAL(clicked()), this, SLOT(on_week()));
    connect(ui->btn_month, SIGNAL(clicked()), this, SLOT(on_month()));

    ui->lblAuthCode->setVisible(false);
    ui->code_1->setVisible(false);
    ui->code_2->setVisible(false);
    ui->code_3->setVisible(false);
    ui->code_4->setVisible(false);
    ui->code_5->setVisible(false);
    ui->code_6->setVisible(false);

    if (!pwalletMain->IsMasternodeController()) {
        if (pwalletMain) {
            bool isConsolidatedOn = pwalletMain->IsAutoConsolidateOn();
            ui->addNewFunds->setChecked(isConsolidatedOn);
        }
    } else {
        ui->addNewFunds->setChecked(false);
        ui->addNewFunds->setEnabled(false);
        QFont font = ui->addNewFunds->font();
        font.setStrikeOut(true);
        ui->addNewFunds->setFont(font);
        ui->addNewFunds->setToolTip("Disabled by default due to controlling Masternode(s) from this wallet.\nEnabling this will incur a minimum 1 DAPS fee each time you receive a new deposit that needs to be consolidated for staking.");
    }
    connect(ui->addNewFunds, SIGNAL(stateChanged(int)), this, SLOT(setAutoConsolidate(int)));
}

void OptionsPage::setStakingToggle()
{
	ui->toggleStaking->setState(fGenerateDapscoins);
}

void OptionsPage::setModel(WalletModel* model)
{
    this->model = model;
    this->options = model->getOptionsModel();

    if (model && model->getOptionsModel()) {
        model->getRecentRequestsTableModel()->sort(RecentRequestsTableModel::Date, Qt::DescendingOrder);
    }

    mapper->setModel(options);
    setMapper();
    mapper->toFirst();
}

static inline int64_t roundint64(double d)
{
    return (int64_t)(d > 0 ? d + 0.5 : d - 0.5);
}

CAmount OptionsPage::getValidatedAmount() {
    double dAmount = ui->lineEditWithhold->text().toDouble();
    CAmount nAmount = roundint64(dAmount * COIN);
    return nAmount;
}

OptionsPage::~OptionsPage()
{
	delete timerStakingToggleSync;
    delete ui;
}

void OptionsPage::resizeEvent(QResizeEvent* event)
{
    QWidget::resizeEvent(event);
}

void OptionsPage::on_pushButtonSave_clicked() {
    double dAmount = ui->lineEditWithhold->text().toDouble();
    if (ui->lineEditWithhold->text().trimmed().isEmpty()) {
        ui->lineEditWithhold->setStyleSheet("border: 2px solid red");
        QMessageBox msgBox;
        msgBox.setWindowTitle("Reserve Balance Empty");
        msgBox.setText("DAPS reserve amount is empty and must be a minimum of 1.\nPlease click Disable if you would like to turn it off.");
        msgBox.setStyleSheet(GUIUtil::loadStyleSheet());
        msgBox.setIcon(QMessageBox::Information);
        msgBox.exec();
        return;
    }
    if (dAmount < 0.0 || dAmount > 250000000) {
        QMessageBox msgBox;
        msgBox.setWindowTitle("Invalid Reserve Amount");
        msgBox.setText("The amount you have attempted to keep as spendable is greater than the 250,000,000 (250M) limit. Please try a smaller amount.");
        msgBox.setStyleSheet(GUIUtil::loadStyleSheet());
        msgBox.setIcon(QMessageBox::Warning);
        msgBox.exec();
        return;
    }
    nReserveBalance = getValidatedAmount();

    CWalletDB walletdb(pwalletMain->strWalletFile);
    walletdb.WriteReserveAmount(nReserveBalance / COIN);

    emit model->stakingStatusChanged(nLastCoinStakeSearchInterval);
    ui->lineEditWithhold->setStyleSheet(GUIUtil::loadStyleSheet());
	
    QString reserveBalance = ui->lineEditWithhold->text().trimmed();
    QMessageBox msgBox;
    msgBox.setWindowTitle("Reserve Balance Set");
    msgBox.setText("Reserve balance of " + reserveBalance + " DAPS is successfully set.");
    msgBox.setStyleSheet(GUIUtil::loadStyleSheet());
    msgBox.setIcon(QMessageBox::Information);
    msgBox.exec();
}

void OptionsPage::on_pushButtonDisable_clicked() {
    ui->lineEditWithhold->setText("0");

    CWalletDB walletdb(pwalletMain->strWalletFile);
    walletdb.WriteReserveAmount(0);

    emit model->stakingStatusChanged(nLastCoinStakeSearchInterval);
    QMessageBox msgBox;
    msgBox.setWindowTitle("Reserve Balance Disabled");
    msgBox.setText("Reserve balance disabled.");
    msgBox.setStyleSheet(GUIUtil::loadStyleSheet());
    msgBox.setIcon(QMessageBox::Information);
    msgBox.exec();
}

void OptionsPage::keyPressEvent(QKeyEvent* event)
{

    this->QDialog::keyPressEvent(event);
}

void OptionsPage::setMapper()
{
}

void OptionsPage::on_pushButtonPassword_clicked()
{
    if ( (!ui->lineEditNewPass->text().length()) || (!ui->lineEditNewPassRepeat->text().length()) ) {
        QMessageBox msgBox;
        msgBox.setWindowTitle("Wallet Encryption Failed");
        msgBox.setText("The passphrase entered for wallet encryption was empty or contained spaces. Please try again.");
        msgBox.setStyleSheet(GUIUtil::loadStyleSheet());
        msgBox.setIcon(QMessageBox::Critical);
        msgBox.exec();
        return;
    }
    //disable password submit button
    SecureString oldPass = SecureString();
    oldPass.reserve(MAX_PASSPHRASE_SIZE);
    oldPass.assign( ui->lineEditOldPass->text().toStdString().c_str() );
    SecureString newPass = SecureString();
    newPass.reserve(MAX_PASSPHRASE_SIZE);
    newPass.assign( ui->lineEditNewPass->text().toStdString().c_str() );

    SecureString newPass2 = SecureString();
    newPass2.reserve(MAX_PASSPHRASE_SIZE);
    newPass2.assign(ui->lineEditNewPassRepeat->text().toStdString().c_str() );

    bool success = false;

    if (newPass == newPass2) {
        double guesses;

        if (oldPass == newPass) {
            QMessageBox msgBox;
            msgBox.setWindowTitle("Wallet Encryption Failed");
            msgBox.setText("The passphrase you have entered is the same as your old passphrase. Please use a different passphrase if you would like to change it.");
            msgBox.setStyleSheet(GUIUtil::loadStyleSheet());
            msgBox.setIcon(QMessageBox::Critical);
            msgBox.exec();
        }
        else if (newPass.length() < 10) {
            QMessageBox msgBox;
            msgBox.setWindowTitle("Wallet Encryption Failed");
            msgBox.setText("The passphrase's length has to be more than 10. Please try again.");
            msgBox.setStyleSheet(GUIUtil::loadStyleSheet());
            msgBox.setIcon(QMessageBox::Critical);
            msgBox.exec();
        }
        else if (!pwalletMain->checkPassPhraseRule(newPass.c_str())) {
            QMessageBox msgBox;
            msgBox.setWindowTitle("Wallet Encryption Failed");
            msgBox.setText("The passphrase must contain lower, upper, digit, symbol. Please try again.");
            msgBox.setStyleSheet(GUIUtil::loadStyleSheet());
            msgBox.setIcon(QMessageBox::Critical);
            msgBox.exec();
        }
        else if (zxcvbn_password_strength(newPass.c_str(), NULL, &guesses, NULL) < 0 || guesses < 10000) {
            QMessageBox msgBox;
            msgBox.setWindowTitle("Wallet Encryption Failed");
            msgBox.setText("The passphrase is too weak. You must use a minimum passphrase length of 10 characters and use uppercase letters, lowercase letters, numbers, and symbols. Please try again.");
            msgBox.setStyleSheet(GUIUtil::loadStyleSheet());
            msgBox.setIcon(QMessageBox::Critical);
            msgBox.exec();
        }
    	else if (model->changePassphrase(oldPass, newPass)) {
            QMessageBox msgBox;
            msgBox.setWindowTitle("Passphrase Change Successful");
            msgBox.setText("Wallet passphrase was successfully changed.\nPlease remember your passphrase as there is no way to recover it.");
            msgBox.setStyleSheet(GUIUtil::loadStyleSheet());
            msgBox.setIcon(QMessageBox::Information);
            msgBox.exec();
    		success = true;
        }
    } else {
            QMessageBox msgBox;
            msgBox.setWindowTitle("Wallet Encryption Failed");
            msgBox.setText("The passphrases entered for wallet encryption do not match. Please try again.");
            msgBox.setStyleSheet(GUIUtil::loadStyleSheet());
            msgBox.setIcon(QMessageBox::Critical);
            msgBox.exec();
    }

    if (success)
        ui->pushButtonPassword->setStyleSheet("border: 2px solid green");
    else ui->pushButtonPassword->setStyleSheet("border: 2px solid red");
    ui->pushButtonPassword->repaint();
}

void OptionsPage::on_pushButtonPasswordClear_clicked()
{
    ui->lineEditOldPass->clear();
    ui->lineEditNewPass->clear();
    ui->lineEditNewPassRepeat->clear();
    ui->lineEditOldPass->setStyleSheet(GUIUtil::loadStyleSheet());
    ui->lineEditNewPass->setStyleSheet(GUIUtil::loadStyleSheet());
    ui->lineEditNewPassRepeat->setStyleSheet(GUIUtil::loadStyleSheet());
}

void OptionsPage::on_pushButtonBackup_clicked(){
    QString filename = GUIUtil::getSaveFileName(this,
        tr("Backup Wallet"), QString(),
        tr("Wallet Data (*.dat)"), NULL);

    if (filename.isEmpty())
        return;

    if (model->backupWallet(QString(filename))) {
        ui->pushButtonBackup->setStyleSheet("border: 2px solid green");
        QMessageBox msgBox;
        msgBox.setWindowTitle("Wallet Backup Successful");
        msgBox.setText("Wallet has been successfully backed up to " + filename);
        msgBox.setStyleSheet(GUIUtil::loadStyleSheet());
        msgBox.setIcon(QMessageBox::Information);
        msgBox.exec();
    } else {
        ui->pushButtonBackup->setStyleSheet("border: 2px solid red");
        QMessageBox msgBox;
        msgBox.setWindowTitle("Wallet Backup Failed");
        msgBox.setText("Wallet backup failed. Please try again.");
        msgBox.setStyleSheet(GUIUtil::loadStyleSheet());
        msgBox.setIcon(QMessageBox::Critical);
        msgBox.exec();
}
    ui->pushButtonBackup->repaint();
}

void OptionsPage::validateNewPass()
{
    if (!ui->lineEditNewPass->text().length())
        ui->lineEditNewPass->setStyleSheet("border-color: red");
    else ui->lineEditNewPass->setStyleSheet(GUIUtil::loadStyleSheet());
    matchNewPasswords();
    ui->lineEditNewPass->repaint();
}

void OptionsPage::validateNewPassRepeat()
{
    matchNewPasswords();
}

void OptionsPage::onOldPassChanged()
{
    QString stylesheet = GUIUtil::loadStyleSheet();
    ui->lineEditOldPass->setStyleSheet(stylesheet);
    ui->lineEditOldPass->repaint();
    ui->pushButtonPassword->setStyleSheet(stylesheet);
    ui->pushButtonPassword->repaint();
    if (!ui->lineEditNewPass->text().length())
        ui->lineEditNewPass->setStyleSheet("border-color: red");
    ui->lineEditNewPass->repaint();
}

bool OptionsPage::matchNewPasswords()
{
    if (ui->lineEditNewPass->text()==ui->lineEditNewPassRepeat->text())
    {
        ui->lineEditNewPassRepeat->setStyleSheet(GUIUtil::loadStyleSheet());
        ui->lineEditNewPassRepeat->repaint();
        return true;
    } else
    {
        ui->lineEditNewPassRepeat->setStyleSheet("border-color: red");
        ui->lineEditNewPassRepeat->repaint();
        return false;
    }
}

void OptionsPage::on_EnableStaking(ToggleButton* widget)
{
    int status = model->getEncryptionStatus();
    if (status == WalletModel::Locked || status == WalletModel::UnlockedForAnonymizationOnly) {
        QMessageBox msgBox;
        msgBox.setWindowTitle("Staking Setting");
        msgBox.setIcon(QMessageBox::Information);
        msgBox.setText("Please unlock the keychain wallet with your passphrase before changing this setting.");
        msgBox.setStyleSheet(GUIUtil::loadStyleSheet());
        msgBox.exec();
        widget->setState(!widget->getState());
        return;
    }

    if (chainActive.Height() < Params().LAST_POW_BLOCK()) {
    	if (widget->getState()) {
            QString msg;
            msg.sprintf("PoW blocks are still being mined.\nPlease wait until Block %d.", Params().LAST_POW_BLOCK());
            QMessageBox msgBox;
            msgBox.setWindowTitle("Information");
            msgBox.setIcon(QMessageBox::Information);
            msgBox.setText(msg);
            msgBox.setStyleSheet(GUIUtil::loadStyleSheet());
            msgBox.exec();
    	}
    	widget->setState(false);
    	pwalletMain->WriteStakingStatus(false);
    	pwalletMain->walletStakingInProgress = false;
        return;
    }
	if (widget->getState()){
        QString error;
        CAmount minFee, maxFee;
        StakingStatusError stt = pwalletMain->StakingCoinStatus(minFee, maxFee);
        std::string errorMessage;
        if (stt == StakingStatusError::UNSTAKABLE_BALANCE_TOO_LOW || 
            stt == UNSTAKABLE_BALANCE_RESERVE_TOO_HIGH ||
            stt == UNSTAKABLE_BALANCE_RESERVE_TOO_HIGH_CONSOLIDATION_FAILED ||
            stt == UNSTAKABLE_BALANCE_TOO_LOW_CONSOLIDATION_FAILED) {
            QMessageBox msgBox;
            if (stt == StakingStatusError::UNSTAKABLE_BALANCE_TOO_LOW) {
                errorMessage = "Your stakeable balance is under the threshold of 400 000 DAPS. Please deposit more DAPS into your account in order to enable staking.";
            } else if (stt == UNSTAKABLE_BALANCE_TOO_LOW_CONSOLIDATION_FAILED) {
                errorMessage = "Your balance requires a consolidation transaction which incurs a fee of between  " + FormatMoney(minFee) + " to " + FormatMoney(maxFee) + " DAPS. However after that transaction fee, your balance will be below the staking threshold of 400 000 DAPS. Please deposit more DAPS into your account or reduce your reserved amount in order to enable staking.";
            } else if (stt == UNSTAKABLE_BALANCE_RESERVE_TOO_HIGH) {
                errorMessage = "Your stakeable balance is under the threshold of 400 000 DAPS. This is due to your reserve balance being too high. Please deposit more DAPS into your account or reduce your reserved amount in order to enable staking.";
            } else {
                CAmount totalFee = maxFee + pwalletMain->ComputeFee(1, 2, MAX_RING_SIZE);
                errorMessage = "Your stakeable balance is under the threshold of 400 000 DAPS. This is due to your reserve balance of " + FormatMoney(nReserveBalance) + " DAPS being too high. The wallet software has tried to consolidate your funds with the reserve balance but without success because of a consolidation fee of " + FormatMoney(totalFee) + " DAPS. Please wait around 10 minutes for the wallet to resolve the reserve to enable staking.";
            }
        	QString msg = QString::fromStdString(errorMessage);
        	msgBox.setWindowTitle("Warning: Staking Issue");
    		msgBox.setIcon(QMessageBox::Warning);
    		msgBox.setText(msg);
            msgBox.setStyleSheet(GUIUtil::loadStyleSheet());
        	msgBox.exec();
        	widget->setState(false);
        	nLastCoinStakeSearchInterval = 0;
        	emit model->stakingStatusChanged(false);
        	pwalletMain->WriteStakingStatus(false);   
            return; 
        } 
        if (stt == StakingStatusError::STAKING_OK) {
            pwalletMain->WriteStakingStatus(true);
            emit model->stakingStatusChanged(true);
            model->generateCoins(true, 1);
            pwalletMain->fCombineDust = true;
            pwalletMain->stakingMode = StakingMode::STAKING_WITH_CONSOLIDATION;
            saveConsolidationSettingTime(ui->addNewFunds->isChecked());
            return;
        }

        QMessageBox::StandardButton reply;
        if (stt == StakingStatusError::STAKABLE_NEED_CONSOLIDATION) {
            errorMessage = "In order to enable staking with 100% of your current balance, your previous DAPS deposits must be consolidated and reorganized. This will incur a fee of between " + FormatMoney(minFee) + " to " + FormatMoney(maxFee) + " DAPS.\n\nWould you like to do this?";
        } else {
            errorMessage = "In order to enable staking with 100% of your current balance except the reserve balance, your previous DAPS deposits must be consolidated and reorganized. This will incur a fee of between " + FormatMoney(minFee) + " to " + FormatMoney(maxFee) + " DAPS.\n\nWould you like to do this?";
        }
        reply = QMessageBox::question(this, "Staking Needs Consolidation", QString::fromStdString(errorMessage), QMessageBox::Yes|QMessageBox::No);
		if (reply == QMessageBox::Yes) { 
            pwalletMain->WriteStakingStatus(true);
            emit model->stakingStatusChanged(true);
            model->generateCoins(true, 1);
            pwalletMain->fCombineDust = true;
            pwalletMain->stakingMode = StakingMode::STAKING_WITH_CONSOLIDATION;
            saveConsolidationSettingTime(ui->addNewFunds->isChecked());
            bool success = false;
        	try {
                uint32_t nTime = pwalletMain->ReadAutoConsolidateSettingTime();
                nTime = (nTime == 0)? GetAdjustedTime() : nTime;
        		success = model->getCWallet()->CreateSweepingTransaction(
								CWallet::MINIMUM_STAKE_AMOUNT,
								CWallet::MINIMUM_STAKE_AMOUNT, nTime);
                if (success) {
                    //nConsolidationTime = 1800;
                    QString msg = "Consolidation transaction created!";
                    QMessageBox msgBox;
                    msgBox.setWindowTitle("Information");
                    msgBox.setIcon(QMessageBox::Information);
                    msgBox.setText(msg);
                    msgBox.setStyleSheet(GUIUtil::loadStyleSheet());
                    msgBox.exec();
                }
            } catch (const std::exception& err) {
                LogPrintf("Sweeping failed, will be done automatically when coins become mature");
        	}            
            return;
        } else {
            pwalletMain->stakingMode = StakingMode::STOPPED;
            nLastCoinStakeSearchInterval = 0;
            model->generateCoins(false, 0);
            emit model->stakingStatusChanged(false);
            pwalletMain->walletStakingInProgress = false;
            pwalletMain->WriteStakingStatus(false);
            return;
        }
        /* if (!error.length()) {
            pwalletMain->WriteStakingStatus(true);
            emit model->stakingStatusChanged(true);
            model->generateCoins(true, 1);
        } else {
        	if (stt != StakingStatusError::UTXO_UNDER_THRESHOLD) {
        		QMessageBox msgBox;
        		QString msg(error);
        		msgBox.setWindowTitle("Warning: Staking Issue");
        		msgBox.setIcon(QMessageBox::Warning);
        		msgBox.setText(msg);
        		msgBox.setStyleSheet(GUIUtil::loadStyleSheet());
        		msgBox.exec();
        		widget->setState(false);
        		nLastCoinStakeSearchInterval = 0;
        		emit model->stakingStatusChanged(false);
        		pwalletMain->WriteStakingStatus(false);
        	} else {
        		QMessageBox::StandardButton reply;
        		reply = QMessageBox::question(this, "Create Stakable Transaction?", error, QMessageBox::Yes|QMessageBox::No);
        		if (reply == QMessageBox::Yes) {
        			//ask yes or no
        			//send to this self wallet MIN staking amount
        			std::string masterAddr;
        			model->getCWallet()->ComputeStealthPublicAddress("masteraccount", masterAddr);
        			CWalletTx resultTx;
        			bool success = false;
        			try {
        				success = model->getCWallet()->SendToStealthAddress(
        						masterAddr,
								CWallet::MINIMUM_STAKE_AMOUNT,
								resultTx,
								false
        				);
                    } catch (const std::exception& err)
                    {
                        QMessageBox msgBox;
                        msgBox.setWindowTitle("Could Not Send");
                        msgBox.setIcon(QMessageBox::Warning);
                        msgBox.setText(QString(err.what()));
                        msgBox.setStyleSheet(GUIUtil::loadStyleSheet());
                        msgBox.exec();
        				return;
        			}

        			if (success){
                        WalletUtil::getTx(pwalletMain, resultTx.GetHash());
                        QString txhash = resultTx.GetHash().GetHex().c_str();
                        QMessageBox msgBox;
                        QPushButton *copyButton = msgBox.addButton(tr("Copy"), QMessageBox::ActionRole);
                        copyButton->setStyleSheet("background:transparent;");
                        copyButton->setIcon(QIcon(":/icons/editcopy"));
                        msgBox.setWindowTitle("Transaction Initialized");
                        msgBox.setText("Transaction initialized.\n\n" + txhash);
                        msgBox.setStyleSheet(GUIUtil::loadStyleSheet());
                        msgBox.setIcon(QMessageBox::Information);
                        msgBox.exec();

                        if (msgBox.clickedButton() == copyButton) {
                        //Copy txhash to clipboard
                        GUIUtil::setClipboard(txhash);
                        }
        			}
        		} else {
        			widget->setState(false);
        			nLastCoinStakeSearchInterval = 0;
        			emit model->stakingStatusChanged(false);
        			pwalletMain->WriteStakingStatus(false);
        		}
        	}
        }*/
    } else {
        pwalletMain->stakingMode = StakingMode::STOPPED;
        nLastCoinStakeSearchInterval = 0;
        model->generateCoins(false, 0);
        emit model->stakingStatusChanged(false);
        pwalletMain->walletStakingInProgress = false;
        pwalletMain->WriteStakingStatus(false);
    }
}

void OptionsPage::on_Enable2FA(ToggleButton* widget)
{
    int status = model->getEncryptionStatus();
    if (status == WalletModel::Locked || status == WalletModel::UnlockedForAnonymizationOnly) {
        QMessageBox msgBox;
        msgBox.setWindowTitle("2FA Setting");
        msgBox.setIcon(QMessageBox::Information);
        msgBox.setText("Please unlock the keychain wallet with your passphrase before changing this setting.");
        msgBox.setStyleSheet(GUIUtil::loadStyleSheet());
        msgBox.exec();

        ui->toggle2FA->setState(!ui->toggle2FA->getState());
        return;
    }

    if (widget->getState()) {
        TwoFAQRDialog qrdlg;
        qrdlg.setWindowTitle("2FA QR Code & Recovery Key");
        qrdlg.setModel(this->model);
        qrdlg.setStyleSheet(GUIUtil::loadStyleSheet());
        connect(&qrdlg, SIGNAL(finished (int)), this, SLOT(qrDialogIsFinished(int)));
        qrdlg.exec();
    } else {
        typeOf2FA = DISABLE;

        TwoFADialog codedlg;
        codedlg.setWindowTitle("2FA Code Verification");
        codedlg.setStyleSheet(GUIUtil::loadStyleSheet());
        connect(&codedlg, SIGNAL(finished (int)), this, SLOT(confirmDialogIsFinished(int)));
        codedlg.exec();
    }
}

void OptionsPage::qrDialogIsFinished(int result) {
    if(result == QDialog::Accepted){
        TwoFADialog codedlg;
        codedlg.setWindowTitle("2FA Code Verification");
        codedlg.setStyleSheet(GUIUtil::loadStyleSheet());
        connect(&codedlg, SIGNAL(finished (int)), this, SLOT(dialogIsFinished(int)));
        codedlg.exec();
    }

    if (result == QDialog::Rejected)
        ui->toggle2FA->setState(false);

}

void OptionsPage::dialogIsFinished(int result) {
   if(result == QDialog::Accepted){
        pwalletMain->Write2FA(true);
        QDateTime current = QDateTime::currentDateTime();
        pwalletMain->Write2FALastTime(current.toTime_t());
        enable2FA();

        QMessageBox msgBox;
        msgBox.setWindowTitle("SUCCESS!");
        msgBox.setIcon(QMessageBox::Information);
        msgBox.setText("Two-factor authentication has been successfully enabled.");
        msgBox.setStyleSheet(GUIUtil::loadStyleSheet());
        msgBox.exec();
   }

   if (result == QDialog::Rejected)
        ui->toggle2FA->setState(false);
}

void OptionsPage::changeTheme(ToggleButton* widget)
{
    if (widget->getState())
        settings.setValue("theme", "dark");
    else settings.setValue("theme", "light");
    	GUIUtil::refreshStyleSheet();
}

void OptionsPage::disable2FA() {
    ui->code_1->setText("");
    ui->code_2->setText("");
    ui->code_3->setText("");
    ui->code_4->setText("");
    ui->code_5->setText("");
    ui->code_6->setText("");

    ui->label_3->setEnabled(false);
    ui->lblAuthCode->setEnabled(false);
    ui->label->setEnabled(false);
    ui->btn_day->setEnabled(false);
    ui->btn_week->setEnabled(false);
    ui->btn_month->setEnabled(false);

    ui->btn_day->setStyleSheet("border-color: none;");
    ui->btn_week->setStyleSheet("border-color: none;");
    ui->btn_month->setStyleSheet("border-color: none;");
    typeOf2FA = NONE2FA;
}

void OptionsPage::enable2FA() {
    ui->label_3->setEnabled(true);
    ui->lblAuthCode->setEnabled(true);
    ui->label->setEnabled(true);
    ui->btn_day->setEnabled(true);
    ui->btn_week->setEnabled(true);
    ui->btn_month->setEnabled(true);

    QString code = QString::fromStdString(pwalletMain->Read2FASecret());
    if (code != "") {
        char chrlist[6];
        memcpy(chrlist, code.toUtf8().data(), 6);
        QString value;
        value.sprintf("%c", chrlist[0]);
        ui->code_1->setText(value);
        value.sprintf("%c", chrlist[1]);
        ui->code_2->setText(value);
        value.sprintf("%c", chrlist[2]);
        ui->code_3->setText(value);
        value.sprintf("%c", chrlist[3]);
        ui->code_4->setText(value);
        value.sprintf("%c", chrlist[4]);
        ui->code_5->setText(value);
        value.sprintf("%c", chrlist[5]);
        ui->code_6->setText(value);
    }
     
    int period = pwalletMain->Read2FAPeriod();
    typeOf2FA = NONE2FA;
    if (period == 1) {
        ui->btn_day->setStyleSheet("border-color: green;");
        typeOf2FA = DAY;
    }
    else if (period == 7) {
        ui->btn_week->setStyleSheet("border-color: green;");
        typeOf2FA = WEEK;
    }
    else if (period == 30) {
        ui->btn_month->setStyleSheet("border-color: green;");
        typeOf2FA = MONTH;
    }
}

void OptionsPage::confirmDialogIsFinished(int result) {
    if(result == QDialog::Accepted){
        if (typeOf2FA == DAY) {
            pwalletMain->Write2FAPeriod(1);
            ui->btn_day->setStyleSheet("border-color: green;");
            ui->btn_week->setStyleSheet("border-color: white;");
            ui->btn_month->setStyleSheet("border-color: white;");
        } else if (typeOf2FA == WEEK) {
            pwalletMain->Write2FAPeriod(7);
            ui->btn_day->setStyleSheet("border-color: white;");
            ui->btn_week->setStyleSheet("border-color: green;");
            ui->btn_month->setStyleSheet("border-color: white;");
        } else if (typeOf2FA == MONTH) {
            pwalletMain->Write2FAPeriod(30);
            ui->btn_day->setStyleSheet("border-color: white;");
            ui->btn_week->setStyleSheet("border-color: white;");
            ui->btn_month->setStyleSheet("border-color: green;");
        } else if (typeOf2FA == DISABLE) {
            pwalletMain->Write2FA(false);
            pwalletMain->Write2FASecret("");
            pwalletMain->Write2FAPeriod(0);
            pwalletMain->Write2FALastTime(0);
            disable2FA();
        }
    }

    if (result == QDialog::Rejected)
        ui->toggle2FA->setState(true);
}

void OptionsPage::on_day() {
    typeOf2FA = DAY;

    TwoFADialog codedlg;
    codedlg.setWindowTitle("2FA Code Verification");
    codedlg.setStyleSheet(GUIUtil::loadStyleSheet());
    connect(&codedlg, SIGNAL(finished (int)), this, SLOT(confirmDialogIsFinished(int)));
    codedlg.exec();
}

void OptionsPage::on_week() {
    typeOf2FA = WEEK;

    TwoFADialog codedlg;
    codedlg.setWindowTitle("2FA Code Verification");
    codedlg.setStyleSheet(GUIUtil::loadStyleSheet());
    connect(&codedlg, SIGNAL(finished (int)), this, SLOT(confirmDialogIsFinished(int)));
    codedlg.exec();   
}

void OptionsPage::on_month() {
    typeOf2FA = MONTH;

    TwoFADialog codedlg;
    codedlg.setWindowTitle("2FA Code Verification");
    codedlg.setStyleSheet(GUIUtil::loadStyleSheet());
    connect(&codedlg, SIGNAL(finished (int)), this, SLOT(confirmDialogIsFinished(int)));
    codedlg.exec();
}

void OptionsPage::onShowMnemonic() {
    int status = model->getEncryptionStatus();
    if (status == WalletModel::Locked || status == WalletModel::UnlockedForAnonymizationOnly) {
        WalletModel::UnlockContext ctx(model->requestUnlock(false));
        if (!ctx.isValid()) {
            QMessageBox msgBox;
            msgBox.setWindowTitle("Mnemonic Recovery Phrase");
            msgBox.setIcon(QMessageBox::Information);
            msgBox.setText("Attempt to view Mnemonic Phrase failed or canceled. Wallet locked for security.");
            msgBox.setStyleSheet(GUIUtil::loadStyleSheet());
            msgBox.exec();
            LogPrintf("Attempt to view Mnemonic Phrase failed or canceled. Wallet locked for security.\n");
            return;
        } else {
            SecureString pass;
            model->setWalletLocked(false, pass);
            LogPrintf("Attempt to view Mnemonic Phrase successful.\n");
        }
    } else {
        QMessageBox::StandardButton reply;
        reply = QMessageBox::question(this, "Are You Sure?", "Are you sure you would like to view your Mnemonic Phrase?\nYou will be required to enter your passphrase. Failed or canceled attempts will be logged.", QMessageBox::Yes|QMessageBox::No);
        if (reply == QMessageBox::Yes) {
            model->setWalletLocked(true);
            WalletModel::UnlockContext ctx(model->requestUnlock(false));
            if (!ctx.isValid()) {
                QMessageBox msgBox;
                msgBox.setWindowTitle("Mnemonic Recovery Phrase");
                msgBox.setIcon(QMessageBox::Information);
                msgBox.setText("Attempt to view Mnemonic Phrase failed or canceled. Wallet locked for security.");
                msgBox.setStyleSheet(GUIUtil::loadStyleSheet());
                msgBox.exec();
                LogPrintf("Attempt to view Mnemonic Phrase failed or canceled. Wallet locked for security.\n");
                return;
            } else {
                SecureString pass;
                model->setWalletLocked(false, pass);
                LogPrintf("Attempt to view Mnemonic Phrase successful.\n");
            }
        } else {
            LogPrintf("Attempt to view Mnemonic Phrase canceled.\n");
            return;
        }
    }
	
    CHDChain hdChainCurrent;
    if (!pwalletMain->GetDecryptedHDChain(hdChainCurrent))
        return;

    SecureString mnemonic;
    SecureString mnemonicPass;
    if (!hdChainCurrent.GetMnemonic(mnemonic, mnemonicPass))
        return;

    QString mPhrase = std::string(mnemonic.begin(), mnemonic.end()).c_str();
    QMessageBox msgBox;
    msgBox.setWindowTitle("Mnemonic Recovery Phrase");
    msgBox.setText("Below is your Mnemonic Recovery Phrase, consisting of 24 seed words. Please copy/write these words down in order. We strongly recommend keeping multiple copies in different locations.");
    msgBox.setInformativeText("\n<b>" + mPhrase + "</b>");
    msgBox.setStyleSheet(GUIUtil::loadStyleSheet());
    msgBox.exec();
}

void OptionsPage::setAutoConsolidate(int state) {
    int status = model->getEncryptionStatus();
    if (status == WalletModel::Locked || status == WalletModel::UnlockedForAnonymizationOnly) {
        QMessageBox msgBox;
        msgBox.setWindowTitle("Staking Settings");
        msgBox.setIcon(QMessageBox::Information);
        msgBox.setText("Please unlock the keychain wallet with your passphrase before attempting to change this setting.");
        msgBox.setStyleSheet(GUIUtil::loadStyleSheet());
        msgBox.exec();
        return;
    }
    LOCK(pwalletMain->cs_wallet);
    saveConsolidationSettingTime(ui->addNewFunds->isChecked());
}

void OptionsPage::saveConsolidationSettingTime(bool autoConsolidate)
{
    if (!pwalletMain->IsMasternodeController() && autoConsolidate) {
        pwalletMain->WriteAutoConsolidateSettingTime(0);
    } else {
        pwalletMain->WriteAutoConsolidateSettingTime(GetAdjustedTime());
    }
}
