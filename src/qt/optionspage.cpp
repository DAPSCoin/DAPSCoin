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

    ui->line_2->setVisible(false);
    ui->lineEditWithhold->setVisible(false);
    ui->labelStaking->setVisible(false);
    ui->label_2->setVisible(false);
    ui->pushButtonSave->setVisible(false);
    ui->pushButtonDisable->setVisible(false);
    ui->addNewFunds->setVisible(false);

    connect(ui->pushButtonRecovery, SIGNAL(clicked()), this, SLOT(onShowMnemonic()));

    bool twoFAStatus = settings.value("2FA")=="enabled";
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

    ui->toggleStaking->setVisible(false);
}

void OptionsPage::setStakingToggle()
{
	//disable in multisig wallet
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
    //disable in multisig wallet
}

void OptionsPage::on_pushButtonDisable_clicked() {
    //disable in multisig wallet
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
	//dont support staking in multisig wallet
	QString msg("Staking is not supported in multisig wallet!");
	QStringList l;
	l.push_back(msg);
	GUIUtil::prompt(QString("<br><br>")+l.join(QString("<br><br>"))+QString("<br><br>"));
	widget->setState(false);
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
    //disabled
}
