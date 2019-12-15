// Copyright (c) 2011-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2017 The DAPS Project developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "sendcoinsdialog.h"
#include "ui_sendcoinsdialog.h"

#include "addresstablemodel.h"
#include "askpassphrasedialog.h"
#include "bitcoinunits.h"
#include "clientmodel.h"
#include "coincontroldialog.h"
#include "guiutil.h"
#include "optionsmodel.h"
#include "sendcoinsentry.h"
#include "walletmodel.h"

#include "base58.h"
#include "coincontrol.h"
#include "ui_interface.h"
#include "utilmoneystr.h"
#include "wallet.h"
#include "2faconfirmdialog.h"
#include "timedata.h"

#include <regex>
#include <QMessageBox>
#include <QScrollBar>
#include <QSettings>
#include <QTextDocument>
#include <QDateTime>
#include <QDebug>
#include <QClipboard>


SendCoinsDialog::SendCoinsDialog(QWidget* parent) : QDialog(parent, Qt::WindowSystemMenuHint | Qt::WindowTitleHint | Qt::WindowCloseButtonHint),
                                                    ui(new Ui::SendCoinsDialog),
                                                    clientModel(0),
                                                    // m_SizeGrip(this),
                                                    model(0),
                                                    fNewRecipientAllowed(true)
{
    ui->setupUi(this);

    addEntry();

    //connect(ui->addButton, SIGNAL(clicked()), this, SLOT(addEntry()));
    connect(ui->copyButton, SIGNAL(clicked()), this, SLOT(on_copyButton_Clicked()));
    // #HIDE multisend
    ui->addButton->setVisible(false);

    ui->copyButton->setStyleSheet("background:transparent;");
    ui->copyButton->setIcon(QIcon(":/icons/editcopy"));
    connect(ui->addButton, SIGNAL(clicked()), this, SLOT(addEntry()));

    // Coin Control
    connect(ui->pushButtonCoinControl, SIGNAL(clicked()), this, SLOT(coinControlButtonClicked()));
    connect(ui->checkBoxCoinControlChange, SIGNAL(stateChanged(int)), this, SLOT(coinControlChangeChecked(int)));
    connect(ui->lineEditCoinControlChange, SIGNAL(textEdited(const QString&)), this, SLOT(coinControlChangeEdited(const QString&)));
    ui->pushButtonCoinControl->setVisible(false);
    ui->checkBoxCoinControlChange->setVisible(false);
    ui->lineEditCoinControlChange->setVisible(false);

    // Coin Control: clipboard actions
    QAction* clipboardQuantityAction = new QAction(tr("Copy quantity"), this);
    QAction* clipboardAmountAction = new QAction(tr("Copy amount"), this);
    QAction* clipboardFeeAction = new QAction(tr("Copy fee"), this);
    QAction* clipboardAfterFeeAction = new QAction(tr("Copy after fee"), this);
    QAction* clipboardBytesAction = new QAction(tr("Copy bytes"), this);
    QAction* clipboardPriorityAction = new QAction(tr("Copy priority"), this);
    QAction* clipboardLowOutputAction = new QAction(tr("Copy dust"), this);
    QAction* clipboardChangeAction = new QAction(tr("Copy change"), this);
    connect(clipboardQuantityAction, SIGNAL(triggered()), this, SLOT(coinControlClipboardQuantity()));
    connect(clipboardAmountAction, SIGNAL(triggered()), this, SLOT(coinControlClipboardAmount()));
    connect(clipboardFeeAction, SIGNAL(triggered()), this, SLOT(coinControlClipboardFee()));
    connect(clipboardAfterFeeAction, SIGNAL(triggered()), this, SLOT(coinControlClipboardAfterFee()));
    connect(clipboardBytesAction, SIGNAL(triggered()), this, SLOT(coinControlClipboardBytes()));
    connect(clipboardPriorityAction, SIGNAL(triggered()), this, SLOT(coinControlClipboardPriority()));
    connect(clipboardLowOutputAction, SIGNAL(triggered()), this, SLOT(coinControlClipboardLowOutput()));
    connect(clipboardChangeAction, SIGNAL(triggered()), this, SLOT(coinControlClipboardChange()));
    ui->labelCoinControlQuantity->addAction(clipboardQuantityAction);
    ui->labelCoinControlAmount->addAction(clipboardAmountAction);
    ui->labelCoinControlFee->addAction(clipboardFeeAction);
    ui->labelCoinControlAfterFee->addAction(clipboardAfterFeeAction);
    ui->labelCoinControlBytes->addAction(clipboardBytesAction);
    ui->labelCoinControlPriority->addAction(clipboardPriorityAction);
    ui->labelCoinControlLowOutput->addAction(clipboardLowOutputAction);
    ui->labelCoinControlChange->addAction(clipboardChangeAction);

    ui->labelCoinControlQuantity->setVisible(false);
    ui->labelCoinControlAmount->setVisible(false);
    ui->labelCoinControlFee->setVisible(false);
    ui->labelCoinControlAfterFee->setVisible(false);
    ui->labelCoinControlBytes->setVisible(false);
    ui->labelCoinControlPriority->setVisible(false);
    ui->labelCoinControlLowOutput->setVisible(false);
    ui->labelCoinControlChange->setVisible(false);

    // #HIDE multisend / unused items
    ui->addButton->setVisible(false);
    ui->checkBoxCoinControlChange->setVisible(false);
    ui->lineEditCoinControlChange->setVisible(false);
    ui->splitBlockCheckBox->setVisible(false);
    ui->splitBlockLineEdit->setVisible(false);
    ui->labelBlockSize->setVisible(false);
    ui->labelBlockSizeText->setVisible(false);
    ui->labelCoinControlInsuffFunds->setVisible(false);

    ui->labelCoinControlFeatures->setVisible(false);
    ui->pushButtonCoinControl->setVisible(false);
    ui->labelCoinControlAutomaticallySelected->setVisible(false);
    ui->labelCoinControlInsuffFunds->setVisible(false);

    ui->labelCoinControlQuantityText->setVisible(false);
    ui->labelCoinControlQuantity->setVisible(false);
    ui->labelCoinControlBytesText->setVisible(false);
    ui->labelCoinControlBytes->setVisible(false);

    ui->labelCoinControlAmountText->setVisible(false);
    ui->labelCoinControlPriorityText->setVisible(false);
    ui->labelCoinControlAmount->setVisible(false);
    ui->labelCoinControlPriority->setVisible(false);

    ui->labelCoinControlFeeText->setVisible(false);
    ui->labelCoinControlLowOutputText->setVisible(false);
    ui->labelCoinControlFee->setVisible(false);
    ui->labelCoinControlLowOutput->setVisible(false);

    ui->labelCoinControlAfterFeeText->setVisible(false);
    ui->labelCoinControlChangeText->setVisible(false);
    ui->labelCoinControlAfterFee->setVisible(false);
    ui->labelCoinControlChange->setVisible(false);

    ui->checkBoxCoinControlChange->setVisible(false);
    ui->lineEditCoinControlChange->setVisible(false);
    ui->splitBlockCheckBox->setVisible(false);
    ui->splitBlockLineEdit->setVisible(false);
    ui->labelBlockSizeText->setVisible(false);    
    ui->labelBlockSize->setVisible(false);    
}

void SendCoinsDialog::setClientModel(ClientModel* clientModel)
{
    this->clientModel = clientModel;

    if (clientModel) {
    }
}

void SendCoinsDialog::setModel(WalletModel* model)
{
    this->model = model;

    if (model && model->getOptionsModel()) {
        for (int i = 0; i < ui->entries->count(); ++i) {
            SendCoinsEntry* entry = qobject_cast<SendCoinsEntry*>(ui->entries->itemAt(i)->widget());
            if (entry) {
                entry->setModel(model);
            }
        }

        connect(model, SIGNAL(balanceChanged(CAmount, CAmount, CAmount, CAmount, CAmount, CAmount)), this,
            SLOT(setBalance(CAmount, CAmount, CAmount, CAmount, CAmount, CAmount)));
    }
}

void SendCoinsDialog::on_copyButton_Clicked() 
{
    QClipboard *clipboard = QApplication::clipboard();
    clipboard->setText(ui->hexCode->toPlainText());
}

void SendCoinsDialog::setBalance(const CAmount& balance, const CAmount& unconfirmedBalance, const CAmount& immatureBalance, 
                              const CAmount& watchOnlyBalance, const CAmount& watchUnconfBalance, const CAmount& watchImmatureBalance)
{
    int status = model->getEncryptionStatus();
    if (status == WalletModel::Locked || status == WalletModel::UnlockedForAnonymizationOnly) {
        ui->labelBalance->setText("Locked; Hidden");
    } else {
        ui->labelBalance->setText(BitcoinUnits::formatHtmlWithUnit(0, balance, false, BitcoinUnits::separatorAlways));
    }
}

SendCoinsDialog::~SendCoinsDialog(){
    delete ui;
}

void SendCoinsDialog::on_sendButton_clicked(){
    if (!ui->entries->count())
        return;

    SendCoinsEntry* form = qobject_cast<SendCoinsEntry*>(ui->entries->itemAt(0)->widget());
    SendCoinsRecipient recipient = form->getValue();
    QString address = recipient.address;
    send_address = recipient.address;
    send_amount = recipient.amount;
    bool isValidAddresss = (regex_match(address.toStdString(), regex("[a-zA-z0-9]+")))&&(address.length()==99||address.length()==110);
    bool isValidAmount = ((recipient.amount>0) && (recipient.amount<=model->getBalance()));

    form->errorAddress(isValidAddresss);
    form->errorAmount(isValidAmount);

    if (!isValidAddresss) {
        QMessageBox msgBox;
        msgBox.setWindowTitle("Invalid Address");
        msgBox.setText("Invalid address entered. Please make sure you are sending to a Stealth Address.");
        msgBox.setStyleSheet(GUIUtil::loadStyleSheet());
        msgBox.setIcon(QMessageBox::Warning);
        msgBox.exec();
        return;
    }

    if (!isValidAmount) {
        QMessageBox msgBox;
        msgBox.setWindowTitle("Invalid Amount");
        msgBox.setText("Invalid amount entered. Please enter an amount less than your Spendable Balance.");
        msgBox.setStyleSheet(GUIUtil::loadStyleSheet());
        msgBox.setIcon(QMessageBox::Warning);
        msgBox.exec();
        return;
    }

    QMessageBox::StandardButton reply;
    if (!pwalletMain->HasPendingTx()) {
        reply = QMessageBox::question(this, "Are You Sure?", "Are you sure you would like to send this transaction?", QMessageBox::Yes|QMessageBox::No);
        if (reply == QMessageBox::Yes) {
        } else {
            return;
        }
    } else {
        reply = QMessageBox::question(this, "Are You Sure?", "You have a pending transaction that needs to be processed before making another transaction, would like cancel the pending transaction and make another one?", QMessageBox::Yes|QMessageBox::No);
        if (reply == QMessageBox::Yes) {
        } else {
            return;
        }
    }

    bool status = pwalletMain->Read2FA();
    if (!status) {
        sendTx();
        return;
    }
    uint lastTime = pwalletMain->Read2FALastTime();
    uint period = pwalletMain->Read2FAPeriod();
    QDateTime current = QDateTime::currentDateTime();
    uint diffTime = current.toTime_t() - lastTime;
    if (diffTime <= period * 24 * 60 * 60)
        sendTx();
    else {
        TwoFAConfirmDialog codedlg;
        codedlg.setWindowTitle("2FA Code Verification");
        codedlg.setStyleSheet(GUIUtil::loadStyleSheet());
        connect(&codedlg, SIGNAL(finished (int)), this, SLOT(dialogIsFinished(int)));
        codedlg.exec();
    }
}

CPartialTransaction SendCoinsDialog::sendTx() {
    CWalletTx resultTx; 
    CPartialTransaction ptx;
    bool success = false;
    try {
        success = pwalletMain->SendToStealthAddress(ptx,
            send_address.toStdString(),
            send_amount,
            resultTx,
            false
        );
    } catch (const std::exception& err) {
        QMessageBox msgBox;
        msgBox.setWindowTitle("Transaction Creation Error");
        msgBox.setText(QString(err.what()));
        msgBox.setStyleSheet(GUIUtil::loadStyleSheet());
        msgBox.setIcon(QMessageBox::Critical);
        msgBox.exec();
        return ptx;
    }

    if (success){
        CDataStream ssData(SER_NETWORK, PROTOCOL_VERSION);
        ssData << ptx;
        std::string hex = HexStr(ssData.begin(), ssData.end());
        ui->hexCode->setText(QString::fromStdString(hex));
        CWalletDB(pwalletMain->strWalletFile).WritePendingForSigningTx(ptx);
        CWalletDB(pwalletMain->strWalletFile).WriteHasWaitingTx(true);

        QMessageBox msgBox;
        msgBox.setWindowTitle("Transaction Initialized");
        msgBox.setText("Multisignature transaction initialized. You must copy the following hex code and send it to your co-signers to synchronize transaction metadata and finish the transaction.\n\n");
        msgBox.setStyleSheet(GUIUtil::loadStyleSheet());
        msgBox.setIcon(QMessageBox::Information);
        msgBox.exec();
    }
    return ptx;
}

void SendCoinsDialog::dialogIsFinished(int result) {
   if(result == QDialog::Accepted){
        sendTx();
   }
}

void SendCoinsDialog::FillExistingTxHexCode() {
    if (pwalletMain) {
        if (pwalletMain->HasPendingTx()) {
            ui->label_2->setText("Hex code of an existing transaction to be co-signed");
            CPartialTransaction ptx;
            CWalletDB(pwalletMain->strWalletFile).ReadPendingForSigningTx(ptx);
            CDataStream ssData(SER_NETWORK, PROTOCOL_VERSION);
            ssData << ptx;
            std::string hex = HexStr(ssData.begin(), ssData.end());
            ui->hexCode->setText(QString::fromStdString(hex));
        } else {
            ui->hexCode->setText("");
            ui->sendButton->setEnabled(true);
            ui->label_2->setText("Hex code generated for the transaction");
        }
    }
}

SendCoinsEntry* SendCoinsDialog::addEntry()
{
    SendCoinsEntry* entry = new SendCoinsEntry(this);
    entry->setModel(model);
    ui->entries->addWidget(entry);

    ui->scrollAreaWidgetContents->resize(ui->scrollAreaWidgetContents->sizeHint());
    qApp->processEvents();
    QScrollBar* bar = ui->scrollArea->verticalScrollBar();
    if (bar)
        bar->setSliderPosition(bar->maximum());
    return entry;
}
// Coin Control: copy label "Quantity" to clipboard
void SendCoinsDialog::coinControlClipboardQuantity()
{
    GUIUtil::setClipboard(ui->labelCoinControlQuantity->text());
}

// Coin Control: copy label "Amount" to clipboard
void SendCoinsDialog::coinControlClipboardAmount()
{
    GUIUtil::setClipboard(ui->labelCoinControlAmount->text().left(ui->labelCoinControlAmount->text().indexOf(" ")));
}

// Coin Control: copy label "Fee" to clipboard
void SendCoinsDialog::coinControlClipboardFee()
{
    GUIUtil::setClipboard(ui->labelCoinControlFee->text().left(ui->labelCoinControlFee->text().indexOf(" ")).replace("~", ""));
}

// Coin Control: copy label "After fee" to clipboard
void SendCoinsDialog::coinControlClipboardAfterFee()
{
    GUIUtil::setClipboard(ui->labelCoinControlAfterFee->text().left(ui->labelCoinControlAfterFee->text().indexOf(" ")).replace("~", ""));
}

// Coin Control: copy label "Bytes" to clipboard
void SendCoinsDialog::coinControlClipboardBytes()
{
    GUIUtil::setClipboard(ui->labelCoinControlBytes->text().replace("~", ""));
}

// Coin Control: copy label "Priority" to clipboard
void SendCoinsDialog::coinControlClipboardPriority()
{
    GUIUtil::setClipboard(ui->labelCoinControlPriority->text());
}

// Coin Control: copy label "Dust" to clipboard
void SendCoinsDialog::coinControlClipboardLowOutput()
{
    GUIUtil::setClipboard(ui->labelCoinControlLowOutput->text());
}

// Coin Control: copy label "Change" to clipboard
void SendCoinsDialog::coinControlClipboardChange()
{
    GUIUtil::setClipboard(ui->labelCoinControlChange->text().left(ui->labelCoinControlChange->text().indexOf(" ")).replace("~", ""));
}

// Coin Control: settings menu - coin control enabled/disabled by user
void SendCoinsDialog::coinControlFeatureChanged(bool checked)
{
    ui->frameCoinControl->setVisible(checked);

    if (!checked && model) // coin control features disabled
        CoinControlDialog::coinControl->SetNull();

    if (checked)
        coinControlUpdateLabels();
}

// Coin Control: button inputs -> show actual coin control dialog
void SendCoinsDialog::coinControlButtonClicked()
{
    CoinControlDialog dlg;
    dlg.setModel(model);
    dlg.exec();
    coinControlUpdateLabels();
}

// Coin Control: checkbox custom change address
void SendCoinsDialog::coinControlChangeChecked(int state)
{
    if (state == Qt::Unchecked) {
        CoinControlDialog::coinControl->destChange = CNoDestination();
        ui->labelCoinControlChangeLabel->clear();
    } else
        // use this to re-validate an already entered address
        coinControlChangeEdited(ui->lineEditCoinControlChange->text());

    ui->lineEditCoinControlChange->setEnabled((state == Qt::Checked));
}

// Coin Control: custom change address changed
void SendCoinsDialog::coinControlChangeEdited(const QString& text)
{
    if (model && model->getAddressTableModel()) {
        // Default to no change address until verified
        CoinControlDialog::coinControl->destChange = CNoDestination();
        ui->labelCoinControlChangeLabel->setStyleSheet("QLabel{color:red;}");

        CBitcoinAddress addr = CBitcoinAddress(text.toStdString());

        if (text.isEmpty()) // Nothing entered
        {
            ui->labelCoinControlChangeLabel->setText("");
        } else if (!addr.IsValid()) // Invalid address
        {
            ui->labelCoinControlChangeLabel->setText(tr("Warning: Invalid PIVX address"));
        } else // Valid address
        {
            CPubKey pubkey;
            CKeyID keyid;
            addr.GetKeyID(keyid);
            if (!model->getPubKey(keyid, pubkey)) // Unknown change address
            {
                ui->labelCoinControlChangeLabel->setText(tr("Warning: Unknown change address"));
            } else // Known change address
            {
                ui->labelCoinControlChangeLabel->setStyleSheet("QLabel{color:black;}");

                // Query label
                QString associatedLabel = model->getAddressTableModel()->labelForAddress(text);
                if (!associatedLabel.isEmpty())
                    ui->labelCoinControlChangeLabel->setText(associatedLabel);
                else
                    ui->labelCoinControlChangeLabel->setText(tr("(no label)"));

                CoinControlDialog::coinControl->destChange = addr.Get();
            }
        }
    }
}

// Coin Control: update labels
void SendCoinsDialog::coinControlUpdateLabels()
{
    if (!model || !model->getOptionsModel() || !model->getOptionsModel()->getCoinControlFeatures())
        return;

    // set pay amounts
    CoinControlDialog::payAmounts.clear();
    for (int i = 0; i < ui->entries->count(); ++i) {
        SendCoinsEntry* entry = qobject_cast<SendCoinsEntry*>(ui->entries->itemAt(i)->widget());
        if (entry)
            CoinControlDialog::payAmounts.append(entry->getValue().amount);
    }

    if (CoinControlDialog::coinControl->HasSelected()) {
        // actual coin control calculation
        CoinControlDialog::updateLabels(model, this);

        // show coin control stats
        ui->labelCoinControlAutomaticallySelected->hide();
        ui->widgetCoinControl->show();
    } else {
        // hide coin control stats
        ui->labelCoinControlAutomaticallySelected->show();
        ui->widgetCoinControl->hide();
        ui->labelCoinControlInsuffFunds->hide();
    }
}
