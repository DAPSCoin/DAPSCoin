// Copyright (c) 2011-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2017 The DAPScoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "cosigntransaction.h"
#include "ui_cosigntransaction.h"

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

#include <regex>
#include <QMessageBox>
#include <QScrollBar>
#include <QSettings>
#include <QTextDocument>
#include <QDateTime>
#include <QDebug>
#include <QClipboard>


CoSignTransaction::CoSignTransaction(QWidget* parent) : QDialog(parent),
                                                    ui(new Ui::CoSignTransaction),
                                                    clientModel(0),
                                                    // m_SizeGrip(this),
                                                    model(0)
{
    ui->setupUi(this);
    connect(ui->sendButton, SIGNAL(clicked()), this, SLOT(cosignTransaction()));

    ui->copyButton->setStyleSheet("background:transparent;");
    ui->copyButton->setIcon(QIcon(":/icons/editcopy"));
	connect(ui->copyButton, SIGNAL(clicked()), this, SLOT(on_copyButton_Clicked()));
}

void CoSignTransaction::setClientModel(ClientModel* clientModel)
{
    this->clientModel = clientModel;

    if (clientModel) {
    }
}

void CoSignTransaction::on_copyButton_Clicked() 
{
    QClipboard *clipboard = QApplication::clipboard();
    clipboard->setText(ui->signedHex->toPlainText());
}

void CoSignTransaction::setModel(WalletModel* model)
{
    this->model = model;
    if (model && model->getOptionsModel()) {
        connect(model, SIGNAL(balanceChanged(CAmount, CAmount, CAmount, CAmount, CAmount, CAmount)), this,
                SLOT(setBalance(CAmount, CAmount, CAmount, CAmount, CAmount, CAmount)));
    }
}

void CoSignTransaction::setBalance(const CAmount& balance, const CAmount& unconfirmedBalance, const CAmount& immatureBalance,
                                   const CAmount& watchOnlyBalance, const CAmount& watchUnconfBalance, const CAmount& watchImmatureBalance)
{
    int status = model->getEncryptionStatus();
    if (status == WalletModel::Locked || status == WalletModel::UnlockedForAnonymizationOnly) {
        ui->labelBalance->setText("Locked; Hidden");
    } else {
        ui->labelBalance->setText(BitcoinUnits::formatHtmlWithUnit(0, balance, false, BitcoinUnits::separatorAlways));
    }
}

CoSignTransaction::~CoSignTransaction(){
    delete ui;
}

void CoSignTransaction::UpdateLabels() {
    ui->label_3->setText("Enter the long hex code of transaction to be signed");
    if (pwalletMain) {
        if (pwalletMain->HasPendingTx()) {
            ui->label_3->setText("You have a pending transaction, in order for your cosigners to co-sign the transaction, please enter \nthe transaction meta-data received from your co-signers here to co-sign the pending transaction.");
        }
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

void CoSignTransaction::cosignTransaction()
{
    if (pwalletMain->IsLocked()) return;
    if (!pwalletMain) return;
    LOCK2(cs_main, pwalletMain->cs_wallet);
    if (!pwalletMain->HasPendingTx()) {
        std::string hexPartial = ui->hexCode->toPlainText().trimmed().toStdString();
        if (!IsHex(hexPartial)) return;
        
        vector<unsigned char> partialTxData(ParseHex(hexPartial));
        CDataStream ssdata(partialTxData, SER_NETWORK, PROTOCOL_VERSION);
        CPartialTransaction partialTx;
        try {
            ssdata >> partialTx;
        } catch (const std::exception&) {
            return;
        }
        {
            CTransaction convertedTx = partialTx.ToTransaction();
            CWalletTx wtx(pwalletMain, convertedTx);
            CAmount nCredit = 0;
            CAmount nDebit = wtx.GetDebit(ISMINE_ALL);
            {
                for (CTxOut out: wtx.vout){
                    CAmount vamount;
                    CKey blind;
                    if (pwalletMain->RevealTxOutAmount(wtx,out,vamount, blind)) {
                        nCredit+=vamount;   //this is the total output
                    }
                }
            }
            CAmount sendAmount = nDebit - nCredit - partialTx.nTxFee;
            std::string receiver(partialTx.receiver.begin(), partialTx.receiver.end());
            QMessageBox::StandardButton reply;
            reply = QMessageBox::question(this, "Are You Sure?", QString("Co-sign this transaction sending ") + QString(ValueFromAmountToString(sendAmount).c_str()) + QString(" to ") + QString(receiver.c_str()) + QString("?"), QMessageBox::Yes|QMessageBox::No);
            if (reply != QMessageBox::Yes) {
                return;
            }
        }
        try {
            pwalletMain->CoSignPartialTransaction(partialTx);
        } catch (const std::exception& err) {
            QMessageBox msgBox;
            msgBox.setWindowTitle("Transaction co-sining failed");
            msgBox.setText(err.what());
            msgBox.setStyleSheet(GUIUtil::loadStyleSheet());
            msgBox.setIcon(QMessageBox::Warning);
            msgBox.exec();
            return;
        }
        CTransaction convertedTx = partialTx.ToTransaction();
        CWalletTx wtx(pwalletMain, convertedTx);
        CReserveKey rsv(pwalletMain);
        if (!pwalletMain->CommitTransaction(wtx, rsv)) {
            CDataStream dex(SER_NETWORK, PROTOCOL_VERSION);
            dex << partialTx;
            std::string hex = HexStr(dex.begin(), dex.end());
            ui->signedHex->setReadOnly(true);
            ui->signedHex->setText(QString::fromStdString(hex));
            QMessageBox msgBox;
            msgBox.setWindowTitle("Transaction Signed");
            msgBox.setText("Multisignatu\re transaction cosigned by you. You can copy the hex code and send it to your co-signers to co-sign and finish the transaction.\n\n");
            msgBox.setStyleSheet(GUIUtil::loadStyleSheet());
            msgBox.setIcon(QMessageBox::Information);
            msgBox.exec();
        } else {
            CDataStream dex(SER_NETWORK, PROTOCOL_VERSION);
            dex << convertedTx;
            std::string hex = HexStr(dex.begin(), dex.end());
            ui->signedHex->setReadOnly(true);
            ui->signedHex->setText(QString::fromStdString(hex));

            QMessageBox msgBox;
            msgBox.setWindowTitle("Transaction Sent");
            msgBox.setText(QString("Multisignature transaction cosigned by you and sent to the network. Here's transaction ID ") + QString(convertedTx.GetHash().GetHex().c_str()));
            msgBox.setStyleSheet(GUIUtil::loadStyleSheet());
            msgBox.setIcon(QMessageBox::Information);
            msgBox.exec();
        }
        
    } else {
        QMessageBox msgBox;
        //Read all partial key images
        QString text = ui->hexCode->toPlainText().trimmed();
        QStringList l = text.split("\n");
        if (l.size() != pwalletMain->ReadNumSigners() - 1) {
            msgBox.setWindowTitle("Transaction Signed");
            msgBox.setText(QString("To co-sign the transaction created by you, you must enter all metadatas obtained \nfrom your co-signers. Each metadata must be separated by a breakline."));
            msgBox.setStyleSheet(GUIUtil::loadStyleSheet());
            msgBox.setIcon(QMessageBox::Warning);
            msgBox.exec();
            return;
        } else {
            std::vector<CListPKeyImageAlpha> list;
            for(size_t i = 0; i < l.size(); i++) {
                std::string str = l.at(i).trimmed().toStdString();
                if (!IsHex(str)) {
                    msgBox.setWindowTitle("Transaction Signed");
                    msgBox.setText(QString("Transaction metadata is invalid."));
                    msgBox.setStyleSheet(GUIUtil::loadStyleSheet());
                    msgBox.setIcon(QMessageBox::Warning);
                    msgBox.exec();
                    return;
                } 
                CListPKeyImageAlpha clpia;
                vector<unsigned char> partialTxData(ParseHex(str));
                CDataStream ssdata(partialTxData, SER_NETWORK, PROTOCOL_VERSION);
                try {
                    ssdata >> clpia;
                } catch (const std::exception&) {
                    msgBox.setWindowTitle("Transaction Signed");
                    msgBox.setText(QString("Transaction metadata is invalid."));
                    msgBox.setStyleSheet(GUIUtil::loadStyleSheet());
                    msgBox.setIcon(QMessageBox::Warning);
                    msgBox.exec();
                    return;
                }
                list.push_back(clpia);
            }
            CPartialTransaction ptx;
            std::string failReason;
            try {
                CWalletDB(pwalletMain->strWalletFile).ReadPendingForSigningTx(ptx);
                pwalletMain->finishRingCTAfterKeyImageSynced(ptx, list, failReason);
            } catch (const std::exception& err) {
                QMessageBox msgBox;
                msgBox.setWindowTitle("Transaction co-sining failed");
                msgBox.setText(QString("An internal error occurs:") + QString(err.what()));
                msgBox.setStyleSheet(GUIUtil::loadStyleSheet());
                msgBox.setIcon(QMessageBox::Warning);
                msgBox.exec();
                return;
            }
            CDataStream dex(SER_NETWORK, PROTOCOL_VERSION);
            dex << ptx;
            std::string hex = HexStr(dex.begin(), dex.end());
            ui->signedHex->setReadOnly(true);
            ui->signedHex->setText(hex.c_str());
            QMessageBox msgBox;
            msgBox.setWindowTitle("Transaction Signed");
            msgBox.setText("Multisignature transaction co-signed by you. You can copy the hex code and send it to your co-signers to co-sign the transaction.\n\n");
            msgBox.setStyleSheet(GUIUtil::loadStyleSheet());
            msgBox.setIcon(QMessageBox::Information);
            msgBox.exec();
            return;
        }
    }
}



