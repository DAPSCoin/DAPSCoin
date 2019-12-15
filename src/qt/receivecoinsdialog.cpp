// Copyright (c) 2011-2014 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "receivecoinsdialog.h"
#include "ui_receivecoinsdialog.h"

#include "addressbookpage.h"
#include "addresstablemodel.h"
#include "bitcoinunits.h"
#include "guiutil.h"
#include "optionsmodel.h"
#include "receiverequestdialog.h"
#include "recentrequeststablemodel.h"
#include "walletmodel.h"

#include <QAction>
#include <QClipboard>
#include <QCursor>
#include <QItemSelection>
#include <QMessageBox>
#include <QScrollBar>
#include <QTextDocument>
#include <QStylePainter>
#include <QDesktopWidget>

ReceiveCoinsDialog::ReceiveCoinsDialog(QWidget* parent) : QDialog(parent, Qt::WindowSystemMenuHint | Qt::WindowTitleHint | Qt::WindowCloseButtonHint),
                                                          ui(new Ui::ReceiveCoinsDialog),
                                                          // m_SizeGrip(this),
                                                          model(0)
{
    ui->setupUi(this);


    // context menu actions
    QAction* copyLabelAction = new QAction(tr("Copy label"), this);
    QAction* copyMessageAction = new QAction(tr("Copy message"), this);
    QAction* copyAmountAction = new QAction(tr("Copy amount"), this);

    // context menu
    contextMenu = new QMenu(this);
    contextMenu->setAttribute(Qt::WA_DeleteOnClose);
    contextMenu->addAction(copyLabelAction);
    contextMenu->addAction(copyMessageAction);
    contextMenu->addAction(copyAmountAction);

    // Show privacy account address
    ui->lineEditAddress->setStyleSheet("border:none; background: transparent; text-align:center;");
    ui->pushButtonCP->setStyleSheet("background:transparent;");
    ui->pushButtonCP->setIcon(QIcon(":/icons/editcopy"));
    connect(ui->pushButtonCP, SIGNAL(clicked()), this, SLOT(copyAddress()));

    //Create privacy account (wallet is unlocked first launch so !pwalletMain->IsLocked() works here)
    if (pwalletMain && !pwalletMain->IsLocked()) {
        CPubKey temp;
        pwalletMain->GetKeyFromPool(temp);
        pwalletMain->CreatePrivacyAccount();
     }

    QLocale lo(QLocale::C);
    lo.setNumberOptions(QLocale::RejectGroupSeparator);
    QDoubleValidator *dblVal = new QDoubleValidator(0, Params().MAX_MONEY, 8, ui->reqAmount);
    dblVal->setNotation(QDoubleValidator::StandardNotation);
    dblVal->setLocale(lo);
    ui->reqAmount->setValidator(dblVal);
}

static inline int64_t roundint64(double d)
{
    return (int64_t)(d > 0 ? d + 0.5 : d - 0.5);
}

CAmount ReceiveCoinsDialog::getValidatedAmount() {
    double dAmount = ui->reqAmount->text().toDouble();
    CAmount nAmount = roundint64(dAmount * COIN);
    return nAmount;
}

void ReceiveCoinsDialog::setModel(WalletModel* model)
{
    this->model = model;

    if (model && model->getOptionsModel()) {
        model->getRecentRequestsTableModel()->sort(RecentRequestsTableModel::Date, Qt::DescendingOrder);
        connect(model->getOptionsModel(), SIGNAL(displayUnitChanged(int)), this, SLOT(updateDisplayUnit()));
        updateDisplayUnit();
        loadAccount();
    }
}

void ReceiveCoinsDialog::loadAccount() {
    QRect rec = QApplication::desktop()->availableGeometry();
    int screenWidth = rec.width();
    QString addr;

    //Set reqAddress as the master stealth address
    std::vector<std::string> addrList, accountList;
    CWallet* wl = model->getCWallet();
    std::string multisig = wl->MyMultisigPubAddress();
    if (!multisig.empty()) {
    	addrList.push_back(multisig);
    	accountList.push_back("Multisig");
    }
    if (addrList.empty()) return;

    QList<QString> stringsList;

    for(size_t i = 0; i < addrList.size(); i++) {
        if (accountList[i] == "masteraccount") continue;
        bool isDuplicate = false;
            if (screenWidth <= 1280) {
                //(truncated for screen with less availableGeometry than 1280px)
                addr = QString(accountList[i].c_str()) + " - " + QString(addrList[i].substr(0, 30).c_str()) + "..." + QString(addrList[i].substr(addrList[i].length() - 30, 30).c_str());
            } else {
                addr = QString(accountList[i].c_str()) + " - " + QString(addrList[i].c_str());
            }
        for (size_t i = 0; i < (size_t)ui->reqAddress->count(); i++) {
            if (ui->reqAddress->itemText(i).contains(QString("Multisig"), Qt::CaseSensitive)) {
                isDuplicate = true;
                break;
            }
        }
        if (!isDuplicate) {
            stringsList.append(addr);
        }
    }
    ui->reqAddress->addItems(stringsList);
    //Set lineEditAddress to Master Account address for copy to clipboard
    if (screenWidth <= 1024) {
        //(truncated for screen with less availableGeometry than 1024px)
        ui->lineEditAddress->setText(QString(addrList[0].substr(0, 30).c_str()) + "..." + QString(addrList[0].substr(addrList[0].length() - 30, 30).c_str()));
    } else {
        ui->lineEditAddress->setText(QString(addrList[0].c_str()));
    }
}

ReceiveCoinsDialog::~ReceiveCoinsDialog()
{
    delete ui;
}

void ReceiveCoinsDialog::clear()
{
    updateDisplayUnit();
}

void ReceiveCoinsDialog::reject()
{
    clear();
}

void ReceiveCoinsDialog::accept()
{
    clear();
}

void ReceiveCoinsDialog::updateDisplayUnit()
{
}

void ReceiveCoinsDialog::on_receiveButton_clicked()
{
    double dAmount = ui->reqAmount->text().toDouble();
    if (dAmount < 0.0 || dAmount > Params().MAX_MONEY) {
        QMessageBox msgBox;
        msgBox.setWindowTitle("Invalid Amount");
        msgBox.setText("Invalid amount entered. Please enter an amount less than 2.1B DAPS.");
        msgBox.setStyleSheet(GUIUtil::loadStyleSheet());
        msgBox.setIcon(QMessageBox::Warning);
        msgBox.exec();
        return;
    }
    if (!model || !model->getOptionsModel() || !model->getAddressTableModel() || !model->getRecentRequestsTableModel())
        return;

    std::vector<std::string> addrList, accountList;
    CWallet* wl = model->getCWallet();
    std::string multisig = wl->MyMultisigPubAddress();
    int selectedIdx = ui->reqAddress->currentIndex();
    addrList.push_back(multisig);
    accountList.push_back("Multisig");
    if ((int)addrList.size() > selectedIdx){
        QString address(addrList[selectedIdx].c_str());
        QString label(accountList[selectedIdx].c_str());
        QString reqMes = ui->reqID->text();
        SendCoinsRecipient info(address, label, getValidatedAmount(), reqMes);
        ReceiveRequestDialog* dialog = new ReceiveRequestDialog(this);
        dialog->setAttribute(Qt::WA_DeleteOnClose);
        dialog->setModel(model->getOptionsModel());
        dialog->setInfo(info);
        dialog->show();
        clear();
        model->getRecentRequestsTableModel()->addNewRequest(info);
    }

}

// We override the virtual resizeEvent of the QWidget to adjust tables column
// sizes as the tables width is proportional to the dialogs width.
void ReceiveCoinsDialog::resizeEvent(QResizeEvent* event)
{
    QWidget::resizeEvent(event);
}

void ReceiveCoinsDialog::keyPressEvent(QKeyEvent* event)
{
    if (event->key() == Qt::Key_Return) {
        // press return -> submit form
        if (ui->reqAddress->hasFocus() || ui->reqAmount->hasFocus() || ui->reqID->hasFocus()) {
            event->ignore();
            on_receiveButton_clicked();
            return;
        }
    }

    this->QDialog::keyPressEvent(event);
}

void ReceiveCoinsDialog::copyAddress(){
    std::vector<std::string> addrList, accountList;
    QClipboard *clipboard = QApplication::clipboard();
    CWallet* wl = model->getCWallet();
    std::string multisig = wl->MyMultisigPubAddress();
    if (!multisig.empty()) {
    	addrList.push_back(multisig);
    }
    clipboard->setText(QString(addrList[0].c_str()));
}
