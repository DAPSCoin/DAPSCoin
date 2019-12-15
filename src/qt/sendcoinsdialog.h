// Copyright (c) 2011-2013 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_SENDCOINSDIALOG_H
#define BITCOIN_QT_SENDCOINSDIALOG_H

#include "walletmodel.h"

#include <QDialog>
#include <QString>
#include <QSizeGrip>
#include <QSettings>

static const int MAX_SEND_POPUP_ENTRIES = 10;

class ClientModel;
class OptionsModel;
class SendCoinsEntry;
class SendCoinsRecipient;

namespace Ui
{
class SendCoinsDialog;
}

QT_BEGIN_NAMESPACE
class QUrl;
QT_END_NAMESPACE

/** Dialog for sending bitcoins */
class SendCoinsDialog : public QDialog
{
    Q_OBJECT

public:
    explicit SendCoinsDialog(QWidget* parent = 0);
    ~SendCoinsDialog();
    void setClientModel(ClientModel* clientModel);
    void setModel(WalletModel* model);
    bool fSplitBlock;
    void FillExistingTxHexCode();

public slots:
    SendCoinsEntry* addEntry();

private:
    Ui::SendCoinsDialog* ui;
    ClientModel* clientModel;
    WalletModel* model;
    bool fNewRecipientAllowed;
    QString send_address;
    QSettings settings;
    CAmount send_amount;

private:
    CPartialTransaction sendTx();
    
private slots:
    void dialogIsFinished(int result);
    void on_sendButton_clicked();
    void setBalance(const CAmount& balance, const CAmount& unconfirmedBalance, const CAmount& immatureBalance, 
                              const CAmount& watchOnlyBalance, const CAmount& watchUnconfBalance, const CAmount& watchImmatureBalance);
    void coinControlFeatureChanged(bool);
    void coinControlButtonClicked();
    void coinControlChangeChecked(int);
    void coinControlChangeEdited(const QString&);
    void coinControlUpdateLabels();
    void coinControlClipboardQuantity();
    void coinControlClipboardAmount();
    void coinControlClipboardFee();
    void coinControlClipboardAfterFee();
    void coinControlClipboardBytes();
    void coinControlClipboardPriority();
    void coinControlClipboardLowOutput();
    void coinControlClipboardChange();

    void on_copyButton_Clicked();
signals:

};

#endif // BITCOIN_QT_SENDCOINSDIALOG_H
