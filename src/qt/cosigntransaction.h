// Copyright (c) 2011-2013 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_COSIGNTRANSACTION_H
#define BITCOIN_QT_COSIGNTRANSACTION_H

#include "walletmodel.h"

#include <QDialog>
#include <QString>
#include <QSizeGrip>
#include <QSettings>

class ClientModel;
class OptionsModel;
class SendCoinsEntry;
class SendCoinsRecipient;

namespace Ui
{
class CoSignTransaction;
}

QT_BEGIN_NAMESPACE
class QUrl;
QT_END_NAMESPACE

/** Dialog for sending bitcoins */
class CoSignTransaction : public QDialog
{
    Q_OBJECT

public:
    explicit CoSignTransaction(QWidget* parent = 0);
    ~CoSignTransaction();
    void setClientModel(ClientModel* clientModel);
    void setModel(WalletModel* model);
    bool fSplitBlock;
    void UpdateLabels();

private:
    Ui::CoSignTransaction* ui;
    ClientModel* clientModel;
    WalletModel* model;

private:
    CPartialTransaction sendTx();

private slots:
	void setBalance(const CAmount& balance, const CAmount& unconfirmedBalance, const CAmount& immatureBalance,
                                 const CAmount& watchOnlyBalance, const CAmount& watchUnconfBalance, const CAmount& watchImmatureBalance);
    void cosignTransaction();
    void on_copyButton_Clicked();
signals:

};

#endif // BITCOIN_QT_COSIGNTRANSACTION_H
