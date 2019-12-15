// Copyright (c) 2011-2013 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_KEYIMAGESYNNC_H
#define BITCOIN_QT_KEYIMAGESYNNC_H

#include "walletmodel.h"

#include <QDialog>
#include <QString>
#include <QSizeGrip>
#include <QSettings>

class ClientModel;
class OptionsModel;

namespace Ui
{
class KeyImageSync;
}

QT_BEGIN_NAMESPACE
class QUrl;
QT_END_NAMESPACE

/** Dialog for sending bitcoins */
class KeyImageSync : public QDialog
{
    Q_OBJECT

public:
    explicit KeyImageSync(QWidget* parent = 0);
    ~KeyImageSync();
    void setClientModel(ClientModel* clientModel);
    void setModel(WalletModel* model);
    bool fSplitBlock;
    void updateKeyImageButtons();

private slots:
    void generateKeyImageHex();
    void syncKeyImages();
    void setBalance(const CAmount& balance, const CAmount& unconfirmedBalance, const CAmount& immatureBalance,
                                 const CAmount& watchOnlyBalance, const CAmount& watchUnconfBalance, const CAmount& watchImmatureBalance);
    void on_copyButton_Clicked();
private:
    Ui::KeyImageSync* ui;
    ClientModel* clientModel;
    WalletModel* model;

signals:

};

#endif // BITCOIN_QT_KEYIMAGESYNNC_H
