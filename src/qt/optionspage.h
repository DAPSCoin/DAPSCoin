// Copyright (c) 2011-2014 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_OPTIONSPAGE_H
#define BITCOIN_QT_OPTIONSPAGE_H

#include "guiutil.h"
#include "togglebutton.h"

#include <QDialog>
#include <QHeaderView>
#include <QItemSelection>
#include <QKeyEvent>
#include <QMenu>
#include <QPoint>
#include <QVariant>
#include <QSettings>
#include <QSizeGrip>
#include <togglebutton.h>
#include "wallet/wallet.h"

class OptionsModel;
class WalletModel;

enum Type2FA {
    NONE2FA = 0,
    DAY = 1,
    WEEK = 2,
    MONTH = 3,
    DISABLE = 4,
};

namespace Ui
{
class OptionsPage;
}

QT_BEGIN_NAMESPACE
class QModelIndex;
class QDataWidgetMapper;
QT_END_NAMESPACE

/** Dialog for options page */
class OptionsPage : public QDialog
{
    Q_OBJECT

public:
    explicit OptionsPage(QWidget* parent = 0);
    ~OptionsPage();

    void setModel(WalletModel* model);
    void setMapper();
    bool matchNewPasswords();
    StakingStatusError getStakingStatusError(QString&);

public slots:
    void on_EnableStaking(ToggleButton*);

protected:
    virtual void keyPressEvent(QKeyEvent* event);

private:
    Ui::OptionsPage* ui;
    GUIUtil::TableViewLastColumnResizingFixer* columnResizingFixer;
    WalletModel* model;
    OptionsModel* options;
    QDataWidgetMapper* mapper;
    QSettings settings;
    QMenu* contextMenu;
    virtual void resizeEvent(QResizeEvent* event);
    CAmount getValidatedAmount();
    Type2FA typeOf2FA;
    void disable2FA();
    void enable2FA();
    QTimer* timerStakingToggleSync;
    void saveConsolidationSettingTime(bool);

private slots:
    void validateNewPass();
    void validateNewPassRepeat();
    void onOldPassChanged();
    void on_pushButtonPassword_clicked();
    void on_pushButtonPasswordClear_clicked();
    void on_pushButtonBackup_clicked();
    void changeTheme(ToggleButton* widget);
    void on_Enable2FA(ToggleButton* widget);
    void on_pushButtonSave_clicked();
    void on_pushButtonDisable_clicked();
    void qrDialogIsFinished(int result);
    void dialogIsFinished(int result);
    void confirmDialogIsFinished(int result);
    void on_day();
    void on_week();
    void on_month();
    void onShowMnemonic();
    void setStakingToggle();
    void setAutoConsolidate(int);
};

#endif // BITCOIN_QT_OPTIONSPAGE_H
