#ifndef MULTISIGSETUPFINISH_H
#define MULTISIGSETUPFINISH_H

#include "walletmodel.h"
#include <QDialog>

namespace Ui {
class MultiSigSetupFinish;
}

class MultiSigSetupFinish : public QDialog
{
    Q_OBJECT

public:
    explicit MultiSigSetupFinish(QWidget *parent = 0);
    ~MultiSigSetupFinish();

    void setModel(WalletModel* model);
private slots:
	void on_btnDone();

private:
    Ui::MultiSigSetupFinish *ui;
    WalletModel* model;
    void closeEvent(QCloseEvent *event);
};

#endif // MULTISIGSETUPFINISH_H
