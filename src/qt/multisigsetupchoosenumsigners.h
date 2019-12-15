#ifndef MULTISIGSETUPCHOOSENUMSIGNERS_H
#define MULTISIGSETUPCHOOSENUMSIGNERS_H

#include "walletmodel.h"
#include <QDialog>

namespace Ui {
class MultiSigSetupChooseNumSigners;
}

class MultiSigSetupChooseNumSigners : public QDialog
{
    Q_OBJECT

public:
    explicit MultiSigSetupChooseNumSigners(QWidget *parent = 0);
    ~MultiSigSetupChooseNumSigners();

    void setModel(WalletModel* model);
private slots:
	void on_btnCancel();
	void on_btnNext();

private:
    Ui::MultiSigSetupChooseNumSigners *ui;
    WalletModel* model;
    void closeEvent(QCloseEvent *event);
};

#endif // MULTISIGSETUPCHOOSENUMSIGNERS_H
