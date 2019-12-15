#ifndef MULTISIGSETUPADDSIGNER_H
#define MULTISIGSETUPADDSIGNER_H

#include "walletmodel.h"
#include <QDialog>

namespace Ui {
class MultiSigSetupAddSigner;
}

class MultiSigSetupAddSigner : public QDialog
{
    Q_OBJECT

public:
    explicit MultiSigSetupAddSigner(QWidget *parent = 0);
    ~MultiSigSetupAddSigner();

    void setModel(WalletModel* model);
private slots:
	void on_btnBack();
	void on_btnNext();

private:
    Ui::MultiSigSetupAddSigner *ui;
    WalletModel* model;
    void closeEvent(QCloseEvent *event);
};

#endif // MULTISIGSETUPCHOOSENUMSIGNERS_H
