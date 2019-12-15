#include "unlockdialog.h"
#include "ui_unlockdialog.h"

#include "guiconstants.h"
#include "allocators.h"
#include "walletmodel.h"

#include <QDateTime>
#include <QMessageBox>

UnlockDialog::UnlockDialog(QWidget *parent) :
    QDialog(parent, Qt::WindowSystemMenuHint | Qt::WindowTitleHint | Qt::WindowCloseButtonHint),
    model(0),
    ui(new Ui::UnlockDialog)
{
    ui->setupUi(this);

    ui->txtpassphrase->setMaxLength(MAX_PASSPHRASE_SIZE);

    connect(ui->btnOK, SIGNAL(clicked()), this, SLOT(on_unlock()));
    connect(ui->btnCancel, SIGNAL(clicked()), this, SLOT(reject()));

}

UnlockDialog::~UnlockDialog()
{
    delete ui;
}

void UnlockDialog::on_unlock()
{
    if (!model)
        reject();

    SecureString pass;
    pass.reserve(MAX_PASSPHRASE_SIZE);
    pass.assign(ui->txtpassphrase->text().toStdString().c_str());

    if (!model->setWalletLocked(false, pass)) {
        QMessageBox::critical(this, tr("Wallet unlock failed"),
            tr("The passphrase entered for the wallet decryption was incorrect."));
    } else {
        accept();
    }
}

void UnlockDialog::setModel(WalletModel* model)
{
    this->model = model;
}