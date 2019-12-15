#include "lockdialog.h"
#include "ui_lockdialog.h"
#include "walletmodel.h"

#include <QDateTime>

LockDialog::LockDialog(QWidget *parent) :
    QDialog(parent, Qt::WindowSystemMenuHint | Qt::WindowTitleHint | Qt::WindowCloseButtonHint),
    model(0),
    ui(new Ui::LockDialog)
{
    ui->setupUi(this);

    connect(ui->btnOK, SIGNAL(clicked()), this, SLOT(on_lock()));
    connect(ui->btnCancel, SIGNAL(clicked()), this, SLOT(reject()));

}

LockDialog::~LockDialog()
{
    delete ui;
}

void LockDialog::on_lock()
{
    if (model->setWalletLocked(true))
    	accept();
}

void LockDialog::setModel(WalletModel* model)
{
    this->model = model;
}