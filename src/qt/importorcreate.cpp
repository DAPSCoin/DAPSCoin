#include "importorcreate.h"
#include "ui_importorcreate.h"

#include "guiconstants.h"
#include "allocators.h"

#include <QDateTime>
#include <QMessageBox>

ImportOrCreate::ImportOrCreate(QWidget *parent) :
    QDialog(parent, Qt::WindowSystemMenuHint | Qt::WindowTitleHint | Qt::WindowCloseButtonHint),
    ui(new Ui::ImportOrCreate)
{
    ui->setupUi(this);
    connect(ui->btnNext, SIGNAL(clicked()), this, SLOT(on_next()));
}

ImportOrCreate::~ImportOrCreate()
{
    delete ui;
}

void ImportOrCreate::on_next()
{
    if (ui->rbCreate->isChecked()) {
        accept();
    } else {
        willRecover = true;
        accept();
    }
}