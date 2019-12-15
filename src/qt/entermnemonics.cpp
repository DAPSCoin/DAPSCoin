#include "entermnemonics.h"
#include "ui_entermnemonics.h"

#include "allocators.h"
#include "guiconstants.h"
#include "walletmodel.h"
#include "walletdb.h"

#include <QDateTime>
#include <QMessageBox>

EnterMnemonics::EnterMnemonics(QWidget* parent) : QDialog(parent, Qt::WindowSystemMenuHint | Qt::WindowTitleHint | Qt::WindowCloseButtonHint),
                                                  ui(new Ui::EnterMnemonics)
{
    ui->setupUi(this);
    connect(ui->btnNext, SIGNAL(clicked()), this, SLOT(on_next()));
}

EnterMnemonics::~EnterMnemonics()
{
    delete ui;
}

void EnterMnemonics::on_next()
{
    std::string phrase = ui->mnemonics->toPlainText().toStdString();
    if (ui->mnemonics->toPlainText().endsWith(" ")) {
       QMessageBox::warning(this, "Recovery Phrase Invalid", "Recovery phrase has an extra space at the end. Please remove it to properly restore your wallet.", QMessageBox::Ok);
       return;
    }
    try {
        pwalletMain->GenerateNewHDChain(&phrase);
        QMessageBox::information(this, "Recovery Phrase Import Successful", "Your mnemonics have been successfully imported into the wallet. Rescanning will be scheduled to recover all your funds.", QMessageBox::Ok);
        CBlockLocator loc = chainActive.GetLocator(chainActive[0]);
        pwalletMain->SetBestChain(loc);
        CWalletDB(pwalletMain->strWalletFile).WriteScannedBlockHeight(0); //reschedule to rescan entire chain to recover all funds and history        
        accept();
    } catch (std::exception& ex) {
       QMessageBox::warning(this, "Recovery Phrase Invalid", "Recovery phrase is invalid. Please try again and double check all words.", QMessageBox::Ok);
    }
}
