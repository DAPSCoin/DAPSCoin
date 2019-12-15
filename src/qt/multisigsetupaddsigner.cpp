#include "multisigsetupaddsigner.h"
#include "ui_multisigsetupaddsigner.h"
#include "guiutil.h"
#include "guiconstants.h"
#include "bitcoingui.h"

#include <QMessageBox>
#include <QCloseEvent>

MultiSigSetupAddSigner::MultiSigSetupAddSigner(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::MultiSigSetupAddSigner)
{
    ui->setupUi(this);

    connect(ui->btnNext, SIGNAL(clicked()), this, SLOT(on_btnNext()));
    connect(ui->btnBack, SIGNAL(clicked()), this, SLOT(on_btnBack()));
}

MultiSigSetupAddSigner::~MultiSigSetupAddSigner()
{
    delete ui;
}

void MultiSigSetupAddSigner::setModel(WalletModel* model)
{
    this->model = model;
    ComboKey mine = pwalletMain->MyComboKey();
    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << mine;
    std::string hex = HexStr(ssTx.begin(), ssTx.end());
    if (pwalletMain->ReadScreenIndex() > 1) {
    	if (pwalletMain->ReadScreenIndex() <= pwalletMain->comboKeys.comboKeys.size()) {
    		CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    		ssTx << pwalletMain->comboKeys.comboKeys[pwalletMain->ReadScreenIndex() - 1];
    		hex = HexStr(ssTx.begin(), ssTx.end());
    	    ui->textComboKey->setText(QString::fromStdString(hex));
    	}
    } else {
        ui->textComboKey->setReadOnly(true);
        ui->textComboKey->setText(QString::fromStdString(hex));
    }
    if (pwalletMain->ReadScreenIndex() == 1) {
        ui->label->setText(QString::fromStdString("My Combo Key (1 of " + std::to_string(pwalletMain->ReadNumSigners())) + ")");
    	std::string labelText = "This is your combo key, consisting of your multisignature keychain wallet's public spend key, \nand private view key. Send this combo key to your " + std::to_string(pwalletMain->ReadNumSigners() - 1) + " co-signer(s).";
    	ui->label_2->setText(QString::fromStdString(labelText));
    } else {
        ui->label->setText(QString::fromStdString("Add Co-Signer (" + std::to_string(pwalletMain->ReadScreenIndex()) + " of " + std::to_string(pwalletMain->ReadNumSigners())) + ")");
        std::string labelText = "Enter the combo key of your co-signer(s).\nYou must enter their combo key if you want to be able to sign for them.";
        ui->label_2->setText(QString::fromStdString(labelText));
    }
}

void MultiSigSetupAddSigner::closeEvent (QCloseEvent *event)
{
    QMessageBox::StandardButton reply;
    reply = QMessageBox::warning(this, "Multisignature Wallet Setup Required", "You must configure a Multisignature wallet to continue. What would you like to do?", QMessageBox::Retry|QMessageBox::Close);
      if (reply == QMessageBox::Retry) {
      event->ignore();
      } else {
      QApplication::quit();
      }
}

void MultiSigSetupAddSigner::on_btnBack()
{
	if (pwalletMain) {
		int idx = pwalletMain->ReadScreenIndex();
		idx--;
		pwalletMain->WriteScreenIndex(idx);
	}
    accept();
}

void MultiSigSetupAddSigner::on_btnNext()
{
	std::string hexCombo = ui->textComboKey->toPlainText().trimmed().toStdString();
	if (!IsHex(hexCombo)) return;

	if (pwalletMain->ReadScreenIndex() > 1) {
		ComboKey mine = pwalletMain->MyComboKey();
		CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
		ssTx << mine;
		std::string hex = HexStr(ssTx.begin(), ssTx.end());
		if (hex == hexCombo) {
			QMessageBox::StandardButton reply;
			reply = QMessageBox::warning(this, "Duplicating Your Combo Key", "You must add the combo key of your co-signers to continue. These will be different than your own combo key. Please try again.", QMessageBox::Ok);
			return;
		}
	}

	vector<unsigned char> comboData(ParseHex(hexCombo));
	CDataStream ssdata(comboData, SER_NETWORK, PROTOCOL_VERSION);
	ComboKey combo;
	try {
		ssdata >> combo;
	} catch (const std::exception&) {
		return;
	}
	if (pwalletMain) {
		pwalletMain->AddCosignerKeyAtIndex(combo, pwalletMain->ReadScreenIndex());
		int idx = pwalletMain->ReadScreenIndex();
		idx++;
		pwalletMain->WriteScreenIndex(idx);
		LogPrintf("Successfully added a combo key");
	}
	accept();
}
