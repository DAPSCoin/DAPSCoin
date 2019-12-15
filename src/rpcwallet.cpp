// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2018 The PIVX developers
// Copyright (c) 2018-2019 The DAPS Project developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "amount.h"
#include "base58.h"
#include "core_io.h"
#include "init.h"
#include "net.h"
#include "netbase.h"
#include "rpcserver.h"
#include "timedata.h"
#include "util.h"
#include "utilmoneystr.h"
#include "wallet.h"
#include "walletdb.h"

#include <stdint.h>
#include <fstream>
#include <boost/algorithm/string.hpp>

#include <boost/assign/list_of.hpp>
#include <univalue.h>

using namespace std;
using namespace boost;
using namespace boost::assign;

int64_t nWalletUnlockTime;
static CCriticalSection cs_nWalletUnlockTime;

std::string HelpRequiringPassphrase()
{
    return pwalletMain && pwalletMain->IsCrypted() ? "\nRequires wallet passphrase to be set with walletpassphrase call." : "";
}

void EnsureWalletIsUnlocked()
{
    if (pwalletMain->IsLocked() || pwalletMain->fWalletUnlockAnonymizeOnly)
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Please enter the wallet passphrase with unlockwallet first.");
}

void WalletTxToJSON(const CWalletTx& wtx, UniValue& entry)
{
    int confirms = wtx.GetDepthInMainChain(false);
    int confirmsTotal = GetIXConfirmations(wtx.GetHash()) + confirms;
    entry.push_back(Pair("confirmations", confirmsTotal));
    entry.push_back(Pair("bcconfirmations", confirms));
    if (wtx.IsCoinBase() || wtx.IsCoinStake())
        entry.push_back(Pair("generated", true));
    if (confirms > 0) {
        entry.push_back(Pair("blockhash", wtx.hashBlock.GetHex()));
        entry.push_back(Pair("blockindex", wtx.nIndex));
        entry.push_back(Pair("blocktime", mapBlockIndex[wtx.hashBlock]->GetBlockTime()));
    }
    uint256 hash = wtx.GetHash();
    entry.push_back(Pair("txid", hash.GetHex()));
    UniValue conflicts(UniValue::VARR);
    for (const uint256& conflict : wtx.GetConflicts())
        conflicts.push_back(conflict.GetHex());
    entry.push_back(Pair("walletconflicts", conflicts));
    entry.push_back(Pair("time", wtx.GetTxTime()));
    entry.push_back(Pair("timereceived", (int64_t)wtx.nTimeReceived));
    for (const PAIRTYPE(string, string) & item : wtx.mapValue)
        entry.push_back(Pair(item.first, item.second));
}

string AccountFromValue(const UniValue& value)
{
    string strAccount = value.get_str();
    if (strAccount == "*")
        throw JSONRPCError(RPC_WALLET_INVALID_ACCOUNT_NAME, "Invalid account name");
    return strAccount;
}

UniValue getnewaddress(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "getnewaddress ( \"account\" )\n"
            "\nReturns a new DAPS address for receiving payments.\n"
            "If 'account' is specified (recommended), it is added to the address book \n"
            "so payments received with the address will be credited to 'account'.\n"
            "\nArguments:\n"
            "1. \"account\"        (string, optional) The account name for the address to be linked to. if not provided, the default account \"\" is used. It can also be set to the empty string \"\" to represent the default account. The account does not need to exist, it will be created if there is no account by the given name.\n"
            "\nResult:\n"
            "\"dapscoinaddress\"    (string) The new dapscoin address\n"
            "\nExamples:\n" +
            HelpExampleCli("getnewaddress", "") + HelpExampleCli("getnewaddress", "\"\"") + HelpExampleCli("getnewaddress", "\"myaccount\"") + HelpExampleRpc("getnewaddress", "\"myaccount\""));

    LOCK2(cs_main, pwalletMain->cs_wallet);

    // Parse the account first so we don't generate a key if there's an error
    string strAccount;
    if (params.size() > 0)
        strAccount = AccountFromValue(params[0]);

    if (!pwalletMain->IsLocked())
        pwalletMain->TopUpKeyPool();

    // Generate a new key that is added to wallet
    CPubKey newKey;
    if (!pwalletMain->GetKeyFromPool(newKey))
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");
    CKeyID keyID = newKey.GetID();

    pwalletMain->SetAddressBook(keyID, strAccount, "receive");

    return CBitcoinAddress(keyID).ToString();
}


CBitcoinAddress GetAccountAddress(string strAccount, bool bForceNew = false)
{
    CWalletDB walletdb(pwalletMain->strWalletFile);

    CAccount account;
    walletdb.ReadAccount(strAccount, account);

    bool bKeyUsed = false;

    // Check if the current key has been used
    if (account.vchPubKey.IsValid()) {
        CScript scriptPubKey = GetScriptForDestination(account.vchPubKey.GetID());
        for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin();
             it != pwalletMain->mapWallet.end() && account.vchPubKey.IsValid();
             ++it) {
            const CWalletTx& wtx = (*it).second;
            for (const CTxOut& txout : wtx.vout)
                if (txout.scriptPubKey == scriptPubKey)
                    bKeyUsed = true;
        }
    }

    // Generate a new key
    if (!account.vchPubKey.IsValid() || bForceNew || bKeyUsed) {
    	EnsureWalletIsUnlocked();
        if (!pwalletMain->GetKeyFromPool(account.vchPubKey))
            throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");

        pwalletMain->SetAddressBook(account.vchPubKey.GetID(), strAccount, "receive");
        walletdb.WriteAccount(strAccount, account);
    }

    return CBitcoinAddress(account.vchPubKey.GetID());
}

CBitcoinAddress GetHDAccountAddress(string strAccount, uint32_t nAccountIndex, bool bForceNew = false)
{
    CWalletDB walletdb(pwalletMain->strWalletFile);

    CAccount account;
    walletdb.ReadAccount(strAccount, account);

    bool bKeyUsed = false;

    // Check if the current key has been used
    if (account.vchPubKey.IsValid()) {
        CScript scriptPubKey = GetScriptForDestination(account.vchPubKey.GetID());
        for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin();
             it != pwalletMain->mapWallet.end() && account.vchPubKey.IsValid();
             ++it) {
            const CWalletTx& wtx = (*it).second;
            for (const CTxOut& txout : wtx.vout)
                if (txout.scriptPubKey == scriptPubKey)
                    bKeyUsed = true;
        }
    }

    // Generate a new key
    if (!account.vchPubKey.IsValid() || bForceNew || bKeyUsed) {
        EnsureWalletIsUnlocked();
        // if (!pwalletMain->GetKeyFromPool(account.vchPubKey))
        //     throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");

        CKey newKey;
        pwalletMain->DeriveNewChildKey(nAccountIndex, newKey);
        account.vchPubKey = newKey.GetPubKey();
        account.nAccountIndex = nAccountIndex;

        pwalletMain->SetAddressBook(account.vchPubKey.GetID(), strAccount, "receive");
        walletdb.WriteAccount(strAccount, account);
    }

    return CBitcoinAddress(account.vchPubKey.GetID());
}

UniValue getaccountaddress(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "getaccountaddress \"account\"\n"
            "\nReturns the current DAPS address for receiving payments to this account.\n"
            "\nArguments:\n"
            "1. \"account\"       (string, required) The account name for the address. It can also be set to the empty string \"\" to represent the default account. The account does not need to exist, it will be created and a new address created  if there is no account by the given name.\n"
            "\nResult:\n"
            "\"dapscoinaddress\"   (string) The account dapscoin address\n"
            "\nExamples:\n" +
            HelpExampleCli("getaccountaddress", "") + HelpExampleCli("getaccountaddress", "\"\"") + HelpExampleCli("getaccountaddress", "\"myaccount\"") + HelpExampleRpc("getaccountaddress", "\"myaccount\""));
    LOCK2(cs_main, pwalletMain->cs_wallet);

    // Parse the account first so we don't generate a key if there's an error
    string strAccount = AccountFromValue(params[0]);

    UniValue ret(UniValue::VSTR);

    ret = GetAccountAddress(strAccount).ToString();
    return ret;
}

UniValue getrawchangeaddress(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "getrawchangeaddress\n"
            "\nReturns a new DAPS address, for receiving change.\n"
            "This is for use with raw transactions, NOT normal use.\n"
            "\nResult:\n"
            "\"address\"    (string) The address\n"
            "\nExamples:\n" +
            HelpExampleCli("getrawchangeaddress", "") + HelpExampleRpc("getrawchangeaddress", ""));
    LOCK2(cs_main, pwalletMain->cs_wallet);

    if (!pwalletMain->IsLocked())
        pwalletMain->TopUpKeyPool();

    CReserveKey reservekey(pwalletMain);
    CPubKey vchPubKey;
    if (!reservekey.GetReservedKey(vchPubKey))
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");

    reservekey.KeepKey();

    CKeyID keyID = vchPubKey.GetID();

    return CBitcoinAddress(keyID).ToString();
}

UniValue setaccount(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "setaccount \"dapscoinaddress\" \"account\"\n"
            "\nSets the account associated with the given address.\n"
            "\nArguments:\n"
            "1. \"dapscoinaddress\"  (string, required) The dapscoin address to be associated with an account.\n"
            "2. \"account\"         (string, required) The account to assign the address to.\n"
            "\nExamples:\n" +
            HelpExampleCli("setaccount", "\"DEQsu2RRB5iphm9tKXiP4iWSRMC17gseW5\" \"tabby\"") + HelpExampleRpc("setaccount", "\"DEQsu2RRB5iphm9tKXiP4iWSRMC17gseW5\", \"tabby\""));

    LOCK2(cs_main, pwalletMain->cs_wallet);

    CBitcoinAddress address(params[0].get_str());
    if (!address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid DAPS address");

    string strAccount;
    if (params.size() > 1)
        strAccount = AccountFromValue(params[1]);

    // Only add the account if the address is yours.
    if (IsMine(*pwalletMain, address.Get())) {
        // Detect when changing the account of an address that is the 'unused current key' of another account:
        if (pwalletMain->mapAddressBook.count(address.Get())) {
            string strOldAccount = pwalletMain->mapAddressBook[address.Get()].name;
            if (address == GetAccountAddress(strOldAccount))
                GetAccountAddress(strOldAccount, true);
        }
        pwalletMain->SetAddressBook(address.Get(), strAccount, "receive");
    } else
        throw JSONRPCError(RPC_MISC_ERROR, "setaccount can only be used with own address");
    return NullUniValue;
}


UniValue getaccount(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "getaccount \"dapscoinaddress\"\n"
            "\nReturns the account associated with the given address.\n"
            "\nArguments:\n"
            "1. \"dapscoinaddress\"  (string, required) The dapscoin address for account lookup.\n"
            "\nResult:\n"
            "\"accountname\"        (string) the account address\n"
            "\nExamples:\n" +
            HelpExampleCli("getaccount", "\"DEQsu2RRB5iphm9tKXiP4iWSRMC17gseW5\"") + HelpExampleRpc("getaccount", "\"DEQsu2RRB5iphm9tKXiP4iWSRMC17gseW5\""));

    LOCK2(cs_main, pwalletMain->cs_wallet);

    CBitcoinAddress address(params[0].get_str());
    if (!address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid DAPS address");

    string strAccount;
    map<CTxDestination, CAddressBookData>::iterator mi = pwalletMain->mapAddressBook.find(address.Get());
    if (mi != pwalletMain->mapAddressBook.end() && !(*mi).second.name.empty())
        strAccount = (*mi).second.name;
    
    return strAccount;
}

UniValue getaddressesbyaccount(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "getaddressesbyaccount \"account\"\n"
            "\nReturns the list of addresses for the given account.\n"
            "\nArguments:\n"
            "1. \"account\"  (string, required) The account name.\n"
            "\nResult:\n"
            "[                     (json array of string)\n"
            "  \"dapscoinaddress\"  (string) a dapscoin address associated with the given account\n"
            "  ,...\n"
            "]\n"
            "\nExamples:\n" +
            HelpExampleCli("getaddressesbyaccount", "\"tabby\"") + HelpExampleRpc("getaddressesbyaccount", "\"tabby\""));

    LOCK2(cs_main, pwalletMain->cs_wallet);

    string strAccount = AccountFromValue(params[0]);

    // Find all addresses that have the given account
    UniValue ret(UniValue::VARR);
    for (const PAIRTYPE(CBitcoinAddress, CAddressBookData) & item : pwalletMain->mapAddressBook) {
        const CBitcoinAddress& address = item.first;
        const string& strName = item.second.name;
        if (strName == strAccount)
            ret.push_back(address.ToString());
    }
    return ret;
}

void SendMoney(const CTxDestination& address, CAmount nValue, CWalletTx& wtxNew, bool fUseIX = false)
{
    // Check amount
    if (nValue <= 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid amount");

    string strError;
    if (pwalletMain->IsLocked()) {
        strError = "Error: Wallet locked, unable to create transaction!";
        LogPrintf("SendMoney() : %s", strError);
        throw JSONRPCError(RPC_WALLET_ERROR, strError);
    }

    // Parse DAPS address
    CScript scriptPubKey = GetScriptForDestination(address);

    // Create and send the transaction
    CReserveKey reservekey(pwalletMain);
    CAmount nFeeRequired;
    if (!pwalletMain->CreateTransaction(scriptPubKey, nValue, wtxNew, reservekey, nFeeRequired, strError, NULL, ALL_COINS, fUseIX, (CAmount)0)) {
        if (nValue + nFeeRequired > pwalletMain->GetBalance())
            strError = strprintf("Error: This transaction requires a transaction fee of at least %s because of its amount, complexity, or use of recently received funds!", FormatMoney(nFeeRequired));
        LogPrintf("SendMoney() : %s\n", strError);
        throw JSONRPCError(RPC_WALLET_ERROR, strError);
    }
    if (!pwalletMain->CommitTransaction(wtxNew, reservekey, (!fUseIX ? "tx" : "ix")))
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: The transaction was rejected! This might happen if some of the coins in your wallet were already spent, such as if you used a copy of multisig_wallet.dat and coins were spent in the copy but not marked as spent here.");
}

UniValue sendtoaddress(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 2)
        throw runtime_error(
            "sendtoaddress \"dapscoinaddress\" amount \n"
            "\nSend an amount to a given address. The amount is a real and is rounded to the nearest 0.00000001\n" +
            HelpRequiringPassphrase() +
            "\nArguments:\n"
            "1. \"dapscoinaddress\"  (string, required) The dapscoin address to send to.\n"
            "2. \"amount\"      (numeric, required) The amount in DAPS to send. eg 0.1\n"
            "\nResult:\n"
            "\"transactionid\"  (string) The transaction id.\n"
            "\nExamples:\n" +
            HelpExampleCli("sendtoaddress", "\"DEQsu2RRB5iphm9tKXiP4iWSRMC17gseW5\" 0.1") + HelpExampleCli("sendtoaddress", "\"DEQsu2RRB5iphm9tKXiP4iWSRMC17gseW5\" 0.1 \"donation\" \"seans outpost\"") + HelpExampleRpc("sendtoaddress", "\"DEQsu2RRB5iphm9tKXiP4iWSRMC17gseW5\", 0.1, \"donation\", \"seans outpost\""));

    std::string stealthAddr = params[0].get_str();

    // Amount
    CAmount nAmount = AmountFromValue(params[1]);

    // Wallet comments
    CWalletTx wtx;

    EnsureWalletIsUnlocked();
    CPartialTransaction ptx;
    if (!pwalletMain->SendToStealthAddress(ptx, stealthAddr, nAmount, wtx)) {
        throw JSONRPCError(RPC_WALLET_ERROR,
                           "Failed to create transaction.");
    }
    return wtx.GetHash().GetHex();
}

UniValue sendtoaddressix(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 4)
        throw runtime_error(
            "sendtoaddressix \"dapscoinaddress\" amount\n"
            "\nSend an amount to a given address. The amount is a real and is rounded to the nearest 0.00000001\n" +
            HelpRequiringPassphrase() +
            "\nArguments:\n"
            "1. \"dapscoinaddress\"  (string, required) The dapscoin address to send to.\n"
            "2. \"amount\"      (numeric, required) The amount in DAPS to send. eg 0.1\n"
            "\nResult:\n"
            "\"transactionid\"  (string) The transaction id.\n"
            "\nExamples:\n" +
            HelpExampleCli("sendtoaddressix", "\"DEQsu2RRB5iphm9tKXiP4iWSRMC17gseW5\" 0.1") + HelpExampleCli("sendtoaddressix", "\"DEQsu2RRB5iphm9tKXiP4iWSRMC17gseW5\" 0.1 \"donation\" \"seans outpost\"") + HelpExampleRpc("sendtoaddressix", "\"DEQsu2RRB5iphm9tKXiP4iWSRMC17gseW5\", 0.1, \"donation\", \"seans outpost\""));

    std::string stealthAddr = params[0].get_str();

    // Amount
    CAmount nAmount = AmountFromValue(params[1]);

    // Wallet comments
    CWalletTx wtx;

    EnsureWalletIsUnlocked();
    CPartialTransaction ptx;
    if (!pwalletMain->SendToStealthAddress(ptx, stealthAddr, nAmount, wtx)) {
        throw JSONRPCError(RPC_WALLET_ERROR,
                           "Failed to create transaction.");
    }
    return wtx.GetHash().GetHex();
}

UniValue listaddressgroupings(const UniValue& params, bool fHelp)
{
    if (fHelp)
        throw runtime_error(
            "listaddressgroupings\n"
            "\nLists groups of addresses which have had their common ownership\n"
            "made public by common use as inputs or as the resulting change\n"
            "in past transactions\n"
            "\nResult:\n"
            "[\n"
            "  [\n"
            "    [\n"
            "      \"dapscoinaddress\",     (string) The dapscoin address\n"
            "      amount,                 (numeric) The amount in DAPS\n"
            "      \"account\"             (string, optional) The account\n"
            "    ]\n"
            "    ,...\n"
            "  ]\n"
            "  ,...\n"
            "]\n"
            "\nExamples:\n" +
            HelpExampleCli("listaddressgroupings", "") + HelpExampleRpc("listaddressgroupings", ""));

    LOCK2(cs_main, pwalletMain->cs_wallet);

    UniValue jsonGroupings(UniValue::VARR);
    map<CTxDestination, CAmount> balances = pwalletMain->GetAddressBalances();
    for (set<CTxDestination> grouping : pwalletMain->GetAddressGroupings()) {
        UniValue jsonGrouping(UniValue::VARR);
        for (CTxDestination address : grouping) {
            UniValue addressInfo(UniValue::VARR);
            addressInfo.push_back(CBitcoinAddress(address).ToString());
            addressInfo.push_back(ValueFromAmount(balances[address]));
            {
                if (pwalletMain->mapAddressBook.find(CBitcoinAddress(address).Get()) != pwalletMain->mapAddressBook.end())
                    addressInfo.push_back(pwalletMain->mapAddressBook.find(CBitcoinAddress(address).Get())->second.name);
            }
            jsonGrouping.push_back(addressInfo);
        }
        jsonGroupings.push_back(jsonGrouping);
    }
    return jsonGroupings;
}

UniValue signmessage(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 2)
        throw runtime_error(
            "signmessage \"dapscoinaddress\" \"message\"\n"
            "\nSign a message with the private key of an address" +
            HelpRequiringPassphrase() + "\n"
                                        "\nArguments:\n"
                                        "1. \"dapscoinaddress\"  (string, required) The dapscoin address to use for the private key.\n"
                                        "2. \"message\"         (string, required) The message to create a signature of.\n"
                                        "\nResult:\n"
                                        "\"signature\"          (string) The signature of the message encoded in base 64\n"
                                        "\nExamples:\n"
                                        "\nUnlock the wallet for 30 seconds\n" +
            HelpExampleCli("unlockwallet", "\"mypassphrase\" 30") +
            "\nCreate the signature\n" + HelpExampleCli("signmessage", "\"DEQsu2RRB5iphm9tKXiP4iWSRMC17gseW5\" \"my message\"") +
            "\nVerify the signature\n" + HelpExampleCli("verifymessage", "\"DEQsu2RRB5iphm9tKXiP4iWSRMC17gseW5\" \"signature\" \"my message\"") +
            "\nAs json rpc\n" + HelpExampleRpc("signmessage", "\"DEQsu2RRB5iphm9tKXiP4iWSRMC17gseW5\", \"my message\""));

    LOCK2(cs_main, pwalletMain->cs_wallet);

    EnsureWalletIsUnlocked();

    string strAddress = params[0].get_str();
    string strMessage = params[1].get_str();

    CBitcoinAddress addr(strAddress);
    if (!addr.IsValid())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");

    CKeyID keyID;
    if (!addr.GetKeyID(keyID))
        throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to key");

    CKey key;
    if (!pwalletMain->GetKey(keyID, key))
        throw JSONRPCError(RPC_WALLET_ERROR, "Private key not available");

    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << strMessage;

    vector<unsigned char> vchSig;
    if (!key.SignCompact(ss.GetHash(), vchSig))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Sign failed");

    return EncodeBase64(&vchSig[0], vchSig.size());
}

UniValue getreceivedbyaddress(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "getreceivedbyaddress \"dapscoinaddress\" ( minconf )\n"
            "\nReturns the total amount received by the given dapscoinaddress in transactions with at least minconf confirmations.\n"
            "\nArguments:\n"
            "1. \"dapscoinaddress\"  (string, required) The dapscoin address for transactions.\n"
            "2. minconf             (numeric, optional, default=1) Only include transactions confirmed at least this many times.\n"
            "\nResult:\n"
            "amount   (numeric) The total amount in DAPS received at this address.\n"
            "\nExamples:\n"
            "\nThe amount from transactions with at least 1 confirmation\n" +
            HelpExampleCli("getreceivedbyaddress", "\"DEQsu2RRB5iphm9tKXiP4iWSRMC17gseW5\"") +
            "\nThe amount including unconfirmed transactions, zero confirmations\n" + HelpExampleCli("getreceivedbyaddress", "\"DEQsu2RRB5iphm9tKXiP4iWSRMC17gseW5\" 0") +
            "\nThe amount with at least 6 confirmation, very safe\n" + HelpExampleCli("getreceivedbyaddress", "\"DEQsu2RRB5iphm9tKXiP4iWSRMC17gseW5\" 6") +
            "\nAs a json rpc call\n" + HelpExampleRpc("getreceivedbyaddress", "\"DEQsu2RRB5iphm9tKXiP4iWSRMC17gseW5\", 6"));

    LOCK2(cs_main, pwalletMain->cs_wallet);

    // dapscoin address
    CBitcoinAddress address = CBitcoinAddress(params[0].get_str());
    if (!address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid DAPS address");
    CScript scriptPubKey = GetScriptForDestination(address.Get());
    if (!IsMine(*pwalletMain, scriptPubKey))
        return (double)0.0;

    // Minimum confirmations
    int nMinDepth = 1;
    if (params.size() > 1)
        nMinDepth = params[1].get_int();

    // Tally
    CAmount nAmount = 0;
    for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it) {
        const CWalletTx& wtx = (*it).second;
        if (wtx.IsCoinBase() || !IsFinalTx(wtx))
            continue;

        for (const CTxOut& txout : wtx.vout)
            if (txout.scriptPubKey == scriptPubKey)
                if (wtx.GetDepthInMainChain() >= nMinDepth)
                    nAmount += txout.nValue;
    }

    return ValueFromAmount(nAmount);
}


UniValue getreceivedbyaccount(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "getreceivedbyaccount \"account\" ( minconf )\n"
            "\nReturns the total amount received by addresses with <account> in transactions with at least [minconf] confirmations.\n"
            "\nArguments:\n"
            "1. \"account\"      (string, required) The selected account, may be the default account using \"\".\n"
            "2. minconf          (numeric, optional, default=1) Only include transactions confirmed at least this many times.\n"
            "\nResult:\n"
            "amount              (numeric) The total amount in DAPS received for this account.\n"
            "\nExamples:\n"
            "\nAmount received by the default account with at least 1 confirmation\n" +
            HelpExampleCli("getreceivedbyaccount", "\"\"") +
            "\nAmount received at the tabby account including unconfirmed amounts with zero confirmations\n" + HelpExampleCli("getreceivedbyaccount", "\"tabby\" 0") +
            "\nThe amount with at least 6 confirmation, very safe\n" + HelpExampleCli("getreceivedbyaccount", "\"tabby\" 6") +
            "\nAs a json rpc call\n" + HelpExampleRpc("getreceivedbyaccount", "\"tabby\", 6"));

    LOCK2(cs_main, pwalletMain->cs_wallet);

    // Minimum confirmations
    int nMinDepth = 1;
    if (params.size() > 1)
        nMinDepth = params[1].get_int();

    // Get the set of pub keys assigned to accountValue getreceivedbyaccount(const Array& params, bool fHelp)
    string strAccount = AccountFromValue(params[0]);
    set<CTxDestination> setAddress = pwalletMain->GetAccountAddresses(strAccount);

    // Tally
    CAmount nAmount = 0;
    for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it) {
        const CWalletTx& wtx = (*it).second;
        if (wtx.IsCoinBase() || !IsFinalTx(wtx))
            continue;

        for (const CTxOut& txout : wtx.vout) {
            CTxDestination address;
            if (ExtractDestination(txout.scriptPubKey, address) && IsMine(*pwalletMain, address) && setAddress.count(address))
                if (wtx.GetDepthInMainChain() >= nMinDepth)
                    nAmount += txout.nValue;
        }
    }

    return (double)nAmount / (double)COIN;
}


CAmount GetAccountBalance(CWalletDB& walletdb, const string& strAccount, int nMinDepth, const isminefilter& filter)
{
    CAmount nBalance = 0;

    // Tally wallet transactions
    for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it) {
        const CWalletTx& wtx = (*it).second;
        if (!IsFinalTx(wtx) || wtx.GetBlocksToMaturity() > 0 || wtx.GetDepthInMainChain() < 0)
            continue;

        CAmount nReceived, nSent, nFee;
        wtx.GetAccountAmounts(strAccount, nReceived, nSent, nFee, filter);

        if (nReceived != 0 && wtx.GetDepthInMainChain() >= nMinDepth)
            nBalance += nReceived;
        nBalance -= nSent + nFee;
    }

    // Tally internal accounting entries
    nBalance += walletdb.GetAccountCreditDebit(strAccount);

    return nBalance;
}

CAmount GetAccountBalance(const string& strAccount, int nMinDepth, const isminefilter& filter)
{
    CWalletDB walletdb(pwalletMain->strWalletFile);
    return GetAccountBalance(walletdb, strAccount, nMinDepth, filter);
}

UniValue getbalance(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 3)
        throw runtime_error(
            "getbalance ( \"account\" minconf includeWatchonly )\n"
            "\nIf account is not specified, returns the server's total available balance.\n"
            "If account is specified, returns the balance in the account.\n"
            "Note that the account \"\" is not the same as leaving the parameter out.\n"
            "The server total may be different to the balance in the default \"\" account.\n"
            "\nArguments:\n"
            "1. \"account\"      (string, optional) The selected account, or \"*\" for entire wallet. It may be the default account using \"\".\n"
            "2. minconf          (numeric, optional, default=1) Only include transactions confirmed at least this many times.\n"
            "3. includeWatchonly (bool, optional, default=false) Also include balance in watchonly addresses (see 'importaddress')\n"
            "\nResult:\n"
            "amount              (numeric) The total amount in DAPS received for this account.\n"
            "\nExamples:\n"
            "\nThe total amount in the server across all accounts\n" +
            HelpExampleCli("getbalance", "") +
            "\nThe total amount in the server across all accounts, with at least 5 confirmations\n" + HelpExampleCli("getbalance", "\"*\" 6") +
            "\nThe total amount in the default account with at least 1 confirmation\n" + HelpExampleCli("getbalance", "\"\"") +
            "\nThe total amount in the account named tabby with at least 6 confirmations\n" + HelpExampleCli("getbalance", "\"tabby\" 6") +
            "\nAs a json rpc call\n" + HelpExampleRpc("getbalance", "\"tabby\", 6"));

    LOCK2(cs_main, pwalletMain->cs_wallet);

    if (params.size() == 0)
        return ValueFromAmount(pwalletMain->GetBalance());

    int nMinDepth = 1;
    if (params.size() > 1)
        nMinDepth = params[1].get_int();
    isminefilter filter = ISMINE_SPENDABLE;
    if (params.size() > 2)
        if (params[2].get_bool())
            filter = filter | ISMINE_WATCH_ONLY;

    if (params[0].get_str() == "*") {
        // Calculate total balance a different way from GetBalance()
        // (GetBalance() sums up all unspent TxOuts)
        // getbalance and "getbalance * 1 true" should return the same number
        CAmount nBalance = 0;
        for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it) {
            const CWalletTx& wtx = (*it).second;
            if (!IsFinalTx(wtx) || wtx.GetBlocksToMaturity() > 0 || wtx.GetDepthInMainChain() < 0)
                continue;

            CAmount allFee;
            string strSentAccount;
            list<COutputEntry> listReceived;
            list<COutputEntry> listSent;
            wtx.GetAmounts(listReceived, listSent, allFee, strSentAccount, filter);
            if (wtx.GetDepthInMainChain() >= nMinDepth) {
                for (const COutputEntry& r : listReceived)
                    nBalance += r.amount;
            }
            for (const COutputEntry& s : listSent)
                nBalance -= s.amount;
            nBalance -= allFee;
        }
        return ValueFromAmount(nBalance);
    }

    string strAccount = AccountFromValue(params[0]);

    CAmount nBalance = GetAccountBalance(strAccount, nMinDepth, filter);

    return ValueFromAmount(nBalance);
}

UniValue getbalances(const UniValue& params, bool fHelp)
{
    if (fHelp)
        throw runtime_error(
            "getbalances"
            "\nArguments:\n"
            "\nResult:\n"
            "total              (numeric) The total amount in DAPS received for this wallet.\n"
        	"spendable 			(numeric) The total amount in DAPS spendable for this wallet.\n"
        	"pending			(numeric) The total amount in DAPS pending for this wallet."
            "\nExamples:\n"
            "\nThe total amount in the server across all accounts\n" +
            HelpExampleCli("getbalances", ""));

    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("total", ValueFromAmount(pwalletMain->GetBalance())));
    obj.push_back(Pair("spendable", ValueFromAmount(pwalletMain->GetSpendableBalance())));
    obj.push_back(Pair("pending", ValueFromAmount(pwalletMain->GetUnconfirmedBalance())));

    return obj;
}

UniValue getunconfirmedbalance(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 0)
        throw runtime_error(
            "getunconfirmedbalance\n"
            "Returns the server's total unconfirmed balance\n");

    LOCK2(cs_main, pwalletMain->cs_wallet);

    return ValueFromAmount(pwalletMain->GetUnconfirmedBalance());
}

UniValue movecmd(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 3 || params.size() > 5)
        throw runtime_error(
            "move \"fromaccount\" \"toaccount\" amount ( minconf \"comment\" )\n"
            "\nMove a specified amount from one account in your wallet to another.\n"
            "\nArguments:\n"
            "1. \"fromaccount\"   (string, required) The name of the account to move funds from. May be the default account using \"\".\n"
            "2. \"toaccount\"     (string, required) The name of the account to move funds to. May be the default account using \"\".\n"
            "3. minconf           (numeric, optional, default=1) Only use funds with at least this many confirmations.\n"
            "4. \"comment\"       (string, optional) An optional comment, stored in the wallet only.\n"
            "\nResult:\n"
            "true|false           (boolean) true if successfull.\n"
            "\nExamples:\n"
            "\nMove 0.01 DAPS from the default account to the account named tabby\n" +
            HelpExampleCli("move", "\"\" \"tabby\" 0.01") +
            "\nMove 0.01 DAPS timotei to akiko with a comment and funds have 6 confirmations\n" + HelpExampleCli("move", "\"timotei\" \"akiko\" 0.01 6 \"happy birthday!\"") +
            "\nAs a json rpc call\n" + HelpExampleRpc("move", "\"timotei\", \"akiko\", 0.01, 6, \"happy birthday!\""));

    LOCK2(cs_main, pwalletMain->cs_wallet);

    string strFrom = AccountFromValue(params[0]);
    string strTo = AccountFromValue(params[1]);
    CAmount nAmount = AmountFromValue(params[2]);
    if (params.size() > 3)
        // unused parameter, used to be nMinDepth, keep type-checking it though
        (void)params[3].get_int();
    string strComment;
    if (params.size() > 4)
        strComment = params[4].get_str();

    CWalletDB walletdb(pwalletMain->strWalletFile);
    if (!walletdb.TxnBegin())
        throw JSONRPCError(RPC_DATABASE_ERROR, "database error");

    int64_t nNow = GetAdjustedTime();

    // Debit
    CAccountingEntry debit;
    debit.nOrderPos = pwalletMain->IncOrderPosNext(&walletdb);
    debit.strAccount = strFrom;
    debit.nCreditDebit = -nAmount;
    debit.nTime = nNow;
    debit.strOtherAccount = strTo;
    debit.strComment = strComment;
    pwalletMain->AddAccountingEntry(debit, walletdb);

    // Credit
    CAccountingEntry credit;
    credit.nOrderPos = pwalletMain->IncOrderPosNext(&walletdb);
    credit.strAccount = strTo;
    credit.nCreditDebit = nAmount;
    credit.nTime = nNow;
    credit.strOtherAccount = strFrom;
    credit.strComment = strComment;
    pwalletMain->AddAccountingEntry(credit, walletdb);

    if (!walletdb.TxnCommit())
        throw JSONRPCError(RPC_DATABASE_ERROR, "database error");

    return true;
}

UniValue sendfrom(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 3 || params.size() > 6)
        throw runtime_error(
            "sendfrom \"fromaccount\" \"todapscoinaddress\" amount ( minconf \"comment\" \"comment-to\" )\n"
            "\nSent an amount from an account to a dapscoin address.\n"
            "The amount is a real and is rounded to the nearest 0.00000001." +
            HelpRequiringPassphrase() + "\n"
                                        "\nArguments:\n"
                                        "1. \"fromaccount\"       (string, required) The name of the account to send funds from. May be the default account using \"\".\n"
                                        "2. \"todapscoinaddress\"  (string, required) The dapscoin address to send funds to.\n"
                                        "3. amount                (numeric, required) The amount in DAPS. (transaction fee is added on top).\n"
                                        "4. minconf               (numeric, optional, default=1) Only use funds with at least this many confirmations.\n"
                                        "5. \"comment\"           (string, optional) A comment used to store what the transaction is for. \n"
                                        "                                     This is not part of the transaction, just kept in your wallet.\n"
                                        "6. \"comment-to\"        (string, optional) An optional comment to store the name of the person or organization \n"
                                        "                                     to which you're sending the transaction. This is not part of the transaction, \n"
                                        "                                     it is just kept in your wallet.\n"
                                        "\nResult:\n"
                                        "\"transactionid\"        (string) The transaction id.\n"
                                        "\nExamples:\n"
                                        "\nSend 0.01 DAPS from the default account to the address, must have at least 1 confirmation\n" +
            HelpExampleCli("sendfrom", "\"\" \"DEQsu2RRB5iphm9tKXiP4iWSRMC17gseW5\" 0.01") +
            "\nSend 0.01 from the tabby account to the given address, funds must have at least 6 confirmations\n" + HelpExampleCli("sendfrom", "\"tabby\" \"DEQsu2RRB5iphm9tKXiP4iWSRMC17gseW5\" 0.01 6 \"donation\" \"seans outpost\"") +
            "\nAs a json rpc call\n" + HelpExampleRpc("sendfrom", "\"tabby\", \"DEQsu2RRB5iphm9tKXiP4iWSRMC17gseW5\", 0.01, 6, \"donation\", \"seans outpost\""));

    LOCK2(cs_main, pwalletMain->cs_wallet);

    string strAccount = AccountFromValue(params[0]);
    CBitcoinAddress address(params[1].get_str());
    if (!address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid DAPS address");
    CAmount nAmount = AmountFromValue(params[2]);
    int nMinDepth = 1;
    if (params.size() > 3)
        nMinDepth = params[3].get_int();

    CWalletTx wtx;
    wtx.strFromAccount = strAccount;
    if (params.size() > 4 && !params[4].isNull() && !params[4].get_str().empty())
        wtx.mapValue["comment"] = params[4].get_str();
    if (params.size() > 5 && !params[5].isNull() && !params[5].get_str().empty())
        wtx.mapValue["to"] = params[5].get_str();

    EnsureWalletIsUnlocked();

    // Check funds
    CAmount nBalance = GetAccountBalance(strAccount, nMinDepth, ISMINE_SPENDABLE);
    if (nAmount > nBalance)
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Account has insufficient funds");

    SendMoney(address.Get(), nAmount, wtx);

    return wtx.GetHash().GetHex();
}

UniValue sendmany(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 4)
        throw runtime_error(
            "sendmany \"fromaccount\" {\"address\":amount,...} ( minconf \"comment\" )\n"
            "\nSend multiple times. Amounts are double-precision floating point numbers." +
            HelpRequiringPassphrase() + "\n"
                                        "\nArguments:\n"
                                        "1. \"fromaccount\"         (string, required) The account to send the funds from, can be \"\" for the default account\n"
                                        "2. \"amounts\"             (string, required) A json object with addresses and amounts\n"
                                        "    {\n"
                                        "      \"address\":amount   (numeric) The dapscoin address is the key, the numeric amount in DAPS is the value\n"
                                        "      ,...\n"
                                        "    }\n"
                                        "3. minconf                 (numeric, optional, default=1) Only use the balance confirmed at least this many times.\n"
                                        "4. \"comment\"             (string, optional) A comment\n"
                                        "\nResult:\n"
                                        "\"transactionid\"          (string) The transaction id for the send. Only 1 transaction is created regardless of \n"
                                        "                                    the number of addresses.\n"
                                        "\nExamples:\n"
                                        "\nSend two amounts to two different addresses:\n" +
            HelpExampleCli("sendmany", "\"tabby\" \"{\\\"DEQsu2RRB5iphm9tKXiP4iWSRMC17gseW5\\\":0.01,\\\"DEQsu2RRB5iphm9tKXiP4iWSRMC17gseW5\\\":0.02}\"") +
            "\nSend two amounts to two different addresses setting the confirmation and comment:\n" + HelpExampleCli("sendmany", "\"tabby\" \"{\\\"DEQsu2RRB5iphm9tKXiP4iWSRMC17gseW5\\\":0.01,\\\"DEQsu2RRB5iphm9tKXiP4iWSRMC17gseW5\\\":0.02}\" 6 \"testing\"") +
            "\nAs a json rpc call\n" + HelpExampleRpc("sendmany", "\"tabby\", \"{\\\"DEQsu2RRB5iphm9tKXiP4iWSRMC17gseW5\\\":0.01,\\\"DEQsu2RRB5iphm9tKXiP4iWSRMC17gseW5\\\":0.02}\", 6, \"testing\""));

    LOCK2(cs_main, pwalletMain->cs_wallet);

    string strAccount = AccountFromValue(params[0]);
    UniValue sendTo = params[1].get_obj();
    int nMinDepth = 1;
    if (params.size() > 2)
        nMinDepth = params[2].get_int();

    CWalletTx wtx;
    wtx.strFromAccount = strAccount;
    if (params.size() > 3 && !params[3].isNull() && !params[3].get_str().empty())
        wtx.mapValue["comment"] = params[3].get_str();

    set<CBitcoinAddress> setAddress;
    vector<pair<CScript, CAmount> > vecSend;

    CAmount totalAmount = 0;
    vector<string> keys = sendTo.getKeys();
    for (const string& name_ : keys) {
        CBitcoinAddress address(name_);
        if (!address.IsValid())
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, string("Invalid PIVX address: ")+name_);

        if (setAddress.count(address))
            throw JSONRPCError(RPC_INVALID_PARAMETER, string("Invalid parameter, duplicated address: ")+name_);
        setAddress.insert(address);

        CScript scriptPubKey = GetScriptForDestination(address.Get());
        CAmount nAmount = AmountFromValue(sendTo[name_]);
        totalAmount += nAmount;

        vecSend.push_back(make_pair(scriptPubKey, nAmount));
    }

    EnsureWalletIsUnlocked();

    // Check funds
    CAmount nBalance = GetAccountBalance(strAccount, nMinDepth, ISMINE_SPENDABLE);
    if (totalAmount > nBalance)
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Account has insufficient funds");

    // Send
    CReserveKey keyChange(pwalletMain);
    CAmount nFeeRequired = 0;
    string strFailReason;
    bool fCreated = pwalletMain->CreateTransaction(vecSend, wtx, keyChange, nFeeRequired, strFailReason);
    if (!fCreated)
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, strFailReason);
    if (!pwalletMain->CommitTransaction(wtx, keyChange))
        throw JSONRPCError(RPC_WALLET_ERROR, "Transaction commit failed");

    return wtx.GetHash().GetHex();
}

// Defined in rpcmisc.cpp
extern CScript _createmultisig_redeemScript(const UniValue& params);

UniValue addmultisigaddress(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 3) {
        string msg = "addmultisigaddress nrequired [\"key\",...] ( \"account\" )\n"
                     "\nAdd a nrequired-to-sign multisignature address to the wallet.\n"
                     "Each key is a DAPS address or hex-encoded public key.\n"
                     "If 'account' is specified, assign address to that account.\n"

                     "\nArguments:\n"
                     "1. nrequired        (numeric, required) The number of required signatures out of the n keys or addresses.\n"
                     "2. \"keysobject\"   (string, required) A json array of dapscoin addresses or hex-encoded public keys\n"
                     "     [\n"
                     "       \"address\"  (string) dapscoin address or hex-encoded public key\n"
                     "       ...,\n"
                     "     ]\n"
                     "3. \"account\"      (string, optional) An account to assign the addresses to.\n"

                     "\nResult:\n"
                     "\"dapscoinaddress\"  (string) A dapscoin address associated with the keys.\n"

                     "\nExamples:\n"
                     "\nAdd a multisig address from 2 addresses\n" +
                     HelpExampleCli("addmultisigaddress", "2 \"[\\\"Xt4qk9uKvQYAonVGSZNXqxeDmtjaEWgfrs\\\",\\\"XoSoWQkpgLpppPoyyzbUFh1fq2RBvW6UK1\\\"]\"") +
                     "\nAs json rpc call\n" + HelpExampleRpc("addmultisigaddress", "2, \"[\\\"Xt4qk9uKvQYAonVGSZNXqxeDmtjaEWgfrs\\\",\\\"XoSoWQkpgLpppPoyyzbUFh1fq2RBvW6UK1\\\"]\"");
        throw runtime_error(msg);
    }

    LOCK2(cs_main, pwalletMain->cs_wallet);

    string strAccount;
    if (params.size() > 2)
        strAccount = AccountFromValue(params[2]);

    // Construct using pay-to-script-hash:
    CScript inner = _createmultisig_redeemScript(params);
    CScriptID innerID(inner);
    pwalletMain->AddCScript(inner);

    pwalletMain->SetAddressBook(innerID, strAccount, "send");
    return CBitcoinAddress(innerID).ToString();
}


struct tallyitem {
    CAmount nAmount;
    int nConf;
    int nBCConf;
    vector<uint256> txids;
    bool fIsWatchonly;
    tallyitem()
    {
        nAmount = 0;
        nConf = std::numeric_limits<int>::max();
        nBCConf = std::numeric_limits<int>::max();
        fIsWatchonly = false;
    }
};

UniValue ListReceived(const UniValue& params, bool fByAccounts)
{
    // Minimum confirmations
    int nMinDepth = 1;
    if (params.size() > 0)
        nMinDepth = params[0].get_int();

    // Whether to include empty accounts
    bool fIncludeEmpty = false;
    if (params.size() > 1)
        fIncludeEmpty = params[1].get_bool();

    isminefilter filter = ISMINE_SPENDABLE;
    if (params.size() > 2)
        if (params[2].get_bool())
            filter = filter | ISMINE_WATCH_ONLY;

    // Tally
    map<CBitcoinAddress, tallyitem> mapTally;
    for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it) {
        const CWalletTx& wtx = (*it).second;

        if (wtx.IsCoinBase() || !IsFinalTx(wtx))
            continue;

        int nDepth = wtx.GetDepthInMainChain();
        int nBCDepth = wtx.GetDepthInMainChain(false);
        if (nDepth < nMinDepth)
            continue;

        for (const CTxOut& txout : wtx.vout) {
            CTxDestination address;
            if (!ExtractDestination(txout.scriptPubKey, address))
                continue;

            isminefilter mine = IsMine(*pwalletMain, address);
            if (!(mine & filter))
                continue;

            tallyitem& item = mapTally[address];
            item.nAmount += txout.nValue;
            item.nConf = min(item.nConf, nDepth);
            item.nBCConf = min(item.nBCConf, nBCDepth);
            item.txids.push_back(wtx.GetHash());
            if (mine & ISMINE_WATCH_ONLY)
                item.fIsWatchonly = true;
        }
    }

    // Reply
    UniValue ret(UniValue::VARR);
    map<string, tallyitem> mapAccountTally;
    for (const PAIRTYPE(CBitcoinAddress, CAddressBookData) & item : pwalletMain->mapAddressBook) {
        const CBitcoinAddress& address = item.first;
        const string& strAccount = item.second.name;
        map<CBitcoinAddress, tallyitem>::iterator it = mapTally.find(address);
        if (it == mapTally.end() && !fIncludeEmpty)
            continue;

        CAmount nAmount = 0;
        int nConf = std::numeric_limits<int>::max();
        int nBCConf = std::numeric_limits<int>::max();
        bool fIsWatchonly = false;
        if (it != mapTally.end()) {
            nAmount = (*it).second.nAmount;
            nConf = (*it).second.nConf;
            nBCConf = (*it).second.nBCConf;
            fIsWatchonly = (*it).second.fIsWatchonly;
        }

        if (fByAccounts) {
            tallyitem& item = mapAccountTally[strAccount];
            item.nAmount += nAmount;
            item.nConf = min(item.nConf, nConf);
            item.nBCConf = min(item.nBCConf, nBCConf);
            item.fIsWatchonly = fIsWatchonly;
        } else {
            UniValue obj(UniValue::VOBJ);
            if (fIsWatchonly)
                obj.push_back(Pair("involvesWatchonly", true));
            obj.push_back(Pair("address", address.ToString()));
            obj.push_back(Pair("account", strAccount));
            obj.push_back(Pair("amount", ValueFromAmount(nAmount)));
            obj.push_back(Pair("confirmations", (nConf == std::numeric_limits<int>::max() ? 0 : nConf)));
            obj.push_back(Pair("bcconfirmations", (nBCConf == std::numeric_limits<int>::max() ? 0 : nBCConf)));
            UniValue transactions(UniValue::VARR);
            if (it != mapTally.end()) {
                for (const uint256& item : (*it).second.txids) {
                    transactions.push_back(item.GetHex());
                }
            }
            obj.push_back(Pair("txids", transactions));
            ret.push_back(obj);
        }
    }

    if (fByAccounts) {
        for (map<string, tallyitem>::iterator it = mapAccountTally.begin(); it != mapAccountTally.end(); ++it) {
            CAmount nAmount = (*it).second.nAmount;
            int nConf = (*it).second.nConf;
            int nBCConf = (*it).second.nBCConf;
            UniValue obj(UniValue::VOBJ);
            if ((*it).second.fIsWatchonly)
                obj.push_back(Pair("involvesWatchonly", true));
            obj.push_back(Pair("account", (*it).first));
            obj.push_back(Pair("amount", ValueFromAmount(nAmount)));
            obj.push_back(Pair("confirmations", (nConf == std::numeric_limits<int>::max() ? 0 : nConf)));
            obj.push_back(Pair("bcconfirmations", (nBCConf == std::numeric_limits<int>::max() ? 0 : nBCConf)));
            ret.push_back(obj);
        }
    }

    return ret;
}

UniValue listreceivedbyaddress(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 3)
        throw runtime_error(
            "listreceivedbyaddress ( minconf includeempty includeWatchonly)\n"
            "\nList balances by receiving address.\n"
            "\nArguments:\n"
            "1. minconf       (numeric, optional, default=1) The minimum number of confirmations before payments are included.\n"
            "2. includeempty  (numeric, optional, default=false) Whether to include addresses that haven't received any payments.\n"
            "3. includeWatchonly (bool, optional, default=false) Whether to include watchonly addresses (see 'importaddress').\n"

            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"involvesWatchonly\" : \"true\",    (bool) Only returned if imported addresses were involved in transaction\n"
            "    \"address\" : \"receivingaddress\",  (string) The receiving address\n"
            "    \"account\" : \"accountname\",       (string) The account of the receiving address. The default account is \"\".\n"
            "    \"amount\" : x.xxx,                  (numeric) The total amount in DAPS received by the address\n"
            "    \"confirmations\" : n                (numeric) The number of confirmations of the most recent transaction included\n"
            "    \"bcconfirmations\" : n              (numeric) The number of blockchain confirmations of the most recent transaction included\n"
            "  }\n"
            "  ,...\n"
            "]\n"

            "\nExamples:\n" +
            HelpExampleCli("listreceivedbyaddress", "") + HelpExampleCli("listreceivedbyaddress", "6 true") + HelpExampleRpc("listreceivedbyaddress", "6, true, true"));

    LOCK2(cs_main, pwalletMain->cs_wallet);

    return ListReceived(params, false);
}

UniValue listreceivedbyaccount(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 3)
        throw runtime_error(
            "listreceivedbyaccount ( minconf includeempty includeWatchonly)\n"
            "\nList balances by account.\n"
            "\nArguments:\n"
            "1. minconf      (numeric, optional, default=1) The minimum number of confirmations before payments are included.\n"
            "2. includeempty (boolean, optional, default=false) Whether to include accounts that haven't received any payments.\n"
            "3. includeWatchonly (bool, optional, default=false) Whether to include watchonly addresses (see 'importaddress').\n"

            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"involvesWatchonly\" : \"true\",    (bool) Only returned if imported addresses were involved in transaction\n"
            "    \"account\" : \"accountname\",  (string) The account name of the receiving account\n"
            "    \"amount\" : x.xxx,             (numeric) The total amount received by addresses with this account\n"
            "    \"confirmations\" : n           (numeric) The number of confirmations of the most recent transaction included\n"
            "    \"bcconfirmations\" : n         (numeric) The number of blockchain confirmations of the most recent transaction included\n"
            "  }\n"
            "  ,...\n"
            "]\n"

            "\nExamples:\n" +
            HelpExampleCli("listreceivedbyaccount", "") + HelpExampleCli("listreceivedbyaccount", "6 true") + HelpExampleRpc("listreceivedbyaccount", "6, true, true"));

    LOCK2(cs_main, pwalletMain->cs_wallet);

    return ListReceived(params, true);
}

static void MaybePushAddress(UniValue & entry, const CTxDestination &dest)
{
    CBitcoinAddress addr;
    if (addr.Set(dest))
        entry.push_back(Pair("address", addr.ToString()));
}

void ListTransactions(const CWalletTx& wtx, const string& strAccount, int nMinDepth, bool fLong, UniValue& ret, const isminefilter& filter)
{
    CAmount nFee;
    string strSentAccount;
    list<COutputEntry> listReceived;
    list<COutputEntry> listSent;

    wtx.GetAmounts(listReceived, listSent, nFee, strSentAccount, filter);

    bool fAllAccounts = (strAccount == string("*"));
    bool involvesWatchonly = wtx.IsFromMe(ISMINE_WATCH_ONLY);

    // Sent
    if ((!listSent.empty() || nFee != 0) && (fAllAccounts || strAccount == strSentAccount)) {
        for (const COutputEntry& s : listSent) {
            UniValue entry(UniValue::VOBJ);
            if (involvesWatchonly || (::IsMine(*pwalletMain, s.destination) & ISMINE_WATCH_ONLY))
                entry.push_back(Pair("involvesWatchonly", true));
            entry.push_back(Pair("account", strSentAccount));
            MaybePushAddress(entry, s.destination);
            std::map<std::string, std::string>::const_iterator it = wtx.mapValue.find("DS");
            entry.push_back(Pair("category", (it != wtx.mapValue.end() && it->second == "1") ? "darksent" : "send"));
            entry.push_back(Pair("amount", ValueFromAmount(-s.amount)));
            entry.push_back(Pair("vout", s.vout));
            entry.push_back(Pair("fee", ValueFromAmount(-nFee)));
            if (fLong)
                WalletTxToJSON(wtx, entry);
            ret.push_back(entry);
        }
    }

    // Received
    if (listReceived.size() > 0 && wtx.GetDepthInMainChain() >= nMinDepth) {
        for (const COutputEntry& r : listReceived) {
            string account;
            if (pwalletMain->mapAddressBook.count(r.destination))
                account = pwalletMain->mapAddressBook[r.destination].name;
            if (fAllAccounts || (account == strAccount)) {
                UniValue entry(UniValue::VOBJ);
                if (involvesWatchonly || (::IsMine(*pwalletMain, r.destination) & ISMINE_WATCH_ONLY))
                    entry.push_back(Pair("involvesWatchonly", true));
                entry.push_back(Pair("account", account));
                MaybePushAddress(entry, r.destination);
                if (wtx.IsCoinBase()) {
                    if (wtx.GetDepthInMainChain() < 1)
                        entry.push_back(Pair("category", "orphan"));
                    else if (wtx.GetBlocksToMaturity() > 0)
                        entry.push_back(Pair("category", "immature"));
                    else
                        entry.push_back(Pair("category", "generate"));
                } else {
                    entry.push_back(Pair("category", "receive"));
                }
                entry.push_back(Pair("amount", ValueFromAmount(r.amount)));
                entry.push_back(Pair("vout", r.vout));
                if (fLong)
                    WalletTxToJSON(wtx, entry);
                ret.push_back(entry);
            }
        }
    }
}

void AcentryToJSON(const CAccountingEntry& acentry, const string& strAccount, UniValue& ret)
{
    bool fAllAccounts = (strAccount == string("*"));

    if (fAllAccounts || acentry.strAccount == strAccount) {
        UniValue entry(UniValue::VOBJ);
        entry.push_back(Pair("account", acentry.strAccount));
        entry.push_back(Pair("category", "move"));
        entry.push_back(Pair("time", acentry.nTime));
        entry.push_back(Pair("amount", ValueFromAmount(acentry.nCreditDebit)));
        entry.push_back(Pair("otheraccount", acentry.strOtherAccount));
        entry.push_back(Pair("comment", acentry.strComment));
        ret.push_back(entry);
    }
}

UniValue listtransactions(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 4)
        throw runtime_error(
            "listtransactions ( \"account\" count from includeWatchonly)\n"
            "\nReturns up to 'count' most recent transactions skipping the first 'from' transactions for account 'account'.\n"
            "\nArguments:\n"
            "1. \"account\"    (string, optional) The account name. If not included, it will list all transactions for all accounts.\n"
            "                                     If \"\" is set, it will list transactions for the default account.\n"
            "2. count          (numeric, optional, default=10) The number of transactions to return\n"
            "3. from           (numeric, optional, default=0) The number of transactions to skip\n"
            "4. includeWatchonly (bool, optional, default=false) Include transactions to watchonly addresses (see 'importaddress')\n"
            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"account\":\"accountname\",       (string) The account name associated with the transaction. \n"
            "                                                It will be \"\" for the default account.\n"
            "    \"address\":\"dapscoinaddress\",    (string) The dapscoin address of the transaction. Not present for \n"
            "                                                move transactions (category = move).\n"
            "    \"category\":\"send|receive|move\", (string) The transaction category. 'move' is a local (off blockchain)\n"
            "                                                transaction between accounts, and not associated with an address,\n"
            "                                                transaction id or block. 'send' and 'receive' transactions are \n"
            "                                                associated with an address, transaction id and block details\n"
            "    \"amount\": x.xxx,          (numeric) The amount in DAPS. This is negative for the 'send' category, and for the\n"
            "                                         'move' category for moves outbound. It is positive for the 'receive' category,\n"
            "                                         and for the 'move' category for inbound funds.\n"
            "    \"vout\" : n,               (numeric) the vout value\n"
            "    \"fee\": x.xxx,             (numeric) The amount of the fee in DAPS. This is negative and only available for the \n"
            "                                         'send' category of transactions.\n"
            "    \"confirmations\": n,       (numeric) The number of confirmations for the transaction. Available for 'send' and \n"
            "                                         'receive' category of transactions.\n"
            "    \"bcconfirmations\": n,     (numeric) The number of blockchain confirmations for the transaction. Available for 'send'\n"
            "                                          and 'receive' category of transactions.\n"
            "    \"blockhash\": \"hashvalue\", (string) The block hash containing the transaction. Available for 'send' and 'receive'\n"
            "                                          category of transactions.\n"
            "    \"blockindex\": n,          (numeric) The block index containing the transaction. Available for 'send' and 'receive'\n"
            "                                          category of transactions.\n"
            "    \"txid\": \"transactionid\", (string) The transaction id. Available for 'send' and 'receive' category of transactions.\n"
            "    \"time\": xxx,              (numeric) The transaction time in seconds since epoch (midnight Jan 1 1970 GMT).\n"
            "    \"timereceived\": xxx,      (numeric) The time received in seconds since epoch (midnight Jan 1 1970 GMT). Available \n"
            "                                          for 'send' and 'receive' category of transactions.\n"
            "    \"comment\": \"...\",       (string) If a comment is associated with the transaction.\n"
            "    \"otheraccount\": \"accountname\",  (string) For the 'move' category of transactions, the account the funds came \n"
            "                                          from (for receiving funds, positive amounts), or went to (for sending funds,\n"
            "                                          negative amounts).\n"
            "  }\n"
            "]\n"

            "\nExamples:\n"
            "\nList the most recent 10 transactions in the systems\n" +
            HelpExampleCli("listtransactions", "") +
            "\nList the most recent 10 transactions for the tabby account\n" + HelpExampleCli("listtransactions", "\"tabby\"") +
            "\nList transactions 100 to 120 from the tabby account\n" + HelpExampleCli("listtransactions", "\"tabby\" 20 100") +
            "\nAs a json rpc call\n" + HelpExampleRpc("listtransactions", "\"tabby\", 20, 100"));

    LOCK2(cs_main, pwalletMain->cs_wallet);

    string strAccount = "*";
    if (params.size() > 0)
        strAccount = params[0].get_str();
    int nCount = 10;
    if (params.size() > 1)
        nCount = params[1].get_int();
    int nFrom = 0;
    if (params.size() > 2)
        nFrom = params[2].get_int();
    isminefilter filter = ISMINE_SPENDABLE;
    if (params.size() > 3)
        if (params[3].get_bool())
            filter = filter | ISMINE_WATCH_ONLY;

    if (nCount < 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Negative count");
    if (nFrom < 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Negative from");

    UniValue ret(UniValue::VARR);

    const CWallet::TxItems & txOrdered = pwalletMain->wtxOrdered;

    // iterate backwards until we have nCount items to return:
    for (CWallet::TxItems::const_reverse_iterator it = txOrdered.rbegin(); it != txOrdered.rend(); ++it) {
        CWalletTx* const pwtx = (*it).second.first;
        if (pwtx != 0)
            ListTransactions(*pwtx, strAccount, 0, true, ret, filter);
        CAccountingEntry* const pacentry = (*it).second.second;
        if (pacentry != 0)
            AcentryToJSON(*pacentry, strAccount, ret);

        if ((int)ret.size() >= (nCount + nFrom)) break;
    }
    // ret is newest to oldest

    if (nFrom > (int)ret.size())
        nFrom = ret.size();
    if ((nFrom + nCount) > (int)ret.size())
        nCount = ret.size() - nFrom;

    vector<UniValue> arrTmp = ret.getValues();

    vector<UniValue>::iterator first = arrTmp.begin();
    std::advance(first, nFrom);

    vector<UniValue>::iterator last = arrTmp.begin();
    std::advance(last, nFrom + nCount);	   

    if (last != arrTmp.end()) arrTmp.erase(last, arrTmp.end());
    if (first != arrTmp.begin()) arrTmp.erase(arrTmp.begin(), first);

    std::reverse(arrTmp.begin(), arrTmp.end()); // Return oldest to newest

    ret.clear();
    ret.setArray();
    ret.push_backV(arrTmp);

    return ret;
}

UniValue listaccounts(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 2)
        throw runtime_error(
            "listaccounts ( minconf includeWatchonly)\n"
            "\nReturns Object that has account names as keys, account balances as values.\n"
            "\nArguments:\n"
            "1. minconf          (numeric, optional, default=1) Only include transactions with at least this many confirmations\n"
            "2. includeWatchonly (bool, optional, default=false) Include balances in watchonly addresses (see 'importaddress')\n"
            "\nResult:\n"
            "{                      (json object where keys are account names, and values are numeric balances\n"
            "  \"account\": x.xxx,  (numeric) The property name is the account name, and the value is the total balance for the account.\n"
            "  ...\n"
            "}\n"
            "\nExamples:\n"
            "\nList account balances where there at least 1 confirmation\n" +
            HelpExampleCli("listaccounts", "") +
            "\nList account balances including zero confirmation transactions\n" + HelpExampleCli("listaccounts", "0") +
            "\nList account balances for 6 or more confirmations\n" + HelpExampleCli("listaccounts", "6") +
            "\nAs json rpc call\n" + HelpExampleRpc("listaccounts", "6"));

    LOCK2(cs_main, pwalletMain->cs_wallet);

    int nMinDepth = 1;
    if (params.size() > 0)
        nMinDepth = params[0].get_int();
    isminefilter includeWatchonly = ISMINE_SPENDABLE;
    if (params.size() > 1)
        if (params[1].get_bool())
            includeWatchonly = includeWatchonly | ISMINE_WATCH_ONLY;

    map<string, CAmount> mapAccountBalances;
    for (const PAIRTYPE(CTxDestination, CAddressBookData) & entry : pwalletMain->mapAddressBook) {
        if (IsMine(*pwalletMain, entry.first) & includeWatchonly) // This address belongs to me
            mapAccountBalances[entry.second.name] = 0;
    }

    for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it) {
        const CWalletTx& wtx = (*it).second;
        CAmount nFee;
        string strSentAccount;
        list<COutputEntry> listReceived;
        list<COutputEntry> listSent;
        int nDepth = wtx.GetDepthInMainChain();
        if (wtx.GetBlocksToMaturity() > 0 || nDepth < 0)
            continue;
        wtx.GetAmounts(listReceived, listSent, nFee, strSentAccount, includeWatchonly);
        mapAccountBalances[strSentAccount] -= nFee;
        for (const COutputEntry& s : listSent)
            mapAccountBalances[strSentAccount] -= s.amount;
        if (nDepth >= nMinDepth) {
            for (const COutputEntry& r : listReceived)
                if (pwalletMain->mapAddressBook.count(r.destination))
                    mapAccountBalances[pwalletMain->mapAddressBook[r.destination].name] += r.amount;
                else
                    mapAccountBalances[""] += r.amount;
        }
    }

    const list<CAccountingEntry> & acentries = pwalletMain->laccentries;
    for (const CAccountingEntry& entry : acentries)
        mapAccountBalances[entry.strAccount] += entry.nCreditDebit;

    UniValue ret(UniValue::VOBJ);
    for (const PAIRTYPE(string, CAmount) & accountBalance : mapAccountBalances) {
        ret.push_back(Pair(accountBalance.first, ValueFromAmount(accountBalance.second)));
    }
    return ret;
}

UniValue listsinceblock(const UniValue& params, bool fHelp)
{
    if (fHelp)
        throw runtime_error(
            "listsinceblock ( \"blockhash\" target-confirmations includeWatchonly)\n"
            "\nGet all transactions in blocks since block [blockhash], or all transactions if omitted\n"
            "\nArguments:\n"
            "1. \"blockhash\"   (string, optional) The block hash to list transactions since\n"
            "2. target-confirmations:    (numeric, optional) The confirmations required, must be 1 or more\n"
            "3. includeWatchonly:        (bool, optional, default=false) Include transactions to watchonly addresses (see 'importaddress')"
            "\nResult:\n"
            "{\n"
            "  \"transactions\": [\n"
            "    \"account\":\"accountname\",       (string) The account name associated with the transaction. Will be \"\" for the default account.\n"
            "    \"address\":\"dapscoinaddress\",    (string) The dapscoin address of the transaction. Not present for move transactions (category = move).\n"
            "    \"category\":\"send|receive\",     (string) The transaction category. 'send' has negative amounts, 'receive' has positive amounts.\n"
            "    \"amount\": x.xxx,          (numeric) The amount in DAPS. This is negative for the 'send' category, and for the 'move' category for moves \n"
            "                                          outbound. It is positive for the 'receive' category, and for the 'move' category for inbound funds.\n"
            "    \"vout\" : n,               (numeric) the vout value\n"
            "    \"fee\": x.xxx,             (numeric) The amount of the fee in DAPS. This is negative and only available for the 'send' category of transactions.\n"
            "    \"confirmations\": n,       (numeric) The number of confirmations for the transaction. Available for 'send' and 'receive' category of transactions.\n"
            "    \"bcconfirmations\" : n,    (numeric) The number of blockchain confirmations for the transaction. Available for 'send' and 'receive' category of transactions.\n"
            "    \"blockhash\": \"hashvalue\",     (string) The block hash containing the transaction. Available for 'send' and 'receive' category of transactions.\n"
            "    \"blockindex\": n,          (numeric) The block index containing the transaction. Available for 'send' and 'receive' category of transactions.\n"
            "    \"blocktime\": xxx,         (numeric) The block time in seconds since epoch (1 Jan 1970 GMT).\n"
            "    \"txid\": \"transactionid\",  (string) The transaction id. Available for 'send' and 'receive' category of transactions.\n"
            "    \"time\": xxx,              (numeric) The transaction time in seconds since epoch (Jan 1 1970 GMT).\n"
            "    \"timereceived\": xxx,      (numeric) The time received in seconds since epoch (Jan 1 1970 GMT). Available for 'send' and 'receive' category of transactions.\n"
            "    \"comment\": \"...\",       (string) If a comment is associated with the transaction.\n"
            "    \"to\": \"...\",            (string) If a comment to is associated with the transaction.\n"
            "  ],\n"
            "  \"lastblock\": \"lastblockhash\"     (string) The hash of the last block\n"
            "}\n"
            "\nExamples:\n" +
            HelpExampleCli("listsinceblock", "") + HelpExampleCli("listsinceblock", "\"000000000000000bacf66f7497b7dc45ef753ee9a7d38571037cdb1a57f663ad\" 6") + HelpExampleRpc("listsinceblock", "\"000000000000000bacf66f7497b7dc45ef753ee9a7d38571037cdb1a57f663ad\", 6"));

    LOCK2(cs_main, pwalletMain->cs_wallet);

    CBlockIndex* pindex = NULL;
    int target_confirms = 1;
    isminefilter filter = ISMINE_SPENDABLE;

    if (params.size() > 0) {
        uint256 blockId = 0;

        blockId.SetHex(params[0].get_str());
        BlockMap::iterator it = mapBlockIndex.find(blockId);
        if (it != mapBlockIndex.end())
            pindex = it->second;
    }

    if (params.size() > 1) {
        target_confirms = params[1].get_int();

        if (target_confirms < 1)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter");
    }

    if (params.size() > 2)
        if (params[2].get_bool())
            filter = filter | ISMINE_WATCH_ONLY;

    int depth = pindex ? (1 + chainActive.Height() - pindex->nHeight) : -1;

    UniValue transactions(UniValue::VARR);

    for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); it++) {
        CWalletTx tx = (*it).second;

        if (depth == -1 || tx.GetDepthInMainChain(false) < depth)
            ListTransactions(tx, "*", 0, true, transactions, filter);
    }

    CBlockIndex* pblockLast = chainActive[chainActive.Height() + 1 - target_confirms];
    uint256 lastblock = pblockLast ? pblockLast->GetBlockHash() : 0;

    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("transactions", transactions));
    ret.push_back(Pair("lastblock", lastblock.GetHex()));

    return ret;
}

UniValue gettransaction(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "gettransaction \"txid\" ( includeWatchonly )\n"
            "\nGet detailed information about in-wallet transaction <txid>\n"
            "\nArguments:\n"
            "1. \"txid\"    (string, required) The transaction id\n"
            "2. \"includeWatchonly\"    (bool, optional, default=false) Whether to include watchonly addresses in balance calculation and details[]\n"
            "\nResult:\n"
            "{\n"
            "  \"amount\" : x.xxx,        (numeric) The transaction amount in DAPS\n"
            "  \"confirmations\" : n,     (numeric) The number of confirmations\n"
            "  \"bcconfirmations\" : n,   (numeric) The number of blockchain confirmations\n"
            "  \"blockhash\" : \"hash\",  (string) The block hash\n"
            "  \"blockindex\" : xx,       (numeric) The block index\n"
            "  \"blocktime\" : ttt,       (numeric) The time in seconds since epoch (1 Jan 1970 GMT)\n"
            "  \"txid\" : \"transactionid\",   (string) The transaction id.\n"
            "  \"time\" : ttt,            (numeric) The transaction time in seconds since epoch (1 Jan 1970 GMT)\n"
            "  \"timereceived\" : ttt,    (numeric) The time received in seconds since epoch (1 Jan 1970 GMT)\n"
            "  \"details\" : [\n"
            "    {\n"
            "      \"account\" : \"accountname\",  (string) The account name involved in the transaction, can be \"\" for the default account.\n"
            "      \"address\" : \"dapscoinaddress\",   (string) The dapscoin address involved in the transaction\n"
            "      \"category\" : \"send|receive\",    (string) The category, either 'send' or 'receive'\n"
            "      \"amount\" : x.xxx                  (numeric) The amount in DAPS\n"
            "      \"vout\" : n,                       (numeric) the vout value\n"
            "    }\n"
            "    ,...\n"
            "  ],\n"
            "  \"hex\" : \"data\"         (string) Raw data for transaction\n"
            "}\n"

            "\nExamples:\n" +
            HelpExampleCli("gettransaction", "\"1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d\"") + HelpExampleCli("gettransaction", "\"1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d\" true") + HelpExampleRpc("gettransaction", "\"1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d\""));

    LOCK2(cs_main, pwalletMain->cs_wallet);

    uint256 hash;
    hash.SetHex(params[0].get_str());

    isminefilter filter = ISMINE_SPENDABLE;
    if (params.size() > 1)
        if (params[1].get_bool())
            filter = filter | ISMINE_WATCH_ONLY;

    UniValue entry(UniValue::VOBJ);
    if (!pwalletMain->mapWallet.count(hash))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid or non-wallet transaction id");
    const CWalletTx& wtx = pwalletMain->mapWallet[hash];

    CAmount nCredit = wtx.GetCredit(filter);
    CAmount nDebit = wtx.GetDebit(filter);
    CAmount nNet = (nCredit > nDebit)? (nCredit - nDebit):(nDebit - nCredit);
    CAmount nFee = wtx.nTxFee;
    entry.push_back(Pair("amount", ValueFromAmount(nNet)));
    if (wtx.IsFromMe(filter))
        entry.push_back(Pair("fee", ValueFromAmount(nFee)));

    WalletTxToJSON(wtx, entry);

    UniValue details(UniValue::VARR);
    ListTransactions(wtx, "*", 0, false, details, filter);
    entry.push_back(Pair("details", details));

    string strHex = EncodeHexTx(static_cast<CTransaction>(wtx));
    entry.push_back(Pair("hex", strHex));

    return entry;
}


UniValue backupwallet(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "backupwallet \"destination\"\n"
            "\nSafely copies multisig_wallet.dat to destination, which can be a directory or a path with filename.\n"
            "\nArguments:\n"
            "1. \"destination\"   (string) The destination directory or file\n"
            "\nExamples:\n" +
            HelpExampleCli("backupwallet", "\"backup.dat\"") + HelpExampleRpc("backupwallet", "\"backup.dat\""));

    LOCK2(cs_main, pwalletMain->cs_wallet);

    string strDest = params[0].get_str();
    if (!BackupWallet(*pwalletMain, strDest))
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: Wallet backup failed!");

    return "Done";
}


UniValue keypoolrefill(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "keypoolrefill ( newsize )\n"
            "\nFills the keypool." +
            HelpRequiringPassphrase() + "\n"
                                        "\nArguments\n"
                                        "1. newsize     (numeric, optional, default=100) The new keypool size\n"
                                        "\nExamples:\n" +
            HelpExampleCli("keypoolrefill", "") + HelpExampleRpc("keypoolrefill", ""));

    LOCK2(cs_main, pwalletMain->cs_wallet);

    // 0 is interpreted by TopUpKeyPool() as the default keypool size given by -keypool
    unsigned int kpSize = 0;
    if (params.size() > 0) {
        if (params[0].get_int() < 0)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, expected valid size.");
        kpSize = (unsigned int)params[0].get_int();
    }

    EnsureWalletIsUnlocked();
    pwalletMain->TopUpKeyPool(kpSize);

    if (pwalletMain->GetKeyPoolSize() < kpSize)
        throw JSONRPCError(RPC_WALLET_ERROR, "Error refreshing keypool.");

    return NullUniValue;
}


static void LockWallet(CWallet* pWallet)
{
    LOCK(cs_nWalletUnlockTime);
    nWalletUnlockTime = 0;
    pWallet->fWalletUnlockAnonymizeOnly = false;
    pWallet->Lock();
}

UniValue unlockwallet(const UniValue& params, bool fHelp)
{
    if (pwalletMain->IsCrypted() && (fHelp || params.size() < 2 || params.size() > 3))
        throw runtime_error(
            "unlockwallet \"passphrase\" timeout ( anonymizeonly )\n"
            "\nStores the wallet decryption key in memory for 'timeout' seconds.\n"
            "This is needed prior to performing transactions related to private keys such as sending DAPSs\n"
            "\nArguments:\n"
            "1. \"passphrase\"     (string, required) The wallet passphrase\n"
            "2. timeout            (numeric, required) The time to keep the decryption key in seconds.\n"
            "3. anonymizeonly      (boolean, optional, default=false) If is true sending functions are disabled."
            "\nNote:\n"
            "Issuing the unlockwallet command while the wallet is already unlocked will set a new unlock\n"
            "time that overrides the old one. A timeout of \"0\" unlocks until the wallet is closed.\n"
            "\nExamples:\n"
            "\nUnlock the wallet for 60 seconds\n" +
            HelpExampleCli("unlockwallet", "\"my pass phrase\" 60") +
            "\nUnlock the wallet for 60 seconds but allow Obfuscation only\n" + HelpExampleCli("unlockwallet", "\"my pass phrase\" 60 true") +
            "\nLock the wallet again (before 60 seconds)\n" + HelpExampleCli("walletlock", "") +
            "\nAs json rpc call\n" + HelpExampleRpc("unlockwallet", "\"my pass phrase\", 60"));

    LOCK2(cs_main, pwalletMain->cs_wallet);

    if (fHelp)
        return true;
    if (!pwalletMain->IsCrypted())
        throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an unencrypted wallet, but unlockwallet was called.");

    // Note that the walletpassphrase is stored in params[0] which is not mlock()ed
    SecureString strWalletPass;
    strWalletPass.reserve(100);
    // TODO: get rid of this .c_str() by implementing SecureString::operator=(std::string)
    // Alternately, find a way to make params[0] mlock()'d to begin with.
    strWalletPass = params[0].get_str().c_str();

    bool anonymizeOnly = false;
    if (params.size() == 3)
        anonymizeOnly = params[2].get_bool();

    if (!pwalletMain->IsLocked() && pwalletMain->fWalletUnlockAnonymizeOnly && anonymizeOnly)
        throw JSONRPCError(RPC_WALLET_ALREADY_UNLOCKED, "Error: Wallet is already unlocked.");

    // Get the timeout
    int64_t nSleepTime = params[1].get_int64();
    // Timeout cannot be negative, otherwise it will relock immediately
    if (nSleepTime < 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Timeout cannot be negative.");
    }
    // Clamp timeout
    constexpr int64_t MAX_SLEEP_TIME = 100000000; // larger values trigger a macos/libevent bug?
    if (nSleepTime > MAX_SLEEP_TIME) {
        nSleepTime = MAX_SLEEP_TIME;
    }

    if (!pwalletMain->Unlock(strWalletPass, anonymizeOnly))
        throw JSONRPCError(RPC_WALLET_PASSPHRASE_INCORRECT, "Error: The wallet passphrase entered was incorrect.");

    pwalletMain->TopUpKeyPool();


    if (nSleepTime > 0) {
        nWalletUnlockTime = GetTime () + nSleepTime;
        RPCRunLater ("lockwallet", boost::bind (LockWallet, pwalletMain), nSleepTime);
    }
    return NullUniValue;
}


UniValue walletpassphrasechange(const UniValue& params, bool fHelp)
{
    if (pwalletMain->IsCrypted() && (fHelp || params.size() != 2))
        throw runtime_error(
            "walletpassphrasechange \"oldpassphrase\" \"newpassphrase\"\n"
            "\nChanges the wallet passphrase from 'oldpassphrase' to 'newpassphrase'.\n"
            "\nArguments:\n"
            "1. \"oldpassphrase\"      (string) The current passphrase\n"
            "2. \"newpassphrase\"      (string) The new passphrase\n"
            "\nExamples:\n" +
            HelpExampleCli("walletpassphrasechange", "\"old one\" \"new one\"") + HelpExampleRpc("walletpassphrasechange", "\"old one\", \"new one\""));

    LOCK2(cs_main, pwalletMain->cs_wallet);

    if (fHelp)
        return true;
    if (!pwalletMain->IsCrypted())
        throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an unencrypted wallet, but walletpassphrasechange was called.");

    // TODO: get rid of these .c_str() calls by implementing SecureString::operator=(std::string)
    // Alternately, find a way to make params[0] mlock()'d to begin with.
    SecureString strOldWalletPass;
    strOldWalletPass.reserve(100);
    strOldWalletPass = params[0].get_str().c_str();

    SecureString strNewWalletPass;
    strNewWalletPass.reserve(100);
    strNewWalletPass = params[1].get_str().c_str();

    if (strOldWalletPass.length() < 1 || strNewWalletPass.length() < 1)
        throw runtime_error(
            "walletpassphrasechange <oldpassphrase> <newpassphrase>\n"
            "Changes the wallet passphrase from <oldpassphrase> to <newpassphrase>.");

    if (!pwalletMain->ChangeWalletPassphrase(strOldWalletPass, strNewWalletPass))
        throw JSONRPCError(RPC_WALLET_PASSPHRASE_INCORRECT, "Error: The wallet passphrase entered was incorrect.");

    return NullUniValue;
}


UniValue walletlock(const UniValue& params, bool fHelp)
{
    if (pwalletMain->IsCrypted() && (fHelp || params.size() != 0))
        throw runtime_error(
            "walletlock\n"
            "\nRemoves the wallet encryption key from memory, locking the wallet.\n"
            "After calling this method, you will need to call unlockwallet again\n"
            "before being able to call any methods which require the wallet to be unlocked.\n"
            "\nExamples:\n"
            "\nSet the passphrase for 2 minutes to perform a transaction\n" +
            HelpExampleCli("unlockwallet", "\"my pass phrase\" 120") +
            "\nPerform a send (requires passphrase set)\n" + HelpExampleCli("sendtoaddress", "\"DEQsu2RRB5iphm9tKXiP4iWSRMC17gseW5\" 1.0") +
            "\nClear the passphrase since we are done before 2 minutes is up\n" + HelpExampleCli("walletlock", "") +
            "\nAs json rpc call\n" + HelpExampleRpc("walletlock", ""));

    /*if (fHelp)
    LOCK2(cs_main, pwalletMain->cs_wallet);

    return Value::null;*/
    return "This feature is currently not available.";
}


UniValue encryptwallet(const UniValue& params, bool fHelp)
{
    if (!pwalletMain->IsCrypted() && (fHelp || params.size() != 1))
        throw runtime_error(
            "encryptwallet \"passphrase\"\n"
            "\nEncrypts the wallet with 'passphrase'. This is for first time encryption.\n"
            "After this, any calls that interact with private keys such as sending or signing \n"
            "will require the passphrase to be set prior the making these calls.\n"
            "Use the unlockwallet call for this, and then walletlock call.\n"
            "If the wallet is already encrypted, use the walletpassphrasechange call.\n"
            "Note that this will shutdown the server.\n"
            "\nArguments:\n"
            "1. \"passphrase\"    (string) The pass phrase to encrypt the wallet with. It must be at least 1 character, but should be long.\n"
            "\nExamples:\n"
            "\nEncrypt you wallet\n" +
            HelpExampleCli("encryptwallet", "\"my pass phrase\"") +
            "\nNow set the passphrase to use the wallet, such as for signing or sending DAPSs\n" + HelpExampleCli("unlockwallet", "\"my pass phrase\"") +
            "\nNow we can so something like sign\n" + HelpExampleCli("signmessage", "\"dapscoinaddress\" \"test message\"") +
            "\nNow lock the wallet again by removing the passphrase\n" + HelpExampleCli("walletlock", "") +
            "\nAs a json rpc call\n" + HelpExampleRpc("encryptwallet", "\"my pass phrase\""));

    LOCK2(cs_main, pwalletMain->cs_wallet);
    if (fHelp)
        return true;
    if (pwalletMain->IsCrypted())
        throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an encrypted wallet, but encryptwallet was called.");

    // TODO: get rid of this .c_str() by implementing SecureString::operator=(std::string)
    // Alternately, find a way to make params[0] mlock()'d to begin with.
    SecureString strWalletPass;
    strWalletPass.reserve(100);
    strWalletPass = params[0].get_str().c_str();

    if (strWalletPass.length() < 1)
        throw runtime_error(
            "encryptwallet <passphrase>\n"
            "Encrypts the wallet with <passphrase>.");


    if (!pwalletMain->EncryptWallet(strWalletPass))
        throw JSONRPCError(RPC_WALLET_ENCRYPTION_FAILED, "Error: Failed to encrypt the wallet.");

    // BDB seems to have a bad habit of writing old data into
    // slack space in .dat files; that is bad if the old data is
    // unencrypted private keys. So:
    StartShutdown();
    return "wallet encrypted; dapscoin server stopping, restart to run with encrypted wallet. The keypool has been flushed, you need to make a new backup.";
}

UniValue lockunspent(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "lockunspent unlock [{\"txid\":\"txid\",\"vout\":n},...]\n"
            "\nUpdates list of temporarily unspendable outputs.\n"
            "Temporarily lock (unlock=false) or unlock (unlock=true) specified transaction outputs.\n"
            "A locked transaction output will not be chosen by automatic coin selection, when spending DAPSs.\n"
            "Locks are stored in memory only. Nodes start with zero locked outputs, and the locked output list\n"
            "is always cleared (by virtue of process exit) when a node stops or fails.\n"
            "Also see the listunspent call\n"
            "\nArguments:\n"
            "1. unlock            (boolean, required) Whether to unlock (true) or lock (false) the specified transactions\n"
            "2. \"transactions\"  (string, required) A json array of objects. Each object the txid (string) vout (numeric)\n"
            "     [           (json array of json objects)\n"
            "       {\n"
            "         \"txid\":\"id\",    (string) The transaction id\n"
            "         \"vout\": n         (numeric) The output number\n"
            "       }\n"
            "       ,...\n"
            "     ]\n"

            "\nResult:\n"
            "true|false    (boolean) Whether the command was successful or not\n"

            "\nExamples:\n"
            "\nList the unspent transactions\n" +
            HelpExampleCli("listunspent", "") +
            "\nLock an unspent transaction\n" + HelpExampleCli("lockunspent", "false \"[{\\\"txid\\\":\\\"afbf98345239a27c35db94c03c33d87104ee9ce5c9790f3f756620e6f23d3816\\\",\\\"vout\\\":1}]\"") +
            "\nList the locked transactions\n" + HelpExampleCli("listlockunspent", "") +
            "\nUnlock the transaction again\n" + HelpExampleCli("lockunspent", "true \"[{\\\"txid\\\":\\\"afbf98345239a27c35db94c03c33d87104ee9ce5c9790f3f756620e6f23d3816\\\",\\\"vout\\\":1}]\"") +
            "\nAs a json rpc call\n" + HelpExampleRpc("lockunspent", "false, \"[{\\\"txid\\\":\\\"afbf98345239a27c35db94c03c33d87104ee9ce5c9790f3f756620e6f23d3816\\\",\\\"vout\\\":1}]\""));

    LOCK2(cs_main, pwalletMain->cs_wallet);

    if (params.size() == 1)
        RPCTypeCheck(params, boost::assign::list_of(UniValue::VBOOL));
    else
        RPCTypeCheck(params, boost::assign::list_of(UniValue::VBOOL)(UniValue::VARR));

    bool fUnlock = params[0].get_bool();

    if (params.size() == 1) {
        if (fUnlock)
            pwalletMain->UnlockAllCoins();
        return true;
    }

    UniValue outputs = params[1].get_array();
    for (unsigned int idx = 0; idx < outputs.size(); idx++) {
        const UniValue& output = outputs[idx];
        if (!output.isObject())
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, expected object");
        const UniValue& o = output.get_obj();
        RPCTypeCheckObj(o, boost::assign::map_list_of("txid", UniValue::VSTR)("vout", UniValue::VNUM));

        string txid = find_value(o, "txid").get_str();
        if (!IsHex(txid))
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, expected hex txid");

        int nOutput = find_value(o, "vout").get_int();
        if (nOutput < 0)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, vout must be positive");

        COutPoint outpt(uint256(txid), nOutput);

        if (fUnlock)
            pwalletMain->UnlockCoin(outpt);
        else
            pwalletMain->LockCoin(outpt);
    }

    return true;
}

UniValue listlockunspent(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 0)
        throw runtime_error(
            "listlockunspent\n"
            "\nReturns list of temporarily unspendable outputs.\n"
            "See the lockunspent call to lock and unlock transactions for spending.\n"
            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"txid\" : \"transactionid\",     (string) The transaction id locked\n"
            "    \"vout\" : n                      (numeric) The vout value\n"
            "  }\n"
            "  ,...\n"
            "]\n"
            "\nExamples:\n"
            "\nList the unspent transactions\n" +
            HelpExampleCli("listunspent", "") +
            "\nLock an unspent transaction\n" + HelpExampleCli("lockunspent", "false \"[{\\\"txid\\\":\\\"afbf98345239a27c35db94c03c33d87104ee9ce5c9790f3f756620e6f23d3816\\\",\\\"vout\\\":1}]\"") +
            "\nList the locked transactions\n" + HelpExampleCli("listlockunspent", "") +
            "\nUnlock the transaction again\n" + HelpExampleCli("lockunspent", "true \"[{\\\"txid\\\":\\\"afbf98345239a27c35db94c03c33d87104ee9ce5c9790f3f756620e6f23d3816\\\",\\\"vout\\\":1}]\"") +
            "\nAs a json rpc call\n" + HelpExampleRpc("listlockunspent", ""));

    LOCK2(cs_main, pwalletMain->cs_wallet);

    vector<COutPoint> vOutpts;
    pwalletMain->ListLockedCoins(vOutpts);

    UniValue ret(UniValue::VARR);

    for (COutPoint& outpt : vOutpts) {
        UniValue o(UniValue::VOBJ);

        o.push_back(Pair("txid", outpt.hash.GetHex()));
        o.push_back(Pair("vout", (int)outpt.n));
        ret.push_back(o);
    }

    return ret;
}

UniValue settxfee(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 1)
        throw runtime_error(
            "settxfee amount\n"
            "\nSet the transaction fee per kB.\n"
            "\nArguments:\n"
            "1. amount         (numeric, required) The transaction fee in DAPS/kB rounded to the nearest 0.00000001\n"
            "\nResult\n"
            "true|false        (boolean) Returns true if successful\n"
            "\nExamples:\n" +
            HelpExampleCli("settxfee", "0.00001") + HelpExampleRpc("settxfee", "0.00001"));

    LOCK2(cs_main, pwalletMain->cs_wallet);

    // Amount
    CAmount nAmount = 0;
    if (params[0].get_real() != 0.0)
        nAmount = AmountFromValue(params[0]); // rejects 0.0 amounts

    payTxFee = CFeeRate(nAmount, 1000);
    return true;
}

UniValue getwalletinfo(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getwalletinfo\n"
            "Returns an object containing various wallet state info.\n"
            "\nResult:\n"
            "{\n"
            "  \"walletversion\": xxxxx,     (numeric) the wallet version\n"
            "  \"balance\": xxxxxxx,         (numeric) the total DAPS balance of the wallet\n"
            "  \"txcount\": xxxxxxx,         (numeric) the total number of transactions in the wallet\n"
            "  \"keypoololdest\": xxxxxx,    (numeric) the timestamp (seconds since GMT epoch) of the oldest pre-generated key in the key pool\n"
            "  \"keypoolsize\": xxxx,        (numeric) how many new keys are pre-generated\n"
            "  \"unlocked_until\": ttt,      (numeric) the timestamp in seconds since epoch (midnight Jan 1 1970 GMT) that the wallet is unlocked for transfers, or 0 if the wallet is locked\n"
            "}\n"
            "\nExamples:\n" +
            HelpExampleCli("getwalletinfo", "") + HelpExampleRpc("getwalletinfo", ""));

    LOCK2(cs_main, pwalletMain->cs_wallet);

    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("walletversion", pwalletMain->GetVersion()));
    obj.push_back(Pair("balance", ValueFromAmount(pwalletMain->GetBalance())));
    obj.push_back(Pair("txcount", (int)pwalletMain->mapWallet.size()));
    obj.push_back(Pair("keypoololdest", pwalletMain->GetOldestKeyPoolTime()));
    obj.push_back(Pair("keypoolsize", (int)pwalletMain->GetKeyPoolSize()));
    if (pwalletMain->IsCrypted())
        obj.push_back(Pair("unlocked_until", nWalletUnlockTime));
    return obj;
}

// ppcoin: reserve balance from being staked for network protection
UniValue reservebalance(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 2)
        throw runtime_error(
            "reservebalance ( reserve amount )\n"
            "\nShow or set the reserve amount not participating in network protection\n"
            "If no parameters provided current setting is printed.\n"

            "\nArguments:\n"
            "1. reserve     (boolean, optional) is true or false to turn balance reserve on or off.\n"
            "2. amount      (numeric, optional) is a real and rounded to cent.\n"

            "\nResult:\n"
            "{\n"
            "  \"reserve\": true|false,     (boolean) Status of the reserve balance\n"
            "  \"amount\": x.xxxx       (numeric) Amount reserved\n"
            "\nExamples:\n" +
            HelpExampleCli("reservebalance", "true 5000") + HelpExampleRpc("reservebalance", "true 5000"));

    LOCK2(cs_main, pwalletMain->cs_wallet);

    if (params.size() > 0) {
        bool fReserve = params[0].get_bool();
        if (fReserve) {
            if (params.size() == 1)
                throw runtime_error("must provide amount to reserve balance.\n");
            CAmount nAmount = AmountFromValue(params[1]);
            nAmount = (nAmount / CENT) * CENT; // round to cent
            if (nAmount < 0)
                throw runtime_error("amount cannot be negative.\n");
            nReserveBalance = nAmount;

            CWalletDB walletdb(pwalletMain->strWalletFile);
            walletdb.WriteReserveAmount(nReserveBalance / COIN);

        } else {
            if (params.size() > 1)
                throw runtime_error("cannot specify amount to turn off reserve.\n");
            nReserveBalance = 0;
        }
    }

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("reserve", (nReserveBalance > 0)));
    result.push_back(Pair("amount", ValueFromAmount(nReserveBalance)));
    return result;
}

// presstab HyperStake
UniValue setstakesplitthreshold(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "setstakesplitthreshold value\n"
            "\nThis will set the output size of your stakes to never be below this number\n"

            "\nArguments:\n"
            "1. value   (numeric, required) Threshold value between 1 and 999999\n"
            "\nResult:\n"
            "{\n"
            "  \"threshold\": n,    (numeric) Threshold value set\n"
            "  \"saved\": true|false    (boolean) 'true' if successfully saved to the wallet file\n"
            "}\n"
            "\nExamples:\n" +
            HelpExampleCli("setstakesplitthreshold", "5000") + HelpExampleRpc("setstakesplitthreshold", "5000"));

    uint64_t nStakeSplitThreshold = params[0].get_int();
    if (pwalletMain->IsLocked())
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Unlock wallet to use this feature");
    if (nStakeSplitThreshold > 999999)
        throw runtime_error("Value out of range, max allowed is 999999");

    CWalletDB walletdb(pwalletMain->strWalletFile);
    LOCK(pwalletMain->cs_wallet);
    {
        bool fFileBacked = pwalletMain->fFileBacked;

        UniValue result(UniValue::VOBJ);
        pwalletMain->nStakeSplitThreshold = nStakeSplitThreshold;
        result.push_back(Pair("threshold", int(pwalletMain->nStakeSplitThreshold)));
        if (fFileBacked) {
            walletdb.WriteStakeSplitThreshold(nStakeSplitThreshold);
            result.push_back(Pair("saved", "true"));
        } else
            result.push_back(Pair("saved", "false"));

        return result;
    }
}

// presstab HyperStake
UniValue getstakesplitthreshold(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getstakesplitthreshold\n"
            "Returns the threshold for stake splitting\n"
            "\nResult:\n"
            "n      (numeric) Threshold value\n"
            "\nExamples:\n" +
            HelpExampleCli("getstakesplitthreshold", "") + HelpExampleRpc("getstakesplitthreshold", ""));

    return int(pwalletMain->nStakeSplitThreshold);
}

UniValue autocombinedust(const UniValue& params, bool fHelp)
{
    bool fEnable;
    if (params.size() >= 1)
        fEnable = params[0].get_bool();

    if (fHelp || params.size() < 1 || (fEnable && params.size() != 2) || params.size() > 2)
        throw runtime_error(
            "autocombinedust true|false ( threshold )\n"
            "\nWallet will automatically monitor for any coins with value below the threshold amount, and combine them if they reside with the same DAPS address\n"
            "When autocombinedust runs it will create a transaction, and therefore will be subject to transaction fees. Minimum of 25 dust transactions before activation.\n"

            "\nArguments:\n"
            "1. true|false      (boolean, required) Enable auto combine (true) or disable (false)\n"
            "2. threshold       (numeric, optional) Threshold amount (default: 0)\n"
            "\nExamples:\n" +
            HelpExampleCli("autocombinedust", "true 540") + HelpExampleRpc("autocombinedust", "true 540"));

    CWalletDB walletdb(pwalletMain->strWalletFile);
    CAmount nThreshold = 0;

    if (fEnable) {
        nThreshold = params[1].get_int();
    } else {
        nThreshold = 0;
    }

    pwalletMain->fCombineDust = fEnable;
    pwalletMain->nAutoCombineThreshold = nThreshold;

    if (!walletdb.WriteAutoCombineSettings(fEnable, nThreshold))
        throw runtime_error("Changed settings in wallet but failed to save to database\n");

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("autocombinedust", params[0].get_bool()));
    result.push_back(Pair("amount", int(pwalletMain->nAutoCombineThreshold)));
    return result;
}

UniValue printMultiSend()
{
    UniValue ret(UniValue::VARR);
    UniValue act(UniValue::VARR);
    act.push_back(Pair("MultiSendStake Activated?", pwalletMain->fMultiSendStake));
    act.push_back(Pair("MultiSendMasternode Activated?", pwalletMain->fMultiSendMasternodeReward));
    ret.push_back(act);

    if (pwalletMain->vDisabledAddresses.size() >= 1) {
        UniValue disAdd(UniValue::VOBJ);
        for (unsigned int i = 0; i < pwalletMain->vDisabledAddresses.size(); i++) {
            disAdd.push_back(Pair("Disabled From Sending", pwalletMain->vDisabledAddresses[i]));
        }
        ret.push_back(disAdd);
    }

    ret.push_back("MultiSend Addresses to Send To:");

    UniValue vMS(UniValue::VOBJ);
    for (unsigned int i = 0; i < pwalletMain->vMultiSend.size(); i++) {
        vMS.push_back(Pair("Address " + std::to_string(i), pwalletMain->vMultiSend[i].first));
        vMS.push_back(Pair("Percent", pwalletMain->vMultiSend[i].second));
    }

    ret.push_back(vMS);
    return ret;
}

UniValue printAddresses()
{
    std::vector<COutput> vCoins;
    pwalletMain->AvailableCoins(vCoins);
    std::map<std::string, double> mapAddresses;
    for (const COutput& out : vCoins) {
        CTxDestination utxoAddress;
        ExtractDestination(out.tx->vout[out.i].scriptPubKey, utxoAddress);
        std::string strAdd = CBitcoinAddress(utxoAddress).ToString();

        if (mapAddresses.find(strAdd) == mapAddresses.end()) //if strAdd is not already part of the map
            mapAddresses[strAdd] = (double)out.tx->vout[out.i].nValue / (double)COIN;
        else
            mapAddresses[strAdd] += (double)out.tx->vout[out.i].nValue / (double)COIN;
    }

    UniValue ret(UniValue::VARR);
    for (map<std::string, double>::const_iterator it = mapAddresses.begin(); it != mapAddresses.end(); ++it) {
        UniValue obj(UniValue::VOBJ);
        const std::string* strAdd = &(*it).first;
        const double* nBalance = &(*it).second;
        obj.push_back(Pair("Address ", *strAdd));
        obj.push_back(Pair("Balance ", *nBalance));
        ret.push_back(obj);
    }

    return ret;
}

unsigned int sumMultiSend()
{
    unsigned int sum = 0;
    for (unsigned int i = 0; i < pwalletMain->vMultiSend.size(); i++)
        sum += pwalletMain->vMultiSend[i].second;
    return sum;
}

UniValue multisend(const UniValue& params, bool fHelp)
{
    CWalletDB walletdb(pwalletMain->strWalletFile);
    bool fFileBacked;
    //MultiSend Commands
    if (params.size() == 1) {
        string strCommand = params[0].get_str();
        UniValue ret(UniValue::VOBJ);
        if (strCommand == "print") {
            return printMultiSend();
        } else if (strCommand == "printaddress" || strCommand == "printaddresses") {
            return printAddresses();
        } else if (strCommand == "clear") {
            LOCK(pwalletMain->cs_wallet);
            {
                bool erased = false;
                if (pwalletMain->fFileBacked) {
                    if (walletdb.EraseMultiSend(pwalletMain->vMultiSend))
                        erased = true;
                }

                pwalletMain->vMultiSend.clear();
                pwalletMain->setMultiSendDisabled();

                UniValue obj(UniValue::VOBJ);
                obj.push_back(Pair("Erased from database", erased));
                obj.push_back(Pair("Erased from RAM", true));

                return obj;
            }
        } else if (strCommand == "enablestake" || strCommand == "activatestake") {
            if (pwalletMain->vMultiSend.size() < 1)
                throw JSONRPCError(RPC_INVALID_REQUEST, "Unable to activate MultiSend, check MultiSend vector");

            if (CBitcoinAddress(pwalletMain->vMultiSend[0].first).IsValid()) {
                pwalletMain->fMultiSendStake = true;
                if (!walletdb.WriteMSettings(true, pwalletMain->fMultiSendMasternodeReward, pwalletMain->nLastMultiSendHeight)) {
                    UniValue obj(UniValue::VOBJ);
                    obj.push_back(Pair("error", "MultiSend activated but writing settings to DB failed"));
                    UniValue arr(UniValue::VARR);
                    arr.push_back(obj);
                    arr.push_back(printMultiSend());
                    return arr;
                } else
                    return printMultiSend();
            }

            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Unable to activate MultiSend, check MultiSend vector");
        } else if (strCommand == "enablemasternode" || strCommand == "activatemasternode") {
            if (pwalletMain->vMultiSend.size() < 1)
                throw JSONRPCError(RPC_INVALID_REQUEST, "Unable to activate MultiSend, check MultiSend vector");

            if (CBitcoinAddress(pwalletMain->vMultiSend[0].first).IsValid()) {
                pwalletMain->fMultiSendMasternodeReward = true;

                if (!walletdb.WriteMSettings(pwalletMain->fMultiSendStake, true, pwalletMain->nLastMultiSendHeight)) {
                    UniValue obj(UniValue::VOBJ);
                    obj.push_back(Pair("error", "MultiSend activated but writing settings to DB failed"));
                    UniValue arr(UniValue::VARR);
                    arr.push_back(obj);
                    arr.push_back(printMultiSend());
                    return arr;
                } else
                    return printMultiSend();
            }

            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Unable to activate MultiSend, check MultiSend vector");
        } else if (strCommand == "disable" || strCommand == "deactivate") {
            pwalletMain->setMultiSendDisabled();
            if (!walletdb.WriteMSettings(false, false, pwalletMain->nLastMultiSendHeight))
                throw JSONRPCError(RPC_DATABASE_ERROR, "MultiSend deactivated but writing settings to DB failed");

            return printMultiSend();
        } else if (strCommand == "enableall") {
            if (!walletdb.EraseMSDisabledAddresses(pwalletMain->vDisabledAddresses))
                return "failed to clear old vector from walletDB";
            else {
                pwalletMain->vDisabledAddresses.clear();
                return printMultiSend();
            }
        }
    }
    if (params.size() == 2 && params[0].get_str() == "delete") {
        int del = std::stoi(params[1].get_str().c_str());
        if (!walletdb.EraseMultiSend(pwalletMain->vMultiSend))
            throw JSONRPCError(RPC_DATABASE_ERROR, "failed to delete old MultiSend vector from database");

        pwalletMain->vMultiSend.erase(pwalletMain->vMultiSend.begin() + del);
        if (!walletdb.WriteMultiSend(pwalletMain->vMultiSend))
            throw JSONRPCError(RPC_DATABASE_ERROR, "walletdb WriteMultiSend failed!");

        return printMultiSend();
    }
    if (params.size() == 2 && params[0].get_str() == "disable") {
        std::string disAddress = params[1].get_str();
        if (!CBitcoinAddress(disAddress).IsValid())
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "address you want to disable is not valid");
        else {
            pwalletMain->vDisabledAddresses.push_back(disAddress);
            if (!walletdb.EraseMSDisabledAddresses(pwalletMain->vDisabledAddresses))
                throw JSONRPCError(RPC_DATABASE_ERROR, "disabled address from sending, but failed to clear old vector from walletDB");

            if (!walletdb.WriteMSDisabledAddresses(pwalletMain->vDisabledAddresses))
                throw JSONRPCError(RPC_DATABASE_ERROR, "disabled address from sending, but failed to store it to walletDB");
            else
                return printMultiSend();
        }
    }

    //if no commands are used
    if (fHelp || params.size() != 2)
        throw runtime_error(
            "multisend <command>\n"
            "****************************************************************\n"
            "WHAT IS MULTISEND?\n"
            "MultiSend allows a user to automatically send a percent of their stake reward to as many addresses as you would like\n"
            "The MultiSend transaction is sent when the staked coins mature (100 confirmations)\n"
            "****************************************************************\n"
            "TO CREATE OR ADD TO THE MULTISEND VECTOR:\n"
            "multisend <DAPS Address> <percent>\n"
            "This will add a new address to the MultiSend vector\n"
            "Percent is a whole number 1 to 100.\n"
            "****************************************************************\n"
            "MULTISEND COMMANDS (usage: multisend <command>)\n"
            " print - displays the current MultiSend vector \n"
            " clear - deletes the current MultiSend vector \n"
            " enablestake/activatestake - activates the current MultiSend vector to be activated on stake rewards\n"
            " enablemasternode/activatemasternode - activates the current MultiSend vector to be activated on masternode rewards\n"
            " disable/deactivate - disables the current MultiSend vector \n"
            " delete <Address #> - deletes an address from the MultiSend vector \n"
            " disable <address> - prevents a specific address from sending MultiSend transactions\n"
            " enableall - enables all addresses to be eligible to send MultiSend transactions\n"
            "****************************************************************\n");

    //if the user is entering a new MultiSend item
    string strAddress = params[0].get_str();
    CBitcoinAddress address(strAddress);
    if (!address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid DAPS address");
    if (std::stoi(params[1].get_str().c_str()) < 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, expected valid percentage");
    if (pwalletMain->IsLocked())
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Please enter the wallet passphrase with unlockwallet first.");
    unsigned int nPercent = (unsigned int) std::stoul(params[1].get_str().c_str());

    LOCK(pwalletMain->cs_wallet);
    {
        fFileBacked = pwalletMain->fFileBacked;
        //Error if 0 is entered
        if (nPercent == 0) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Sending 0% of stake is not valid");
        }

        //MultiSend can only send 100% of your stake
        if (nPercent + sumMultiSend() > 100)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Failed to add to MultiSend vector, the sum of your MultiSend is greater than 100%");

        for (unsigned int i = 0; i < pwalletMain->vMultiSend.size(); i++) {
            if (pwalletMain->vMultiSend[i].first == strAddress)
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Failed to add to MultiSend vector, cannot use the same address twice");
        }

        if (fFileBacked)
            walletdb.EraseMultiSend(pwalletMain->vMultiSend);

        std::pair<std::string, int> newMultiSend;
        newMultiSend.first = strAddress;
        newMultiSend.second = nPercent;
        pwalletMain->vMultiSend.push_back(newMultiSend);
        if (fFileBacked) {
            if (!walletdb.WriteMultiSend(pwalletMain->vMultiSend))
                throw JSONRPCError(RPC_DATABASE_ERROR, "walletdb WriteMultiSend failed!");
        }
    }
    return printMultiSend();
}

UniValue createprivacywallet(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() >2 || params.size() < 1)
        throw runtime_error(
                "createprivacywallet \"password\" (\"language\") \n"
                "\nCreate a new wallet for privacy with dual-key stealth address.\n"
                "If 'language' is specified, it is used, otherwise english \n"
                "\nArguments:\n"
                "1. \"account\"        (string, required) password for the wallet \n"
                "2. \"language\"        (string, optional) language for the wallet's mnemmonics \n"
                "\nResult:\n"
                "\"privacy wallet created\"    (string) the base address of the wallet\n"
                "\nExamples:\n" +
                HelpExampleCli("createprivacywallet", "") + HelpExampleCli("createprivacywallet", "\"\"") + HelpExampleCli("createprivacywallet", "\"1234567890\"") + HelpExampleRpc("createprivacywallet", "\"1234567890\""));

    LOCK2(cs_main, pwalletMain->cs_wallet);

    //privacy wallet is already created
    throw JSONRPCError(RPC_PRIVACY_WALLET_EXISTED,
                           "Error: RPC unimplemented.");
}

UniValue createprivacyaccount(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
                "createprivacyaccount \n"
                "\nCreate a new wallet account for privacy.\n"
                "\nArguments:\n"
                "\nResult:\n"
                "\"account address\"    (string) the address of the created account\n"
                "\nExamples:\n" +
                HelpExampleCli("createprivacyaccount", "") + HelpExampleCli("createprivacyaccount", "\"\"") + HelpExampleCli("createprivacyaccount", "") + HelpExampleRpc("createprivacyaccount", ""));

    if (!pwalletMain) {
        //privacy wallet is already created
        throw JSONRPCError(RPC_PRIVACY_WALLET_EXISTED,
                           "Error: There is no privacy wallet, please use createprivacyaccount to create one.");
    }

    CWalletDB walletdb(pwalletMain->strWalletFile);
    UniValue ret(UniValue::VOBJ);
    int i = 0;
    while (i < 10) {
        std::string viewAccountLabel = "viewaccount";
        std::string spendAccountLabel = "spendaccount";

        CAccount viewAccount;
        walletdb.ReadAccount(viewAccountLabel, viewAccount);
        if (!viewAccount.vchPubKey.IsValid()) {
            std::string viewAccountAddress = GetHDAccountAddress(viewAccountLabel, 0).ToString();
        }

        CAccount spendAccount;
        walletdb.ReadAccount(spendAccountLabel, spendAccount);
        if (!spendAccount.vchPubKey.IsValid()) {
            std::string spendAccountAddress = GetHDAccountAddress(spendAccountLabel, 1).ToString();
        }
        if (viewAccount.vchPubKey.GetHex() == "" || spendAccount.vchPubKey.GetHex() == "") {
            i++;
            continue;
        }
        ret.push_back(Pair("viewpublickey", viewAccount.vchPubKey.GetHex()));

        ret.push_back(Pair("spendpublickey", spendAccount.vchPubKey.GetHex()));

        std::string stealthAddr;
        if (pwalletMain->EncodeStealthPublicAddress(viewAccount.vchPubKey, spendAccount.vchPubKey, stealthAddr)) {
        	ret.push_back(Pair("stealthaddress", stealthAddr));
        }
        break;
    }
    return ret;
}

UniValue showstealthaddress(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
                "showstealthaddress \n"
                "\nShow stealth address.\n"
                "\nArguments:\n"
                "\nResult:\n"
                "\"account address\"    (string) the address of the created account\n"
                "\nExamples:\n" +
                HelpExampleCli("showstealthaddress", "") + HelpExampleCli("showstealthaddress", "\"\"") + HelpExampleCli("showstealthaddress", "") + HelpExampleRpc("showstealthaddress", ""));

    if (!pwalletMain) {
        //privacy wallet is already created
        throw JSONRPCError(RPC_PRIVACY_WALLET_EXISTED,
                           "Error: There is no privacy wallet, please use createprivacyaccount to create one.");
    }

    CWalletDB walletdb(pwalletMain->strWalletFile);
    UniValue ret(UniValue::VOBJ);
    int i = 0;
    while (i < 10) {
        std::string viewAccountLabel = "viewaccount";
        std::string spendAccountLabel = "spendaccount";

        CAccount viewAccount;
        walletdb.ReadAccount(viewAccountLabel, viewAccount);
        if (!viewAccount.vchPubKey.IsValid()) {
            std::string viewAccountAddress = GetHDAccountAddress(viewAccountLabel, 0).ToString();
        }

        CAccount spendAccount;
        walletdb.ReadAccount(spendAccountLabel, spendAccount);
        if (!spendAccount.vchPubKey.IsValid()) {
            std::string spendAccountAddress = GetHDAccountAddress(spendAccountLabel, 1).ToString();
        }
        if (viewAccount.vchPubKey.GetHex() == "" || spendAccount.vchPubKey.GetHex() == "") {
            i++;
            continue;
        }
        std::string stealthAddr;
        if (pwalletMain->EncodeStealthPublicAddress(viewAccount.vchPubKey, spendAccount.vchPubKey, stealthAddr)) {
            ret.push_back(Pair("stealthaddress", stealthAddr));
        }
        break;
    }
    return ret;
}

UniValue generateintegratedaddress(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
                "generateintegratedaddress <paymentID>\n"
                "\nGenerate integrated addresses for this wallet with a random payment ID.\n"
                "\nArguments:\n"
                "optional: paymentID"
                "\nResult:\n"
                "\nExamples:\n" +
                HelpExampleCli("generateintegratedaddress", "1234") + HelpExampleCli("generateintegratedaddress", "\"\"") + HelpExampleCli("generateintegratedaddress", "") + HelpExampleRpc("generateintegratedaddress", ""));

    if (!pwalletMain) {
        //privacy wallet is already created
        throw JSONRPCError(RPC_PRIVACY_WALLET_EXISTED,
                           "Error: There is no privacy wallet, please use createprivacyaccount to create one.");
    }

    UniValue ret(UniValue::VOBJ);
    uint64_t paymentID = 0;
    std::string address;
    if (params.size() == 1) {
        paymentID = params[0].get_int64();
        address = pwalletMain->GenerateIntegratedAddressWithProvidedPaymentID("masteraccount", paymentID);
    } else {
        address = pwalletMain->GenerateIntegratedAddressWithRandomPaymentID("masteraccount", paymentID);
    }
    ret.push_back(Pair("integratedaddress", address));
    ret.push_back(Pair("paymentid", paymentID));
    return ret;
}

UniValue importkeys(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 2)
        throw runtime_error(
                "importkeys \n"
                "\nCreate a new wallet account for privacy.\n"
                "\nArguments:\n"
                "\nResult:\n"
                "\"account address\"    (string) the address of the created account\n"
                "\nExamples:\n" +
                HelpExampleCli("importkeys", "") + HelpExampleCli("importkeys", "\"\"") + HelpExampleCli("importkeys", "") + HelpExampleRpc("importkeys", ""));

    if (!pwalletMain) {
        //privacy wallet is already created
        throw JSONRPCError(RPC_PRIVACY_WALLET_EXISTED,
                           "Error: There is no privacy wallet, please use createprivacyaccount to create one.");
    }

    CWalletDB walletdb(pwalletMain->strWalletFile);

    std::string viewStr = params[0].get_str();
    std::string spendStr = params[1].get_str();

    CAccount viewAc, spendAc;

    std::vector<unsigned char> view, spend;
    DecodeBase58(viewStr, view);
    DecodeBase58(spendStr, spend);
    std::string viewAccountLabel = "viewaccount";
    std::string spendAccountLabel = "spendaccount";

    CKey viewPk, spendPk;
    viewPk.Set(view.begin(), view.end(), true);
    spendPk.Set(spend.begin(), spend.end(), true);

    pwalletMain->AddKey(viewPk);
    pwalletMain->AddKey(spendPk);
    viewAc.vchPubKey = viewPk.GetPubKey();
    spendAc.vchPubKey = spendPk.GetPubKey();

    pwalletMain->SetAddressBook(viewAc.vchPubKey.GetID(), viewAccountLabel, "receive");
    walletdb.WriteAccount(viewAccountLabel, viewAc);

    pwalletMain->SetAddressBook(spendAc.vchPubKey.GetID(), spendAccountLabel, "receive");
    walletdb.WriteAccount(spendAccountLabel, spendAc);

    return true;
}

UniValue createprivacysubaddress(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
                "createprivacysubaddress \"label\" \n"
                "\nCreate a new wallet account subaddress for privacy transaction.\n"
                "\nArguments:\n"
                "1. \"label\"        (string, required) label for the wallet account address\n"
                "\nResult:\n"
                "\"account address\"    (string) the created address for the corresponding account\n"
                "\"address index\"    (string) the index of the created address for the account\n"
                "\nExamples:\n" +
                HelpExampleCli("createprivacysubaddress", "") + HelpExampleCli("createprivacysubaddress", "\"\"") + HelpExampleCli("createprivacysubaddress", "\"address1\"") + HelpExampleRpc("createprivacysubaddress", "\"address1\""));

    if (!pwalletMain) {
        //privacy wallet is already created
        throw JSONRPCError(RPC_PRIVACY_WALLET_EXISTED,
                           "Error: There is no privacy wallet, please use createprivacyaccount to create one.");
    }

    EnsureWalletIsUnlocked();

    std::string label = params[0].get_str();

    CWalletDB walletdb(pwalletMain->strWalletFile);
    std::string viewAccountLabel = label + "view";
    std::string spendAccountLabel = label + "spend";
    CStealthAccount account;
    if (!walletdb.ReadStealthAccount(label, account)) {
        int i = 0;
        while (i < 10) {
            CAccount viewAccount;
            walletdb.ReadAccount(label + "view", viewAccount);
            if (!viewAccount.vchPubKey.IsValid()) {
                GetAccountAddress(viewAccountLabel).ToString();
            }

            CAccount spendAccount;
            walletdb.ReadAccount(spendAccountLabel, spendAccount);
            if (!spendAccount.vchPubKey.IsValid()) {
                GetAccountAddress(spendAccountLabel).ToString();
            }
            if (viewAccount.vchPubKey.GetHex() == "" || spendAccount.vchPubKey.GetHex() == "") {
                i++;
                continue;
            }
            account.viewAccount = viewAccount;
            account.spendAccount = spendAccount;
            walletdb.AppendStealthAccountList(label);
            break;
        }
    }

    UniValue ret(UniValue::VOBJ);

    ret.push_back(Pair("viewpublickey", account.viewAccount.vchPubKey.GetHex()));

    ret.push_back(Pair("spendpublickey", account.spendAccount.vchPubKey.GetHex()));

    std::string stealthAddr;
    if (pwalletMain->EncodeStealthPublicAddress(account.viewAccount.vchPubKey, account.spendAccount.vchPubKey, stealthAddr)) {
    	ret.push_back(Pair("stealthaddress", stealthAddr));
    }
    return ret;
}

UniValue readmasteraccount(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
                "readmasteraccount \n"
                "\nRead stealth master account address.\n"
                "\nArguments:\n"
                "\nResult:\n"
                "\"public address\" (string) the public address"
                "\nExamples:\n" +
                HelpExampleCli("readmasteraccount", "") + HelpExampleCli("readmasteraccount", "\"\"") + HelpExampleCli("readmasteraccount", "") + HelpExampleRpc("readmasteraccount", ""));

    if (!pwalletMain) {
        //privacy wallet is not yet created
        throw JSONRPCError(RPC_PRIVACY_WALLET_EXISTED,
                           "Error: There is no privacy wallet, please use createprivacyaccount to create one.");
    }
    std::string address;
    pwalletMain->ComputeStealthPublicAddress("masteraccount", address);
    return address;
}

UniValue decodestealthaddress(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
                "decodestealthaddress \n"
                "\nDecode a stealth address into spend and view public keys.\n"
                "\nArguments:\n"
                "1. \"stealth_address\"        (string, required) The Base58 stealth address\n"
                "\nResult:\n"
                "\"public view key\"    (string) the view public key\n"
                "\"public spend key\"   (string) the spend public key"
                "\nExamples:\n" +
                HelpExampleCli("decodestealthaddress", "") + HelpExampleCli("decodestealthaddress", "\"\"") + HelpExampleCli("decodestealthaddress", "") + HelpExampleRpc("decodestealthaddress", ""));

    if (!pwalletMain) {
        //privacy wallet is already created
        throw JSONRPCError(RPC_PRIVACY_WALLET_EXISTED,
                           "Error: There is no privacy wallet, please use createprivacyaccount to create one.");
    }
    std::string addr = params[0].get_str();

    UniValue ret(UniValue::VOBJ);
    CPubKey viewKey, spendKey;
    bool hasPaymentID;
    uint64_t paymentID;

    if (!CWallet::DecodeStealthAddress(addr, viewKey, spendKey, hasPaymentID, paymentID)) {
        throw JSONRPCError(RPC_WALLET_ERROR,
                           "Error: Stealth address is not correctly formatted.");
    }
    ret.push_back(Pair("spendpublickey", spendKey.GetHex()));
    ret.push_back(Pair("viewpublickey", viewKey.GetHex()));
    if (hasPaymentID) {
        ret.push_back(Pair("paymentid", paymentID));
    }

    return ret;
}

UniValue sendtostealthaddress(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 2)
        throw runtime_error(
                "sendtostealthaddress \"dapsstealthaddress\" amount\n"
                "\nSend an amount to a given daps stealth address address. The amount is a real and is rounded to the nearest 0.00000001\n" +
                HelpRequiringPassphrase() +
                "\nArguments:\n"
                "1. \"dapsstealthaddress\"  (string, required) The dapscoin stealth address to send to.\n"
                "2. \"amount\"      (numeric, required) The amount in btc to send. eg 0.1\n"
                "\nResult:\n"
                "\"transactionid\"  (string) The transaction id.\n"
                "\nExamples:\n" +
                HelpExampleCli("sendtostealthaddress", "\"41kYDmcd27f2ULWE6tfC19UnEHYpEhMBtfiYwVFUYbZhXrjLomZXSovQPGzwTCAgwQLpWiEQPA5uyNjmEVLPr4g71AUMNjaVD3n\" 0.1") + HelpExampleCli("sendtostealthaddress", "\"41kYDmcd27f2ULWE6tfC19UnEHYpEhMBtfiYwVFUYbZhXrjLomZXSovQPGzwTCAgwQLpWiEQPA5uyNjmEVLPr4g71AUMNjaVD3n\" 0.1 \"donation\" \"seans outpost\"") + HelpExampleRpc("sendtostealthaddress", "\"41kYDmcd27f2ULWE6tfC19UnEHYpEhMBtfiYwVFUYbZhXrjLomZXSovQPGzwTCAgwQLpWiEQPA5uyNjmEVLPr4g71AUMNjaVD3n\", 0.1, \"donation\", \"seans outpost\""));

    std::string stealthAddr = params[0].get_str();

    // Amount
    CAmount nAmount = AmountFromValue(params[1]);

    // Wallet comments
    CWalletTx wtx;

    EnsureWalletIsUnlocked();
    CPartialTransaction ptx;
    if (!pwalletMain->SendToStealthAddress(ptx, stealthAddr, nAmount, wtx)) {
        throw JSONRPCError(RPC_WALLET_ERROR,
                           "Cannot create transaction.");
    }
    return wtx.GetHash().GetHex();
}

UniValue setdecoyconfirmation(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
                "setdecoyconfirmation\n"
                "\nSend the minimum confirmation for decoys in RingCT\n" +
                HelpRequiringPassphrase() +
                "\nArguments:\n"
                "2. \"confirm\"      (numeric, required) The required minim confirmation for decoys\n"
                "\nResult:\n"
                "\"decoy_confirmation\"  (numeric) The minimum decoy confirmation.\n"
                "\nExamples:\n" +
                HelpExampleCli("setdecoyconfirmation", "\"20\"") + HelpExampleCli("setdecoyconfirmation", "\"20\"") + HelpExampleRpc("setdecoyconfirmation", "\"20\""));

    if (!pwalletMain) {
        //privacy wallet is already created
        throw JSONRPCError(RPC_PRIVACY_WALLET_EXISTED,
                           "Error: There is no privacy wallet, please use createprivacyaccount to create one.");
    }

    int confirmation = params[0].get_int();

    if (confirmation <= 0) {
        throw JSONRPCError(RPC_PRIVACY_DECOY_MIN,
                           "Error: Min decoy confirmation must be positive.");
    }
    pwalletMain->DecoyConfirmationMinimum = confirmation;
    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("decoy_confirmation", confirmation));
    return ret;
}

UniValue getdecoyconfirmation(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
                "getdecoyconfirmation\n"
                "\nShow the current decoy confirmation\n" +
                HelpRequiringPassphrase() +
                "\nArguments:\n"
                "\nResult:\n"
                "\"decoy_confirmation\"  (numeric) The minimum decoy confirmation.\n"
                "\nExamples:\n" +
                HelpExampleCli("getdecoyconfirmation", "") + HelpExampleCli("getdecoyconfirmation", "") + HelpExampleRpc("getdecoyconfirmation", ""));
    if (!pwalletMain) {
        //privacy wallet is already created
        throw JSONRPCError(RPC_PRIVACY_WALLET_EXISTED,
                           "Error: There is no privacy wallet, please use createprivacyaccount to create one.");
    }

    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("decoy_confirmation", pwalletMain->DecoyConfirmationMinimum));
    return ret;
}

std::string GetHex(const unsigned char* vch, int sz) {
    char psz[sz * 2 + 1];
    for (int i = 0; i < sz; i++)
        sprintf(psz + i * 2, "%02x", vch[sz - i - 1]);
    return std::string(psz, psz + sz * 2);
}

UniValue revealviewprivatekey(const UniValue& params, bool fHelp) {
    if (fHelp || params.size() != 0)
        throw runtime_error(
                "revealviewprivatekey \n"
                "\nReveal view private key.\n"
                "\nArguments:\n"
                "\nResult:\n"
                "\"Private view key\"    (string) the private view key\n"
                "\nExamples:\n" +
                HelpExampleCli("revealviewprivatekey", "") + HelpExampleCli("revealviewprivatekey", "\"\"") +
                HelpExampleCli("revealviewprivatekey", "") + HelpExampleRpc("revealviewprivatekey", ""));

    if (!pwalletMain) {
        //privacy wallet is already created
        throw JSONRPCError(RPC_PRIVACY_WALLET_EXISTED,
                           "Error: There is no privacy wallet, please use createprivacyaccount to create one.");
    }

    EnsureWalletIsUnlocked();

    CKey view;
    pwalletMain->myViewPrivateKey(view);
    return CBitcoinSecret(view).ToString();
}

UniValue showcombokey(const UniValue& params, bool fHelp) {
    if (fHelp || params.size() != 0)
        throw runtime_error(
                "showcombokey \n"
                "\nAdd all co-signers except this wallet.\n"
                "\nArguments:\n"
                "\nResult:\n"
                "\nExamples:\n" +
                HelpExampleCli("showcombokey", "") + HelpExampleCli("showcombokey", "\"\"") +
                HelpExampleCli("showcombokey", "") + HelpExampleRpc("showcombokey", ""));

    if (!pwalletMain) {
        //privacy wallet is already created
        throw JSONRPCError(RPC_PRIVACY_WALLET_EXISTED,
                           "Error: There is no privacy wallet, please use createprivacywallet to create one.");
    }

    EnsureWalletIsUnlocked();

    ComboKey combo = pwalletMain->MyComboKey();

    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << combo;
    return HexStr(ssTx.begin(), ssTx.end());
}

UniValue showmultisigaddress(const UniValue& params, bool fHelp) {
    if (fHelp || params.size() != 0)
        throw runtime_error(
                "showmultisigaddress \n"
                "\nAdd all co-signers except this wallet.\n"
                "\nArguments:\n"
                "\nResult:\n"
                "\nExamples:\n" +
                HelpExampleCli("showmultisigaddress", "") + HelpExampleCli("showmultisigaddress", "\"\"") +
                HelpExampleCli("showmultisigaddress", "") + HelpExampleRpc("showmultisigaddress", ""));

    if (!pwalletMain) {
        //privacy wallet is already created
        throw JSONRPCError(RPC_PRIVACY_WALLET_EXISTED,
                           "Error: There is no privacy wallet, please use createprivacywallet to create one.");
    }
    std::string combo = pwalletMain->MyMultisigPubAddress();
    return combo;
}

UniValue addcosigners(const UniValue& params, bool fHelp) {
    if (fHelp || params.size() < 1)
        throw runtime_error(
                "addcosigners \n"
                "\nAdd all co-signers except this wallet.\n"
                "\nArguments:\n"
                "\nResult:\n"
                "\nExamples:\n" +
                HelpExampleCli("addCoSigners", "combo1 combo2") + HelpExampleCli("addCoSigners", "\"\"") +
                HelpExampleCli("addCoSigners", "") + HelpExampleRpc("addCoSigners", ""));

    if (!pwalletMain) {
        //privacy wallet is already created
        throw JSONRPCError(RPC_PRIVACY_WALLET_EXISTED,
                           "Error: There is no privacy wallet, please use createprivacywallet to create one.");
    }

    EnsureWalletIsUnlocked();

    for (size_t i = 0; i < params.size(); i++) {
    	std::string hex = params[i].get_str();
    	if (!IsHex(hex)) throw runtime_error("Fail to decode combo key " + std::to_string(i + 1));
    	vector<unsigned char> comboData(ParseHex(hex));
    	CDataStream ssdata(comboData, SER_NETWORK, PROTOCOL_VERSION);
    	ComboKey combo;
    	try {
    		ssdata >> combo;
    	} catch (const std::exception&) {
    		throw runtime_error("Fail to decode combo key " + std::to_string(i + 1));
    	}
    	if (pwalletMain) {
    		pwalletMain->AddCosignerKeyAtIndex(combo, pwalletMain->ReadScreenIndex());
    	}
    }

    pwalletMain->SetNumSigners(params.size() + 1);
    pwalletMain->GenerateMultisigWallet(pwalletMain->ReadNumSigners());

    return pwalletMain->MyMultisigPubAddress();
}

UniValue cosigntransaction(const UniValue& params, bool fHelp) {
    if (fHelp || params.size() != 1)
        throw runtime_error(
                "cosigntransaction <hexcode>\n"
                "\nCosign a transaction.\n"
                "\nArguments:\n"
                "\nResult:\n"
                "\nExamples:\n" +
                HelpExampleCli("cosigntransaction", "hexcode") + HelpExampleCli("cosigntransaction", "\"\"") +
                HelpExampleCli("cosigntransaction", "") + HelpExampleRpc("cosigntransaction", ""));

    if (!pwalletMain) {
        //privacy wallet is already created
        throw JSONRPCError(RPC_PRIVACY_WALLET_EXISTED,
                           "Error: There is no privacy wallet, please use createprivacywallet to create one.");
    }

    EnsureWalletIsUnlocked();

    std::string hexPartial = params[0].get_str();
	if (!IsHex(hexPartial)) throw runtime_error("Invalid hex code");
    
    vector<unsigned char> partialTxData(ParseHex(hexPartial));
	CDataStream ssdata(partialTxData, SER_NETWORK, PROTOCOL_VERSION);
	CPartialTransaction partialTx;
	try {
		ssdata >> partialTx;
	} catch (const std::exception&) {
		throw runtime_error("Fail to parse hex code");
	}
    bool ret = false;
    try {
        ret = pwalletMain->CoSignPartialTransaction(partialTx);
    } catch(std::exception& e) {
        throw runtime_error(e.what());
    }
    if (!ret) {
        throw runtime_error("Fail to co-sign transaction");
    }

    CDataStream dex(SER_NETWORK, PROTOCOL_VERSION);
    dex << partialTx;
    std::string hex = HexStr(dex.begin(), dex.end());
    return hex;
}

UniValue revealspendprivatekey(const UniValue& params, bool fHelp) {
    if (fHelp || params.size() != 0)
        throw runtime_error(
                "revealspendprivatekey \n"
                "\nReveal view private key.\n"
                "\nArguments:\n"
                "\nResult:\n"
                "\"Private spend key\"    (string) the private spend key\n"
                "\nExamples:\n" +
                HelpExampleCli("revealspendprivatekey", "") + HelpExampleCli("revealspendprivatekey", "\"\"") +
                HelpExampleCli("revealspendprivatekey", "") + HelpExampleRpc("revealspendprivatekey", ""));

    if (!pwalletMain) {
        //privacy wallet is already created
        throw JSONRPCError(RPC_PRIVACY_WALLET_EXISTED,
                           "Error: There is no privacy wallet, please use createprivacyaccount to create one.");
    }

    EnsureWalletIsUnlocked();

    CKey spend;
    pwalletMain->mySpendPrivateKey(spend);
    return CBitcoinSecret(spend).ToString();
}

UniValue generatekeyimageforsync(const UniValue& params, bool fHelp) {
    if (fHelp || params.size() != 1)
        throw runtime_error(
                "generatekeyimageforsync \n"
                "\nGenerate key image for sync.\n"
                "\nArguments:\n"
                "\n 1: hex of transaction in progress\n"
                "\nResult:\n"
                "\"Hex of sync key image\"    (string) \n"
                "\nExamples:\n" +
                HelpExampleCli("generatekeyimageforsync", "") + HelpExampleCli("generatekeyimageforsync", "\"\"") +
                HelpExampleCli("generatekeyimageforsync", "") + HelpExampleRpc("generatekeyimageforsync", ""));

    if (!pwalletMain) {
        //privacy wallet is already created
        throw JSONRPCError(RPC_PRIVACY_WALLET_EXISTED,
                           "Error: There is no privacy wallet, please use createprivacywallet to create one.");
    }

    EnsureWalletIsUnlocked();

    std::string hexCode = params[0].get_str();
	if (!IsHex(hexCode)) throw runtime_error("Invalid hex code");;
	vector<unsigned char> partialTxHex(ParseHex(hexCode));
	CDataStream ssdata(partialTxHex, SER_NETWORK, PROTOCOL_VERSION);
	CPartialTransaction ptx;
	try {
		ssdata >> ptx;
	} catch (const std::exception&) {
		throw runtime_error("Invalid hex code");
	}
	CListPKeyImageAlpha keyImageAlpha;
	pwalletMain->generatePKeyImageAlphaListFromPartialTx(ptx, keyImageAlpha);
	CDataStream ssWritedata(SER_NETWORK, PROTOCOL_VERSION);
	ssWritedata << keyImageAlpha;
	std::string hex = HexStr(ssWritedata.begin(), ssWritedata.end());
	return hex;
}

UniValue showtxprivatekeys(const UniValue& params, bool fHelp) {
    if (fHelp || params.size() != 1)
        throw runtime_error(
                "showtxprivatekeys <txhash>\n"
                "\nShow transaction private keys for each UTXO of a transaction.\n"
                "\nArguments:\n"
                "\nResult:\n"
                "\"Private spend key\"    (string) the private spend key\n"
                "\nExamples:\n" +
                HelpExampleCli("showtxprivatekeys", "") + HelpExampleCli("showtxprivatekeys", "\"\"") +
                HelpExampleCli("showtxprivatekeys", "") + HelpExampleRpc("showtxprivatekeys", ""));

    if (!pwalletMain) {
        //privacy wallet is already created
        throw JSONRPCError(RPC_PRIVACY_WALLET_EXISTED,
                           "Error: There is no privacy wallet, please use createprivacyaccount to create one.");
    }

    EnsureWalletIsUnlocked();
    UniValue ret(UniValue::VOBJ);
    CWalletDB db(pwalletMain->strWalletFile);
    for(int i = 0; i < 10; i++) {
    	std::string key = params[0].get_str() + std::to_string(i);
    	std::string secret;
    	if (db.ReadTxPrivateKey(key, secret)) {
    		ret.push_back(Pair(std::to_string(i), secret));
    	} else break;
    }
    return ret;
}

UniValue rescan(const UniValue& params, bool fHelp) {
    if (fHelp || params.size() != 0)
        throw runtime_error(
                "rescan\n"
                "\nRescan wallet transactions from the first block.\n"
                "\nArguments:\n"
                "\nResult:\n"
                "\"scanned wallet transactions\"    \n"
                "\nExamples:\n" +
                HelpExampleCli("rescan", "") + HelpExampleCli("rescan", "\"\"") +
                HelpExampleRpc("rescan", ""));

    if (!pwalletMain) {
        //privacy wallet is already created
        throw JSONRPCError(RPC_PRIVACY_WALLET_EXISTED,
                           "Error: There is no privacy wallet, please use createprivacyaccount to create one.");
    }

    EnsureWalletIsUnlocked();

    int nHeight = 1;
    if (!pwalletMain->RescanAfterUnlock(nHeight)) {
        return "Failed to rescan";
    }
    return "Done";
}

UniValue rescanwallettransactions(const UniValue& params, bool fHelp) {
    if (fHelp || params.size() != 1)
        throw runtime_error(
                "rescanwallettransactions \"block height\"\n"
                "\nRescan wallet transactions from a certain block height.\n"
                "\nArguments:\n"
                "\nblock height: block height from which the chain will be rescanned\n"
                "\nResult:\n"
                "\"scanned wallet transactions\"    \n"
                "\nExamples:\n" +
                HelpExampleCli("rescanwallettransactions", "") + HelpExampleCli("rescanwallettransactions", "\"\"") +
                HelpExampleRpc("rescanwallettransactions", ""));

    if (!pwalletMain) {
        //privacy wallet is already created
        throw JSONRPCError(RPC_PRIVACY_WALLET_EXISTED,
                           "Error: There is no privacy wallet, please use createprivacyaccount to create one.");
    }

    EnsureWalletIsUnlocked();

    int nHeight = 0;
    if (params.size() == 1) {
    	nHeight = params[0].get_int();
    }
    if (!pwalletMain->RescanAfterUnlock(nHeight)) {
    	return "Failed to rescan";
    }
    return "Done";
}

UniValue revealmnemonicphrase(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
                "revealmnemonicphrase \n"
                "\nReveal Mnemonic Phrase.\n"
                "\nArguments:\n"
                "\nResult:\n"
                "\"Mnemonic Phrase\"    (string) mnemonic phrase\n"
                "\nExamples:\n" +
                HelpExampleCli("revealmnemonicphrase", "") + HelpExampleCli("revealmnemonicphrase", "\"\"") +
                HelpExampleCli("revealmnemonicphrase", "") + HelpExampleRpc("revealmnemonicphrase", ""));

    EnsureWalletIsUnlocked();
    
    CHDChain hdChainCurrent;
    if (!pwalletMain->GetDecryptedHDChain(hdChainCurrent))
        throw JSONRPCError(RPC_WALLET_ERROR,
                           "Error: There was a problem while getting mnemonic phrase.");

    SecureString mnemonic;
    SecureString mnemonicPass;
    if (!hdChainCurrent.GetMnemonic(mnemonic, mnemonicPass))
        throw JSONRPCError(RPC_WALLET_ERROR,
                           "Error: There was a problem while getting mnemonic phrase.");

    string mPhrase = std::string(mnemonic.begin(), mnemonic.end()).c_str();

    return mPhrase;
}
