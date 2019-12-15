// Copyright (c) 2014 The Bitcoin Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "keystore.h"
#include "chainparams.h"

#include <vector>

#include <boost/test/unit_test.hpp>

using namespace std;

BOOST_AUTO_TEST_SUITE(hd_tests)

BOOST_AUTO_TEST_CASE(hd_test1)
{
    CHDChain newHdChain;
    string strMnemonic = "sorry jelly twice human measure impact caution despair inner stock spare gossip connect someone industry provide panel decade dose loud tunnel famous knife belt";
    string strMnemonicPassphrase = "";

    SecureVector vchMnemonic(strMnemonic.begin(), strMnemonic.end());
    SecureVector vchMnemonicPassphrase(strMnemonicPassphrase.begin(), strMnemonicPassphrase.end());

    BOOST_CHECK(newHdChain.SetMnemonic(vchMnemonic, vchMnemonicPassphrase, true));
    BOOST_CHECK(Params().ExtCoinType() == 0x80000166);

    SecureVector vchSeed = newHdChain.GetSeed();

    CExtKey masterKey;              //hd master key
    CExtKey purposeKey;             //key at m/purpose'
    CExtKey cointypeKey;            //key at m/purpose'/coin_type'
    CExtKey accountKey;             //key at m/purpose'/coin_type'/account'
    CExtKey changeKey;              //key at m/purpose'/coin_type'/account'/change
    CExtKey childKey;               //key at m/purpose'/coin_type'/account'/change/address_index
    CKey newKey;
    CPubKey newPubKey;
    int nAccountIndex = 0;
    int nChildIndex = 0;
    bool fInternal = false;

    masterKey.SetMaster(&vchSeed[0], vchSeed.size());

    masterKey.Derive(purposeKey, 44 | 0x80000000);
    purposeKey.Derive(cointypeKey, Params().ExtCoinType());
    cointypeKey.Derive(accountKey, nAccountIndex | 0x80000000);
    accountKey.Derive(changeKey, fInternal ? 1 : 0);
    changeKey.Derive(childKey, nChildIndex);

    newKey = childKey.key;
    newPubKey = newKey.GetPubKey();
    BOOST_CHECK(newPubKey.GetHex() == "5c0d4f0b9383a9d83addc16929cd90f5cfacbc3ab35b1ee930fc215b9dffe8e402");

    nAccountIndex = 1;
    cointypeKey.Derive(accountKey, nAccountIndex | 0x80000000);
    accountKey.Derive(changeKey, fInternal ? 1 : 0);
    changeKey.Derive(childKey, nChildIndex);

    newKey = childKey.key;
    newPubKey = newKey.GetPubKey();
    BOOST_CHECK(newPubKey.GetHex() == "c6a5832438db1047eea30ce51213aa976f96e029f3c626dd36c85d4bc3ea75da03");
}

BOOST_AUTO_TEST_SUITE_END()