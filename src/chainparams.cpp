// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2018 The PIVX developers
// Copyright (c) 2018-2019 The DAPS Project developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "random.h"
#include "util.h"
#include "utilstrencodings.h"
#include "streams.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>

using namespace std;
using namespace boost::assign;

std::string EncodeHexTx(const CMutableTransaction& tx)
{
    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << tx;
    return HexStr(ssTx.begin(), ssTx.end());
}

std::string EncodeHexBlock(const CBlock& b)
{
    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << b;
    return HexStr(ssTx.begin(), ssTx.end());
}

struct SeedSpec6 {
    uint8_t addr[16];
    uint16_t port;
};

#include "chainparamsseeds.h"

/**
 * Main network
 */

//! Convert the pnSeeds6 array into usable address objects.
static void convertSeed6(std::vector<CAddress>& vSeedsOut, const SeedSpec6* data, unsigned int count)
{
    // It'll only connect to one or two seed nodes because once it connects,
    // it'll get a pile of addresses with newer timestamps.
    // Seed nodes are given a random 'last seen time' of between one and two
    // weeks ago.
    const int64_t nOneWeek = 7 * 24 * 60 * 60;
    for (unsigned int i = 0; i < count; i++) {
        struct in6_addr ip;
        memcpy(&ip, data[i].addr, sizeof(ip));
        CAddress addr(CService(ip, data[i].port));
        addr.nTime = GetTime() - GetRand(nOneWeek) - nOneWeek;
        vSeedsOut.push_back(addr);
    }
}

//   What makes a good checkpoint block?
// + Is surrounded by blocks with reasonable timestamps
//   (no blocks before with a timestamp after, none after with
//    timestamp before)
// + Contains no strange transactions
static Checkpoints::MapCheckpoints mapCheckpoints =
    boost::assign::map_list_of
    (0, uint256("0000039a711dba61e12c29fb86542fa059e9616aafe9b4c61e065d393f31535e"))
    (32653, uint256("eaab21ed33e4f1245310693023bbbdb1ae3066b1ba14bebb028a3a994de241c2"))
    (40000, uint256("9ffbac0d42cd54d9ba248c63f36d9a61bc661a04afa78f3ecbcb718bc2f2d21b"))
    (45000, uint256("64c12e8da3b2c07fea03626d05b6d38e736f954a2fc21536a8b8bbdc020d334c"))
    (50000, uint256("abf91e61c4f4c132f70fd35e8806cc0552fc0633c7ff652ba3a4c2d3f76da313"))
    (55000, uint256("ea6b18ed1d3ecb137355c48f932498a7d3700299fdf1482914999659ff76f5fc"))
    (60000, uint256("6736bf033ffd8693a994a4309daa6fcf1949ec682f0079275a18a6b6d5824d29"))
    (65000, uint256("0a1b37f796434886d05b217bfe20f72a9c80d4360a24ac6b964099270047b421"))
    (70000, uint256("ef0c9cb28314963cdea903262ef5d9b7392e4592b49ef52898914761df3deecb"))
    (75000, uint256("dd4977555ce2fa67a24eb4706c916314819fb1aa2d53692f65887c79b1de46dc"))
    (80000, uint256("5f765e960d3ef71146d72adb0df3cd0f28f84267df6572447e3894d5a5c71a22"))
    (85000, uint256("25d5eef4a7c950b3cd211d9153698994e5a7120fe7a196854212763a5725c121"))
    (90000, uint256("708fa5b0c083cb2fb5dec4427932a05cadad248e1ee07e55d260d4db93fd0f0f"))
    (95000, uint256("ee8aef24bf22bd20cc6fa147193455a1792c3bd54bc4bcb974198b0f00fd25e6"))
    (100000, uint256("f5ea8462d802d664ffd17d4311ec08b90b6c7e173fe91fbb1cf875fba8d51b46"))
    (105000, uint256("61a55a787fe2630da750996b8b0e7fd5d3926c4780d60fec61aabe842882c075"))
    (110000, uint256("23c351cfb8d784f209df8ee944cf5819caca6b33b3ee871f952ed047305b5d1f"))
    (115000, uint256("7d2056457c12bba157e63ff9cb22764c279b8862954fc298fcc31a0d33cca6e1"))
    (120000, uint256("676c1258d58f5f5c2c8f4edd62221f34344936691d94bd3ccbd5381505199ffd"))
    (125000, uint256("06c9e0bd74b426f1079aec4ec16d0492ee5787d55c18229ab2bf510d0f29b4cf"))
    (130000, uint256("a6a819a10706c225f6590eb790e7453201fcde628d06817bc71962ed934e6c7f"))
    (135000, uint256("2d3aa77215fa2dba565910a208d4f97e671aea2f9faf769b23e5fb877623357b"))
    (140000, uint256("bfd1387b9672b8f0f8a6605079473a14f0509f4b3556bddaf45244aef47e806b"))
    (145000, uint256("1f8b28270448158f397bae1ca75804212182eea9dab0258a8d0fec6d1d697ce0"))
    (146000, uint256("591dedf96ab6ba5c60389862570a1326e58610af13657e9d5289646704f81e0f"))
    (146100, uint256("fb77b9b4294457cefdcfedf5f39369f7173c8bf2b39bdb241a683fe2e9bac3d3"))
    (146200, uint256("ec4c0b626e5100cc4bdbf3c2b8ae98c7d51a0fd151ff58553d2ca66e0a05515c"))
    (146300, uint256("a85ca48f6e4b1d543e8a838a0b27c49e5f71934b4b28c05d040275c3cec2268d"))
    (146400, uint256("44ec2778fcfc5f737bf1dbd318ecdd31f9e65aad4692f0cea292108861e58234"))
    (146500, uint256("e73bb158b9fc2075bf8c8935548b77f6d2b4bd9bd6e932483c073846bce4a4e0"))
    (146600, uint256("95c6a698083ddc27a8fb342086b055d3823c040f32f5728c9ded7d8fe675bd8b"))
    (146700, uint256("ba7a089a31940f6c8569c07ef25915c50d28182dc78d6af2590a2dc65476c9b2"))
    (146800, uint256("85d7b80f682f4d480e85816786f821576c7f1df182276358ad3917742fa11bd7"))
    (146898, uint256("a0e3853d98c6d60febd57ad2c879e590bda09de271527b396efc5be22ab5ce9e"))
    (146899, uint256("22c90bbb2ae11c3bd5fd6c716d543f8f207e6379e14d26fc04ba7220681dd13b"))
    (146900, uint256("a879e6b5f62ed437d2108366a8152130c21df38322556f06dd71ad08854210b8"))
    (147000, uint256("e60eb87bdbeaee7582826418c8c4504637e51684a3e631b5683390497a4e2535"))
    (147200, uint256("55fcf4abbd7a1b3aa91460378c3b833f9d1569780b0a1e7e6ee2d1b3a4256b24"))
    (147400, uint256("15d8ed0575995a4b3ab8337d87213943abb9e3fba5389c57cbd48a2751f78a5d"))
    ;
static const Checkpoints::CCheckpointData data = {
    &mapCheckpoints,
    1573659116, // * UNIX timestamp of last checkpoint block
    379717,    // * total number of transactions between genesis and last checkpoint
                //   (the tx=... number in the SetBestChain debug.log lines)
    0        // * estimated number of transactions per day after checkpoint
};

static Checkpoints::MapCheckpoints mapCheckpointsTestnet =
    boost::assign::map_list_of(0, uint256("0x00000561b6da32b1b305690648d7eec908a538e9b9f496f1a9ad5d20ed533af8"));
static const Checkpoints::CCheckpointData dataTestnet = {
    &mapCheckpointsTestnet,
    1536808115,
    0,
    0};

static Checkpoints::MapCheckpoints mapCheckpointsRegtest =
    boost::assign::map_list_of(0, uint256("0x519fc91c13da2eb1301e87ebb7db993f15b57fb1fd7f3e172411bf4262c2efdb"));
static const Checkpoints::CCheckpointData dataRegtest = {
    &mapCheckpointsRegtest,
    1536808341,
    0,
    0};

class CMainParams : public CChainParams
{
public:
    CMainParams()
    {
        networkID = CBaseChainParams::MAIN;
        strNetworkID = "main";
        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 4-byte int at any alignment.
         */
        pchMessageStart[0] = 0xa4;
        pchMessageStart[1] = 0xb7;
        pchMessageStart[2] = 0x79;
        pchMessageStart[3] = 0x84;
        vAlertPubKey = ParseHex("049def8e22e7f78b624dc62007c66c06066d032310b3507642306b143326a8295e03576ffab7469c552e1a68655598d78d501eb10cc27408bfd7876dbadb08b0ee");
        nDefaultPort = 53572; //default port for multisig
        bnProofOfWorkLimit = ~uint256(0) >> 1; // DAPScoin starting difficulty is 1 / 2^12
        nSubsidyHalvingInterval = 210000;
        nMaxReorganizationDepth = 100;
        nEnforceBlockUpgradeMajority = 750;
        nRejectBlockOutdatedMajority = 950;
        nToCheckBlockUpgradeMajority = 1000;
        nMinerThreads = 0;
        nTargetTimespan = 1 * 60; // DAPScoin: 1 day
        nTargetSpacing = 1 * 60;  // DAPScoin: 1 minute
        nMaturity = 100;
        nMasternodeCountDrift = 20;
        MAX_MONEY = 2000000000.0;
        nMaxMoneyOut = MAX_MONEY * COIN;

        /** Height or Time Based Activations **/
        nLastPOWBlock = 500;
        nStartPOABlock = 560;
        nModifierUpdateBlock = 615800;
        nPoABlockTime = 60 * 60; //a PoA block every 30 minutes
        nMinNumPoSBlocks = 59;

        /**
         * Build the genesis block. Note that the output of the genesis coinbase cannot
         * be spent as it did not originally exist in the database.
         *
         * CBlock(hash=00000ffd590b14, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=e0028e, nTime=1390095618, nBits=1e0ffff0, nNonce=28917698, vtx=1)
         *   CTransaction(hash=e0028e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
         *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d01044c5957697265642030392f4a616e2f3230313420546865204772616e64204578706572696d656e7420476f6573204c6976653a204f76657273746f636b2e636f6d204973204e6f7720416363657074696e6720426974636f696e73)
         *     CTxOut(nValue=50.00000000, scriptPubKey=0xA9037BAC7050C479B121CF)
         *   vMerkleTree: e0028e
         */
        const char* pszTimestamp = "30 September 2019 DAPS Coin Development Team - Privacy Is A Right, Not A Privilege";
        CMutableTransaction txNew;
        txNew.vin.resize(1);
        txNew.vout.resize(1);
        txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew.vout[0].nValue = 0 * COIN;
        txNew.vout[0].scriptPubKey = CScript() << ParseHex("041db2a1b75bc00fc1a18e9f8de27c65fede32eb9ac1c11e2587402a66732656d71f7b5de649c8dc7f94aeb433485ce3122ba856644b02e433c2d5fc94ea26bf8e") << OP_CHECKSIG;
        genesis.vtx.push_back(txNew);
        genesis.hashPrevBlock = 0;
        genesis.hashMerkleRoot = genesis.BuildMerkleTree();
        genesis.nVersion = 1;
        genesis.nTime = 1569750052; //09/29/2019 @ 9:40am (UTC)
        genesis.nBits = 0x1e0ffff0;
        genesis.nNonce = 18289272;

        //change blockhash from 0x00000e9468bba3df97334bfb5015543488a0fb38193c82b101472937590e3037 because of transaction structure change
        if(genesis.GetHash()!=uint256("0000039a711dba61e12c29fb86542fa059e9616aafe9b4c61e065d393f31535e"))
        {
            printf("Searchingforgenesisblock...\n");
            uint256 hashTarget=uint256().SetCompact(genesis.nBits);

            printf("hashTarget:%s\n",hashTarget.ToString().c_str());

            while(uint256(genesis.GetHash())>hashTarget)
            {
                printf("loop:%s\n",genesis.GetHash().ToString().c_str());
                ++genesis.nNonce;
                if(genesis.nNonce==0)
                {
                    printf("NONCEWRAPPED,incrementingtime");
                    std::cout<<std::string("NONCEWRAPPED,incrementingtime:\n");
                    ++genesis.nTime;
                }
                if(genesis.nNonce%10000==0)
                {
                    printf("Mainnet:nonce%08u:hash=%s\n",genesis.nNonce,genesis.GetHash().ToString().c_str());
                }
            }
            printf("block.nTime=%u\n",genesis.nTime);
            printf("block.nNonce=%u\n",genesis.nNonce);
            printf("block.GetHash=%s\n",genesis.GetHash().ToString().c_str());
            printf("hashMerkleRoot=%s\n",genesis.hashMerkleRoot.ToString().c_str());

        }



        hashGenesisBlock = genesis.GetHash();
        assert(hashGenesisBlock == uint256("0000039a711dba61e12c29fb86542fa059e9616aafe9b4c61e065d393f31535e"));
        assert(genesis.hashMerkleRoot == uint256("4dc798fa29a037570075a87a39c9a54c210f005c4c59c72f32036a87273f4cf8"));

        vSeeds.push_back(CDNSSeedData("seed.dapscoin.com", "seed.dapscoin.com"));        // Single node address
        vSeeds.push_back(CDNSSeedData("seed1.dapscoin.com", "seed1.dapscoin.com"));        // Single node address
        vSeeds.push_back(CDNSSeedData("seed2.dapscoin.com", "seed2.dapscoin.com"));        // Single node address
        vSeeds.push_back(CDNSSeedData("seed3.dapscoin.com", "seed3.dapscoin.com"));        // Single node address
        vSeeds.push_back(CDNSSeedData("seed4.dapscoin.com", "seed4.dapscoin.com"));        // Single node address
        vSeeds.push_back(CDNSSeedData("seed5.dapscoin.com", "seed5.dapscoin.com"));        // Single node address
        vSeeds.push_back(CDNSSeedData("seed6.dapscoin.com", "seed6.dapscoin.com"));        // Single node address
        vSeeds.push_back(CDNSSeedData("seed7.dapscoin.com", "seed7.dapscoin.com"));        // Single node address
        vSeeds.push_back(CDNSSeedData("seed8.dapscoin.com", "seed8.dapscoin.com"));        // Single node address
        vSeeds.push_back(CDNSSeedData("seed9.dapscoin.com", "seed9.dapscoin.com"));        // Single node address
        vSeeds.push_back(CDNSSeedData("seed.dapscoin-seeds.com", "seed.dapscoin-seeds.com"));        // Single node address
        vSeeds.push_back(CDNSSeedData("seed1.dapscoin-seeds.com", "seed1.dapscoin-seeds.com"));        // Single node address
        vSeeds.push_back(CDNSSeedData("seed2.dapscoin-seeds.com", "seed2.dapscoin-seeds.com"));        // Single node address
        vSeeds.push_back(CDNSSeedData("seed3.dapscoin-seeds.com", "seed3.dapscoin-seeds.com"));        // Single node address
        vSeeds.push_back(CDNSSeedData("seed4.dapscoin-seeds.com", "seed4.dapscoin-seeds.com"));        // Single node address
        vSeeds.push_back(CDNSSeedData("seed5.dapscoin-seeds.com", "seed5.dapscoin-seeds.com"));        // Single node address

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 30);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 13);
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 212);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x02)(0x2D)(0x25)(0x33).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x02)(0x21)(0x31)(0x2B).convert_to_container<std::vector<unsigned char> >();
        // 	BIP44 coin type is from https://github.com/satoshilabs/slips/blob/master/slip-0044.md
        nExtCoinType = 0x80000166;

        convertSeed6(vFixedSeeds, pnSeed6_main, ARRAYLEN(pnSeed6_main));

        fRequireRPCPassword = true;
        fMiningRequiresPeers = true;
        fAllowMinDifficultyBlocks = false;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fSkipProofOfWorkCheck = false;
        fTestnetToBeDeprecatedFieldRPC = false;
        fHeadersFirstSyncingActive = false;

        nPoolMaxTransactions = 3;
        strObfuscationPoolDummyAddress = "D87q2gC9j6nNrnzCsg4aY6bHMLsT9nUhEw";
        nStartMasternodePayments = 1546809115; //Wed, 25 Jun 2014 20:36:16 GMT
    }

    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return data;
    }
};
static CMainParams mainParams;

/**
 * Testnet (v3)
 */
class CTestNetParams : public CMainParams
{
public:
    CTestNetParams()
    {
        networkID = CBaseChainParams::TESTNET;
        strNetworkID = "test";
        pchMessageStart[0] = 0xa5;
        pchMessageStart[1] = 0xb8;
        pchMessageStart[2] = 0x7a;
        pchMessageStart[3] = 0x85;
        vAlertPubKey = ParseHex("04b6c4c72f1ef439a603ab52aa2ca7c73c59c5cfb0ebdae305f7fd2928bb90b41293dc746753f59fea3a6fb2cc546bbebf4387a368bdf1a3755d4545fe28ba449e");
        nDefaultPort = 53574;
        nEnforceBlockUpgradeMajority = 51;
        nRejectBlockOutdatedMajority = 75;
        nToCheckBlockUpgradeMajority = 100;
        nMinerThreads = 0;
        nTargetTimespan = 1 * 60; // DAPScoin: 1 day
        nTargetSpacing = 1 * 60;  // DAPScoin: 1 minute
        nLastPOWBlock = 500;
        nStartPOABlock = 560;
        nPoABlockTime = 30 * 60;  //1 PoA block every 30 minutes
        nMinNumPoSBlocks = 20;
        nMaturity = 15;
        nMasternodeCountDrift = 4;
        nModifierUpdateBlock = 51197; //approx Mon, 17 Apr 2017 04:00:00 GMT
        MAX_MONEY = 5000000000.0;
        nMaxMoneyOut = MAX_MONEY * COIN;
        nBlockEnforceSerialRange = 1; //Enforce serial range starting this block
        nBlockRecalculateAccumulators = 9908000; //Trigger a recalculation of accumulators
        nBlockFirstFraudulent = 9891737; //First block that bad serials emerged
        nBlockLastGoodCheckpoint = 9891730; //Last valid accumulator checkpoint
        nBlockEnforceInvalidUTXO = 9902850; //Start enforcing the invalid UTXO's

        //! Modify the testnet genesis block so the timestamp is valid for a later start.
        genesis.nTime = 1569319143;
        genesis.nNonce = 14995439;

        if(genesis.GetHash()!=uint256("0000061003c91526e4ecb49305e5bc8f5e880e7542ca4d4b3b1057688aa9aba4"))
        {
            printf("Searchingforgenesisblock...\n");
            uint256 hashTarget=uint256().SetCompact(genesis.nBits);

            printf("hashTarget:%s\n",hashTarget.ToString().c_str());

            while(uint256(genesis.GetHash())>hashTarget)
            {
                printf("loop:%s\n",genesis.GetHash().ToString().c_str());
                ++genesis.nNonce;
                if(genesis.nNonce==0)
                {
                    printf("NONCEWRAPPED,incrementingtime");
                    std::cout<<std::string("NONCEWRAPPED,incrementingtime:\n");
                    ++genesis.nTime;
                }
                if(genesis.nNonce%10000==0)
                {
                    printf("Mainnet:nonce%08u:hash=%s\n",genesis.nNonce,genesis.GetHash().ToString().c_str());
                }
            }
            printf("block.nTime=%u\n",genesis.nTime);
            printf("block.nNonce=%u\n",genesis.nNonce);
            printf("block.GetHash=%s\n",genesis.GetHash().ToString().c_str());
            printf("hashMerkleRoot=%s\n",genesis.hashMerkleRoot.ToString().c_str());

        }

        hashGenesisBlock = genesis.GetHash();
        assert(hashGenesisBlock == uint256("0000061003c91526e4ecb49305e5bc8f5e880e7542ca4d4b3b1057688aa9aba4"));

        vFixedSeeds.clear();
        vSeeds.clear();
        vSeeds.push_back(CDNSSeedData("192.168.2.202", "192.168.2.202"));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 139); // Testnet dapscoin addresses start with 'x' or 'y'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 19);  // Testnet dapscoin script addresses start with '8' or '9'
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 239);     // Testnet private keys start with '9' or 'c' (Bitcoin defaults)
        // Testnet dapscoin BIP32 pubkeys start with 'DRKV'
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x3a)(0x80)(0x61)(0xa0).convert_to_container<std::vector<unsigned char> >();
        // Testnet dapscoin BIP32 prvkeys start with 'DRKP'
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x3a)(0x80)(0x58)(0x37).convert_to_container<std::vector<unsigned char> >();
        // Testnet dapscoin BIP44 coin type is '1' (All coin's testnet default)
        nExtCoinType = 0x80000001;

        convertSeed6(vFixedSeeds, pnSeed6_test, ARRAYLEN(pnSeed6_test));

        fRequireRPCPassword = true;
        fMiningRequiresPeers = true;
        fAllowMinDifficultyBlocks = false;
        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = true;

        nPoolMaxTransactions = 2;
        strObfuscationPoolDummyAddress = "y57cqfGRkekRyDRNeJiLtYVEbvhXrNbmox";
        nStartMasternodePayments = 1420837558; //Fri, 09 Jan 2015 21:05:58 GMT
        nBudget_Fee_Confirmations = 3; // Number of confirmations for the finalization fee. We have to make this very short
                                       // here because we only have a 8 block finalization window on testnet
    }
    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return dataTestnet;
    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CTestNetParams
{
public:
    CRegTestParams()
    {
        networkID = CBaseChainParams::REGTEST;
        strNetworkID = "regtest";
        strNetworkID = "regtest";
        pchMessageStart[0] = 0xa1;
        pchMessageStart[1] = 0xcf;
        pchMessageStart[2] = 0x7e;
        pchMessageStart[3] = 0xac;
        nSubsidyHalvingInterval = 150;
        nEnforceBlockUpgradeMajority = 750;
        nRejectBlockOutdatedMajority = 950;
        nToCheckBlockUpgradeMajority = 1000;
        nMinerThreads = 1;
        nTargetTimespan = 24 * 60 * 60; // Dapscoin: 1 day
        nTargetSpacing = 1 * 60;        // Dapscoin: 1 minutes
        bnProofOfWorkLimit = ~uint256(0) >> 1;
        genesis.nTime = 1569319143;
        genesis.nBits = 0x207fffff;
        genesis.nNonce = 12359;

        if(genesis.GetHash()!=uint256("2ed32054ce47f012ff186e6116b4906a8cd9d73ff5c689a8623bf36aed774536"))
        {
            printf("Searchingforgenesisblock...\n");
            uint256 hashTarget=uint256().SetCompact(genesis.nBits);

            printf("hashTarget:%s\n",hashTarget.ToString().c_str());

            while(uint256(genesis.GetHash())>hashTarget)
            {
                printf("loop:%s\n",genesis.GetHash().ToString().c_str());
                ++genesis.nNonce;
                if(genesis.nNonce==0)
                {
                    printf("NONCEWRAPPED,incrementingtime");
                    std::cout<<std::string("NONCEWRAPPED,incrementingtime:\n");
                    ++genesis.nTime;
                }
                if(genesis.nNonce%10000==0)
                {
                    printf("Mainnet:nonce%08u:hash=%s\n",genesis.nNonce,genesis.GetHash().ToString().c_str());
                }
            }
            printf("block.nTime=%u\n",genesis.nTime);
            printf("block.nNonce=%u\n",genesis.nNonce);
            printf("block.GetHash=%s\n",genesis.GetHash().ToString().c_str());
            printf("hashMerkleRoot=%s\n",genesis.hashMerkleRoot.ToString().c_str());

        }

        hashGenesisBlock = genesis.GetHash();
        nDefaultPort = 51476;

        assert(hashGenesisBlock == uint256("2ed32054ce47f012ff186e6116b4906a8cd9d73ff5c689a8623bf36aed774536"));

        vFixedSeeds.clear(); //! Testnet mode doesn't have any fixed seeds.
        vSeeds.clear();      //! Testnet mode doesn't have any DNS seeds.

        fRequireRPCPassword = false;
        fMiningRequiresPeers = false;
        fAllowMinDifficultyBlocks = true;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;
    }
    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return dataRegtest;
    }
};
static CRegTestParams regTestParams;

/**
 * Unit test
 */
class CUnitTestParams : public CMainParams, public CModifiableParams
{
public:
    CUnitTestParams()
    {
        networkID = CBaseChainParams::UNITTEST;
        strNetworkID = "unittest";
        nDefaultPort = 51478;
        vFixedSeeds.clear(); //! Unit test mode doesn't have any fixed seeds.
        vSeeds.clear();      //! Unit test mode doesn't have any DNS seeds.

        fRequireRPCPassword = false;
        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fAllowMinDifficultyBlocks = false;
        fMineBlocksOnDemand = true;

        nExtCoinType = 0x80000166;
    }

    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        // UnitTest share the same checkpoints as MAIN
        return data;
    }

    //! Published setters to allow changing values in unit test cases
    virtual void setSubsidyHalvingInterval(int anSubsidyHalvingInterval) { nSubsidyHalvingInterval = anSubsidyHalvingInterval; }
    virtual void setEnforceBlockUpgradeMajority(int anEnforceBlockUpgradeMajority) { nEnforceBlockUpgradeMajority = anEnforceBlockUpgradeMajority; }
    virtual void setRejectBlockOutdatedMajority(int anRejectBlockOutdatedMajority) { nRejectBlockOutdatedMajority = anRejectBlockOutdatedMajority; }
    virtual void setToCheckBlockUpgradeMajority(int anToCheckBlockUpgradeMajority) { nToCheckBlockUpgradeMajority = anToCheckBlockUpgradeMajority; }
    virtual void setDefaultConsistencyChecks(bool afDefaultConsistencyChecks) { fDefaultConsistencyChecks = afDefaultConsistencyChecks; }
    virtual void setAllowMinDifficultyBlocks(bool afAllowMinDifficultyBlocks) { fAllowMinDifficultyBlocks = afAllowMinDifficultyBlocks; }
    virtual void setSkipProofOfWorkCheck(bool afSkipProofOfWorkCheck) { fSkipProofOfWorkCheck = afSkipProofOfWorkCheck; }
};
static CUnitTestParams unitTestParams;


static CChainParams* pCurrentParams = 0;

CModifiableParams* ModifiableParams()
{
    assert(pCurrentParams);
    assert(pCurrentParams == &unitTestParams);
    return (CModifiableParams*)&unitTestParams;
}

const CChainParams& Params()
{
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams& Params(CBaseChainParams::Network network)
{
    switch (network) {
    case CBaseChainParams::MAIN:
        return mainParams;
    case CBaseChainParams::TESTNET:
        return testNetParams;
    case CBaseChainParams::REGTEST:
        return regTestParams;
    case CBaseChainParams::UNITTEST:
        return unitTestParams;
    default:
        assert(false && "Unimplemented network");
        return mainParams;
    }
}

void SelectParams(CBaseChainParams::Network network)
{
    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}

bool SelectParamsFromCommandLine()
{
    CBaseChainParams::Network network = NetworkIdFromCommandLine();
    if (network == CBaseChainParams::MAX_NETWORK_TYPES)
        return false;

    SelectParams(network);
    return true;
}
