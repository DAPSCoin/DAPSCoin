// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2018 The PIVX developers
// Copyright (c) 2018-2019 The DAPS Project developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.



#include "miner.h"

#include "amount.h"
#include "hash.h"
#include "main.h"
#include "masternode-sync.h"
#include "net.h"
#include "pow.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "timedata.h"
#include "util.h"
#include "utilmoneystr.h"
#ifdef ENABLE_WALLET
#include "wallet.h"
extern CWallet *pwalletMain;
#endif
#include "masternode-payments.h"

#include <boost/thread.hpp>
#include <boost/tuple/tuple.hpp>

using namespace std;

//////////////////////////////////////////////////////////////////////////////
//
// DAPScoinMiner
//

//
// Unconfirmed transactions in the memory pool often depend on other
// transactions in the memory pool. When we select transactions from the
// pool, we select by highest priority or fee rate, so we might consider
// transactions that depend on transactions that aren't yet in the block.
// The COrphan class keeps track of these 'temporary orphans' while
// CreateBlock is figuring out which transactions to include.
//
class COrphan
{
public:
    const CTransaction* ptx;
    set<uint256> setDependsOn;
    CFeeRate feeRate;
    double dPriority;

    COrphan(const CTransaction* ptxIn) : ptx(ptxIn), feeRate(0), dPriority(0)
    {
    }
};

uint64_t nLastBlockTx = 0;
uint64_t nLastBlockSize = 0;
int64_t nLastCoinStakeSearchInterval = 0;
int64_t nConsolidationTime = 0;

// We want to sort transactions by priority and fee rate, so:
typedef boost::tuple<double, CFeeRate, const CTransaction*> TxPriority;
class TxPriorityCompare
{
    bool byFee;

public:
    TxPriorityCompare(bool _byFee) : byFee(_byFee) {}

    bool operator()(const TxPriority& a, const TxPriority& b)
    {
        if (byFee) {
            if (a.get<1>() == b.get<1>())
                return a.get<0>() < b.get<0>();
            return a.get<1>() < b.get<1>();
        } else {
            if (a.get<0>() == b.get<0>())
                return a.get<1>() < b.get<1>();
            return a.get<0>() < b.get<0>();
        }
    }
};

void UpdateTime(CBlockHeader* pblock, const CBlockIndex* pindexPrev)
{
    pblock->nTime = std::max(pindexPrev->GetMedianTimePast() + 1, GetAdjustedTime());

    // Updating time can change work required on testnet:
    if (Params().AllowMinDifficultyBlocks())
        pblock->nBits = GetNextWorkRequired(pindexPrev, pblock);
}

uint32_t GetListOfPoSInfo(uint32_t currentHeight, std::vector<PoSBlockSummary>& audits) {
	//A PoA block should be mined only after at least 59 PoS blocks have not been audited
	//Look for the previous PoA block
	uint32_t nloopIdx = currentHeight;
	while (nloopIdx >= Params().START_POA_BLOCK()) {
		if (chainActive[nloopIdx]->GetBlockHeader().IsPoABlockByVersion()) {
			break;
		}
		nloopIdx--;
	}
    if (nloopIdx <= Params().START_POA_BLOCK()) {
        //this is the first PoA block ==> take all PoS blocks from LAST_POW_BLOCK up to currentHeight - 60 inclusive
        for (int i = Params().LAST_POW_BLOCK() + 1; i <= Params().LAST_POW_BLOCK() + 60; i++) {
            PoSBlockSummary pos;
            pos.hash = chainActive[i]->GetBlockHash();
            CBlockIndex* pindex = mapBlockIndex[pos.hash];
            pos.nTime = ReVerifyPoSBlock(pindex) ? chainActive[i]->GetBlockHeader().nTime : 0;
            pos.height = i;
            audits.push_back(pos);
        }
    } else {
        //Find the previous PoA block
        uint32_t start = nloopIdx;
        if (start > Params().START_POA_BLOCK()) {
            CBlockIndex* pblockindex = chainActive[start];
            CBlock block;
            if (!ReadBlockFromDisk(block, pblockindex))
                throw runtime_error("Can't read block from disk");
            PoSBlockSummary back = block.posBlocksAudited.back();
            uint32_t lastAuditedHeight = back.height;
            uint32_t nextAuditHeight = lastAuditedHeight + 1;
            
            while (nextAuditHeight <= currentHeight) {
                CBlockIndex* posIndex = chainActive[nextAuditHeight];
                CBlock posBlock;
                if (!ReadBlockFromDisk(posBlock, posIndex))
                    throw runtime_error("Can't read block from disk");
                if (posBlock.IsProofOfStake()) {
                    PoSBlockSummary pos;
                    pos.hash = chainActive[nextAuditHeight]->GetBlockHash();
                    CBlockIndex* pindex = mapBlockIndex[pos.hash];
                    pos.nTime = ReVerifyPoSBlock(pindex) ? chainActive[nextAuditHeight]->GetBlockHeader().nTime : 0;
                    pos.height = nextAuditHeight;
                    audits.push_back(pos);
                }
                //The current number of PoS blocks audited in a PoA block is changed from 59 to 61
                if (audits.size() == 61) {
                    break;
                }
                nextAuditHeight++;
            }
        }
    }
    return nloopIdx;
}

CBlockTemplate* CreateNewBlock(const CScript& scriptPubKeyIn, const CPubKey& txPub, const CKey& txPriv, CWallet* pwallet, bool fProofOfStake)
{
    CReserveKey reservekey(pwallet);

    // Create new block
    unique_ptr<CBlockTemplate> pblocktemplate(new CBlockTemplate());
    if (!pblocktemplate.get())
        return NULL;

    CBlock* pblock = &pblocktemplate->block; // pointer for convenience

    // -regtest only: allow overriding block.nVersion with
    // -blockversion=N to test forking scenarios
    if (Params().MineBlocksOnDemand())
        pblock->nVersion = GetArg("-blockversion", pblock->nVersion);

    pblock->nVersion = 3;

    // Create coinbase tx
    CMutableTransaction txNew;
    txNew.vin.resize(1);
    txNew.vin[0].prevout.SetNull();
    txNew.vout.resize(1);
    txNew.vout[0].scriptPubKey = scriptPubKeyIn;
    std::copy(txPub.begin(), txPub.end(), std::back_inserter(txNew.vout[0].txPub));
    std::copy(txPriv.begin(), txPriv.end(), std::back_inserter(txNew.vout[0].txPriv));

    CBlockIndex* prev = chainActive.Tip();
    CAmount nValue = GetBlockValue(prev);
    txNew.vout[0].nValue = nValue;

    pblock->vtx.push_back(txNew);
    pblocktemplate->vTxFees.push_back(-1);   // updated at end
    pblocktemplate->vTxSigOps.push_back(-1); // updated at end

    // ppcoin: if coinstake available add coinstake tx
    static int64_t nLastCoinStakeSearchTime = GetAdjustedTime(); // only initialized at startup

    if (fProofOfStake) {
        boost::this_thread::interruption_point();
        pblock->nTime = GetAdjustedTime();
        CBlockIndex* pindexPrev = chainActive.Tip();
        pblock->nBits = GetNextWorkRequired(pindexPrev, pblock);

        int64_t nSearchTime = pblock->nTime; // search to current time
        bool fStakeFound = false;
        if (nSearchTime >= nLastCoinStakeSearchTime) {
            unsigned int nTxNewTime = 0;
            CMutableTransaction txCoinStake;
            if (pwallet->CreateCoinStake(*pwallet, pblock->nBits, nSearchTime - nLastCoinStakeSearchTime, txCoinStake, nTxNewTime)) {
                pblock->nTime = nTxNewTime;
                pblock->vtx[0].vout[0].SetEmpty();
                CTransaction copied(txCoinStake);
                pblock->vtx.push_back(copied);
                fStakeFound = true;
            }

            nLastCoinStakeSearchInterval = nSearchTime - nLastCoinStakeSearchTime;
            nLastCoinStakeSearchTime = nSearchTime;
        }

        if (!fStakeFound)
            return NULL;
    }

    // Largest block you're willing to create:
    unsigned int nBlockMaxSize = GetArg("-blockmaxsize", DEFAULT_BLOCK_MAX_SIZE);
    // Limit to betweeen 1K and MAX_BLOCK_SIZE-1K for sanity:
    unsigned int nBlockMaxSizeNetwork = MAX_BLOCK_SIZE_CURRENT;
    nBlockMaxSize = std::max((unsigned int)1000, std::min((nBlockMaxSizeNetwork - 1000), nBlockMaxSize));

    // How much of the block should be dedicated to high-priority transactions,
    // included regardless of the fees they pay
    unsigned int nBlockPrioritySize = GetArg("-blockprioritysize", DEFAULT_BLOCK_PRIORITY_SIZE);
    nBlockPrioritySize = std::min(nBlockMaxSize, nBlockPrioritySize);

    // Minimum block size you want to create; block will be filled with free transactions
    // until there are no more or the block reaches this size:
    unsigned int nBlockMinSize = GetArg("-blockminsize", DEFAULT_BLOCK_MIN_SIZE);
    nBlockMinSize = std::min(nBlockMaxSize, nBlockMinSize);

    // Collect memory pool transactions into the block
    CAmount nFees = 0;

    {
        LOCK2(cs_main, mempool.cs);

        CBlockIndex* pindexPrev = chainActive.Tip();
        const int nHeight = pindexPrev->nHeight + 1;
        CCoinsViewCache view(pcoinsTip);

        // Priority order to process transactions
        list<COrphan> vOrphan; // list memory doesn't move
        map<uint256, vector<COrphan*> > mapDependers;
        bool fPrintPriority = GetBoolArg("-printpriority", false);

        // This vector will be sorted into a priority queue:
        vector<TxPriority> vecPriority;
        vecPriority.reserve(mempool.mapTx.size());
        std::set<CKeyImage> keyImages;
        for (map<uint256, CTxMemPoolEntry>::iterator mi = mempool.mapTx.begin();
             mi != mempool.mapTx.end(); ++mi) {
            const CTransaction& tx = mi->second.GetTx();
            if (tx.IsCoinBase() || tx.IsCoinStake() || !IsFinalTx(tx, nHeight)){
                continue;
            }
            bool fKeyImageCheck = true;
            // Check key images not duplicated with what in db
            for (const CTxIn& txin: tx.vin) {
            	const CKeyImage& keyImage = txin.keyImage;
            	if (IsKeyImageSpend1(keyImage.GetHex(), uint256())) {
            		fKeyImageCheck = false;
            		break;
            	}
            }

            if (!fKeyImageCheck) {
            	continue;
            }

            if (!CheckHaveInputs(view, tx)) continue;

            COrphan* porphan = NULL;
            double dPriority = 0;
            CAmount nTotalIn = 0;

            // Priority is sum(valuein * age) / modified_txsize
            unsigned int nTxSize = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);
            dPriority = GetPriority(tx, chainActive.Height());

            uint256 hash = tx.GetHash();
            mempool.ApplyDeltas(hash, dPriority, nTotalIn);

            CFeeRate feeRate(tx.nTxFee, nTxSize);

            bool isDuplicate = false;
            for (const CTxIn& txin: tx.vin) {
            	const CKeyImage& keyImage = txin.keyImage;
            	if (keyImages.count(keyImage)) {
            		isDuplicate = true;
            		break;
            	}
            	keyImages.insert(keyImage);
            }
            if (isDuplicate) continue;
            vecPriority.push_back(TxPriority(dPriority, feeRate, &mi->second.GetTx()));
        }
        LogPrintf("Selecting %d transactions from mempool\n", vecPriority.size());
        // Collect transactions into block
        uint64_t nBlockSize = 1000;
        uint64_t nBlockTx = 0;
        int nBlockSigOps = 100;
        bool fSortedByFee = (nBlockPrioritySize <= 0);

        TxPriorityCompare comparer(fSortedByFee);
        std::make_heap(vecPriority.begin(), vecPriority.end(), comparer);

        vector<CBigNum> vBlockSerials;
        vector<CBigNum> vTxSerials;
        while (!vecPriority.empty()) {
            // Take highest priority transaction off the priority queue:
            double dPriority = vecPriority.front().get<0>();
            CFeeRate feeRate = vecPriority.front().get<1>();
            const CTransaction& tx = *(vecPriority.front().get<2>());

            std::pop_heap(vecPriority.begin(), vecPriority.end(), comparer);
            vecPriority.pop_back();

            // Size limits
            unsigned int nTxSize = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);
            if (nBlockSize + nTxSize >= nBlockMaxSize)
                continue;

            // Skip free transactions if we're past the minimum block size:
            const uint256& hash = tx.GetHash();
            double dPriorityDelta = 0;
            CAmount nFeeDelta = 0;
            mempool.ApplyDeltas(hash, dPriorityDelta, nFeeDelta);
            CFeeRate customMinRelayTxFee = CFeeRate(5000);
            if (fSortedByFee && (feeRate < customMinRelayTxFee) && (nBlockSize + nTxSize >= nBlockMinSize))
                continue;

            // Prioritise by fee once past the priority size or we run out of high-priority
            // transactions:
            if (!fSortedByFee &&
                ((nBlockSize + nTxSize >= nBlockPrioritySize) || !AllowFree(dPriority))) {
                fSortedByFee = true;
                comparer = TxPriorityCompare(fSortedByFee);
                std::make_heap(vecPriority.begin(), vecPriority.end(), comparer);
            }

            if (!CheckHaveInputs(view, tx))
                continue;

            CAmount nTxFees = tx.nTxFee;

            // Note that flags: we don't want to set mempool/IsStandard()
            // policy here, but we still have to ensure that the block we
            // create only contains transactions that are valid in new blocks.
            CValidationState state;
            if (!CheckInputs(tx, state, view, true, MANDATORY_SCRIPT_VERIFY_FLAGS, true))
                continue;

            CTxUndo txundo;
            if (tx.IsCoinStake()) {
            	UpdateCoins(tx, state, view, txundo, nHeight);
            }

            // Added
            pblock->vtx.push_back(tx);
            pblocktemplate->vTxFees.push_back(nTxFees);
            pblocktemplate->vTxSigOps.push_back(0);
            nBlockSize += nTxSize;
            ++nBlockTx;
            nFees += nTxFees;

            for (const CBigNum bnSerial : vTxSerials)
                vBlockSerials.emplace_back(bnSerial);

            if (fPrintPriority) {
                LogPrintf("priority %.1f fee %s txid %s\n",
                    dPriority, feeRate.ToString(), tx.GetHash().ToString());
            }

            // Add transactions that depend on this one to the priority queue
            if (mapDependers.count(hash)) {
                for (COrphan* porphan : mapDependers[hash]) {
                    if (!porphan->setDependsOn.empty()) {
                        porphan->setDependsOn.erase(hash);
                        if (porphan->setDependsOn.empty()) {
                            vecPriority.push_back(TxPriority(porphan->dPriority, porphan->feeRate, porphan->ptx));
                            std::push_heap(vecPriority.begin(), vecPriority.end(), comparer);
                        }
                    }
                }
            }
        }

        if (!fProofOfStake) {
            //Masternode and general budget payments
            FillBlockPayee(txNew, nFees, fProofOfStake);

            //Make payee
            if (txNew.vout.size() > 1) {
                pblock->payee = txNew.vout[1].scriptPubKey;
            }
        }

        nLastBlockTx = nBlockTx;
        nLastBlockSize = nBlockSize;

        // Compute final coinbase transaction.
        pblock->vtx[0].vin[0].scriptSig = CScript() << nHeight << OP_0;
        pblock->vtx[0].txType = TX_TYPE_REVEAL_AMOUNT;
        if (!fProofOfStake) {
            pblock->vtx[0].vout[0].nValue += nFees;
            pblocktemplate->vTxFees[0] = nFees;
        } else {
        	pblock->vtx[1].vout[2].nValue += nFees;
        	pblocktemplate->vTxFees[0] = nFees;
        }
        
        CPubKey sharedSec;
        sharedSec.Set(txPub.begin(), txPub.end());
        //compute commitment
        unsigned char zeroBlind[32];
        memset(zeroBlind, 0, 32);
        if (pblock->IsProofOfWork()) {
            pwallet->EncodeTxOutAmount(pblock->vtx[0].vout[0], pblock->vtx[0].vout[0].nValue, sharedSec.begin());
            nValue = pblock->vtx[0].vout[0].nValue;
            if (!pwallet->CreateCommitment(zeroBlind, nValue, pblock->vtx[0].vout[0].commitment)) {
                return NULL;
            }
        } else {
            sharedSec.Set(pblock->vtx[1].vout[2].txPub.begin(), pblock->vtx[1].vout[2].txPub.end());
            pwallet->EncodeTxOutAmount(pblock->vtx[1].vout[2], pblock->vtx[1].vout[2].nValue, sharedSec.begin());
            nValue = pblock->vtx[1].vout[2].nValue;
            pblock->vtx[1].vout[2].commitment.clear();
            if (!pwallet->CreateCommitment(zeroBlind, nValue, pblock->vtx[1].vout[2].commitment)) {
                return NULL;
            }

            //Shnorr sign
            if (!pwalletMain->MakeShnorrSignature(pblock->vtx[1])) {
            	LogPrintf("%s : failed to make Shnorr signature\n", __func__);
            	return NULL;
            }

            //Test verify shnorr signature
            if (!VerifyShnorrKeyImageTx(pblock->vtx[1])) {
                LogPrintf("%s: Failed to verify shnorr key image\n", __func__);
            	return NULL;
            }
            pwalletMain->IsTransactionForMe(pblock->vtx[1]);
        }

        // Fill in header
        pblock->hashPrevBlock = pindexPrev->GetBlockHash();
        if (!fProofOfStake)
            UpdateTime(pblock, pindexPrev);
        pblock->nBits = GetNextWorkRequired(pindexPrev, pblock);
        pblock->nNonce = 0;
        uint256 nCheckpoint = 0;
        pblock->nAccumulatorCheckpoint = nCheckpoint;
        pblocktemplate->vTxSigOps[0] = GetLegacySigOpCount(pblock->vtx[0]);
    }

    return pblocktemplate.release();
}

CBlockTemplate* CreateNewPoABlock(const CScript& scriptPubKeyIn, const CPubKey& txPub, const CKey& txPriv, CWallet* pwallet) {
	CReserveKey reservekey(pwallet);

	if (chainActive.Tip()->nHeight < Params().START_POA_BLOCK()) {
		return NULL;
	}

	// Create new block
	unique_ptr<CBlockTemplate> pblocktemplate(new CBlockTemplate());
	if (!pblocktemplate.get())
		return NULL;
	CBlock* pblock = &pblocktemplate->block; // pointer for convenience

	pblock->SetNull();
	// Create coinbase tx
	CMutableTransaction txNew;
	txNew.vin.resize(1);
	txNew.vin[0].prevout.SetNull();
	txNew.vout.resize(1);
	//Value of this vout coinbase will be computed based on the number of audited PoS blocks
	//This will be computed later
	txNew.vout[0].scriptPubKey = scriptPubKeyIn;
    std::copy(txPub.begin(), txPub.end(), std::back_inserter(txNew.vout[0].txPub));
    std::copy(txPriv.begin(), txPriv.end(), std::back_inserter(txNew.vout[0].txPriv));

	pblock->vtx.push_back(txNew);
	pblocktemplate->vTxFees.push_back(-1);   // updated at end
	pblocktemplate->vTxSigOps.push_back(-1); // updated at end

	boost::this_thread::interruption_point();
	pblock->nTime = GetAdjustedTime();
	CBlockIndex* pindexPrev = chainActive.Tip();
	pblock->nBits = GetNextWorkRequired(pindexPrev, pblock);

	int nprevPoAHeight;


	nprevPoAHeight = GetListOfPoSInfo(pindexPrev->nHeight, pblock->posBlocksAudited);
	if (pblock->posBlocksAudited.size() == 0) {
		return NULL;
	}
	// Set block version to differentiate PoA blocks from PoS blocks
	pblock->SetVersionPoABlock();
	pblock->nTime = GetAdjustedTime();

	//compute PoA block reward
	CAmount nReward = pblock->posBlocksAudited.size() * 100 * COIN;
	pblock->vtx[0].vout[0].nValue = nReward;

    pblock->vtx[0].txType = TX_TYPE_REVEAL_AMOUNT;

    CPubKey sharedSec;
    sharedSec.Set(txPub.begin(), txPub.end());
    unsigned char zeroBlind[32];
    memset(zeroBlind, 0, 32);
    pwallet->EncodeTxOutAmount(pblock->vtx[0].vout[0], pblock->vtx[0].vout[0].nValue, sharedSec.begin());
    if (!pwallet->CreateCommitment(zeroBlind, pblock->vtx[0].vout[0].nValue, pblock->vtx[0].vout[0].commitment)) {
        LogPrintf("%s: unable to create commitment to 0\n", __func__);
        return NULL;
    }
    pwallet->EncodeTxOutAmount(pblock->vtx[0].vout[0], pblock->vtx[0].vout[0].nValue, sharedSec.begin());

    //Comment out all previous code, because a PoA block does not verify any transaction, except reward transactions to miners
	// No need to collect memory pool transactions into the block
	const int nHeight = pindexPrev->nHeight + 1;

	// Fill in header
	pblock->hashPrevBlock = pindexPrev->GetBlockHash();
	if (nprevPoAHeight >= Params().START_POA_BLOCK()) {
		pblock->hashPrevPoABlock = *(chainActive[nprevPoAHeight]->phashBlock);
	} else {
		pblock->hashPrevPoABlock.SetNull();
	}

	//ATTENTION: This is used for setting always the easiest difficulty for PoA miners
	pblock->nBits = GetNextWorkRequired(pindexPrev, pblock);
	pblock->nNonce = 0;

	pblocktemplate->vTxSigOps[0] = GetLegacySigOpCount(pblock->vtx[0]);

	// Compute final coinbase transaction.
	CMutableTransaction txCoinbase(pblock->vtx[0]);
	txCoinbase.vin[0].scriptSig = (CScript() << nHeight << CScriptNum(1)) + COINBASE_FLAGS;
	assert(txCoinbase.vin[0].scriptSig.size() <= 100);

	pblock->vtx[0] = txCoinbase;
	pblock->hashMerkleRoot = pblock->BuildMerkleTree();

    pblock->hashPoAMerkleRoot = pblock->BuildPoAMerkleTree();
	pblock->minedHash = pblock->ComputeMinedHash();

	return pblocktemplate.release();
}

void IncrementExtraNonce(CBlock* pblock, CBlockIndex* pindexPrev, unsigned int& nExtraNonce)
{
    // Update nExtraNonce
    static uint256 hashPrevBlock;
    if (hashPrevBlock != pblock->hashPrevBlock) {
        nExtraNonce = 0;
        hashPrevBlock = pblock->hashPrevBlock;
    }
    ++nExtraNonce;
    unsigned int nHeight = pindexPrev->nHeight + 1; // Height first in coinbase required for block.version=2
    CMutableTransaction txCoinbase(pblock->vtx[0]);
    txCoinbase.vin[0].scriptSig = (CScript() << nHeight << CScriptNum(nExtraNonce)) + COINBASE_FLAGS;
    assert(txCoinbase.vin[0].scriptSig.size() <= 100);

    pblock->vtx[0] = txCoinbase;
    pblock->hashMerkleRoot = pblock->BuildMerkleTree();
}

#ifdef ENABLE_WALLET
//////////////////////////////////////////////////////////////////////////////
//
// Internal miner
//
double dHashesPerSec = 0.0;
int64_t nHPSTimerStart = 0;

CBlockTemplate* CreateNewBlockWithKey(CReserveKey& reservekey, CWallet* pwallet, bool fProofOfStake)
{
    CPubKey pubkey, txPub;
    CKey priv;
    if (!pwallet->GenerateAddress(pubkey, txPub, priv))
        return NULL;

    CScript scriptPubKey = CScript() << ToByteVector(pubkey) << OP_CHECKSIG;
    return CreateNewBlock(scriptPubKey, txPub, priv, pwallet, fProofOfStake);
}

CBlockTemplate* CreateNewPoABlockWithKey(CReserveKey& reservekey, CWallet* pwallet)
{
    CPubKey pubkey, txPub;
    CKey txPriv;
    if (!pwallet->GenerateAddress(pubkey, txPub, txPriv))
        return NULL;

    CScript scriptPubKey = CScript() << ToByteVector(pubkey) << OP_CHECKSIG;
    return CreateNewPoABlock(scriptPubKey, txPub, txPriv, pwallet);
}

bool ProcessBlockFound(CBlock* pblock, CWallet& wallet, CReserveKey& reservekey)
{
    LogPrintf("%s\n", pblock->ToString());

    // Found a solution
    {
        LOCK(cs_main);
        if (pblock->hashPrevBlock != chainActive.Tip()->GetBlockHash())
            return error("DAPScoinMiner : generated block is stale");
    }

    // Remove key from key pool
    reservekey.KeepKey();

    // Track how many getdata requests this block gets
    {
        LOCK(wallet.cs_wallet);
        wallet.mapRequestCount[pblock->GetHash()] = 0;
    }

    // Process this block the same as if we had received it from another node
    CValidationState state;
    if (!ProcessNewBlock(state, NULL, pblock))
        return error("DAPScoinMiner : ProcessNewBlock, block not accepted");

    for (CNode* node : vNodes) {
        node->PushInventory(CInv(MSG_BLOCK, pblock->GetHash()));
    }

    return true;
}

bool fGenerateDapscoins = false;

// ***TODO*** that part changed in bitcoin, we are using a mix with old one here for now

void BitcoinMiner(CWallet* pwallet, bool fProofOfStake, MineType mineType)
{
	//disable in multisig
}

void static ThreadBitcoinMiner(void* parg)
{
    boost::this_thread::interruption_point();
    CWallet* pwallet = (CWallet*)parg;
    try {
        if (chainActive.Tip()->nHeight >= Params().LAST_POW_BLOCK()) {
            BitcoinMiner(pwallet, true);
        } else {
            BitcoinMiner(pwallet, false);
        }
        boost::this_thread::interruption_point();
    } catch (std::exception& e) {
        LogPrintf("ThreadBitcoinMiner() exception");
    } catch (...) {
        LogPrintf("ThreadBitcoinMiner() exception");
    }

    LogPrintf("ThreadBitcoinMiner exiting\n");
}

void static ThreadDapscoinMiner(void* parg)
{
    boost::this_thread::interruption_point();
    try {
    	//create a PoA after every 3 minute if enough PoS blocks created
    	while (true) {
    		boost::this_thread::sleep_for(boost::chrono::milliseconds(180 * 1000));
    		//TODO: call CreateNewPoABlock function to create PoA blocks
    	}
        boost::this_thread::interruption_point();
    } catch (std::exception& e) {
        LogPrintf("ThreadBitcoinMiner() exception");
    } catch (...) {
        LogPrintf("ThreadBitcoinMiner() exception");
    }

    LogPrintf("ThreadBitcoinMiner exiting\n");
}

void GeneratePoADapscoin(CWallet* pwallet, int period)
{
    static boost::thread_group* minerThreads = NULL;

    if (minerThreads != NULL) {
        minerThreads->interrupt_all();
        delete minerThreads;
        minerThreads = NULL;
    }

    minerThreads = new boost::thread_group();
    minerThreads->create_thread(boost::bind(&ThreadDapscoinMiner, pwallet));
}

void GenerateDapscoins(bool fGenerate, CWallet* pwallet, int nThreads)
{
    static boost::thread_group* minerThreads = NULL;
    fGenerateDapscoins = fGenerate;

    if (nThreads < 0) {
        // In regtest threads defaults to 1
        if (Params().DefaultMinerThreads())
            nThreads = Params().DefaultMinerThreads();
        else
            nThreads = boost::thread::hardware_concurrency();
    }

    if (minerThreads != NULL) {
        minerThreads->interrupt_all();
        delete minerThreads;
        minerThreads = NULL;
    }

    if (nThreads == 0 || !fGenerate)
        return;

    minerThreads = new boost::thread_group();
    for (int i = 0; i < nThreads; i++)
        minerThreads->create_thread(boost::bind(&ThreadBitcoinMiner, pwallet));
}

// ppcoin: stake minter thread
void ThreadStakeMinter() {
    boost::this_thread::interruption_point();
    LogPrintf("ThreadStakeMinter started\n");
    CWallet *pwallet = pwalletMain;
    try {
        BitcoinMiner(pwallet, true);
        boost::this_thread::interruption_point();
    } catch (std::exception &e) {
        LogPrintf("ThreadStakeMinter() exception \n");
    } catch (...) {
        LogPrintf("ThreadStakeMinter() error \n");
    }
    LogPrintf("ThreadStakeMinter exiting,\n");
}

#endif // ENABLE_WALLET
