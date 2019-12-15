// Copyright (c) 2011-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2018 The PIVX developers
// Copyright (c) 2018-2019 The DAPS Project developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "transactionrecord.h"

#include "base58.h"
#include "obfuscation.h"
#include "swifttx.h"
#include "timedata.h"
#include "wallet.h"

#include <stdint.h>

/* Return positive answer if transaction should be shown in list.
 */
bool TransactionRecord::showTransaction(const CWalletTx& wtx)
{
    if (wtx.IsCoinBase()) {
        // Ensures we show generated coins / mined transactions at depth 1
        if (!wtx.IsInMainChain()) {
            return false;
        }
    }
    return true;
}

/*
 * Decompose CWallet transaction to model transaction records.
 */
QList<TransactionRecord> TransactionRecord::decomposeTransaction(const CWallet* wallet, const CWalletTx& wtx)
{
    QList<TransactionRecord> parts;
    int64_t nTime = wtx.GetComputedTxTime();
    CAmount nCredit = wtx.GetCredit(ISMINE_ALL);
    CAmount nDebit = wtx.GetDebit(ISMINE_ALL);
    CAmount nNet = nCredit - nDebit;
    uint256 hash = wtx.GetHash();
    std::map<std::string, std::string> mapValue = wtx.mapValue;
    if (wtx.IsCoinStake()) {
        TransactionRecord sub(hash, nTime);
        CTxDestination address;
        if (!ExtractDestination(wtx.vout[1].scriptPubKey, address))
            return parts;
        if (!IsMine(*wallet, address)) {
            //if the address is not yours then it means you have a tx sent to you in someone elses coinstake tx
            for (unsigned int i = 1; i < wtx.vout.size(); i++) {
                CTxDestination outAddress;
                if (ExtractDestination(wtx.vout[i].scriptPubKey, outAddress)) {
                    if (IsMine(*wallet, outAddress)) {
                        isminetype mine = wallet->IsMine(wtx.vout[i]);
                        sub.involvesWatchAddress = mine & ISMINE_WATCH_ONLY;
                        sub.type = TransactionRecord::MNReward;
                        sub.address = CBitcoinAddress(outAddress).ToString();
                        sub.credit = wallet->getCTxOutValue(wtx, wtx.vout[i]);
                    }
                }
            }
        } else {
            //stake reward
            isminetype mine = wallet->IsMine(wtx.vout[1]);
            sub.involvesWatchAddress = mine & ISMINE_WATCH_ONLY;
            sub.type = TransactionRecord::StakeMint;
            sub.address = CBitcoinAddress(address).ToString();
            sub.credit = nNet;
            sub.debit = 0;
        }
        parts.append(sub);
    } else if (nNet > 0 || wtx.IsCoinBase() || wtx.IsCoinAudit()) {
        //
        // Credit
        //
        for (const CTxOut& txout : wtx.vout) {
            isminetype mine = wallet->IsMine(txout);
            if (mine) {
                TransactionRecord sub(hash, nTime);
                CTxDestination address;
                sub.idx = parts.size(); // sequence number
                sub.involvesWatchAddress = mine & ISMINE_WATCH_ONLY;
                sub.address = CBitcoinAddress(address).ToString();
                if (ExtractDestination(txout.scriptPubKey, address) && IsMine(*wallet, address)) {
                    // Received by DAPS Address
                    sub.credit = IsMine(*wallet, address) ? wallet->getCTxOutValue(wtx, txout) : 0;
                    sub.type = TransactionRecord::RecvWithAddress;
                    sub.address = CBitcoinAddress(address).ToString();
                } else {
                    // Received by IP connection (deprecated features), or a multisignature or other non-simple transaction
                    sub.type = TransactionRecord::RecvFromOther;
                    sub.address = CBitcoinAddress(address).ToString();
                }
                if (wtx.IsCoinBase() || wtx.IsCoinAudit()) {
                    // Generated
                    sub.type = TransactionRecord::Generated;
                }

                parts.append(sub);
            }
        }
    } else {
        bool fAllFromMeDenom = true;
        int nFromMe = 0;
        bool involvesWatchAddress = false;
        isminetype fAllFromMe = ISMINE_SPENDABLE;
        for (const CTxIn& txin : wtx.vin) {
            if (wallet->IsMine(wtx, txin)) {
                fAllFromMeDenom = fAllFromMeDenom && wallet->IsDenominated(wtx, txin);
                nFromMe++;
            }
            isminetype mine = wallet->IsMine(wtx, txin);
            if (mine & ISMINE_WATCH_ONLY) involvesWatchAddress = true;
            if (fAllFromMe > mine) fAllFromMe = mine;
        }

        isminetype fAllToMe = ISMINE_SPENDABLE;
        bool fAllToMeDenom = true;
        int nToMe = 0;
        for (const CTxOut& txout : wtx.vout) {
            if (wallet->IsMine(txout)) {
                CAmount c = wallet->getCTxOutValue(wtx, txout);
                fAllToMeDenom = fAllToMeDenom && wallet->IsDenominatedAmount(c);
                nToMe++;
            }
            isminetype mine = wallet->IsMine(txout);
            if (mine & ISMINE_WATCH_ONLY) involvesWatchAddress = true;
            if (fAllToMe > mine) fAllToMe = mine;
        }

        if (fAllFromMeDenom && fAllToMeDenom && nFromMe && nToMe) {
            parts.append(TransactionRecord(hash, nTime, TransactionRecord::ObfuscationDenominate, "", -nDebit, nCredit));
            parts.last().involvesWatchAddress = false; // maybe pass to TransactionRecord as constructor argument
        } else if (fAllFromMe && fAllToMe) {
            // Payment to self
            TransactionRecord sub(hash, nTime);
            // Payment to self by default
            sub.type = TransactionRecord::SendToSelf;
            sub.address = "";

            if (mapValue["DS"] == "1") {
                sub.type = TransactionRecord::Obfuscated;
                CTxDestination address;
                if (ExtractDestination(wtx.vout[0].scriptPubKey, address)) {
                    // Sent to DAPS Address
                    sub.address = CBitcoinAddress(address).ToString();
                } else {
                    // Sent to IP, or other non-address transaction like OP_EVAL
                    sub.address = mapValue["to"];
                }
            } else {
                for (unsigned int nOut = 0; nOut < wtx.vout.size(); nOut++) {
                    const CTxOut& txout = wtx.vout[nOut];
                    sub.idx = parts.size();

                    if (wallet->IsCollateralAmount(wallet->getCTxOutValue(wtx, txout))) sub.type = TransactionRecord::ObfuscationMakeCollaterals;
                    if (nDebit - wtx.GetValueOut() == OBFUSCATION_COLLATERAL) sub.type = TransactionRecord::ObfuscationCollateralPayment;
                }
                CTxDestination address;
                if (ExtractDestination(wtx.vout[0].scriptPubKey, address)) {
                	// Sent to DAPS Address
                	sub.address = CBitcoinAddress(address).ToString();
                }
            }

            //a sendtoself transaction has second output as change
            CAmount nChange = 0;
            if (wtx.vout.size() >= 2) nChange = pwalletMain->getCTxOutValue(wtx, wtx.vout[1]);

            sub.debit = nCredit - nChange;
            sub.credit = 0;
            parts.append(sub);
            parts.last().involvesWatchAddress = involvesWatchAddress; // maybe pass to TransactionRecord as constructor argument
        } else if (fAllFromMe) {
            //
            // Debit
            //
            CAmount nTxFee = 0;//nDebit - wtx.GetValueOut();

            for (unsigned int nOut = 0; nOut < wtx.vout.size(); nOut++) {
                const CTxOut& txout = wtx.vout[nOut];
                TransactionRecord sub(hash, nTime);
                sub.idx = parts.size();
                sub.involvesWatchAddress = involvesWatchAddress;

                if (wallet->IsMine(txout)) {
                    // Ignore parts sent to self, as this is usually the change
                    // from a transaction sent back to our own address.
                    continue;
                }

                CTxDestination address;
                if (ExtractDestination(txout.scriptPubKey, address)) {
                    // Sent to DAPS Address
                    sub.type = TransactionRecord::SendToAddress;
                    sub.address = CBitcoinAddress(address).ToString();
                } else {
                    // Sent to IP, or other non-address transaction like OP_EVAL
                    sub.type = TransactionRecord::SendToOther;
                    sub.address = mapValue["to"];
                }

                if (mapValue["DS"] == "1") {
                    sub.type = TransactionRecord::Obfuscated;
                }

                CAmount nValue = wallet->getCTxOutValue(wtx, txout);
                /* Add fee to first output */
                if (nTxFee > 0) {
                    nValue += nTxFee;
                    nTxFee = 0;
                }
                sub.debit = nDebit - nCredit - wtx.nTxFee;

                parts.append(sub);
            }
        } else {
            //
            // Mixed debit transaction, can't break down payees
            //
            parts.append(TransactionRecord(hash, nTime, TransactionRecord::Other, "", nNet, 0));
            parts.last().involvesWatchAddress = involvesWatchAddress;
        }
    }

    return parts;
}

void TransactionRecord::updateStatus(const CWalletTx& wtx)
{
    AssertLockHeld(cs_main);
    // Determine transaction status

    // Find the block the tx is in
    CBlockIndex* pindex = NULL;
    BlockMap::iterator mi = mapBlockIndex.find(wtx.hashBlock);
    if (mi != mapBlockIndex.end())
        pindex = (*mi).second;

    // Sort order, unrecorded transactions sort to the top
    status.sortKey = strprintf("%010d-%01d-%010u-%03d",
        (pindex ? pindex->nHeight : std::numeric_limits<int>::max()),
        (wtx.IsCoinBase() ? 1 : 0),
        wtx.nTimeReceived,
        idx);
    status.countsForBalance = wtx.IsTrusted() && !(wtx.GetBlocksToMaturity() > 0);
    status.depth = wtx.GetDepthInMainChain();
    status.cur_num_blocks = chainActive.Height();
    status.cur_num_ix_locks = nCompleteTXLocks;

    if (!IsFinalTx(wtx, chainActive.Height() + 1)) {
        if (wtx.nLockTime < LOCKTIME_THRESHOLD) {
            status.status = TransactionStatus::OpenUntilBlock;
            status.open_for = wtx.nLockTime - chainActive.Height();
        } else {
            status.status = TransactionStatus::OpenUntilDate;
            status.open_for = wtx.nLockTime;
        }
    }
    // For generated transactions, determine maturity
    else if (type == TransactionRecord::Generated || type == TransactionRecord::StakeMint || type == TransactionRecord::MNReward) {
        if (wtx.GetBlocksToMaturity() > 0) {
            status.status = TransactionStatus::Immature;

            if (wtx.IsInMainChain()) {
                status.matures_in = wtx.GetBlocksToMaturity();

                // Check if the block was requested by anyone
                if (GetAdjustedTime() - wtx.nTimeReceived > 2 * 60 && wtx.GetRequestCount() == 0)
                    status.status = TransactionStatus::MaturesWarning;
            } else {
                status.status = TransactionStatus::NotAccepted;
            }
        } else {
            status.status = TransactionStatus::Confirmed;
        }
    } else {
        if (status.depth < 0) {
            status.status = TransactionStatus::Conflicted;
        } else if (GetAdjustedTime() - wtx.nTimeReceived > 2 * 60 && wtx.GetRequestCount() == 0) {
            status.status = TransactionStatus::Offline;
        } else if (status.depth == 0) {
            status.status = TransactionStatus::Unconfirmed;
        } else if (status.depth < RecommendedNumConfirmations) {
            status.status = TransactionStatus::Confirming;
        } else {
            status.status = TransactionStatus::Confirmed;
        }
    }
}

bool TransactionRecord::statusUpdateNeeded()
{
    AssertLockHeld(cs_main);
    return status.cur_num_blocks != chainActive.Height() || status.cur_num_ix_locks != nCompleteTXLocks;
}

QString TransactionRecord::getTxID() const
{
    return QString::fromStdString(hash.ToString());
}

int TransactionRecord::getOutputIndex() const
{
    return idx;
}
