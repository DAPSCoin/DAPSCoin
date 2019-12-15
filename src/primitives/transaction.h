// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2015-2018 The PIVX developers
// Copyright (c) 2018-2019 The DAPS Project developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIMITIVES_TRANSACTION_H
#define BITCOIN_PRIMITIVES_TRANSACTION_H

#include "amount.h"
#include "script/script.h"
#include "serialize.h"
#include "uint256.h"
#include "../bip38.h"
#include <iostream>
#include "key.h"

#include <list>

//Elliptic Curve Diffie Helman: encodes and decodes the amount b and mask a
// where C= aG + bH
void ecdhEncode(uint256& unmasked, uint256& amount, const unsigned char * sharedSec, int size);
void ecdhDecode(uint256& masked, uint256& amount, const unsigned char * sharedSec, int size);

class ECDHInfo {
public:
    static void ComputeSharedSec(const CKey& priv, const CPubKey& pubKey, CPubKey& sharedSec);
    static void Encode(const CKey& mask, const CAmount& amount, const CPubKey& sharedSec, uint256& encodedMask, uint256& encodedAmount);
    static void Decode(unsigned char* encodedMask, unsigned char* encodedAmount, const CPubKey& sharedSec, CKey& decodedMask, CAmount& decodedAmount);
};

class CTransaction;

/** An outpoint - a combination of a transaction hash and an index n into its vout */
class COutPoint
{
public:
    uint256 hash;
    uint32_t n;

    COutPoint() { SetNull(); }
    COutPoint(uint256 hashIn, uint32_t nIn) { hash = hashIn; n = nIn; }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(FLATDATA(*this));
    }

    void SetNull() { hash.SetNull(); n = (uint32_t) -1; }
    bool IsNull() const { return (hash.IsNull() && n == (uint32_t) -1); }
    bool IsMasternodeReward(const CTransaction* tx) const;

    friend bool operator<(const COutPoint& a, const COutPoint& b)
    {
        return (a.hash < b.hash || (a.hash == b.hash && a.n < b.n));
    }

    friend bool operator==(const COutPoint& a, const COutPoint& b)
    {
        return (a.hash == b.hash && a.n == b.n);
    }

    friend bool operator!=(const COutPoint& a, const COutPoint& b)
    {
        return !(a == b);
    }

    std::string ToString() const;
    std::string ToStringShort() const;

    uint256 GetHash() const;

};

/** An input of a transaction.  It contains the location of the previous
 * transaction's output that it claims and a signature that matches the
 * output's public key.
 */
class CTxIn
{
public:
    COutPoint prevout;
    CScript scriptSig;
    uint32_t nSequence;
    CScript prevPubKey;
    std::vector<unsigned char> s;	//used for shnor sig
    std::vector<unsigned char> R;	//used for shnor sig

    //ECDH key used for encrypting/decrypting the transaction amount
    //it is only not NULL when the prevout is used for staking to prove the transaction amount
    //the prevout has the hash of encryptionKey to ensure that the staking node is not cheating
    std::vector<unsigned char> encryptionKey;   //33bytes
    CKeyImage keyImage;   //have the same number element as vin
    std::vector<COutPoint> decoys;
    std::vector<unsigned char> masternodeStealthAddress;

    CTxIn()
    {
        nSequence = std::numeric_limits<unsigned int>::max();
    }

    explicit CTxIn(COutPoint prevoutIn, CScript scriptSigIn=CScript(), uint32_t nSequenceIn=std::numeric_limits<unsigned int>::max());
    CTxIn(uint256 hashPrevTx, uint32_t nOut, CScript scriptSigIn=CScript(), uint32_t nSequenceIn=std::numeric_limits<uint32_t>::max());

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(prevout);
        READWRITE(scriptSig);
        READWRITE(nSequence);
        READWRITE(encryptionKey);
        READWRITE(keyImage);
        READWRITE(decoys);
        READWRITE(masternodeStealthAddress);
        READWRITE(this->s);
        READWRITE(R);
    }

    bool IsFinal() const
    {
        return (nSequence == std::numeric_limits<uint32_t>::max());
    }

    friend bool operator==(const CTxIn& a, const CTxIn& b)
    {
        return (a.prevout   == b.prevout &&
                a.scriptSig == b.scriptSig &&
                a.nSequence == b.nSequence &&
                a.encryptionKey == b.encryptionKey &&
                a.keyImage == b.keyImage &&
                a.decoys == b.decoys);
    }

    friend bool operator!=(const CTxIn& a, const CTxIn& b)
    {
        return !(a == b);
    }

    std::string ToString() const;
};

typedef struct MaskValue {
    CPubKey sharedSec;  //secret is computed based on the transaction pubkey, using diffie hellman
                        //sharedSec = txPub * viewPrivateKey of receiver = txPriv * viewPublicKey of receiver
    uint256 amount;
    uint256 mask;   //blinding factor, this is encoded throug ECDH before sending to the receiver
    CKey inMemoryRawBind;
    uint256 hashOfKey; //hash of encrypting key
    MaskValue() {
        amount.SetNull();
        mask.SetNull();
        hashOfKey.SetNull();
    }
} MaskValue;

/** An output of a transaction.  It contains the public key that the next input
 * must be able to sign with to claim it.
 */
class CTxOut
{
public:
    CAmount nValue; //should always be 0
    CScript scriptPubKey;
    int nRounds;
    //txPriv is optional and will be used for PoS blocks to incentivize masternodes
    //and fullnodes will use it to verify whether the reward is really sent to the registered address of masternodes
    std::vector<unsigned char> txPriv;
    std::vector<unsigned char> txPub;
    //ECDH encoded value for the amount: the idea is the use the shared secret and a key derivation function to
    //encode the value and the mask so that only the sender and the receiver of the tx output can decode the encoded amount
    MaskValue maskValue;
    std::vector<unsigned char> masternodeStealthAddress;  //will be clone from the tx having 1000000 daps output
    std::vector<unsigned char> commitment;  //Commitment C = mask * G + amount * H, H = Hp(G), Hp = toHashPoint

    CTxOut()
    {
        SetNull();
    }

    CTxOut(const CAmount& nValueIn, CScript scriptPubKeyIn);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(nValue);
        READWRITE(scriptPubKey);
        READWRITE(txPriv);
        READWRITE(txPub);
        READWRITE(maskValue.amount);
        READWRITE(maskValue.mask);
        READWRITE(maskValue.hashOfKey);
        READWRITE(masternodeStealthAddress);
        READWRITE(commitment);
    }

    void SetNull()
    {
        nValue = -1;
        scriptPubKey.clear();
        nRounds = -10; // an initial value, should be no way to get this by calculations
    }

    bool IsNull() const
    {
        return (nValue == -1);
    }

    void SetEmpty()
    {
        nValue = 0;
        scriptPubKey.clear();
    }

    bool IsEmpty() const
    {
        return (nValue == 0 && scriptPubKey.empty());
    }

    uint256 GetHash() const;

    bool IsDust(CFeeRate minRelayTxFee) const
    {
        // "Dust" is defined in terms of CTransaction::minRelayTxFee, which has units duffs-per-kilobyte.
        // If you'd pay more than 1/3 in fees to spend something, then we consider it dust.
        // A typical txout is 34 bytes big, and will need a CTxIn of at least 148 bytes to spend
        // i.e. total is 148 + 32 = 182 bytes. Default -minrelaytxfee is 10000 duffs per kB
        // and that means that fee per txout is 182 * 10000 / 1000 = 1820 duffs.
        // So dust is a txout less than 1820 *3 = 5460 duffs
        // with default -minrelaytxfee = minRelayTxFee = 10000 duffs per kB.
        size_t nSize = GetSerializeSize(SER_DISK,0)+148u;
        return (nValue < 3*minRelayTxFee.GetFee(nSize));
    }

    friend bool operator==(const CTxOut& a, const CTxOut& b)
    {
        return (a.nValue       == b.nValue &&
                a.scriptPubKey == b.scriptPubKey &&
                a.nRounds      == b.nRounds);
    }

    friend bool operator!=(const CTxOut& a, const CTxOut& b)
    {
        return !(a == b);
    }

    std::string ToString() const;
};

struct CMutableTransaction;

enum {
    TX_TYPE_FULL  =  0, //used for any normal transaction
    //transaction with no hidden amount (used for collateral transaction, rewarding transaction
    // (for masternode and staking node), and PoA mining rew)
    TX_TYPE_REVEAL_AMOUNT,
    TX_TYPE_REVEAL_SENDER,    //transaction with no ring signature (used for decollateral transaction + reward transaction
    TX_TYPE_REVEAL_BOTH         //this is a staking transaction that consumes a staking coin and rewards the staking node and masternode
};

/** The basic transaction that is broadcasted on the network and contained in
 * blocks.  A transaction can contain multiple inputs and outputs.
 */
class CTransaction
{
private:
    /** Memory only. */
    const uint256 hash;
    void UpdateHash() const;

public:
    static const int32_t CURRENT_VERSION=1;

    // The local variables are made const to prevent unintended modification
    // without updating the cached hash value. However, CTransaction is not
    // actually immutable; deserialization and assignment are implemented,
    // and bypass the constness. This is safe, as they update the entire
    // structure, including the hash.
    const int32_t nVersion;
    std::vector<CTxIn> vin;
    std::vector<CTxOut> vout;
    const uint32_t nLockTime;

    //For stealth transactions
    CKey txPrivM;    //only  in-memory
    char hasPaymentID;
    uint64_t paymentID;
    //const unsigned int nTime;
    uint32_t txType;

    std::vector<unsigned char> bulletproofs;

    CAmount nTxFee;

    uint256 c;
    std::vector<std::vector<uint256>> S;

    //additional key image for transaction fee
    CKeyImage ntxFeeKeyImage;

    /** Construct a CTransaction that qualifies as IsNull() */
    CTransaction();

    /** Convert a CMutableTransaction into a CTransaction. */
    CTransaction(const CMutableTransaction &tx);

    CTransaction& operator=(const CTransaction& tx);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(*const_cast<int32_t*>(&this->nVersion));
        nVersion = this->nVersion;
        READWRITE(*const_cast<std::vector<CTxIn>*>(&vin));
        READWRITE(*const_cast<std::vector<CTxOut>*>(&vout));
        READWRITE(*const_cast<uint32_t*>(&nLockTime));
        READWRITE(hasPaymentID);
        if (hasPaymentID != 0) {
            READWRITE(paymentID);
        }
        READWRITE(txType);
        READWRITE(bulletproofs);
        READWRITE(nTxFee);
        
        READWRITE(c);
        READWRITE(S);
        READWRITE(ntxFeeKeyImage);
        if (ser_action.ForRead())
            UpdateHash();
    }

    bool IsNull() const {
        return vin.empty() && vout.empty();
    }

    const uint256& GetHash() const {
        UpdateHash();
        return hash;
    }

    // Return sum of txouts.
    CAmount GetValueOut() const;

    // Compute priority, given priority of inputs and (optionally) tx size
    double ComputePriority(double dPriorityInputs, unsigned int nTxSize=0) const;

    // Compute modified tx size for priority calculation (optionally given tx size)
    unsigned int CalculateModifiedSize(unsigned int nTxSize=0) const;

    bool UsesUTXO(const COutPoint out);
    std::list<COutPoint> GetOutPoints() const;

    bool IsCoinBase() const
    {
        return (vin.size() == 1 && vin[0].prevout.IsNull());
    }

    bool IsCoinAudit() const
    {
        return (vin.size() == 1 && vin[0].prevout.IsNull());
    }

    bool IsCoinStake() const
    {
        // ppcoin: the coin stake transaction is marked with the first output empty
        return (vin.size() > 0 && (!vin[0].prevout.IsNull() && vin[0].decoys.empty()) && vout.size() >= 2 && vout[0].IsEmpty());
    }

    friend bool operator==(const CTransaction& a, const CTransaction& b)
    {
        return a.hash == b.hash;
    }

    friend bool operator!=(const CTransaction& a, const CTransaction& b)
    {
        return a.hash != b.hash;
    }
    std::string ToString() const;
};

/** A mutable version of CTransaction. */
struct CMutableTransaction
{
    int32_t nVersion;
    std::vector<CTxIn> vin;
    std::vector<CTxOut> vout;
    uint32_t nLockTime;
    //For stealth transactions
    CKey txPrivM;
    char hasPaymentID;
    uint64_t paymentID;
    uint32_t txType;
    std::vector<unsigned char> bulletproofs;

    CAmount nTxFee;
    uint256 c;
    std::vector<std::vector<uint256>> S;
    CKeyImage ntxFeeKeyImage;

    CMutableTransaction();
    CMutableTransaction(const CTransaction& tx);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(this->nVersion);
        nVersion = this->nVersion;
        READWRITE(vin);
        READWRITE(vout);
        READWRITE(nLockTime);
        READWRITE(hasPaymentID);
        if (hasPaymentID != 0) {
            READWRITE(paymentID);
        }
        READWRITE(txType);

        READWRITE(bulletproofs);

        READWRITE(nTxFee);
        READWRITE(c);
        READWRITE(S);
        READWRITE(ntxFeeKeyImage);
    }

    /** Compute the hash of this CMutableTransaction. This is computed on the
     * fly, as opposed to GetHash() in CTransaction, which uses a cached result.
     */
    uint256 GetHash() const;

    std::string ToString() const;
};

struct CTransactionSignature
{
	int32_t nVersion;
	std::vector<CTxIn> vin;
	std::vector<CTxOut> vout;
	uint32_t nLockTime;
	//For stealth transactions
	CKey txPrivM;
	char hasPaymentID;
	uint64_t paymentID;
	uint32_t txType;

	CAmount nTxFee;

	CTransactionSignature(const CTransaction& tx) {
		*const_cast<int*>(&nVersion) = tx.nVersion;
		*const_cast<std::vector<CTxIn>*>(&vin) = tx.vin;
		*const_cast<std::vector<CTxOut>*>(&vout) = tx.vout;
		*const_cast<unsigned int*>(&nLockTime) = tx.nLockTime;
		hasPaymentID = tx.hasPaymentID;
		*const_cast<uint64_t*>(&paymentID) = tx.paymentID;
		*const_cast<uint32_t*>(&txType) = tx.txType;
		nTxFee = tx.nTxFee;

		//set transaction output amounts as 0
		for (size_t i = 0; i < vout.size(); i++) {
			vout[i].nValue = 0;
		}
	}

	ADD_SERIALIZE_METHODS;

	template <typename Stream, typename Operation>
	inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
		READWRITE(this->nVersion);
		nVersion = this->nVersion;
		READWRITE(vin);
		READWRITE(vout);
		READWRITE(nLockTime);
		READWRITE(hasPaymentID);
		if (hasPaymentID != 0) {
			READWRITE(paymentID);
		}
		READWRITE(txType);

		READWRITE(nTxFee);
	}

	uint256 GetHash() {
		return SerializeHash(*this);
	}
};

class CTxInShortDigest
{
public:
    COutPoint prevout;
    CScript scriptSig;
    uint32_t nSequence;

    std::vector<unsigned char> encryptionKey;   //33bytes
    CKeyImage keyImage;   //have the same number element as vin
    std::vector<unsigned char> masternodeStealthAddress;

    CTxInShortDigest(const CTxIn& in)
    {
        prevout = in.prevout;
        scriptSig = in.scriptSig;
        nSequence = in.nSequence;
        encryptionKey = in.encryptionKey;
        keyImage = in.keyImage;
        masternodeStealthAddress = in.masternodeStealthAddress;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(prevout);
        READWRITE(scriptSig);
        READWRITE(nSequence);
        READWRITE(encryptionKey);
        READWRITE(keyImage);
        READWRITE(masternodeStealthAddress);
    }

    uint256 GetHash() {
    	return SerializeHash(*this);
    }
};

/** A partial version of CTransaction that contains additional information for multi sig transaction */
struct CPartialTransaction
{
    int32_t nVersion;
    std::vector<CTxIn> vin;
    std::vector<CTxOut> vout;
    uint32_t nLockTime;
    //For stealth transactions
    char hasPaymentID;
    uint64_t paymentID;
    uint32_t txType;
    std::vector<unsigned char> bulletproofs;

    CAmount nTxFee;
    uint256 c;
    std::vector<std::vector<uint256>> S;
    CKeyImage ntxFeeKeyImage;
    std::vector<unsigned char> receiver;

    //this marks the participants who already signs the transaction
    //If N/N case, this is the hashes of the private keys of participants
    //if N-1/N case, this is the hashes of the hash of the ECDHs between participants
    std::vector<uint256> hashesOfSignedSecrets;
    uint256 selectedUTXOHash;
    uint256 encodedC_PI;
    std::vector<std::vector<unsigned char>> blinds;

    CPartialTransaction() {};
    CPartialTransaction(const CTransaction& tx)
    {
    	*const_cast<int*>(&nVersion) = tx.nVersion;
    	*const_cast<std::vector<CTxIn>*>(&vin) = tx.vin;
    	*const_cast<std::vector<CTxOut>*>(&vout) = tx.vout;
    	*const_cast<unsigned int*>(&nLockTime) = tx.nLockTime;
    	*const_cast<char*>(&hasPaymentID) = tx.hasPaymentID;
    	*const_cast<uint64_t*>(&paymentID) = tx.paymentID;
    	*const_cast<uint32_t*>(&txType) = tx.txType;
    	bulletproofs = tx.bulletproofs;
    	c = tx.c;
    	S = tx.S;
    	//*const_cast<std::vector<CKeyImage>*>(&keyImages) = tx.keyImages;
    	//*const_cast<std::vector<std::vector<CTxIn>>*>(&decoys) = tx.decoys;
    	nTxFee = tx.nTxFee;
    	ntxFeeKeyImage = tx.ntxFeeKeyImage;
        for(int i = 0; i < tx.vout.size(); i++) {
            std::vector<unsigned char> blind;
            std::copy(tx.vout[i].maskValue.inMemoryRawBind.begin(), tx.vout[i].maskValue.inMemoryRawBind.end(), std::back_inserter(blind));
            blinds.push_back(blind);
        }
    }
    CTransaction ToTransaction() const {
    	CTransaction tx;
    	*const_cast<int*>(&tx.nVersion) = nVersion;
    	*const_cast<std::vector<CTxIn>*>(&tx.vin) = vin;
    	*const_cast<std::vector<CTxOut>*>(&tx.vout) = vout;
    	*const_cast<unsigned int*>(&tx.nLockTime) = nLockTime;
    	*const_cast<char*>(&tx.hasPaymentID) = hasPaymentID;
    	*const_cast<uint64_t*>(&tx.paymentID) = paymentID;
    	*const_cast<uint32_t*>(&tx.txType) = txType;
    	tx.bulletproofs = bulletproofs;
    	tx.c = c;
    	tx.S = S;
    	//*const_cast<std::vector<CKeyImage>*>(&keyImages) = tx.keyImages;
    	//*const_cast<std::vector<std::vector<CTxIn>>*>(&decoys) = tx.decoys;
    	tx.nTxFee = nTxFee;
    	tx.ntxFeeKeyImage = ntxFeeKeyImage;
    	return tx;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(this->nVersion);
        nVersion = this->nVersion;
        READWRITE(vin);
        READWRITE(vout);

        READWRITE(nLockTime);
        READWRITE(hasPaymentID);
        if (hasPaymentID != 0) {
            READWRITE(paymentID);
        }
        READWRITE(txType);

        READWRITE(bulletproofs);

        READWRITE(nTxFee);
        READWRITE(c);
        READWRITE(S);
        READWRITE(ntxFeeKeyImage);
        READWRITE(hashesOfSignedSecrets);
        READWRITE(selectedUTXOHash);
        READWRITE(encodedC_PI);
        READWRITE(blinds);
        READWRITE(receiver);
    }

    void copyFrom(const CPartialTransaction& ptx) {
    	//*const_cast<std::vector<CKeyImage>*>(&keyImages) = tx.keyImages;
    	//*const_cast<std::vector<std::vector<CTxIn>>*>(&decoys) = tx.decoys;
    	this->nVersion = ptx.nVersion;
    	*const_cast<std::vector<CTxIn>*>(&vin) = ptx.vin;
    	*const_cast<std::vector<CTxOut>*>(&vout) = ptx.vout;
    	this->nLockTime = ptx.nLockTime;
    	this->hasPaymentID = ptx.hasPaymentID;
    	this->paymentID = ptx.paymentID;
    	this->txType = ptx.txType;
    	this->bulletproofs = ptx.bulletproofs;
    	this->nTxFee = ptx.nTxFee;
    	this->c = ptx.c;
    	this->S = ptx.S;
    	this->ntxFeeKeyImage = ptx.ntxFeeKeyImage;
    	this->hashesOfSignedSecrets = ptx.hashesOfSignedSecrets;
    	this->selectedUTXOHash = ptx.selectedUTXOHash;
    	this->encodedC_PI = ptx.encodedC_PI;
    	this->blinds = ptx.blinds;
        this->receiver = ptx.receiver;
    }
};

#endif // BITCOIN_PRIMITIVES_TRANSACTION_H
