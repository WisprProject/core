// Copyright (c) 2012-2013 The PPCoin developers
// Copyright (c) 2015-2018 The PIVX developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/assign/list_of.hpp>
#include <boost/lexical_cast.hpp>

#include "db.h"
#include "kernel.h"
#include "script/interpreter.h"
#include "timedata.h"
#include "util.h"
#include "stakeinput.h"
#include "zwspchain.h"

using namespace std;

bool fTestNet = false; //Params().NetworkID() == CBaseChainParams::TESTNET;

// Modifier interval: time to elapse before new modifier is computed
// Set to 3-hour for production network and 20-minute for test network
int nStakeTargetSpacing = 64;
unsigned int getIntervalVersion(bool fTestNet)
{
    if (fTestNet)
        return MODIFIER_INTERVAL_TESTNET;
    else
        return MODIFIER_INTERVAL;
}

// Hard checkpoints of stake modifiers to ensure they are deterministic
static std::map<int, unsigned int> mapStakeModifierCheckpoints =
    boost::assign::map_list_of(0, 0xfd11f4e7u);

// Get time weight
int64_t GetWeight(int64_t nIntervalBeginning, int64_t nIntervalEnd)
{
    return nIntervalEnd - nIntervalBeginning - nStakeMinAge;
}

// Get the last stake modifier and its generation time from a given block
static bool GetLastStakeModifier(const CBlockIndex* pindex, uint64_t& nStakeModifier, int64_t& nModifierTime)
{
    if (!pindex)
        return error("GetLastStakeModifier: null pindex");
    while (pindex && pindex->pprev && !pindex->GeneratedStakeModifier())
        pindex = pindex->pprev;
    if (!pindex->GeneratedStakeModifier())
        return error("GetLastStakeModifier: no generation at genesis block");
    nStakeModifier = pindex->nStakeModifier;
    nModifierTime = pindex->GetBlockTime();
    return true;
}

// Get selection interval section (in seconds)
static int64_t GetStakeModifierSelectionIntervalSection(int nSection)
{
    assert(nSection >= 0 && nSection < 64);
    return (nModifierInterval * 63 / (63 + ((63 - nSection) * (MODIFIER_INTERVAL_RATIO - 1))));
}

// Get stake modifier selection interval (in seconds)
static int64_t GetStakeModifierSelectionInterval()
{
    int64_t nSelectionInterval = 0;
    for (int nSection = 0; nSection < 64; nSection++) {
        nSelectionInterval += GetStakeModifierSelectionIntervalSection(nSection);
    }
    return nSelectionInterval;
}

// select a block from the candidate blocks in vSortedByTimestamp, excluding
// already selected blocks in vSelectedBlocks, and with timestamp up to
// nSelectionIntervalStop.
static bool SelectBlockFromCandidates(
    vector<pair<int64_t, uint256> >& vSortedByTimestamp,
    map<uint256, const CBlockIndex*>& mapSelectedBlocks,
    int64_t nSelectionIntervalStop,
    uint64_t nStakeModifierPrev,
    const CBlockIndex** pindexSelected)
{
    bool fModifierV2 = false;
    bool fFirstRun = true;
    bool fSelected = false;
    uint256 hashBest = 0;
    *pindexSelected = (const CBlockIndex*)0;
    BOOST_FOREACH (const PAIRTYPE(int64_t, uint256) & item, vSortedByTimestamp) {
        if (!mapBlockIndex.count(item.second))
            return error("SelectBlockFromCandidates: failed to find block index for candidate block %s", item.second.ToString().c_str());

        const CBlockIndex* pindex = mapBlockIndex[item.second];
        if (fSelected && pindex->GetBlockTime() > nSelectionIntervalStop)
            break;

        //if the lowest block height (vSortedByTimestamp[0]) is >= switch height, use new modifier calc
        if (fFirstRun){
            fModifierV2 = pindex->nHeight >= Params().NEW_PROTOCOLS_STARTHEIGHT();
            fFirstRun = false;
        }

        if (mapSelectedBlocks.count(pindex->GetBlockHash()) > 0)
            continue;

        // compute the selection hash by hashing an input that is unique to that block
        uint256 hashProof;
        if(fModifierV2)
            hashProof = pindex->GetBlockHash();
        else
            hashProof = pindex->hashProofOfStake;

        CDataStream ss(SER_GETHASH, 0);
        ss << hashProof << nStakeModifierPrev;
        uint256 hashSelection = Hash(ss.begin(), ss.end());

        // the selection hash is divided by 2**32 so that proof-of-stake block
        // is always favored over proof-of-work block. this is to preserve
        // the energy efficiency property
        if (pindex->IsProofOfStake())
            hashSelection >>= 32;

        if (fSelected && hashSelection < hashBest) {
            hashBest = hashSelection;
            *pindexSelected = (const CBlockIndex*)pindex;
        } else if (!fSelected) {
            fSelected = true;
            hashBest = hashSelection;
            *pindexSelected = (const CBlockIndex*)pindex;
        }
    }
    if (GetBoolArg("-printstakemodifier", false))
        LogPrintf("SelectBlockFromCandidates: selection hash=%s\n", hashBest.ToString().c_str());
    return fSelected;
}

// Stake Modifier (hash modifier of proof-of-stake):
// The purpose of stake modifier is to prevent a txout (coin) owner from
// computing future proof-of-stake generated by this txout at the time
// of transaction confirmation. To meet kernel protocol, the txout
// must hash with a future stake modifier to generate the proof.
uint256 ComputeStakeModifier(const CBlockIndex *pindexPrev, const uint256 &kernel) {
    if (!pindexPrev)
        return 0;  // genesis block's modifier is 0
    LogPrintf("ComputeStakeModifier: kernel=%s, bnStakeModifierV2=%s\n", kernel.ToString().c_str(), pindexPrev->bnStakeModifierV2.ToString().c_str());
    CDataStream ss(SER_GETHASH, 0);
    ss << kernel << pindexPrev->bnStakeModifierV2;
    uint256 hash = Hash(ss.begin(), ss.end());
    LogPrintf("ComputeStakeModifier: hash=%s\n", hash.ToString().c_str());
    return hash;
}


// Stake Modifier (hash modifier of proof-of-stake):
// The purpose of stake modifier is to prevent a txout (coin) owner from
// computing future proof-of-stake generated by this txout at the time
// of transaction confirmation. To meet kernel protocol, the txout
// must hash with a future stake modifier to generate the proof.
// Stake modifier consists of bits each of which is contributed from a
// selected block of a given block group in the past.
// The selection of a block is based on a hash of the block's proof-hash and
// the previous stake modifier.
// Stake modifier is recomputed at a fixed time interval instead of every
// block. This is to make it difficult for an attacker to gain control of
// additional bits in the stake modifier, even after generating a chain of
// blocks.
bool ComputeNextStakeModifier(const CBlockIndex* pindexPrev, uint64_t& nStakeModifier, bool& fGeneratedStakeModifier)
{
    nStakeModifier = 0;
    fGeneratedStakeModifier = false;
    if (!pindexPrev)
    {
        fGeneratedStakeModifier = true;
        return true;  // genesis block's modifier is 0
    }
    if(pindexPrev->nHeight == 0){
        return true;
    }
    if (pindexPrev->nHeight == 1) {
        fGeneratedStakeModifier = true;
        nStakeModifier |= (((uint64_t) pindexPrev->GetStakeEntropyBit()) << 1);
        return true;
    }
    // First find current stake modifier and its generation block time
    // if it's not old enough, return the same stake modifier
    int64_t nModifierTime = 0;
    if (!GetLastStakeModifier(pindexPrev, nStakeModifier, nModifierTime))
        return error("ComputeNextStakeModifier: unable to get last modifier");
//    LogPrint("stakemodifier", "ComputeNextStakeModifier: prev modifier=0x%016x time=%s\n", nStakeModifier, DateTimeStrFormat(nModifierTime));
    if (nModifierTime / nModifierInterval >= pindexPrev->GetBlockTime() / nModifierInterval)
        return true;

    // Sort candidate blocks by timestamp
    vector<pair<int64_t, uint256> > vSortedByTimestamp;
    vSortedByTimestamp.reserve(64 * nModifierInterval / GetTargetSpacing());
    int64_t nSelectionInterval = GetStakeModifierSelectionInterval();
    int64_t nSelectionIntervalStart = (pindexPrev->GetBlockTime() / nModifierInterval) * nModifierInterval - nSelectionInterval;
    const CBlockIndex* pindex = pindexPrev;
    while (pindex && pindex->GetBlockTime() >= nSelectionIntervalStart)
    {
        vSortedByTimestamp.push_back(make_pair(pindex->GetBlockTime(), pindex->GetBlockHash()));
        pindex = pindex->pprev;
    }
    int nHeightFirstCandidate = pindex ? (pindex->nHeight + 1) : 0;
    reverse(vSortedByTimestamp.begin(), vSortedByTimestamp.end());
    sort(vSortedByTimestamp.begin(), vSortedByTimestamp.end());

    // Select 64 blocks from candidate blocks to generate stake modifier
    uint64_t nStakeModifierNew = 0;
    int64_t nSelectionIntervalStop = nSelectionIntervalStart;
    map<uint256, const CBlockIndex*> mapSelectedBlocks;
    for (int nRound=0; nRound<min(64, (int)vSortedByTimestamp.size()); nRound++)
    {
        // add an interval section to the current selection round
        nSelectionIntervalStop += GetStakeModifierSelectionIntervalSection(nRound);
        // select a block from the candidates of current round
        if (!SelectBlockFromCandidates(vSortedByTimestamp, mapSelectedBlocks, nSelectionIntervalStop, nStakeModifier, &pindex))
            return error("ComputeNextStakeModifier: unable to select block at round %d", nRound);
        // write the entropy bit of the selected block
        nStakeModifierNew |= (((uint64_t)pindex->GetStakeEntropyBit()) << nRound);
        // add the selected block from candidates to selected list
        mapSelectedBlocks.insert(make_pair(pindex->GetBlockHash(), pindex));
//        LogPrint("stakemodifier", "ComputeNextStakeModifier: selected round %d stop=%s height=%d bit=%d\n", nRound, DateTimeStrFormat(nSelectionIntervalStop), pindex->nHeight, pindex->GetStakeEntropyBit());
    }

    // Print selection map for visualization of the selected blocks
    if (LogAcceptCategory("stakemodifier"))
    {
        string strSelectionMap = "";
        // '-' indicates proof-of-work blocks not selected
        strSelectionMap.insert(0, pindexPrev->nHeight - nHeightFirstCandidate + 1, '-');
        pindex = pindexPrev;
        while (pindex && pindex->nHeight >= nHeightFirstCandidate)
        {
            // '=' indicates proof-of-stake blocks not selected
            if (pindex->IsProofOfStake())
                strSelectionMap.replace(pindex->nHeight - nHeightFirstCandidate, 1, "=");
            pindex = pindex->pprev;
        }
        BOOST_FOREACH(const PAIRTYPE(uint256, const CBlockIndex*)& item, mapSelectedBlocks)
        {
            // 'S' indicates selected proof-of-stake blocks
            // 'W' indicates selected proof-of-work blocks
            strSelectionMap.replace(item.second->nHeight - nHeightFirstCandidate, 1, item.second->IsProofOfStake()? "S" : "W");
        }
        LogPrintf("ComputeNextStakeModifier: selection height [%d, %d] map %s\n", nHeightFirstCandidate, pindexPrev->nHeight, strSelectionMap);
    }
//    LogPrint("stakemodifier", "ComputeNextStakeModifier: new modifier=0x%016x time=%s\n", nStakeModifierNew, DateTimeStrFormat(pindexPrev->GetBlockTime()));

    nStakeModifier = nStakeModifierNew;
    fGeneratedStakeModifier = true;
    return true;
}

// The stake modifier used to hash for a stake kernel is chosen as the stake
// modifier about a selection interval later than the coin generating the kernel
bool GetKernelStakeModifier(uint256 hashBlockFrom, uint64_t& nStakeModifier, int& nStakeModifierHeight, int64_t& nStakeModifierTime, bool fPrintProofOfStake)
{
    nStakeModifier = 0;
    if (!mapBlockIndex.count(hashBlockFrom))
        return error("GetKernelStakeModifier() : block not indexed");
    const CBlockIndex* pindexFrom = mapBlockIndex[hashBlockFrom];
    nStakeModifierHeight = pindexFrom->nHeight;
    nStakeModifierTime = pindexFrom->GetBlockTime();
    int64_t nStakeModifierSelectionInterval = GetStakeModifierSelectionInterval();
    const CBlockIndex* pindex = pindexFrom;
    CBlockIndex* pindexNext = chainActive[pindexFrom->nHeight + 1];

    // loop to find the stake modifier later by a selection interval
    while (nStakeModifierTime < pindexFrom->GetBlockTime() + nStakeModifierSelectionInterval && (pindexNext->nHeight + 1) < chainActive.Height()) {
        if (!pindexNext) {
            // Should never happen
            return error("Null pindexNext\n");
        }

        pindex = pindexNext;
        pindexNext = chainActive[pindexNext->nHeight + 1];
        if (pindex->GeneratedStakeModifier()) {
            nStakeModifierHeight = pindex->nHeight;
            nStakeModifierTime = pindex->GetBlockTime();
        }
    }
    nStakeModifier = pindex->nStakeModifier;
    return true;
}

//test hash vs target
bool stakeTargetHit(uint256 hashProofOfStake, int64_t nValueIn, uint256 bnTargetPerCoinDay)
{
    //get the stake weight - weight is equal to coin amount
    uint256 bnCoinDayWeight = uint256(nValueIn) / 100;

    // Now check if proof-of-stake hash meets target protocol
    return hashProofOfStake < (bnCoinDayWeight * bnTargetPerCoinDay);
}
bool stakeTargetHitOld(uint256 hashProofOfStake, uint256 bnTargetPerCoinDay) {
    if (hashProofOfStake > bnTargetPerCoinDay)
        return false;

    return true;
}
bool CheckStakeV2(const CDataStream& ssUniqueID, CAmount nValueIn, const uint64_t nStakeModifier, const uint256& bnTarget,
                unsigned int nTimeBlockFrom, unsigned int& nTimeTx, uint256& hashProofOfStake)
{
    CDataStream ss(SER_GETHASH, 0);
    ss << nStakeModifier << nTimeBlockFrom << ssUniqueID << nTimeTx;
    hashProofOfStake = Hash(ss.begin(), ss.end());
    //LogPrintf("%s: modifier:%d nTimeBlockFrom:%d nTimeTx:%d hash:%s\n", __func__, nStakeModifier, nTimeBlockFrom, nTimeTx, hashProofOfStake.GetHex());

    return stakeTargetHit(hashProofOfStake, nValueIn, bnTarget);
}
bool CheckStakeV1(unsigned int nTxPrevTime, const COutPoint &prevout,
                unsigned int nTimeTx, uint256 &hashProofOfStake, int64_t nValueIn, CBlockIndex *pindexPrev,
                  unsigned int nBits, bool fDebug = false) {

    string function = __func__;
    LogPrintf(
            "%s :nTimeTxPrev=%u"
            "nTimeTx=%u\n", function, nTxPrevTime, nTimeTx);

    if (nTimeTx < nTxPrevTime)  // Transaction timestamp violation
        return error("CheckStakeV1() : nTime violation");

    // Base target
    uint256 bnTarget;
    uint256 bnTargetOld;
    bnTarget.SetCompact(nBits);
    bnTargetOld.SetCompact(nBits);

    // Weighted target
    //int64_t nValueIn = txPrev.vout[prevout.n].nValue;
    uint256 bnWeight = uint256(nValueIn);
    bnTarget *= bnWeight;

//    uint256 targetProofOfStake = bnTarget;

    uint64_t nStakeModifier = pindexPrev->nStakeModifier;
    uint256 bnStakeModifierV2 = pindexPrev->bnStakeModifierV2;
    int nStakeModifierHeight = pindexPrev->nHeight;
    int64_t nStakeModifierTime = pindexPrev->nTime;

    // Calculate hash
    CDataStream ss(SER_GETHASH, 0);
    ss << bnStakeModifierV2;
    ss << nTxPrevTime << prevout.hash << prevout.n << nTimeTx;
    hashProofOfStake = Hash(ss.begin(), ss.end());

    if(fDebug) {
        LogPrintf("%s : Checking block at height=%ds\n",
                  function, (nStakeModifierHeight + 1));
        LogPrintf(
                "%s : height=%ds, using modifier %016x, bnStakeModifierV2 %s\n nTimeTxPrev=%u nPrevout=%u "
                "nTimeTx=%u, nBits = %08x, modifier checksum %016x, prevoutHash=%s \n hashProofOfStake=%s\n", function,
                nStakeModifierHeight, nStakeModifier,
                bnStakeModifierV2.ToString(), nTxPrevTime,
                prevout.n, nTimeTx, nBits, pindexPrev->nStakeModifierChecksum, prevout.hash.ToString(),
                hashProofOfStake.ToString());
        LogPrintf(
                "%s :  bnTarget=%s \n bnCoinDayWeight=%s \n bnTarget * bnCoinDayWeight=%s \n",
                function,
                bnTargetOld.ToString(), bnWeight.ToString(),
                bnTarget.ToString());
    }

    return stakeTargetHitOld(hashProofOfStake, bnTarget);
}
bool Stake(CStakeInput* stakeInput, unsigned int nBits, unsigned int nTimeBlockFrom, unsigned int& nTimeTx, uint256& hashProofOfStake)
{
    if (nTimeTx < nTimeBlockFrom)
        return error("Stake() : nTime violation");

    if (nTimeBlockFrom + nStakeMinAge > nTimeTx) // Min age requirement
        return error("Stake() : min age violation - nTimeBlockFrom=%d nStakeMinAge=%d nTimeTx=%d",
                     nTimeBlockFrom, nStakeMinAge, nTimeTx);

    //grab difficulty
    uint256 bnTargetPerCoinDay;
    bnTargetPerCoinDay.SetCompact(nBits);
//    const CTxIn &txin = txNew.vin[0];



    bool fSuccess = false;
    unsigned int nTryTime = 0;
    int nHeightStart = chainActive.Height();
    unsigned int nHashDrift = 30;
    CDataStream ssUniqueID = stakeInput->GetUniqueness();
    LogPrintf("Stake(): Checking for stake\n");
    CBlockIndex *pindex = stakeInput->GetIndexFrom();
    LogPrintf("Stake(): stake input height %ds\n", pindex->nHeight);
    CBlock block;
    ReadBlockFromDisk(block, pindex);
//    const CTxIn &txin = block.vtx[1].vin[0];
    uint256 hashBlock;
    CTransaction txPrev;
    stakeInput->GetTxFrom(txPrev);
    const CTxIn &txin = txPrev.vin[0];
    // Locate the transaction
    int nIndex;
    for (nIndex = 0; nIndex < (int)block.vtx.size(); nIndex++) {
        if (block.vtx[nIndex] == txPrev) {
            break;
        }
    }
    COutPoint prev;
    prev.n = nIndex == 2 ? 0 : nIndex;
    prev.hash = txPrev.GetHash();
    CAmount nValueIn = stakeInput->GetValue();
    LogPrintf(
            "%s : nPrevout=%u "
            "nTimeTx=%u prevoutHash=%s \n", __func__,
             txin.prevout.n, nTimeTx, txin.prevout.hash.ToString());
    nTryTime &= ~STAKE_TIMESTAMP_MASK;
    for (unsigned int i = 0; i < nHashDrift; i++) //iterate the hashing
    {
        //new block came in, move on
        if (chainActive.Height() != nHeightStart)
            break;

        //hash this iteration
        if (stakeInput->GetIndexFrom()->nHeight > Params().NEW_PROTOCOLS_STARTHEIGHT()) {
            //grab stake modifier
            uint64_t nStakeModifier = 0;
            if (!stakeInput->GetModifier(nStakeModifier))
                return error("failed to get kernel stake modifier");
            nTryTime = nTimeTx + nHashDrift - i;
            // if stake hash does not meet the target then continue to next iteration
             if (!CheckStakeV2(ssUniqueID, nValueIn, nStakeModifier, bnTargetPerCoinDay, nTimeBlockFrom, nTryTime, hashProofOfStake))
                continue;
        } else {
            nTryTime = nTimeTx + nHashDrift - i;
            if (!CheckStakeV1(txPrev.nTime, prev, nTryTime, hashProofOfStake, nValueIn, chainActive.Tip(),
                              nBits, true)) {
//                LogPrintf("%s: No stake found proof of hash hashproof=%s\n", __func__, hashProofOfStake.ToString());
                continue;
            }
        }

        fSuccess = true; // if we make it this far then we have successfully created a stake hash
        LogPrintf("%s: hashproof=%s\n", __func__, hashProofOfStake.GetHex());
        nTimeTx = nTryTime;
        break;
    }

    mapHashedBlocks.clear();
    mapHashedBlocks[chainActive.Tip()->nHeight] = GetTime(); //store a time stamp of when we last hashed on this block
    return fSuccess;
}

// Check kernel hash target and coinstake signature
bool CheckProofOfStake(const CBlock block, uint256& hashProofOfStake, std::unique_ptr<CStakeInput>& stake)
{
    const CTransaction tx = block.vtx[1];
    if (!tx.IsCoinStake())
        return error("CheckProofOfStake() : called on non-coinstake %s", tx.GetHash().ToString().c_str());

    // Kernel (input 0) must match the stake hash target per coin age (nBits)
    const CTxIn& txin = tx.vin[0];

    //Construct the stakeinput object
    CTransaction txPrev;

    if (tx.IsZerocoinSpend()) {
        libzerocoin::CoinSpend spend = TxInToZerocoinSpend(txin);
        if (spend.getSpendType() != libzerocoin::SpendType::STAKE)
            return error("%s: spend is using the wrong SpendType (%d)", __func__, (int)spend.getSpendType());

        stake = std::unique_ptr<CStakeInput>(new CZWspStake(spend));
    } else {
        // First try finding the previous transaction in database
        uint256 hashBlock;
        if (!GetTransaction(txin.prevout.hash, txPrev, hashBlock, true))
            return error("CheckProofOfStake() : INFO: read txPrev failed");

        //verify signature and script
        if (!VerifyScript(txin.scriptSig, txPrev.vout[txin.prevout.n].scriptPubKey, SCRIPT_VERIFY_NONE, TransactionSignatureChecker(&tx, 0)))
            return error("CheckProofOfStake() : VerifySignature failed on coinstake %s", tx.GetHash().ToString().c_str());

        CWspStake* wspInput = new CWspStake();
        wspInput->SetInput(txPrev, txin.prevout.n);
        stake = std::unique_ptr<CStakeInput>(wspInput);
    }

    CBlockIndex* pindex = stake->GetIndexFrom();
    if (!pindex)
        return error("%s: Failed to find the block index", __func__);

    // Read block header
    CBlock blockprev;
    if (!ReadBlockFromDisk(blockprev, pindex->GetBlockPos()))
        return error("CheckProofOfStake(): INFO: failed to find block");

    uint256 bnTargetPerCoinDay;
    bnTargetPerCoinDay.SetCompact(block.nBits);

    uint64_t nStakeModifier = 0;

    int64_t nValueIn = txPrev.vout[txin.prevout.n].nValue;
    LogPrintf("Stake(): stake input height %d\n", pindex->nHeight);
    LogPrintf("Stake(): stake blockFromTime %u\n", blockprev.nTime);
    LogPrintf("Stake(): stake TxTime %u\n", block.nTime);
//    uint256 hsp = uint256("02a441aace4b4291dbaf78b7e49f5ecc2fe336328df09921f1f3d65cca7dc93d");
//    uint256 weight =  uint256("0b5e56b0e5f0b800000000000000000000000000000000000000000000000000");
//    if(hsp > weight){
//        LogPrintf("Larger then is true not false\n");
//    }
    unsigned int nBlockFromTime = blockprev.nTime;
    unsigned int nTxTime = block.nTime;
    if (pindex->nHeight > Params().NEW_PROTOCOLS_STARTHEIGHT()) {
        if (!stake->GetModifier(nStakeModifier))
            return error("%s failed to get modifier for stake input\n", __func__);
        if(!CheckStakeV2(stake->GetUniqueness(), stake->GetValue(), nStakeModifier, bnTargetPerCoinDay, nBlockFromTime,
                         nTxTime, hashProofOfStake)){
            return error("CheckProofOfStake() : INFO: check kernel failed on coinstake %s, hashProof=%s \n",
                         tx.GetHash().ToString(), hashProofOfStake.ToString());
        }

    } else {
//        uint256 bnTargetPerC = bnTargetPerCoinDay.GetCompact();
        if (!CheckStakeV1(txPrev.nTime, txin.prevout, tx.nTime, hashProofOfStake, nValueIn, chainActive.Tip(), block.nBits, true)) {
            DeleteTip();
            LogPrintf("Stake(): Delete Tip\n");
            return error("CheckProofOfStake() : INFO: old bnStakeModifierV2 check kernel failed on coinstake %s, hashProof=%s \n",
                  tx.GetHash().ToString(), hashProofOfStake.ToString());
        }
    }
    return true;
}

// Check whether the coinstake timestamp meets protocol
bool CheckCoinStakeTimestamp(int64_t nTimeBlock, int64_t nTimeTx)
{
    // v0.3 protocol
    return (nTimeBlock == nTimeTx) && ((nTimeTx & STAKE_TIMESTAMP_MASK) == 0);
}

// Get stake modifier checksum
unsigned int GetStakeModifierChecksum(const CBlockIndex* pindex)
{
    assert(pindex->pprev || pindex->GetBlockHash() == Params().HashGenesisBlock());
    // Hash previous checksum with flags, hashProofOfStake and nStakeModifier
    CDataStream ss(SER_GETHASH, 0);
    if (pindex->pprev)
        ss << pindex->pprev->nStakeModifierChecksum;
    ss << pindex->nFlags << pindex->hashProofOfStake << pindex->nStakeModifier;
    uint256 hashChecksum = Hash(ss.begin(), ss.end());
    hashChecksum >>= (256 - 32);
    return hashChecksum.Get64();
}

// Check stake modifier hard checkpoints
bool CheckStakeModifierCheckpoints(int nHeight, unsigned int nStakeModifierChecksum)
{
    if (fTestNet) return true; // Testnet has no checkpoints
    if (mapStakeModifierCheckpoints.count(nHeight)) {
        return nStakeModifierChecksum == mapStakeModifierCheckpoints[nHeight];
    }
    return true;
}
void DeleteTip()
{
    CValidationState state;
    {
        LOCK(cs_main);
        DisconnectBlocksAndReprocess(1);
    }
}