// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/block.h>

#include <hash.h>
#include "hashblock.h"
#include <tinyformat.h>
#include <util/strencodings.h>
#include <crypto/common.h>
#include <crypto/scrypt.h>

GLOBAL sph_skein512_context     z_skein;
uint256 CBlockHeader::GetHash() const
{
    return SerializeHash(*this);
}

uint256 CBlockHeader::GetPoWHash() const
{
        //printf("Our block: %s \n", ToString().c_str());
        //printf("Inside block header get PoWHash \n");
        //printf(" hi there %s \n", this->ToString().c_str());
        //printf("Performing pow hash on block of time %i \n", nTime);
        uint256 thash, thash2;
        //scrypt_1024_1_1_256(BEGIN(nVersion), BEGIN(thash));
        skein2hash(&thash2, BEGIN(nVersion));

        //thash = Hash2(BEGIN(nVersion), END(nNonce));
        //thash = Hash2(BEGIN(nVersion), END(nNonce));
        //printf("Thash Out Is: %s \n ",thash.ToString().c_str());
        //printf("Thash2 Out Is: %s \n ",thash2.ToString().c_str());
        return thash2;
}

std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, ver=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, vtx=%u)\n",
        GetHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nTime, nBits, nNonce,
        vtx.size());
    for (const auto& tx : vtx) {
        s << "  " << tx->ToString() << "\n";
    }
    return s.str();
}

CTransactionRef CBlock::GetHogEx() const noexcept
{
    if (vtx.size() >= 2 && vtx.back()->IsHogEx()) {
        assert(!vtx.back()->vout.empty());
        return vtx.back();
    }

    return nullptr;
}
