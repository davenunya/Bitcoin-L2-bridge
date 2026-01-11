// fraud_proof_verifier.cpp
// Helpers for fraud proof building and verification (UTXO-SMT)

#include <optional>
#include <string>
#include <vector>

// Note: This file assumes the repository defines the following types and functions elsewhere:
// - FraudProof, Hash32, Hash20, TraceEntry, TraceReply, BlockHeaderLite, MerklePathNode, Tx
// - verify_header_chain_pow_linkage, merkle_verify_leaf_hash32, hash32_from_hex,
// - recompute_post_root_from_trace_and_tx, IShardDataProvider

static bool verify_fraud_proof_utxo_smt(
    const FraudProof& fp,
    const std::array<Hash32,257>& smt_defaults,
    std::string& err
) {
    err.clear();

    // 1) verify header chain integrity
    if (!verify_header_chain_pow_linkage(fp.headers_to_tip)) {
        err = "bad_header_chain";
        return false; // malformed
    }

    // 2) disputed header is the first
    const auto& disputed_hdr = fp.headers_to_tip.front();

    // 3) verify trace inclusion in disputed block trace_root
    // Reconstruct leaf hash from TraceEntry
    Hash32 leaf = fp.entry.leaf_hash(smt_defaults);
    Hash32 expected_trace_root{};
    {
        // trace_root_hex in header -> Hash32
        // (You likely already have hex->Hash32 helper in your combined file; if not, add one.)
        expected_trace_root = hash32_from_hex(disputed_hdr.trace_root_hex);
    }
    if (!merkle_verify_leaf_hash32(leaf, fp.trace_leaf_path, expected_trace_root)) {
        err = "trace_inclusion_failed";
        return false; // malformed
    }

    // 4) Determine if disputed tx is payout (must be last tx in block)
    if (fp.block_txids_in_order.empty()) { err = "missing_block_txids"; return false; }
    if (fp.tx_index >= fp.block_txids_in_order.size()) { err = "tx_index_oob"; return false; }

    const bool is_payout = (fp.tx_index + 1 == fp.block_txids_in_order.size());

    // 5) Need the full tx to re-execute; trace entry must include tx
    // (In your kernel, TraceEntry currently stores txid + steps only.
    //  To verify consensus rules, FraudProof must include the tx itself.)
    // -> FIX: add Tx tx; into TraceEntry or store it in FraudProof alongside entry.
    //
    // For now assume FraudProof has fp.tx (add it).
    //
    // We'll enforce this as required:
    // if (fp.tx.vin empty etc) error.

    // 6) Recompute post root and compare: any mismatch => fraud proven
    Hash32 recomputed_post{};
    std::string re_err;

    const bool fraud = recompute_post_root_from_trace_and_tx(
        fp.tx, is_payout, fp.fee_recipient_pkh, fp.block_txids_in_order,
        fp.entry, smt_defaults, re_err, recomputed_post
    );

    if (!re_err.empty()) {
        err = "reexec_failed:" + re_err;
        return false; // malformed (can't verify)
    }

    if (fraud) {
        err.clear();
        return true; // FRAUD PROVEN
    }

    err = "no_fraud";
    return false;
}


static std::optional<FraudProof> remote_build_fraud_proof_utxo_smt(
    IShardDataProvider& prov,
    uint64_t shard_id,
    uint64_t disputed_height,
    uint64_t tx_index
) {
    // For now, build proof to current best tip height returned by headers request.
    // In (4) this becomes "anchored tip height".

    // naive: ask for headers [disputed..disputed] only (just the disputed header)
    // better: request some tip; but provider API doesn’t expose tip height here yet.
    // So we assume caller knows a tip height. If not, use disputed only.

    // Minimal version: just disputed header
    auto hdrs = prov.GetHeaders(shard_id, disputed_height, disputed_height);
    if (hdrs.empty()) return std::nullopt;

    auto tr = prov.GetTrace(shard_id, disputed_height, tx_index);
    if (!tr.ok) return std::nullopt;

    auto txids = prov.GetBlockTxids(shard_id, disputed_height);
    if (txids.empty()) return std::nullopt;

    FraudProof fp;
    fp.shard_id = shard_id;
    fp.disputed_height = disputed_height;
    fp.tx_index = tx_index;

    fp.headers_to_tip = hdrs;
    fp.entry = tr.entry;
    fp.trace_leaf_path = tr.path_to_trace_root;

    fp.block_txids_in_order = txids;

    // MUST include tx for consensus reexec:
    fp.tx = tr.tx; // ensure TraceReply carries tx (add it)

    // fee_recipient_pkh must be derivable (from payout vout[0])
    // easiest: provider also returns it; or infer from txids by fetching payout tx.
    // For now, ask provider to return it in TraceReply or in a separate method.
    fp.fee_recipient_pkh = tr.fee_recipient_pkh;

    return fp;
}


struct TraceReply {
    bool ok=false;
    std::string err;
    BlockHeaderLite header;

    TraceEntry entry;
    Tx tx;  // <-- add
    Hash20 fee_recipient_pkh; // <-- add (block-level)

    std::vector<MerklePathNode> path_to_trace_root;
};


// End of fraud_proof_verifier.cpp
