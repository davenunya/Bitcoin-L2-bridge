#pragma once

#include <array>
#include <vector>
#include <string>
#include <cstdint>

namespace bridge {

// 32-byte hash type
using Hash32 = std::array<uint8_t, 32>;

// A minimal FraudProof structure used by the verifier.
// Extend with real fields as needed by the project.
struct FraudProof {
    // identifier (e.g. txid or proof id)
    Hash32 id;

    // raw proof bytes
    std::vector<uint8_t> raw;

    // optional human-readable source or metadata
    std::string source;
};

// Reply/trace returned by the verifier when processing a proof.
struct TraceReply {
    bool ok = false;
    std::string message;
    std::vector<uint8_t> trace;
};

} // namespace bridge
