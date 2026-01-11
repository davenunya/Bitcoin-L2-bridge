#include "fraud_proof.hpp"

#include <string>
#include <cctype>
#include <cstdint>

using namespace bridge;

// Small helper: convert a hex character to its 4-bit nibble value.
static bool hexCharToNibble(char c, uint8_t &out) {
    if (c >= '0' && c <= '9') { out = static_cast<uint8_t>(c - '0'); return true; }
    if (c >= 'a' && c <= 'f') { out = static_cast<uint8_t>(10 + (c - 'a')); return true; }
    if (c >= 'A' && c <= 'F') { out = static_cast<uint8_t>(10 + (c - 'A')); return true; }
    return false;
}

// Parse a 64-char hex string into a 32-byte Hash32.
// Returns true on success, false for invalid length or non-hex input.
bool parseHexToHash32(const std::string &hex, Hash32 &out) {
    if (hex.size() != 64) return false;
    for (size_t i = 0; i < 32; ++i) {
        uint8_t hi, lo;
        if (!hexCharToNibble(hex[2*i], hi)) return false;
        if (!hexCharToNibble(hex[2*i + 1], lo)) return false;
        out[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return true;
}

// Example verifier stub that uses FraudProof and TraceReply.
// Replace with real verification logic as needed.
TraceReply verifyFraudProof(const FraudProof &proof) {
    TraceReply reply;

    // Basic sanity: ensure id is not all zeros.
    bool all_zero = true;
    for (auto b : proof.id) {
        if (b != 0) { all_zero = false; break; }
    }

    if (all_zero) {
        reply.ok = false;
        reply.message = "Invalid proof id (all zeros)";
        return reply;
    }

    // TODO: add real fraud verification logic here.
    reply.ok = true;
    reply.message = "Proof processed (stub)";
    reply.trace = proof.raw;
    return reply;
}
