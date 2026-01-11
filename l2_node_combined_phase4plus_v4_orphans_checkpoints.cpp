// l2_node_combined_phase4plus_v4_orphans_checkpoints.cpp
// Continuation (Option C):
//   - Real fork storage (block DAG)
//   - Orphan pool (store unknown-parent blocks, connect later)
//   - Checkpoints + undo logs (UTXO undo + SMT undo via trace step reversal)
//
// This remains a harness: no real P2P transport. But "import block" is realistic.
//
// Build:
//   g++ -std=c++20 l2_node_combined_phase4plus_v4_orphans_checkpoints.cpp -O2 -pthread -lssl -lcrypto -o l2node

#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>

#include <array>
#include <atomic>
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <iostream>
#include <memory>
#include <optional>
#include <queue>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>
#include <map>
#include <mutex>
#include <stdexcept>

// ============================================================
// Bytes / Hashing
// ============================================================
using Bytes  = std::vector<uint8_t>;
using Hash32 = std::array<uint8_t, 32>;
using Hash20 = std::array<uint8_t, 20>;

static void append_u32_le(Bytes& b, uint32_t v) {
    b.push_back((uint8_t)(v));
    b.push_back((uint8_t)(v >> 8));
    b.push_back((uint8_t)(v >> 16));
    b.push_back((uint8_t)(v >> 24));
}
static void append_u64_le(Bytes& b, uint64_t v) {
    for (int i = 0; i < 8; i++) b.push_back((uint8_t)(v >> (8 * i)));
}
static void append_bytes(Bytes& b, const Bytes& x) { b.insert(b.end(), x.begin(), x.end()); }

static void append_varint(Bytes& out, uint64_t v) {
    if (v < 0xFD) out.push_back((uint8_t)v);
    else if (v <= 0xFFFF) {
        out.push_back(0xFD);
        out.push_back((uint8_t)(v));
        out.push_back((uint8_t)(v >> 8));
    } else if (v <= 0xFFFFFFFFULL) {
        out.push_back(0xFE);
        append_u32_le(out, (uint32_t)v);
    } else {
        out.push_back(0xFF);
        append_u64_le(out, v);
    }
}

static Hash32 sha256d(const Bytes& b) {
    uint8_t h1[32], h2[32];
    SHA256(b.data(), b.size(), h1);
    SHA256(h1, 32, h2);
    Hash32 out{};
    std::memcpy(out.data(), h2, 32);
    return out;
}
static Hash32 sha256_1(const Bytes& b) {
    uint8_t h[32];
    SHA256(b.data(), b.size(), h);
    Hash32 out{};
    std::memcpy(out.data(), h, 32);
    return out;
}
static Hash20 hash160(const Bytes& b) {
    uint8_t h1[32];
    SHA256(b.data(), b.size(), h1);
    uint8_t h2[20];
    RIPEMD160(h1, 32, h2);
    Hash20 out{};
    std::memcpy(out.data(), h2, 20);
    return out;
}

static bool hash32_eq(const Hash32& a, const Hash32& b) {
    return std::memcmp(a.data(), b.data(), 32) == 0;
}
static std::string hex_of(const Hash32& h) {
    static const char* d = "0123456789abcdef";
    std::string s; s.resize(64);
    for (int i = 0; i < 32; i++) {
        s[2*i+0] = d[(h[i] >> 4) & 0xF];
        s[2*i+1] = d[(h[i] >> 0) & 0xF];
    }
    return s;
}

// ============================================================
// Consensus parameters (Base A style)
// ============================================================
namespace consensus {
    constexpr size_t  MAX_TXS_PER_BLOCK  = 20'000;
    constexpr size_t  MAX_INPUTS         = 1000;
    constexpr size_t  MAX_OUTPUTS        = 2000;
    constexpr size_t  MAX_WIT_ITEM_BYTES = 10'000;

    // Fees (demo)
    constexpr uint64_t GOLD_FLOOR_BPS_TENTHS = 3; // 0.3 bps
    constexpr uint64_t TX_VALUE_BPS_TENTHS   = 2; // 0.2 bps
}

// Checkpoint every N blocks (demo-friendly)
static constexpr uint64_t CHECKPOINT_INTERVAL = 25;

// Demo PoW difficulty (leading hex zeros)
static constexpr uint64_t POW_DIFFICULTY_ZEROS = 3;

// ============================================================
// Core types: OutPoint / Tx
// ============================================================
struct OutPoint {
    Hash32   txid{};
    uint32_t vout{0};

    bool operator<(const OutPoint& o) const {
        int c = std::memcmp(txid.data(), o.txid.data(), 32);
        if (c != 0) return c < 0;
        return vout < o.vout;
    }
    bool operator==(const OutPoint& o) const {
        return (vout == o.vout) && (std::memcmp(txid.data(), o.txid.data(), 32) == 0);
    }
};

struct TxIn {
    OutPoint prevout{};
    uint32_t sequence{0xFFFFFFFF};
    Bytes witness_sig;    // DER(sig)+sighash
    Bytes witness_pubkey; // 33-byte compressed
};

struct TxOut {
    uint64_t value{0};
    Bytes script_pubkey; // allowed: P2WPKH or fee sink
};

struct Tx {
    int32_t version{2};
    std::vector<TxIn>  vin;
    std::vector<TxOut> vout;
    uint32_t locktime{0};
    Hash32 txid{};
};

struct FeeSnapshot {
    uint64_t gold_1oz_price_sats{0};
};

// ============================================================
// Fee logic
// ============================================================
static uint64_t round_mul_div_u64(uint64_t x, uint64_t num, uint64_t den) {
    __uint128_t v = (__uint128_t)x * num + den / 2;
    return (uint64_t)(v / den);
}
static uint64_t fee_from_bps_tenths(uint64_t base, uint64_t bps_tenths) {
    return round_mul_div_u64(base, bps_tenths, 100'000);
}
static uint64_t sum_transferred_ex_fee(const Tx& tx) {
    uint64_t s = 0;
    for (size_t i = 1; i < tx.vout.size(); i++) s += tx.vout[i].value;
    return s;
}
static uint64_t compute_fee(const Tx& tx, const std::optional<FeeSnapshot>& snap) {
    const uint64_t transferred = sum_transferred_ex_fee(tx);
    const uint64_t bps_fee = fee_from_bps_tenths(transferred, consensus::TX_VALUE_BPS_TENTHS);

    uint64_t gold_floor = 0;
    if (snap && snap->gold_1oz_price_sats > 0) {
        gold_floor = fee_from_bps_tenths(snap->gold_1oz_price_sats, consensus::GOLD_FLOOR_BPS_TENTHS);
    }
    return (gold_floor > bps_fee) ? gold_floor : bps_fee;
}

// ============================================================
// Scripts: P2WPKH + fee sink only
// ============================================================
static Bytes fee_sink_scriptpubkey() {
    Bytes spk;
    spk.push_back(0x00);
    spk.push_back(0x14);
    spk.insert(spk.end(), 20, 0x00);
    return spk;
}
static bool is_fee_sink_spk(const Bytes& spk) { return spk == fee_sink_scriptpubkey(); }

static bool is_p2wpkh_scriptpubkey(const Bytes& spk, Hash20& out_h160) {
    if (spk.size() != 22) return false;
    if (spk[0] != 0x00 || spk[1] != 0x14) return false;
    std::memcpy(out_h160.data(), spk.data() + 2, 20);
    return true;
}
static bool is_p2wpkh_spk(const Bytes& spk) {
    Hash20 h{};
    return is_p2wpkh_scriptpubkey(spk, h);
}
static Bytes p2wpkh_spk_from_h160(const Hash20& h160) {
    Bytes spk;
    spk.push_back(0x00);
    spk.push_back(0x14);
    spk.insert(spk.end(), h160.begin(), h160.end());
    return spk;
}

// ============================================================
// Persistent / COW UTXO Set (Treap)
// ============================================================
struct Coin {
    uint64_t value{0};
    Bytes script_pubkey;
};

struct Undo {
    OutPoint op{};
    bool had_prev{false};
    Coin prev{};
};

struct UTXONode {
    OutPoint key{};
    Coin val{};
    uint64_t prio{0};
    std::shared_ptr<const UTXONode> l;
    std::shared_ptr<const UTXONode> r;
};

class UTXOSet {
public:
    bool has(const OutPoint& op) const { return find(root_, op) != nullptr; }
    const Coin* get_ptr(const OutPoint& op) const { return find(root_, op); }

    bool apply_tx(const Tx& tx, std::vector<Undo>& undo, std::string& err) {
        // spend inputs
        for (const auto& in : tx.vin) {
            const Coin* c = find(root_, in.prevout);
            if (!c) { err = "missing_utxo"; return false; }
            undo.push_back({in.prevout, true, *c});
            root_ = erase(root_, in.prevout);
        }
        // create outputs
        for (uint32_t i = 0; i < (uint32_t)tx.vout.size(); i++) {
            OutPoint op{tx.txid, i};
            undo.push_back({op, false, {}});
            root_ = insert(root_, op, Coin{tx.vout[i].value, tx.vout[i].script_pubkey});
        }
        err.clear();
        return true;
    }

    void undo_from_log_reverse(const std::vector<Undo>& undo_log) {
        // Reverse application:
        // - For outputs created (had_prev=false), erase.
        // - For spent inputs (had_prev=true), restore previous.
        for (auto it = undo_log.rbegin(); it != undo_log.rend(); ++it) {
            const Undo& u = *it;
            if (!u.had_prev) {
                root_ = erase(root_, u.op);
            } else {
                root_ = insert(root_, u.op, u.prev);
            }
        }
    }

private:
    std::shared_ptr<const UTXONode> root_{nullptr};

    static uint64_t prio_from_key(const OutPoint& k) {
        Bytes b;
        b.insert(b.end(), k.txid.begin(), k.txid.end());
        append_u32_le(b, k.vout);
        Hash32 h = sha256d(b);
        uint64_t p = 0;
        for (int i = 0; i < 8; i++) p |= (uint64_t)h[i] << (8 * i);
        return p ? p : 1;
    }

    static std::shared_ptr<const UTXONode> mk(const OutPoint& k, const Coin& v, uint64_t p,
                                              std::shared_ptr<const UTXONode> l,
                                              std::shared_ptr<const UTXONode> r) {
        auto n = std::make_shared<UTXONode>();
        n->key = k; n->val = v; n->prio = p; n->l = std::move(l); n->r = std::move(r);
        return n;
    }

    static int cmp(const OutPoint& a, const OutPoint& b) {
        int c = std::memcmp(a.txid.data(), b.txid.data(), 32);
        if (c != 0) return c;
        if (a.vout < b.vout) return -1;
        if (a.vout > b.vout) return 1;
        return 0;
    }

    static void split(std::shared_ptr<const UTXONode> t, const OutPoint& key,
                      std::shared_ptr<const UTXONode>& a,
                      std::shared_ptr<const UTXONode>& b) {
        if (!t) { a = nullptr; b = nullptr; return; }
        if (cmp(t->key, key) < 0) {
            std::shared_ptr<const UTXONode> t2a, t2b;
            split(t->r, key, t2a, t2b);
            a = mk(t->key, t->val, t->prio, t->l, t2a);
            b = t2b;
        } else {
            std::shared_ptr<const UTXONode> t2a, t2b;
            split(t->l, key, t2a, t2b);
            a = t2a;
            b = mk(t->key, t->val, t->prio, t2b, t->r);
        }
    }

    static std::shared_ptr<const UTXONode> merge(std::shared_ptr<const UTXONode> a,
                                                 std::shared_ptr<const UTXONode> b) {
        if (!a) return b;
        if (!b) return a;
        if (a->prio > b->prio) {
            auto nr = merge(a->r, b);
            return mk(a->key, a->val, a->prio, a->l, nr);
        } else {
            auto nl = merge(a, b->l);
            return mk(b->key, b->val, b->prio, nl, b->r);
        }
    }

    static std::shared_ptr<const UTXONode> erase(std::shared_ptr<const UTXONode> t, const OutPoint& key) {
        if (!t) return nullptr;
        int c = cmp(key, t->key);
        if (c == 0) return merge(t->l, t->r);
        if (c < 0) return mk(t->key, t->val, t->prio, erase(t->l, key), t->r);
        return mk(t->key, t->val, t->prio, t->l, erase(t->r, key));
    }

    static std::shared_ptr<const UTXONode> insert(std::shared_ptr<const UTXONode> t,
                                                  const OutPoint& key, const Coin& val) {
        t = erase(t, key);
        auto item = mk(key, val, prio_from_key(key), nullptr, nullptr);
        std::shared_ptr<const UTXONode> a, b;
        split(t, key, a, b);
        return merge(merge(a, item), b);
    }

    static const Coin* find(std::shared_ptr<const UTXONode> t, const OutPoint& key) {
        while (t) {
            int c = cmp(key, t->key);
            if (c == 0) return &t->val;
            t = (c < 0) ? t->l : t->r;
        }
        return nullptr;
    }
};

// ============================================================
// TXID serialization (witness excluded, empty scriptSig)
// ============================================================
static void ser_outpoint(Bytes& out, const OutPoint& op) {
    out.insert(out.end(), op.txid.begin(), op.txid.end());
    append_u32_le(out, op.vout);
}
static void ser_tx_nw(Bytes& out, const Tx& tx) {
    append_u32_le(out, (uint32_t)tx.version);
    append_varint(out, tx.vin.size());
    for (const auto& in : tx.vin) {
        ser_outpoint(out, in.prevout);
        append_varint(out, 0);
        append_u32_le(out, in.sequence);
    }
    append_varint(out, tx.vout.size());
    for (const auto& o : tx.vout) {
        append_u64_le(out, o.value);
        append_varint(out, o.script_pubkey.size());
        append_bytes(out, o.script_pubkey);
    }
    append_u32_le(out, tx.locktime);
}
static Hash32 compute_txid(const Tx& tx) {
    Bytes b;
    ser_tx_nw(b, tx);
    return sha256d(b);
}

// ============================================================
// BIP143 P2WPKH SIGHASH_ALL helpers
// ============================================================
static Bytes scriptcode_p2wpkh(const Hash20& h160) {
    Bytes sc;
    sc.push_back(0x76); sc.push_back(0xA9); sc.push_back(0x14);
    sc.insert(sc.end(), h160.begin(), h160.end());
    sc.push_back(0x88); sc.push_back(0xAC);
    return sc;
}
static Hash32 hashPrevouts(const Tx& tx) {
    Bytes cat;
    for (const auto& in : tx.vin) ser_outpoint(cat, in.prevout);
    return sha256d(cat);
}
static Hash32 hashSequence(const Tx& tx) {
    Bytes cat;
    for (const auto& in : tx.vin) append_u32_le(cat, in.sequence);
    return sha256d(cat);
}
static Hash32 hashOutputs(const Tx& tx) {
    Bytes cat;
    for (const auto& o : tx.vout) {
        append_u64_le(cat, o.value);
        append_varint(cat, o.script_pubkey.size());
        append_bytes(cat, o.script_pubkey);
    }
    return sha256d(cat);
}
static Hash32 bip143_sighash_all_p2wpkh_prehashed(const Tx& tx, size_t in_index,
                                                 const Coin& prevcoin, const Hash20& pubkey_h160,
                                                 const Hash32& hp, const Hash32& hs, const Hash32& ho,
                                                 uint32_t sighash_type /*=1*/) {
    Bytes pre;
    append_u32_le(pre, (uint32_t)tx.version);
    pre.insert(pre.end(), hp.begin(), hp.end());
    pre.insert(pre.end(), hs.begin(), hs.end());
    ser_outpoint(pre, tx.vin[in_index].prevout);

    Bytes sc = scriptcode_p2wpkh(pubkey_h160);
    append_varint(pre, sc.size());
    append_bytes(pre, sc);

    append_u64_le(pre, prevcoin.value);
    append_u32_le(pre, tx.vin[in_index].sequence);
    pre.insert(pre.end(), ho.begin(), ho.end());
    append_u32_le(pre, tx.locktime);
    append_u32_le(pre, sighash_type);
    return sha256d(pre);
}

// ============================================================
// OpenSSL secp256k1 signing/verify (demo, low-S enforced)
// ============================================================
struct KeyPair {
    EC_KEY* key{nullptr};
    Bytes pubkey33;
    Hash20 pkh;

    ~KeyPair() { if (key) EC_KEY_free(key); key = nullptr; }
    KeyPair(const KeyPair&) = delete;
    KeyPair& operator=(const KeyPair&) = delete;
    KeyPair() = default;
    KeyPair(KeyPair&& o) noexcept : key(o.key), pubkey33(std::move(o.pubkey33)), pkh(o.pkh) { o.key = nullptr; }
};

static Bytes ec_pubkey_compressed(EC_KEY* key) {
    Bytes out(33);
    EC_KEY_set_conv_form(key, POINT_CONVERSION_COMPRESSED);
    int len = i2o_ECPublicKey(key, nullptr);
    if (len != 33) throw std::runtime_error("unexpected pubkey len");
    unsigned char* p = out.data();
    if (i2o_ECPublicKey(key, &p) != 33) throw std::runtime_error("i2o_ECPublicKey failed");
    return out;
}
static KeyPair generate_keypair() {
    KeyPair kp;
    kp.key = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!kp.key) throw std::runtime_error("EC_KEY_new_by_curve_name failed");
    if (EC_KEY_generate_key(kp.key) != 1) throw std::runtime_error("EC_KEY_generate_key failed");
    kp.pubkey33 = ec_pubkey_compressed(kp.key);
    kp.pkh = hash160(kp.pubkey33);
    return kp;
}

static bool ecdsa_sig_is_low_s(const ECDSA_SIG* sig) {
    const BIGNUM *r=nullptr, *s=nullptr;
    ECDSA_SIG_get0(sig, &r, &s);
    if (!s) return false;

    BIGNUM* n = BN_new();
    BIGNUM* half = BN_new();
    if (!n || !half) { if(n)BN_free(n); if(half)BN_free(half); return false; }
    BN_hex2bn(&n, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
    BN_rshift1(half, n);
    bool ok = (BN_cmp(s, half) <= 0);
    BN_free(n); BN_free(half);
    return ok;
}

static Bytes ecdsa_sign_der_sighashall_lowS(EC_KEY* key, const Hash32& msg32) {
    ECDSA_SIG* sig = ECDSA_do_sign(msg32.data(), 32, key);
    if (!sig) throw std::runtime_error("ECDSA_do_sign failed");

    if (!ecdsa_sig_is_low_s(sig)) {
        const BIGNUM *r=nullptr, *s=nullptr;
        ECDSA_SIG_get0(sig, &r, &s);

        BIGNUM* n = BN_new();
        BIGNUM* new_s = BN_new();
        if (!n || !new_s) throw std::runtime_error("BN alloc failed");
        BN_hex2bn(&n, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
        BN_sub(new_s, n, s);

        ECDSA_SIG* sig2 = ECDSA_SIG_new();
        if (!sig2) throw std::runtime_error("ECDSA_SIG_new failed");
        BIGNUM* rdup = BN_dup(r);
        if (!rdup) throw std::runtime_error("BN_dup failed");
        if (ECDSA_SIG_set0(sig2, rdup, new_s) != 1) throw std::runtime_error("ECDSA_SIG_set0 failed");

        ECDSA_SIG_free(sig);
        BN_free(n);
        sig = sig2;
    }

    int der_len = i2d_ECDSA_SIG(sig, nullptr);
    if (der_len <= 0) { ECDSA_SIG_free(sig); throw std::runtime_error("i2d_ECDSA_SIG len failed"); }

    Bytes der((size_t)der_len);
    unsigned char* p = der.data();
    if (i2d_ECDSA_SIG(sig, &p) != der_len) { ECDSA_SIG_free(sig); throw std::runtime_error("i2d_ECDSA_SIG write failed"); }

    ECDSA_SIG_free(sig);
    der.push_back(0x01);
    return der;
}

static bool parse_der_sig_drop_hashtype(const Bytes& sig_with_hashtype,
                                       Bytes& der_sig,
                                       uint8_t& sighash,
                                       std::string& err) {
    if (sig_with_hashtype.size() < 9) { err = "sig_too_short"; return false; }
    der_sig.assign(sig_with_hashtype.begin(), sig_with_hashtype.end() - 1);
    sighash = sig_with_hashtype.back();
    if (der_sig.size() > consensus::MAX_WIT_ITEM_BYTES) { err = "sig_too_large"; return false; }
    return true;
}

static bool verify_secp256k1_ecdsa_lows(const Bytes& pubkey_sec,
                                       const Bytes& der_sig,
                                       const Hash32& msg32,
                                       std::string& err) {
    err.clear();

    EC_KEY* key = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!key) { err = "ec_key_new_failed"; return false; }

    const unsigned char* p = pubkey_sec.data();
    if (!o2i_ECPublicKey(&key, &p, (long)pubkey_sec.size())) {
        EC_KEY_free(key);
        err = "bad_pubkey";
        return false;
    }

    const unsigned char* sp = der_sig.data();
    ECDSA_SIG* sig = d2i_ECDSA_SIG(nullptr, &sp, (long)der_sig.size());
    if (!sig) {
        EC_KEY_free(key);
        err = "bad_der_sig";
        return false;
    }

    if (!ecdsa_sig_is_low_s(sig)) {
        ECDSA_SIG_free(sig);
        EC_KEY_free(key);
        err = "high_s";
        return false;
    }

    int ok = ECDSA_do_verify(msg32.data(), 32, sig, key);
    ECDSA_SIG_free(sig);
    EC_KEY_free(key);

    if (ok != 1) { err = "ecdsa_verify_failed"; return false; }
    return true;
}

// ============================================================
// Parallel helper
// ============================================================
template <typename Fn>
static bool parallel_for(size_t n, Fn&& fn) {
    if (n == 0) return true;
    const unsigned hw = std::max(1u, std::thread::hardware_concurrency());
    const unsigned threads = (unsigned)std::min<size_t>(n, hw);

    std::atomic<bool> stop{false};
    std::vector<std::thread> ts;
    ts.reserve(threads);

    for (unsigned t = 0; t < threads; t++) {
        ts.emplace_back([&, t]() {
            for (size_t i = (size_t)t; i < n && !stop.load(std::memory_order_relaxed); i += threads) {
                if (!fn(i)) stop.store(true, std::memory_order_relaxed);
            }
        });
    }
    for (auto& th : ts) th.join();
    return !stop.load(std::memory_order_relaxed);
}

// ============================================================
// Value conservation helpers
// ============================================================
static bool add_u64_checked(uint64_t& acc, uint64_t x) {
    if (UINT64_MAX - acc < x) return false;
    acc += x;
    return true;
}
static bool sum_inputs_outputs(const Tx& tx, const UTXOSet& view,
                              uint64_t& in_sum, uint64_t& out_sum,
                              std::string& err) {
    in_sum = 0; out_sum = 0;
    for (const auto& in : tx.vin) {
        const Coin* c = view.get_ptr(in.prevout);
        if (!c) { err = "missing_utxo"; return false; }
        if (!add_u64_checked(in_sum, c->value)) { err = "input_sum_overflow"; return false; }
    }
    for (const auto& o : tx.vout) {
        if (!add_u64_checked(out_sum, o.value)) { err = "output_sum_overflow"; return false; }
    }
    err.clear();
    return true;
}

// ============================================================
// Sigcheck (BIP143 P2WPKH SIGHASH_ALL)
// ============================================================
static bool sigcheck_p2wpkh_sighashall_prehashed(const Tx& tx, size_t in_index,
                                                const UTXOSet& view, const Hash32& hp,
                                                const Hash32& hs, const Hash32& ho,
                                                std::string& err) {
    if (in_index >= tx.vin.size()) { err = "bad_in_index"; return false; }
    const auto& in = tx.vin[in_index];

    const Coin* prev = view.get_ptr(in.prevout);
    if (!prev) { err = "missing_utxo"; return false; }

    Hash20 prev_h160{};
    if (!is_p2wpkh_scriptpubkey(prev->script_pubkey, prev_h160)) {
        err = "prev_not_p2wpkh";
        return false;
    }

    if (in.witness_sig.empty() || in.witness_pubkey.empty()) { err = "missing_witness"; return false; }
    if (in.witness_sig.size() > consensus::MAX_WIT_ITEM_BYTES) { err = "sig_too_large"; return false; }
    if (in.witness_pubkey.size() > consensus::MAX_WIT_ITEM_BYTES) { err = "pubkey_too_large"; return false; }

    if (in.witness_pubkey.size() != 33 || (in.witness_pubkey[0] != 0x02 && in.witness_pubkey[0] != 0x03)) {
        err = "non_compressed_pubkey";
        return false;
    }

    Hash20 pk_h160 = hash160(in.witness_pubkey);
    if (pk_h160 != prev_h160) { err = "pubkey_hash_mismatch"; return false; }

    Bytes der;
    uint8_t sighash_byte = 0;
    if (!parse_der_sig_drop_hashtype(in.witness_sig, der, sighash_byte, err)) return false;
    if (sighash_byte != 0x01) { err = "unsupported_sighash"; return false; }

    const Hash32 digest = bip143_sighash_all_p2wpkh_prehashed(
        tx, in_index, *prev, pk_h160, hp, hs, ho, 1
    );

    return verify_secp256k1_ecdsa_lows(in.witness_pubkey, der, digest, err);
}

// ============================================================
// Base-A block/tx validation (fee sink + payout rules)
// ============================================================
static bool validate_normal_tx(const Tx& tx,
                              const UTXOSet& view,
                              const std::optional<FeeSnapshot>& snap,
                              bool parallel_sigs,
                              std::string& err) {
    if (tx.vin.empty()) { err = "empty_vin"; return false; }
    if (tx.vin.size() > consensus::MAX_INPUTS) { err = "too_many_inputs"; return false; }
    if (tx.vout.size() < 2) { err = "missing_transfer_output"; return false; }
    if (tx.vout.size() > consensus::MAX_OUTPUTS) { err = "too_many_outputs"; return false; }

    if (!is_fee_sink_spk(tx.vout[0].script_pubkey)) { err = "bad_fee_sink"; return false; }
    for (size_t i = 1; i < tx.vout.size(); i++) {
        if (!is_p2wpkh_spk(tx.vout[i].script_pubkey)) { err = "non_p2wpkh_output"; return false; }
    }

    // Duplicate inputs
    {
        std::vector<OutPoint> ops;
        ops.reserve(tx.vin.size());
        for (const auto& in : tx.vin) ops.push_back(in.prevout);
        std::sort(ops.begin(), ops.end());
        for (size_t i = 1; i < ops.size(); i++) {
            if (ops[i] == ops[i-1]) { err = "duplicate_input"; return false; }
        }
    }

    // Inputs exist; forbid spending fee sink in normal tx
    for (const auto& in : tx.vin) {
        const Coin* pc = view.get_ptr(in.prevout);
        if (!pc) { err = "missing_utxo"; return false; }
        if (is_fee_sink_spk(pc->script_pubkey)) { err = "spend_fee_sink_forbidden"; return false; }
    }

    // Value conservation
    uint64_t in_sum=0, out_sum=0;
    {
        std::string se;
        if (!sum_inputs_outputs(tx, view, in_sum, out_sum, se)) { err = se; return false; }
        if (in_sum < out_sum) { err = "insufficient_input_value"; return false; }
    }

    // Fee rule
    const uint64_t need_fee = compute_fee(tx, snap);
    if (tx.vout[0].value < need_fee) { err = "fee_too_low"; return false; }
    if (tx.vout[0].value > in_sum) { err = "fee_exceeds_inputs"; return false; }

    const Hash32 hp = hashPrevouts(tx);
    const Hash32 hs = hashSequence(tx);
    const Hash32 ho = hashOutputs(tx);

    if (!parallel_sigs) {
        for (size_t i = 0; i < tx.vin.size(); i++) {
            std::string e;
            if (!sigcheck_p2wpkh_sighashall_prehashed(tx, i, view, hp, hs, ho, e)) {
                err = "vin[" + std::to_string(i) + "]:" + (e.empty() ? "sigcheck_failed" : e);
                return false;
            }
        }
        err.clear();
        return true;
    }

    std::vector<std::string> errs(tx.vin.size());
    bool ok = parallel_for(tx.vin.size(), [&](size_t i)->bool {
        std::string e;
        if (!sigcheck_p2wpkh_sighashall_prehashed(tx, i, view, hp, hs, ho, e)) {
            errs[i] = e.empty() ? "sigcheck_failed" : e;
            return false;
        }
        return true;
    });

    if (!ok) {
        for (size_t i = 0; i < errs.size(); i++) {
            if (!errs[i].empty()) { err = "vin[" + std::to_string(i) + "]:" + errs[i]; return false; }
        }
        err = "sigcheck_failed";
        return false;
    }

    err.clear();
    return true;
}

struct Block {
    uint32_t height{0};
    Hash20 fee_recipient_pkh{};
    std::vector<Tx> txs;
};

struct Hash32Eq {
    bool operator()(const Hash32& a, const Hash32& b) const noexcept { return hash32_eq(a,b); }
};
struct Hash32Hasher {
    size_t operator()(const Hash32& h) const noexcept {
        if constexpr (sizeof(size_t) == 8) {
            uint64_t x=0,y=0;
            std::memcpy(&x, h.data(), 8);
            std::memcpy(&y, h.data()+8, 8);
            return (size_t)(x ^ (y * 0x9E3779B97F4A7C15ULL));
        } else {
            uint32_t x=0,y=0;
            std::memcpy(&x, h.data(), 4);
            std::memcpy(&y, h.data()+4, 4);
            return (size_t)(x ^ (y * 0x9E3779B9U));
        }
    }
};

static bool build_topo_levels(const Block& b,
                              std::vector<std::vector<size_t>>& levels,
                              std::vector<size_t>& level_of,
                              std::string& err) {
    const size_t n = b.txs.size();
    levels.clear();
    level_of.assign(n, (size_t)-1);
    err.clear();
    if (n == 0) return true;

    std::unordered_map<Hash32, size_t, Hash32Hasher, Hash32Eq> txid_to_index;
    txid_to_index.reserve(n * 2);

    for (size_t i = 0; i < n; i++) {
        const auto& txid = b.txs[i].txid;
        if (txid_to_index.find(txid) != txid_to_index.end()) {
            err = "duplicate_txid_in_block";
            return false;
        }
        txid_to_index.emplace(txid, i);
    }

    std::vector<std::vector<size_t>> adj(n);
    std::vector<size_t> indeg(n, 0);

    for (size_t i = 0; i < n; i++) {
        const auto& tx = b.txs[i];
        for (const auto& in : tx.vin) {
            auto it = txid_to_index.find(in.prevout.txid);
            if (it == txid_to_index.end()) continue;
            const size_t prod = it->second;
            adj[prod].push_back(i);
            indeg[i]++;
        }
    }

    std::queue<size_t> q;
    for (size_t i = 0; i < n; i++) if (indeg[i] == 0) q.push(i);

    size_t produced = 0;
    size_t lvl_idx = 0;

    while (!q.empty()) {
        const size_t level_sz = q.size();
        std::vector<size_t> lvl;
        lvl.reserve(level_sz);
        for (size_t k = 0; k < level_sz; k++) { size_t u = q.front(); q.pop(); lvl.push_back(u); }
        std::sort(lvl.begin(), lvl.end());

        for (size_t u : lvl) {
            level_of[u] = lvl_idx;
            produced++;
            for (size_t v : adj[u]) {
                if (indeg[v] == 0) { err = "bad_indegree_state"; return false; }
                indeg[v]--;
            }
        }
        for (size_t u : lvl) {
            for (size_t v : adj[u]) if (indeg[v] == 0) q.push(v);
        }

        levels.push_back(std::move(lvl));
        lvl_idx++;
    }

    if (produced != n) { err = "cyclic_dependency_in_block"; return false; }
    return true;
}

static bool level_has_double_spends(const Block& b,
                                    const std::vector<size_t>& level,
                                    std::string& err) {
    std::vector<OutPoint> spent;
    for (size_t idx : level) for (const auto& in : b.txs[idx].vin) spent.push_back(in.prevout);
    std::sort(spent.begin(), spent.end());
    for (size_t i = 1; i < spent.size(); i++) {
        if (spent[i] == spent[i-1]) { err = "double_spend_within_level"; return true; }
    }
    err.clear();
    return false;
}

static bool enforce_payout_is_last_level_only_tx(const std::vector<std::vector<size_t>>& levels,
                                                const std::vector<size_t>& level_of,
                                                size_t payout_index,
                                                std::string& err) {
    if (levels.empty()) { err = "no_levels"; return false; }
    const size_t last_level = levels.size() - 1;
    if (payout_index >= level_of.size() || level_of[payout_index] == (size_t)-1) { err = "payout_not_in_levels"; return false; }
    if (level_of[payout_index] != last_level) { err = "payout_not_in_last_level"; return false; }
    if (levels[last_level].size() != 1 || levels[last_level][0] != payout_index) { err = "payout_not_only_tx_in_last_level"; return false; }
    err.clear();
    return true;
}

static bool validate_payout_tx(const Block& b,
                              const Tx& payout,
                              const std::vector<OutPoint>& expected_fee_outpoints_sorted,
                              const UTXOSet& view,
                              std::string& err) {
    for (const auto& o : payout.vout) {
        if (!(is_p2wpkh_spk(o.script_pubkey) || is_fee_sink_spk(o.script_pubkey))) {
            err = "payout_bad_output_script";
            return false;
        }
    }

    std::vector<OutPoint> got;
    got.reserve(payout.vin.size());
    for (const auto& in : payout.vin) got.push_back(in.prevout);
    std::sort(got.begin(), got.end());
    if (got != expected_fee_outpoints_sorted) { err = "payout_inputs_mismatch"; return false; }

    uint64_t total_collected = 0;
    for (const auto& op : expected_fee_outpoints_sorted) {
        const Coin* c = view.get_ptr(op);
        if (!c) { err = "payout_missing_fee_utxo"; return false; }
        if (!is_fee_sink_spk(c->script_pubkey)) { err = "payout_spent_non_fee_sink"; return false; }
        if (!add_u64_checked(total_collected, c->value)) { err = "payout_sum_overflow"; return false; }
    }

    if (payout.vout.empty() || payout.vout.size() > 2) { err = "payout_bad_vout_count"; return false; }

    Bytes recip_spk = p2wpkh_spk_from_h160(b.fee_recipient_pkh);
    if (payout.vout[0].script_pubkey != recip_spk) { err = "payout_bad_recipient_spk"; return false; }
    if (payout.vout[0].value == 0) { err = "payout_zero_recipient"; return false; }
    if (payout.vout[0].value > total_collected) { err = "payout_overpay"; return false; }

    uint64_t out_sum = 0;
    for (const auto& o : payout.vout) if (!add_u64_checked(out_sum, o.value)) { err = "payout_out_overflow"; return false; }

    if (payout.vout.size() == 2) {
        if (!is_fee_sink_spk(payout.vout[1].script_pubkey)) { err = "payout_bad_rollover_spk"; return false; }
    }

    if (out_sum > total_collected) { err = "payout_overpay"; return false; }
    if (out_sum < total_collected) {
        if (payout.vout.size() != 2) { err = "payout_missing_rollover"; return false; }
        const uint64_t remainder = total_collected - payout.vout[0].value;
        if (payout.vout[1].value != remainder) { err = "payout_bad_rollover_value"; return false; }
    }
    err.clear();
    return true;
}

// ============================================================
// SMT (compact proofs) over outpoints -> coin hash
// ============================================================
static Hash32 smt_hash_node(const Hash32& L, const Hash32& R) {
    Bytes b;
    b.push_back('n'); b.push_back('|');
    b.insert(b.end(), L.begin(), L.end());
    b.push_back('|');
    b.insert(b.end(), R.begin(), R.end());
    return sha256_1(b);
}
static Hash32 smt_empty_leaf() {
    Bytes b; b.push_back('l'); b.push_back('|'); b.push_back('E'); b.push_back('M'); b.push_back('P'); b.push_back('T'); b.push_back('Y');
    return sha256_1(b);
}
static Hash32 hash_outpoint_key(const OutPoint& op) {
    Bytes b;
    b.insert(b.end(), op.txid.begin(), op.txid.end());
    append_u32_le(b, op.vout);
    return sha256_1(b);
}
static Hash32 hash_coin_value(const Coin& c) {
    Bytes b;
    b.push_back('c'); b.push_back('|');
    append_u64_le(b, c.value);
    b.push_back('|');
    append_varint(b, c.script_pubkey.size());
    append_bytes(b, c.script_pubkey);
    return sha256_1(b);
}
static Hash32 smt_leaf_present(const Hash32& key_h, const Hash32& coin_h) {
    Bytes b;
    b.push_back('l'); b.push_back('|');
    b.insert(b.end(), key_h.begin(), key_h.end());
    b.push_back('|');
    b.insert(b.end(), coin_h.begin(), coin_h.end());
    return sha256_1(b);
}
static int get_bit(const Hash32& h, int bit_index_0_255) {
    int byte_index = bit_index_0_255 / 8;
    int bit_in_byte = 7 - (bit_index_0_255 % 8);
    return (h[byte_index] >> bit_in_byte) & 1;
}

struct SMT {
    std::map<std::string, Hash32> nodes;
    std::array<Hash32, 257> default_hash{};

    SMT() {
        default_hash[256] = smt_empty_leaf();
        for (int d = 255; d >= 0; --d) default_hash[d] = smt_hash_node(default_hash[d+1], default_hash[d+1]);
        nodes["ROOT"] = default_hash[0];
    }

    Hash32 root() const {
        auto it = nodes.find("ROOT");
        return (it != nodes.end()) ? it->second : default_hash[0];
    }

    static std::string prefix_key(int depth, const Bytes& prefix_bits_packed) {
        static const char* d = "0123456789abcdef";
        std::string hex;
        hex.reserve(prefix_bits_packed.size() * 2);
        for (uint8_t x : prefix_bits_packed) {
            hex.push_back(d[(x >> 4) & 0xF]);
            hex.push_back(d[(x >> 0) & 0xF]);
        }
        return "d:" + std::to_string(depth) + ":" + hex;
    }

    static Bytes pack_prefix_bits(const Hash32& key_h, int depth_bits) {
        int bytes = (depth_bits + 7) / 8;
        Bytes out(bytes, 0);
        for (int i = 0; i < depth_bits; i++) {
            int bit = get_bit(key_h, i);
            int bi = i / 8;
            int bj = 7 - (i % 8);
            out[bi] |= (uint8_t)(bit << bj);
        }
        return out;
    }

    void set_subroot_by_prefix(int depth, const Bytes& pref_packed, const Hash32& h) {
        nodes[prefix_key(depth, pref_packed)] = h;
    }
    void set_root(const Hash32& r) { nodes["ROOT"] = r; }

    struct KeyProofCompact {
        OutPoint op{};
        bool present_before{false};
        Hash32 key_h{};
        Hash32 coin_h_before{};
        std::vector<std::pair<uint16_t, Hash32>> sib_nondefault; // (d, sibling_hash)

        Hash32 sibling_at(int d, const std::array<Hash32,257>& defaults) const {
            for (const auto& kv : sib_nondefault) if ((int)kv.first == d) return kv.second;
            return defaults[d+1];
        }
    };
