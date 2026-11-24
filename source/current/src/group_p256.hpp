// Included inside namespace otac by core.hpp.
#pragma once

namespace p256 {
using PointPtr = std::unique_ptr<EC_POINT, decltype(&EC_POINT_free)>;
using Number = std::unique_ptr<BIGNUM, decltype(&BN_free)>;
inline std::unique_ptr<EC_GROUP, decltype(&EC_GROUP_free)> group{nullptr, EC_GROUP_free};

inline BN_CTX* context() {
    static thread_local std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)> value{BN_CTX_new(), BN_CTX_free};
    require(bool(value), "BN context");
    return value.get();
}

inline PointPtr point() {
    PointPtr p{EC_POINT_new(group.get()), EC_POINT_free};
    require(bool(p), "EC point");
    return p;
}

inline void add(PointPtr& out, const PointPtr& a, const PointPtr& b) {
    require(EC_POINT_add(group.get(), out.get(), a.get(), b.get(), context()) == 1, "EC add");
}

inline void twice(PointPtr& out, const PointPtr& a) {
    require(EC_POINT_dbl(group.get(), out.get(), a.get(), context()) == 1, "EC double");
}

inline std::array<unsigned char, 32> sha256(const std::string& input) {
    std::array<unsigned char, 32> digest{};
    require(SHA256(reinterpret_cast<const unsigned char*>(input.data()), input.size(), digest.data()) != nullptr,
            "SHA-256");
    return digest;
}

// RFC 9380 §5.3.1, specialized to SHA-256, two 48-byte field elements and a short DST.
inline std::array<unsigned char, 96> expand(const std::string& input, const std::string& dst) {
    require(!dst.empty() && dst.size() <= 255, "hash-to-curve domain length");
    const std::string domain = dst + char(dst.size());
    const auto b0 = sha256(std::string(64, '\0') + input + std::string("\0\x60\0", 3) + domain);
    auto previous = sha256(std::string(reinterpret_cast<const char*>(b0.data()), b0.size()) + '\1' + domain);
    std::array<unsigned char, 96> output{};
    std::copy(previous.begin(), previous.end(), output.begin());
    for (unsigned block = 2; block <= 3; ++block) {
        std::string mixed(b0.size(), '\0');
        for (size_t i = 0; i < b0.size(); ++i) mixed[i] = char(b0[i] ^ previous[i]);
        previous = sha256(mixed + char(block) + domain);
        std::copy(previous.begin(), previous.end(), output.begin() + (block - 1) * previous.size());
    }
    return output;
}

// RFC 9380 §6.6.2 and §8.2. Inputs here are public generator labels.
inline PointPtr map_public(const unsigned char* bytes) {
    struct Scratch {
        BN_CTX* ctx = context();
        Scratch() { BN_CTX_start(ctx); }
        ~Scratch() { BN_CTX_end(ctx); }
        BIGNUM* next() {
            BIGNUM* value = BN_CTX_get(ctx);
            require(value != nullptr, "BN scratch");
            return value;
        }
    } scratch;
    auto* ctx = scratch.ctx;
    auto* p = scratch.next();
    auto* a = scratch.next();
    auto* b = scratch.next();
    auto* u = scratch.next();
    auto* z = scratch.next();
    auto* zu2 = scratch.next();
    auto* denominator = scratch.next();
    auto* factor = scratch.next();
    auto* x = scratch.next();
    auto* rhs = scratch.next();
    auto* y = scratch.next();
    auto* exponent = scratch.next();
    auto* check = scratch.next();
    require(EC_GROUP_get_curve(group.get(), p, a, b, ctx) == 1, "P-256 equation");
    require(BN_bin2bn(bytes, 48, u) && BN_nnmod(u, u, p, ctx), "hash-to-field");
    require(BN_copy(z, p) && BN_sub_word(z, 10), "SWU Z");
    require(BN_mod_sqr(zu2, u, p, ctx) && BN_mod_mul(zu2, zu2, z, p, ctx) &&
            BN_mod_sqr(denominator, zu2, p, ctx) && BN_mod_add(denominator, denominator, zu2, p, ctx),
            "SWU denominator");
    if (BN_is_zero(denominator)) {
        require(BN_mod_mul(factor, z, a, p, ctx) &&
                BN_mod_inverse(factor, factor, p, ctx) && BN_mod_mul(x, b, factor, p, ctx), "SWU exception");
    } else {
        require(BN_mod_inverse(factor, denominator, p, ctx) && BN_add_word(factor, 1) &&
                BN_mod_inverse(x, a, p, ctx) && BN_mod_mul(x, x, b, p, ctx) &&
                BN_mod_mul(x, x, factor, p, ctx) && BN_sub(x, p, x), "SWU x1");
    }
    // p = 3 mod 4, so (p+1)/4 gives a square-root candidate.
    require(BN_copy(exponent, p) && BN_add_word(exponent, 1) && BN_rshift(exponent, exponent, 2), "SWU exponent");
    auto root = [&] {
        require(BN_mod_sqr(rhs, x, p, ctx) && BN_mod_add(rhs, rhs, a, p, ctx) &&
                BN_mod_mul(rhs, rhs, x, p, ctx) && BN_mod_add(rhs, rhs, b, p, ctx) &&
                BN_mod_exp(y, rhs, exponent, p, ctx) && BN_mod_sqr(check, y, p, ctx), "SWU square root");
        return BN_cmp(check, rhs) == 0;
    };
    if (!root()) {
        require(BN_mod_mul(x, x, zu2, p, ctx) && root(), "SWU x2");
    }
    if (BN_is_odd(y) != BN_is_odd(u)) require(BN_sub(y, p, y), "SWU sign");
    auto mapped = point();
    require(EC_POINT_set_affine_coordinates(group.get(), mapped.get(), x, y, ctx) == 1, "SWU point");
    return mapped;
}

inline PointPtr hash(const std::string& input, const std::string& dst) {
    const auto expanded = expand(input, dst);
    auto out = map_public(expanded.data());
    const auto second = map_public(expanded.data() + 48);
    add(out, out, second);
    return out; // P-256 has cofactor one.
}
} // namespace p256

struct G {
    static constexpr size_t encoded_size = 33;
    p256::PointPtr v = p256::point();

    G() = default;
    G(const G& other) : v(EC_POINT_dup(other.v.get(), p256::group.get()), EC_POINT_free) {
        require(bool(v), "EC point copy");
    }
    G(G&&) noexcept = default;
    G& operator=(const G& other) {
        if (!v) v = p256::point();
        require(EC_POINT_copy(v.get(), other.v.get()) == 1, "EC point copy");
        return *this;
    }
    G& operator=(G&&) noexcept = default;
    bool operator==(const G& other) const {
        const int result = EC_POINT_cmp(p256::group.get(), v.get(), other.v.get(), p256::context());
        require(result >= 0, "EC point comparison");
        return result == 0;
    }
    bool operator!=(const G& other) const { return !(*this == other); }
    bool identity() const { return EC_POINT_is_at_infinity(p256::group.get(), v.get()) == 1; }
    void reset() { require(EC_POINT_set_to_infinity(p256::group.get(), v.get()) == 1, "EC identity"); }
    void mul_in(const G& other) { p256::add(v, v, other.v); }
    void square() { p256::twice(v, v); }
    void prepare() {} // Arbitrary bases use OpenSSL scalar multiplication.

    std::string bytes() const {
        std::string encoded(encoded_size, '\0'); // Keep infinity fixed-width in protocol frames.
        if (identity()) return encoded;
        require(EC_POINT_point2oct(p256::group.get(), v.get(), POINT_CONVERSION_COMPRESSED,
                    reinterpret_cast<unsigned char*>(encoded.data()), encoded.size(),
                    p256::context()) == encoded.size(), "P-256 encode");
        return encoded;
    }

    static G from_bytes(const std::string& encoded) {
        require(encoded.size() == encoded_size, "bad group length");
        G point;
        if (encoded.front() == 0) {
            require(encoded == std::string(encoded_size, '\0'), "noncanonical identity");
            return point;
        }
        require(encoded.front() == 2 || encoded.front() == 3, "bad compressed point tag");
        const int decoded = EC_POINT_oct2point(p256::group.get(), point.v.get(),
                              reinterpret_cast<const unsigned char*>(encoded.data()),
                              encoded.size(), p256::context());
        if (decoded != 1) ERR_clear_error();
        require(decoded == 1 && !point.identity() && point.bytes() == encoded, "invalid P-256 point");
        return point; // A finite point on P-256 belongs to the prime-order group.
    }

    static G hash(const std::string& label) {
        G out;
        out.v = p256::hash(label, "OTAC-P256_XMD:SHA-256_SSWU_RO_");
        require(!out.identity(), "hash point identity");
        return out;
    }
};

inline G operator*(const G& a, const G& b) {
    G out;
    p256::add(out.v, a.v, b.v);
    return out;
}

inline G inv(const G& a) {
    G out = a;
    require(EC_POINT_invert(p256::group.get(), out.v.get(), p256::context()) == 1, "EC inverse");
    return out;
}

inline G operator/(const G& a, const G& b) {
    G out = inv(b);
    out.mul_in(a);
    return out;
}

inline G pow(const G& a, const S& s) {
    G out;
    if (a.identity() || mpz_sgn(s.v) == 0) return out;
    std::array<unsigned char, 32> bytes{};
    size_t size = 0;
    mpz_export(bytes.data(), &size, 1, 1, 1, 0, s.v);
    p256::Number scalar{BN_bin2bn(bytes.data(), int(size), nullptr), BN_free};
    require(scalar && EC_POINT_mul(p256::group.get(), out.v.get(), nullptr, a.v.get(), scalar.get(),
                                   p256::context()) == 1, "P-256 multiply");
    return out;
}

inline G msm(const std::vector<G>& bases, const std::vector<S>& exponents) {
    require(bases.size() == exponents.size(), "MSM length mismatch");
    G out;
    if (bases.size() < 8) {
        for (size_t i = 0; i < bases.size(); ++i) out.mul_in(pow(bases[i], exponents[i]));
        return out;
    }
    const unsigned width = bases.size() < 32 ? 3 : bases.size() < 128 ? 4 : bases.size() < 512 ? 5 : 6;
    unsigned bits = 0;
    for (const auto& scalar : exponents) bits = std::max(bits, unsigned(mpz_sizeinbase(scalar.v, 2)));
    std::vector<G> buckets(size_t(1) << width);
    G running;
    const unsigned top = (bits - 1) / width * width;
    for (int bit = int(top); bit >= 0; bit -= int(width)) {
        if (unsigned(bit) != top) for (unsigned j = 0; j < width; ++j) out.square();
        for (auto& point : buckets) point.reset();
        for (size_t i = 0; i < bases.size(); ++i) {
            const auto digit = exponents[i].digit(bit, width);
            if (digit != 0) buckets[digit].mul_in(bases[i]);
        }
        running.reset();
        for (size_t j = buckets.size() - 1; j > 0; --j) {
            running.mul_in(buckets[j]);
            out.mul_in(running);
        }
    }
    return out;
}

namespace curve_ops {
// The comb and signed-window loops share this interface with the Type F backend.
inline const EC_GROUP* point_field(const p256::PointPtr&) { return p256::group.get(); }
struct Workspace { explicit Workspace(const p256::PointPtr&) {} };
class Point {
    G value;
public:
    explicit Point(const EC_GROUP*) {}
    void assign(const p256::PointPtr& point) {
        require(EC_POINT_copy(value.v.get(), point.get()) == 1, "EC point copy");
    }
    void twice(Workspace&) { value.square(); }
    void add_affine(const p256::PointPtr& point, Workspace&) { p256::add(value.v, value.v, point); }
    void write(p256::PointPtr& out, Workspace&) const {
        require(EC_POINT_copy(out.get(), value.v.get()) == 1, "EC point copy");
    }
};
} // namespace curve_ops

inline void init(const std::string& parameter) {
    require(parameter == "prime256v1", "P-256 benchmark expects prime256v1");
    require(!p256::group, "curve context already initialized");
    p256::group.reset(EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1));
    require(p256::group && EC_GROUP_get_degree(p256::group.get()) == 256, "P-256 group");
    std::array<unsigned char, 32> bytes{};
    const auto* n = EC_GROUP_get0_order(p256::group.get());
    require(n && BN_bn2binpad(n, bytes.data(), bytes.size()) == int(bytes.size()), "P-256 order");
    mpz_init(order);
    mpz_import(order, bytes.size(), 1, 1, 1, 0, bytes.data());
    order_bits = mpz_sizeinbase(order, 2);
    scalar_bytes = (order_bits + 7) / 8;
}
