#include "../src/ours.hpp"

int main() try {
    using namespace otac;
    init("prime256v1");
    require(order_bits == 256 && scalar_bytes == 32, "unexpected P-256 order");
    const std::string dst = "QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_";
    const auto vector_check = [&](const std::string& input, const std::string& expected) {
        G actual;
        actual.v = p256::hash(input, dst);
        std::ostringstream hex;
        for (unsigned char byte : actual.bytes()) hex << std::hex << std::setw(2)
                                                       << std::setfill('0') << unsigned(byte);
        require(hex.str() == expected, "RFC 9380 P-256 vector mismatch");
    };
    vector_check("", "032c15230b26dbc6fc9a37051158c95b79656e17a1a920b11394ca91c44247d3e4");
    vector_check("abc", "020bb8b87485551aa43ed54f009230450b492fead5f1cc91658775dac4a3388a0f");
    vector_check("abcdef0123456789", "0365038ac8f2b1def042a5df0b33b1f4eca6bff7cb0f9c6c1526811864e544ed80");

    const auto generator = G::hash("p256-generator-check");
    const scheme::oom_fixed::Comb comb(generator);
    require(generator.bytes().size() == 33 && G::from_bytes(generator.bytes()) == generator
            && G::from_bytes(G().bytes()).identity(), "compressed point round trip");
    std::vector<G> bases;
    std::vector<S> exponents;
    G expected;
    for (size_t i = 1; i <= 136; ++i) {
        bases.push_back(i % 7 == 0 ? G() : G::hash("p256-product/" + std::to_string(i)));
        exponents.push_back(i % 11 == 0 ? S(0) : S::random());
        const auto& scalar = exponents.back();
        require(comb.power(scalar) == pow(generator, scalar), "comb and OpenSSL disagree");
        expected.mul_in(pow(bases.back(), scalar));
        if (i == 1 || i == 8 || i == 32 || i == 128 || i == 136) {
            require(msm(bases, exponents) == expected, "bucket MSM and OpenSSL disagree");
            require(scheme::spend_verification_product(bases, exponents, 64) == expected,
                    "Spend verification MSM and OpenSSL disagree");
        }
    }
    std::cout << "P-256 group checks passed\n";
    return 0;
} catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
}
