#include "../src/benchmark_defaults.hpp"
#include "../src/issuance_v2.hpp"
#include "../baselines/acl/acl.hpp"
#include "../baselines/protocol_checks.hpp"

namespace {
using namespace otac;
constexpr int warmups = 3;
constexpr int matched = default_match_count;

void emit(const char* scheme, const char* operation, int n, int ell, int repetition,
          double milliseconds, size_t payload = 0, size_t wire = 0, size_t private_bytes = 0) {
    if (repetition >= 0)
        std::cout << scheme << ',' << operation << ',' << n << ',' << ell << ',' << matched
                  << ',' << repetition << ',' << milliseconds << ',' << payload << ','
                  << wire << ',' << private_bytes << '\n';
}

scheme::Credential issue(const scheme::Params& params, issuance_v2::Issuer& issuer,
                         const std::vector<S>& attributes, int account, scheme::Opening& opening) {
    const issuance_v2::Context context{"holder-" + std::to_string(account), "presentation-fixture"};
    const auto request = issuance_v2::cred_gen(params, context, true, S::random(true), attributes, opening);
    const auto credential = issuer.issue_parsed(context, request, &attributes);
    require(credential.has_value(), "presentation fixture issuance");
    return *credential;
}

void measure_otac(const scheme::Params& params, const std::vector<S>& attributes, const Req& req,
                  int n, int ell, int repetitions) {
    scheme::Ledger state;
    issuance_v2::Issuer issuer(params, state);
    for (int i = 0; i < ell - 1; ++i) {
        scheme::Opening decoy;
        issue(params, issuer, attributes, i, decoy);
    }
    const bool measure_transfer = ell == default_candidate_count && n % 8 == 0;
    for (int rep = -warmups; rep < repetitions; ++rep) {
        scheme::Opening opening;
        const auto credential = issue(params, issuer, attributes, ell + rep + warmups, opening);
        scheme::Show proof;
        const double generation = timed([&] {
            proof = scheme::proof_gen(params, state, credential.C, opening, ell, req);
        });
        if (rep == 0) proof = scheme::Show::from_bytes(params, proof.bytes());
        scheme::Ledger presented(state);
        bool accepted = false;
        const double verification = timed([&] { accepted = scheme::verify(params, presented, req, proof); });
        require(accepted, "OTAC presentation");
        emit("OTAC", "show", n, ell, rep, generation, proof.payload_bytes().size(), proof.bytes().size());
        emit("OTAC", "verify", n, ell, rep, verification);
        if (measure_transfer) {
            scheme::TransferResult transfer;
            const double generated = timed([&] {
                transfer = scheme::transfer(params, state, credential.C, opening, ell);
            });
            if (rep == 0) transfer.proof = scheme::TransferProof::from_bytes(params, transfer.proof.bytes());
            scheme::Ledger transferred(state);
            const double verified = timed([&] { accepted = scheme::verify_transfer(params, transferred, transfer.proof); });
            require(accepted, "OTAC transfer");
            const size_t private_bytes = credential.C.bytes().size() + (attributes.size() + 1) * scalar_bytes;
            emit("OTAC", "transfer", n, ell, rep, generated,
                 transfer.proof.payload_bytes().size(), transfer.proof.bytes().size(), private_bytes);
            emit("OTAC", "verify_transfer", n, ell, rep, verified);
        }
        require(state.attrs.erase(credential.C.bytes()) == 1, "presentation fixture cleanup");
    }
    std::cerr << "OTAC n=" << n << ", ell=" << ell << " complete\n";
}

void measure_baselines(const PP& common, const std::vector<S>& attributes,
                       const Req& req, int n, int repetitions) {
    const uprove::Params up(common);
    for (int rep = -warmups; rep < repetitions; ++rep) {
        Opening opening;
        opening.x = S::random(true);
        opening.r = S::random();
        opening.a = attributes;
        const auto registration = acl::register_user(common, opening);
        const auto issuer = acl::issuer_prepare(common, registration, attributes);
        const auto user = acl::user_prepare(common, registration, issuer);
        const auto token = acl::user_finish(user, acl::issuer_reply(common, issuer, user));
        require(acl::token_verify(common, token), "ACL credential");
        acl::Presentation acl_proof;
        const double acl_generation = timed([&] { acl_proof = acl::present(common, token, opening, user, issuer, req); });
        std::set<std::string> acl_spent;
        bool accepted = false;
        const double acl_verify = timed([&] { accepted = acl::verify(common, req, acl_proof, acl_spent); });
        require(accepted, "ACL presentation");
        emit("ACL", "show", n, 0, rep, acl_generation, acl_proof.bytes().size());
        emit("ACL", "verify", n, 0, rep, acl_verify);

        const auto first = uprove::issuer_first(up, attributes);
        const auto second = uprove::user_second(up, attributes, first.msg);
        const auto issued = uprove::issuer_third(up, first, second.challenge);
        const auto credential = uprove::user_finish(up, second, issued);
        const auto context = "presentation/" + std::to_string(n) + '/' + std::to_string(rep);
        uprove::Presentation up_proof;
        const double up_generation = timed([&] { up_proof = uprove::present(up, credential, attributes, req, context); });
        std::set<std::string> up_spent;
        const double up_verify = timed([&] { accepted = uprove::verify(up, req, up_proof, context, up_spent); });
        require(accepted, "U-Prove presentation");
        emit("UPROVE", "show", n, 0, rep, up_generation, up_proof.bytes().size());
        emit("UPROVE", "verify", n, 0, rep, up_verify);
    }
    std::cerr << "ACL and U-Prove n=" << n << " complete\n";
}
} // namespace

int main(int argc, char** argv) try {
    require(argc == 3 || argc == 4, "usage: presentation_transfer_bench prime256v1 REPETITIONS [N]");
    init(argv[1]);
    const int repetitions = std::stoi(argv[2]);
    require(repetitions > 0, "positive repetitions required");
    std::cout << "scheme,operation,n,ell,d,repetition,ms,payload_bytes,wire_bytes,private_bytes\n"
              << std::setprecision(12);
    for (const int n : wide_attribute_counts) {
        if (argc == 4 && n != std::stoi(argv[3])) continue;
        const PP common(n);
        const scheme::Params params(common);
        const auto attributes = baseline_checks::attributes(n);
        const auto req = request(attributes, matched);
        for (const int ell : {32, 64, 128}) measure_otac(params, attributes, req, n, ell, repetitions);
        measure_baselines(common, attributes, req, n, repetitions);
    }
    return 0;
} catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
}
