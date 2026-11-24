#include "ours.hpp"
#include "benchmark_defaults.hpp"
#include "../baselines/acl/acl.hpp"
#include "../baselines/protocol_checks.hpp"

namespace otac::legacy_scheme {
namespace oom_fixed = scheme::oom_fixed;
namespace oom_windows = scheme::oom_windows;
}
#define scheme legacy_scheme
#include "legacy_ours.hpp"
#undef scheme

using namespace otac;

namespace {
constexpr int warmups = 3;
constexpr int paired_attributes = 32;
constexpr int paired_candidates = 64;

void emit(const char* implementation, int n, int ell, int repetition,
          int order, double sampling, double generation, double verification) {
    if (repetition >= 0) {
        std::cout << implementation << ',' << n << ',' << ell << ',' << default_match_count << ','
                  << repetition << ',' << order << ',' << sampling << ',' << generation << ','
                  << verification << '\n';
    }
}

void measure_baselines(const PP& common, const uprove::Params& up,
                       const std::vector<S>& attributes, const Req& req, int n, int repetition) {
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
    double generation = timed([&] { acl_proof = acl::present(common, token, opening, user, issuer, req); });
    std::set<std::string> spent;
    bool accepted = false;
    double verification = timed([&] { accepted = acl::verify(common, req, acl_proof, spent); });
    require(accepted, "ACL presentation");
    emit("ACL", n, 0, repetition, -1, 0, generation, verification);

    const auto first = uprove::issuer_first(up, attributes);
    const auto second = uprove::user_second(up, attributes, first.msg);
    const auto credential = uprove::user_finish(up, second, uprove::issuer_third(up, first, second.challenge));
    const auto context = "integrated-presentation/" + std::to_string(n) + '/' + std::to_string(repetition);
    uprove::Presentation up_proof;
    generation = timed([&] { up_proof = uprove::present(up, credential, attributes, req, context); });
    spent.clear();
    verification = timed([&] { accepted = uprove::verify(up, req, up_proof, context, spent); });
    require(accepted, "U-Prove presentation");
    emit("UPROVE", n, 0, repetition, -1, 0, generation, verification);
}

void run(int n, int ell, int repetitions) {
    const bool paired = n == paired_attributes && ell == paired_candidates;
    const PP common(n);
    const scheme::Params params(common);
    const uprove::Params up(common);
    std::unique_ptr<legacy_scheme::Params> legacy;
    if (paired) legacy = std::make_unique<legacy_scheme::Params>(common);
    if (paired) require(legacy->id == params.id, "legacy parameter mismatch");

    const auto attributes = baseline_checks::attributes(n);
    const auto req = request(attributes, default_match_count);
    scheme::Ledger pool;
    for (int i = 0; i < ell - 1; ++i) {
        scheme::Opening decoy;
        const auto application = scheme::cred_gen(params, S::random(true), attributes, decoy);
        require(pool.register_issued(params, scheme::issue(params, application, attributes)), "decoy admission");
    }
    for (int repetition = -warmups; repetition < repetitions; ++repetition) {
        scheme::Opening opening;
        const auto application = scheme::cred_gen(params, S::random(true), attributes, opening);
        const auto credential = scheme::issue(params, application, attributes);
        scheme::Ledger ledger(pool);
        require(ledger.register_issued(params, credential), "holder admission");

        scheme::Selection selection;
        const double sampling = timed([&] { selection = scheme::sample_candidates(ledger, credential.C, ell); });
        const bool legacy_first = paired && repetition % 2 == 0;
        const auto current_proof = [&] {
            scheme::Show proof;
            const double generation = timed([&] { proof = scheme::prove(params, selection.list, selection.index, opening, req); });
            if (repetition == 0) proof = scheme::Show::from_bytes(params, proof.bytes());
            scheme::Ledger state(ledger);
            bool accepted = false;
            const double verification = timed([&] { accepted = scheme::verify(params, state, req, proof); });
            require(accepted, "OAS3 presentation");
            emit("OAS3", n, ell, repetition, paired ? int(legacy_first) : -1, sampling, generation, verification);
        };
        const auto legacy_proof = [&] {
            legacy_scheme::Show proof;
            const legacy_scheme::Opening legacy_opening{opening.a, opening.r};
            const double generation = timed([&] { proof = legacy_scheme::prove(*legacy, selection.list, selection.index, legacy_opening, req); });
            if (repetition == 0) proof = legacy_scheme::Show::from_bytes(*legacy, proof.bytes());
            legacy_scheme::Ledger state;
            state.attrs = ledger.attrs;
            bool accepted = false;
            const double verification = timed([&] { accepted = legacy_scheme::verify(*legacy, state, req, proof); });
            require(accepted, "OAS2 presentation");
            emit("OAS2", n, ell, repetition, int(!legacy_first), sampling, generation, verification);
        };
        if (legacy_first) legacy_proof();
        current_proof();
        if (paired && !legacy_first) legacy_proof();
        if (ell == default_candidate_count) measure_baselines(common, up, attributes, req, n, repetition);
    }
    std::cerr << "n=" << n << " ell=" << ell << " complete\n";
}
}  // namespace

int main(int argc, char** argv) try {
    require(argc == 3 || argc == 5, "usage: presentation_integrated_bench PARAM REPETITIONS [N ELL]");
    init(argv[1]);
    const int repetitions = std::stoi(argv[2]);
    require(repetitions > 0, "positive repetitions required");
    std::cout << "implementation,n,ell,d,repetition,order,sample_ms,prove_ms,verify_ms\n" << std::setprecision(12);
    if (argc == 5) run(std::stoi(argv[3]), std::stoi(argv[4]), repetitions);
    else for (int n : wide_attribute_counts) for (int ell : {32, 64, 128}) run(n, ell, repetitions);
    return 0;
} catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
}
