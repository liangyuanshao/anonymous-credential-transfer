#include "ours.hpp"
#include "benchmark_defaults.hpp"
#include "../baselines/protocol_checks.hpp"

namespace otac::legacy_scheme {
namespace oom_fixed = scheme::oom_fixed;
namespace oom_windows = scheme::oom_windows;
}
#define scheme legacy_scheme
// Stage this header from src/ours.hpp in the original OAS3 measured-source.zip.
#include "legacy_ours.hpp"
#undef scheme

using namespace otac;

namespace {
constexpr int warmups = 3;

void run(int n, int repetitions) {
    constexpr int ell = default_candidate_count;
    constexpr int d = default_match_count;
    const bool paired = n >= 56;
    const PP common(n);
    const scheme::Params params(common);
    std::unique_ptr<legacy_scheme::Params> legacy;
    if (paired) {
        legacy = std::make_unique<legacy_scheme::Params>(common);
        require(legacy->id == params.id, "archived OAS3 parameter mismatch");
    }

    const auto attributes = baseline_checks::attributes(n);
    const auto req = request(attributes, d);
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

        const auto selection = scheme::sample_candidates(ledger, credential.C, ell);
        auto proof = scheme::prove(params, selection.list, selection.index, opening, req);
        legacy_scheme::Show archived_proof;
        if (paired) {
            archived_proof = legacy_scheme::Show::from_bytes(*legacy, proof.bytes());
        }
        if (repetition == 0) {
            proof = scheme::Show::from_bytes(params, proof.bytes());
        }

        double new_ms = 0, old_ms = 0;
        const auto measure_new = [&] {
            scheme::Ledger state(ledger);
            bool accepted = false;
            new_ms = timed([&] { accepted = scheme::verify(params, state, req, proof); });
            require(accepted, "updated OAS3 presentation");
        };
        const auto measure_old = [&] {
            legacy_scheme::Ledger state;
            state.attrs = ledger.attrs;
            bool accepted = false;
            old_ms = timed([&] { accepted = legacy_scheme::verify(*legacy, state, req, archived_proof); });
            require(accepted, "archived OAS3 presentation");
        };
        const bool old_first = paired && repetition % 2 == 0;
        if (old_first) measure_old();
        measure_new();
        if (paired && !old_first) measure_old();
        if (repetition >= 0) {
            std::cout << n << ',' << ell << ',' << d << ',' << repetition << ','
                      << (paired ? int(old_first) : -1) << ',' << new_ms << ',';
            if (paired) std::cout << old_ms;
            std::cout << '\n';
        }
        if (paired && repetition == 0) {
            auto tampered = proof;
            tampered.sa.back() = tampered.sa.back() + S(1);
            const auto archived_tampered = legacy_scheme::Show::from_bytes(*legacy, tampered.bytes());
            require(!scheme::verify_proof(params, req, tampered), "updated verifier accepted tampering");
            require(!legacy_scheme::verify_proof(*legacy, req, archived_tampered),
                    "archived verifier accepted tampering");
        }
    }
    std::cerr << "n=" << n << " ell=" << ell << " complete\n";
}
}  // namespace

int main(int argc, char** argv) try {
    require(argc == 3 || argc == 4, "usage: presentation_verify_window_bench PARAM REPETITIONS [N]");
    init(argv[1]);
    const int repetitions = std::stoi(argv[2]);
    require(repetitions > 0, "positive repetitions required");
    std::cout << "n,ell,d,repetition,order,verify_ms,old_verify_ms\n" << std::setprecision(12);
    if (argc == 4) {
        run(std::stoi(argv[3]), repetitions);
    } else {
        for (const int n : wide_attribute_counts) {
            run(n, repetitions);
            if (n == 56) {
                run(58, repetitions);
                run(59, repetitions);
            }
        }
    }
    return 0;
} catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
}
