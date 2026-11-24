#include "../src/ours.hpp"
#include "../baselines/protocol_checks.hpp"
#include <fstream>

// Use the measured reference prover with the same compiled group backend.
#define scheme reference_scheme
#include "oom_reference.hpp"
#undef scheme

using namespace otac;
using Clock = std::chrono::steady_clock;

template<class Ledger, class Generate, class Verify>
static void measure(const char* variant, const char* operation, size_t ell,
                    int repetition, int order, const Ledger& ledger,
                    Generate generate, Verify verify) {
    const auto start = Clock::now();
    auto proof = generate();
    const double generation_ms = std::chrono::duration<double, std::milli>(Clock::now() - start).count();

    Ledger state(ledger);
    bool accepted = false;
    const double verification_ms = timed([&] { accepted = verify(state, proof); });
    require(accepted, "benchmark generated an invalid proof");
    if (repetition >= 0) {
        std::cout << variant << ',' << operation << ',' << ell << ',' << repetition << ','
                  << order << ',' << generation_ms << ',' << verification_ms << ','
                  << proof.payload_bytes().size() << '\n';
    }
}

static void compare(size_t ell, int repetitions, const char* reference_label, const char* current_label) {
    PP common(16);
    scheme::Params current(common);
    reference_scheme::Params reference(common);
    require(current.id == reference.id, "different proof parameters");
    auto attributes = baseline_checks::attributes(16);
    auto req = request(attributes, 4);
    const S holder_key = S::random(true);

    scheme::Ledger pool;
    for (size_t i = 1; i < ell; ++i) {
        scheme::Opening decoy;
        auto issued = scheme::issue(current, scheme::cred_gen(current, S::random(true), attributes, decoy), attributes);
        require(pool.register_issued(current, issued), "decoy registration failed");
    }

    for (int rep = -3; rep < repetitions; ++rep) {
        scheme::Opening opening;
        auto issued = scheme::issue(current, scheme::cred_gen(current, holder_key, attributes, opening), attributes);
        scheme::Ledger ledger(pool);
        require(ledger.register_issued(current, issued), "credential registration failed");
        reference_scheme::Ledger old_ledger;
        old_ledger.attrs = ledger.attrs;
        reference_scheme::Opening old_opening{opening.a, opening.r};

        auto direct = [&](int order) {
            measure(reference_label, "show", ell, rep, order, old_ledger,
                    [&] { return reference_scheme::proof_gen(reference, old_ledger, issued.C, old_opening, ell, req); },
                    [&](auto& state, const auto& proof) { return reference_scheme::verify(reference, state, req, proof); });
            measure(reference_label, "transfer", ell, rep, order, old_ledger,
                    [&] { return reference_scheme::transfer(reference, old_ledger, issued.C, old_opening, ell).proof; },
                    [&](auto& state, const auto& proof) { return reference_scheme::verify_transfer(reference, state, proof); });
        };
        auto factored = [&](int order) {
            measure(current_label, "show", ell, rep, order, ledger,
                    [&] { return scheme::proof_gen(current, ledger, issued.C, opening, ell, req); },
                    [&](auto& state, const auto& proof) { return scheme::verify(current, state, req, proof); });
            measure(current_label, "transfer", ell, rep, order, ledger,
                    [&] { return scheme::transfer(current, ledger, issued.C, opening, ell).proof; },
                    [&](auto& state, const auto& proof) { return scheme::verify_transfer(current, state, proof); });
        };
        if (rep % 2 == 0) {
            direct(0);
            factored(1);
        } else {
            factored(0);
            direct(1);
        }
        if (rep >= 0 && ((rep + 1) % 10 == 0 || rep + 1 == repetitions)) {
            std::cerr << "ell=" << ell << " paired repetitions " << rep + 1 << '/' << repetitions << '\n';
        }
    }
}

int main(int argc, char** argv) try {
    require(argc >= 7, "usage: oom_ab PARAM REPS REFERENCE CURRENT SETUP_CSV ELL [ELL...]");
    init(argv[1]);
    const int repetitions = std::stoi(argv[2]);
    require(repetitions > 0, "positive repetitions required");
    std::cout << "variant,operation,ell,repetition,order,generation_ms,verification_ms,payload_bytes\n"
              << std::setprecision(12);
    for (int i = 6; i < argc; ++i) {
        const auto ell = size_t(std::stoul(argv[i]));
        scheme::gk_dimension(ell);
        compare(ell, repetitions, argv[3], argv[4]);
    }
    // Measure scheme-specific public parameter construction on a shared PP.
    // Record construction alone and let each object destruct after its timer.
    PP common(16);
    std::ofstream setup(argv[5]);
    require(bool(setup), "cannot write setup measurements");
    setup << "variant,repetition,ms\n" << std::setprecision(12);
    auto measure_setup = [&](const char* label, int rep, auto make) {
        const auto start = Clock::now();
        auto params = make();
        const double ms = std::chrono::duration<double, std::milli>(Clock::now() - start).count();
        require(!params.id.empty(), "public parameter construction");
        if (rep >= 0) setup << label << ',' << rep << ',' << ms << '\n';
    };
    for (int rep = -3; rep < repetitions; ++rep) {
        auto before = [&] {
            measure_setup(argv[3], rep, [&] { return reference_scheme::Params(common); });
        };
        auto after = [&] {
            measure_setup(argv[4], rep, [&] { return scheme::Params(common); });
        };
        if (rep % 2 == 0) { before(); after(); }
        else { after(); before(); }
    }
    require(bool(setup), "incomplete setup measurements");
    return 0;
} catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
}
