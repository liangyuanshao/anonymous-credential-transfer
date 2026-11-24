#include "benchmark_defaults.hpp"
#include "issuance_v2.hpp"
#include "../baselines/acl/acl.hpp"
#include "../baselines/uprove/uprove.hpp"

#include <algorithm>
#include <array>
#include <iomanip>
#include <iostream>

namespace {
using namespace otac;

struct Timing {
    double holder_ms = 0;
    double issuer_ms = 0;
    double admission_ms = 0;
};

using IssuancePair = std::array<Timing, 2>;
constexpr int warmups = 3;
constexpr int default_repetitions = 100;

IssuancePair measure_otac(const scheme::Params& params, const Opening& holder) {
    scheme::Ledger ledger;
    issuance_v2::Issuer issuer(params, ledger);
    IssuancePair timings;
    for (std::size_t mode = 0; mode < timings.size(); ++mode) {
        const bool first = mode == 0;
        const issuance_v2::Context context{"benchmark-holder", first ? "first-session" : "repeat-session"};
        const auto* audited = first ? &holder.a : nullptr;
        auto& result = timings[mode];
        scheme::Opening opening;
        issuance_v2::Request request;
        std::optional<scheme::Credential> credential;
        result.holder_ms = timed([&] {
            request = issuance_v2::cred_gen(params, context, first, holder.x, holder.a, opening);
        });
        const double issuer_and_admission_ms = timed([&] {
            credential = issuer.issue_parsed(context, request, audited, &result.admission_ms);
        });
        result.issuer_ms = issuer_and_admission_ms - result.admission_ms;
        require(credential && credential->C == scheme::commitment(params, opening) &&
                    ledger.contains(credential->C), "OTAC issuance or registration failed");
    }
    return timings;
}

IssuancePair measure_acl(const PP& params, const Opening& holder) {
    Opening opening = holder;
    acl::Registration registration;
    IssuancePair timings;
    timings[0].holder_ms = timed([&] {
        opening.r = S::random();
        registration = acl::register_user(params, opening);
    });
    for (std::size_t mode = 0; mode < timings.size(); ++mode) {
        auto& result = timings[mode];
        acl::IssuerState issuer;
        acl::UserState user;
        acl::Reply reply;
        result.issuer_ms = timed([&] {
            issuer = acl::issuer_prepare(params, registration, opening.a, mode == 0);
        });
        result.holder_ms += timed([&] { user = acl::user_prepare(params, registration, issuer); });
        result.issuer_ms += timed([&] { reply = acl::issuer_reply(params, issuer, user); });
        result.holder_ms += timed([&] {
            const auto token = acl::user_finish(user, reply);
            require(acl::token_verify(params, token), "ACL issuance validation failed");
        });
    }
    return timings;
}

IssuancePair measure_uprove(const uprove::Params& params, const Opening& holder) {
    IssuancePair timings;
    for (auto& result : timings) {
        uprove::IssuerState issuer;
        uprove::UserState user;
        S reply;
        uprove::Credential credential;
        result.issuer_ms = timed([&] { issuer = uprove::issuer_first(params, holder.a); });
        result.holder_ms = timed([&] { user = uprove::user_second(params, holder.a, issuer.msg); });
        result.issuer_ms += timed([&] { reply = uprove::issuer_third(params, issuer, user.challenge); });
        result.holder_ms += timed([&] { credential = uprove::user_finish(params, user, reply); });
        require(uprove::token_verify(params, credential.token), "U-Prove issuance validation failed");
    }
    return timings;
}

void write_row(int n, const char* scheme, const char* mode, const char* role,
               int repetition, double milliseconds) {
    require(milliseconds > 0, "non-positive issuance duration");
    std::cout << n << ',' << scheme << ',' << mode << ',' << role << ','
              << repetition << ',' << milliseconds << '\n';
}

void measure_attributes(int n, int repetitions) {
    const PP common(n);
    const scheme::Params params(common);
    const uprove::Params up(common);
    const auto holder = opening(n);
    const std::array<const char*, 3> schemes{"OTAC", "ACL", "UPROVE"};
    const std::array<std::function<IssuancePair()>, 3> measure{
        [&] { return measure_otac(params, holder); },
        [&] { return measure_acl(common, holder); },
        [&] { return measure_uprove(up, holder); },
    };
    std::array<std::size_t, 3> order{0, 1, 2};
    for (int repetition = -warmups; repetition < repetitions; ++repetition) {
        std::array<IssuancePair, 3> observations;
        for (const auto index : order) observations[index] = measure[index]();
        std::next_permutation(order.begin(), order.end());
        if (repetition < 0) continue;
        for (std::size_t index = 0; index < schemes.size(); ++index) {
            for (std::size_t mode = 0; mode < observations[index].size(); ++mode) {
                const auto& row = observations[index][mode];
                const auto* label = mode == 0 ? "first" : "repeat";
                write_row(n, schemes[index], label, "holder", repetition, row.holder_ms);
                write_row(n, schemes[index], label, "issuer", repetition, row.issuer_ms);
                if (index == 0) write_row(n, schemes[index], label, "admit", repetition, row.admission_ms);
            }
        }
    }
    std::cerr << "Completed n=" << n << '\n';
}
} // namespace

int main(int argc, char** argv) try {
    otac::require(argc == 2 || argc == 3, "usage: issuance_timing PARAM [REPETITIONS]");
    const int repetitions = argc == 3 ? std::stoi(argv[2]) : default_repetitions;
    otac::require(repetitions > 0, "repetitions must be positive");
    otac::init(argv[1]);
    std::cout << std::setprecision(12) << "n,scheme,mode,role,repetition,ms\n";
    for (const int n : otac::wide_attribute_counts) measure_attributes(n, repetitions);
    std::cout.flush();
    otac::require(bool(std::cout), "incomplete issuance timing output");
    return 0;
} catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
}
