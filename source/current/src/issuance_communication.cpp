#include "benchmark_defaults.hpp"
#include "issuance_v2.hpp"
#include "../baselines/acl/acl.hpp"
#include "../baselines/uprove/uprove.hpp"

#include <cstddef>
#include <exception>
#include <iostream>

namespace {
using namespace otac;

struct Traffic {
    std::size_t user_bytes = 0;
    std::size_t issuer_bytes = 0;
    std::size_t bilateral_messages = 0;
    std::size_t ledger_bytes = 0;
    std::size_t ledger_messages = 0;

    void user_to_issuer(std::size_t bytes) {
        user_bytes += bytes;
        ++bilateral_messages;
    }

    void issuer_to_user(std::size_t bytes) {
        issuer_bytes += bytes;
        ++bilateral_messages;
    }

    void issuer_to_ledger(std::size_t bytes) {
        ledger_bytes += bytes;
        ++ledger_messages;
    }

    void write(int n, const char* name, bool first, std::size_t credential_bytes) const {
        std::cout << n << ',' << name << ',' << (first ? "first" : "repeat") << ','
                  << user_bytes << ',' << issuer_bytes << ',' << user_bytes + issuer_bytes << ','
                  << bilateral_messages << ',' << ledger_bytes << ',' << ledger_messages << ','
                  << credential_bytes << '\n';
    }
};

void measure_otac(int n, const PP& common, const Opening& holder) {
    const scheme::Params params(common);
    scheme::Ledger ledger;
    issuance_v2::Issuer issuer(params, ledger);
    const bool check = n == wide_attribute_counts.front();
    for (const bool first : {true, false}) {
        Traffic traffic;
        const issuance_v2::Context context{"benchmark-holder", first ? "first-session" : "repeat-session"};
        const auto* audited_attributes = first ? &holder.a : nullptr;
        scheme::Opening credential_opening;
        const auto request = issuance_v2::cred_gen(params, context, first, holder.x, holder.a,
                                                   credential_opening);
        const auto payload = request.payload_bytes();
        if (check && first) {
            auto wrong_attributes = holder.a;
            wrong_attributes.front() = wrong_attributes.front() + S(1);
            require(!issuer.issue(context, payload, &wrong_attributes), "mismatched attributes accepted");
            auto bad_key = request;
            bad_key.key->response = bad_key.key->response + S(1);
            require(!issuer.issue(context, bad_key.payload_bytes(), audited_attributes),
                    "invalid key proof accepted");
            auto bad_opening = request;
            bad_opening.opening.response = bad_opening.opening.response + S(1);
            require(!issuer.issue(context, bad_opening.payload_bytes(), audited_attributes),
                    "invalid opening proof accepted");
        }
        if (check && !first) {
            require(!issuer.issue({"unregistered-holder", context.session}, payload),
                    "subsequent issuance without a record accepted");
            require(!issuer.issue({context.account, "wrong-session"}, payload),
                    "proof from another session accepted");
        }

        traffic.user_to_issuer(payload.size());
        const auto credential = issuer.issue(context, payload, audited_attributes);
        require(credential && credential->C == scheme::commitment(params, credential_opening) &&
                    ledger.contains(credential->C), "OTAC issuance or registration failed");
        const auto bytes = credential->bytes();
        traffic.issuer_to_user(bytes.size());
        traffic.issuer_to_ledger(bytes.size());
        traffic.write(n, "OTAC", first, bytes.size());
        if (check && !first) {
            require(!issuer.issue(context, payload), "duplicate credential registration accepted");
        }
    }
}

void measure_acl(int n, const PP& common, const Opening& holder) {
    const auto registration = acl::register_user(common, holder);
    for (const bool first : {true, false}) {
        Traffic traffic;
        if (first) traffic.user_to_issuer(registration.bytes(holder).size());
        const auto issuer = acl::issuer_prepare(common, registration, holder.a, first);
        traffic.issuer_to_user(issuer.rnd.bytes().size() + issuer.a.bytes().size() +
                               issuer.b1.bytes().size() + issuer.b2.bytes().size());
        const auto user = acl::user_prepare(common, registration, issuer);
        traffic.user_to_issuer(user.e.bytes().size());
        const auto reply = acl::issuer_reply(common, issuer, user);
        traffic.issuer_to_user(reply.c.bytes().size() + reply.r.bytes().size() + reply.cp.bytes().size() +
                               reply.rp1.bytes().size() + reply.rp2.bytes().size());
        const auto token = acl::user_finish(user, reply);
        require(acl::token_verify(common, token), "ACL token rejected");
        traffic.write(n, "ACL", first, token.bytes().size());
    }
}

void measure_uprove(int n, const PP& common, const Opening& holder) {
    const uprove::Params params(common);
    std::size_t attribute_bytes = 0;
    for (const auto& attribute : holder.a) attribute_bytes += attribute.bytes().size();
    for (const bool first : {true, false}) {
        Traffic traffic;
        // The first run provisions attributes separately; the second uses the same known values.
        if (first) traffic.user_to_issuer(attribute_bytes);
        const auto issuer = uprove::issuer_first(params, holder.a);
        traffic.issuer_to_user(issuer.msg.bytes().size());
        const auto user = uprove::user_second(params, holder.a, issuer.msg);
        traffic.user_to_issuer(user.challenge.bytes().size());
        const auto reply = uprove::issuer_third(params, issuer, user.challenge);
        traffic.issuer_to_user(reply.bytes().size());
        const auto credential = uprove::user_finish(params, user, reply);
        require(uprove::token_verify(params, credential.token), "U-Prove token rejected");
        traffic.write(n, "UPROVE", first, credential.token.bytes().size());
    }
}
}  // namespace

int main(int argc, char** argv) try {
    otac::require(argc == 2, "usage: issuance_communication PARAM");
    otac::init(argv[1]);
    std::cout << "n,scheme,mode,user_to_issuer_bytes,issuer_to_user_bytes,bilateral_bytes,"
                 "user_issuer_messages,ledger_bytes,ledger_messages,public_credential_bytes\n";
    for (int n : otac::wide_attribute_counts) {
        const otac::PP common(n);
        const auto holder = otac::opening(n);
        measure_otac(n, common, holder);
        measure_acl(n, common, holder);
        measure_uprove(n, common, holder);
    }
    std::cout.flush();
    otac::require(bool(std::cout), "incomplete communication output");
    return 0;
} catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
}
