#include "benchmark_defaults.hpp"
#include "issuance_v2.hpp"
#include "../baselines/acl/acl.hpp"
#include "../baselines/uprove/uprove.hpp"
#include <numeric>
#include <random>

using namespace otac;

namespace {
constexpr int default_holder_count = 64;
constexpr int match_count = default_match_count;
static_assert(default_holder_count >= default_candidate_count);
constexpr int warmups = 3;
constexpr uint64_t order_seed = 20261107;

struct Holder {
    S key;
    std::vector<S> attributes;
};

struct Costs {
    size_t use_order = 0;
    double holder_issue = 0, issuer_issue = 0, admit = 0, show = 0, verify = 0;
    double acl_holder_registration = 0, acl_issuer_registration = 0;
};

std::vector<Holder> holders_for(int batch, int attribute_count, int holder_count) {
    std::vector<Holder> holders;
    holders.reserve(holder_count);
    for (int i = 0; i < holder_count; ++i) {
        Holder holder{S::random(true), {}};
        for (int j = 0; j < attribute_count; ++j) {
            Hash h("otac/utilization/attribute");
            h.u32(j);
            if (j >= match_count) {
                h.u32(static_cast<uint32_t>(batch + warmups));
                h.u32(i);
            }
            holder.attributes.push_back(h.finish());
        }
        holders.push_back(std::move(holder));
    }
    return holders;
}

template<class Credential, class Issue, class Use>
std::vector<Costs> workload(const std::vector<Holder>& holders, const std::vector<size_t>& order,
                            Issue issue, Use use) {
    std::vector<Costs> costs(holders.size());
    std::vector<Credential> credentials;
    credentials.reserve(holders.size());
    for (size_t i = 0; i < holders.size(); ++i) {
        credentials.push_back(issue(holders[i], costs[i]));
    }
    for (size_t rank = 0; rank < order.size(); ++rank) {
        const size_t i = order[rank];
        costs[i].use_order = rank + 1;
        use(holders[i], credentials[i], costs[i]);
    }
    return costs;
}

struct OtacCredential { scheme::Opening opening; scheme::Credential credential; };
std::vector<Costs> otac_workload(const scheme::Params& p, const Req& req,
                                 const std::vector<Holder>& holders, const std::vector<size_t>& order,
                                 bool first_v2) {
    scheme::Ledger ledger;
    issuance_v2::Issuer issuer(p, ledger);
    size_t account = 0;
    auto result = workload<OtacCredential>(holders, order,
        [&](const Holder& holder, Costs& cost) {
            OtacCredential item;
            if (first_v2) {
                const issuance_v2::Context context{"holder-" + std::to_string(account++), "first-issuance"};
                issuance_v2::Request application;
                cost.holder_issue = timed([&] {
                    application = issuance_v2::cred_gen(p, context, true, holder.key,
                                                        holder.attributes, item.opening);
                });
                std::optional<scheme::Credential> credential;
                const double issuer_and_admit = timed([&] {
                    credential = issuer.issue_parsed(context, application, &holder.attributes, &cost.admit);
                });
                cost.issuer_issue = issuer_and_admit - cost.admit;
                require(credential.has_value(), "OTAC v2 first issuance and admission");
                item.credential = std::move(*credential);
                return item;
            }
            scheme::CredRequest application;
            cost.holder_issue = timed([&] {
                application = scheme::cred_gen(p, holder.key, holder.attributes, item.opening);
            });
            cost.issuer_issue = timed([&] {
                item.credential = scheme::issue(p, application, holder.attributes);
            });
            bool admitted = false;
            cost.admit = timed([&] { admitted = ledger.register_issued(p, item.credential); });
            require(admitted, "OTAC credential admission");
            return item;
        },
        [&](const Holder&, const OtacCredential& item, Costs& cost) {
            scheme::Show proof;
            cost.show = timed([&] {
                proof = scheme::proof_gen(p, ledger, item.credential.C, item.opening, default_candidate_count, req);
            });
            bool accepted = false;
            cost.verify = timed([&] { accepted = scheme::verify(p, ledger, req, proof); });
            require(accepted, "OTAC consumption");
        });
    require(ledger.attrs.size() == holders.size() && ledger.spent.size() == order.size(), "OTAC workload counts");
    return result;
}

struct AclCredential { Opening opening; acl::UserState user; acl::IssuerState issuer; acl::Token token; };
std::vector<Costs> acl_workload(const PP& p, const Req& req,
                                const std::vector<Holder>& holders, const std::vector<size_t>& order) {
    std::set<std::string> spent;
    auto result = workload<AclCredential>(holders, order,
        [&](const Holder& holder, Costs& cost) {
            AclCredential item;
            item.opening.x = holder.key;
            item.opening.a = holder.attributes;
            acl::Registration registration;
            cost.acl_holder_registration = timed([&] {
                item.opening.r = S::random();
                registration = acl::register_user(p, item.opening);
            });
            bool verified = false;
            cost.acl_issuer_registration = timed([&] {
                verified = acl::register_verify(p, registration, holder.attributes);
            });
            require(verified, "ACL initial registration");
            cost.holder_issue = cost.acl_holder_registration;
            cost.issuer_issue = cost.acl_issuer_registration;
            cost.issuer_issue += timed([&] {
                item.issuer = acl::issuer_prepare(p, registration, holder.attributes, false);
            });
            cost.holder_issue += timed([&] { item.user = acl::user_prepare(p, registration, item.issuer); });
            acl::Reply response;
            cost.issuer_issue += timed([&] { response = acl::issuer_reply(p, item.issuer, item.user); });
            cost.holder_issue += timed([&] {
                item.token = acl::user_finish(item.user, response);
                require(acl::token_verify(p, item.token), "ACL issued token");
            });
            return item;
        },
        [&](const Holder&, const AclCredential& item, Costs& cost) {
            acl::Presentation proof;
            cost.show = timed([&] {
                proof = acl::present(p, item.token, item.opening, item.user, item.issuer, req);
            });
            bool accepted = false;
            cost.verify = timed([&] { accepted = acl::verify(p, req, proof, spent); });
            require(accepted, "ACL consumption");
        });
    require(spent.size() == order.size(), "ACL workload counts");
    return result;
}

std::vector<Costs> uprove_workload(const uprove::Params& p, const Req& req, int batch,
                                   const std::vector<Holder>& holders, const std::vector<size_t>& order) {
    std::set<std::string> spent;
    auto result = workload<uprove::Credential>(holders, order,
        [&](const Holder& holder, Costs& cost) {
            uprove::IssuerState issuer;
            uprove::UserState user;
            S reply;
            uprove::Credential credential;
            cost.issuer_issue = timed([&] { issuer = uprove::issuer_first(p, holder.attributes); });
            cost.holder_issue = timed([&] { user = uprove::user_second(p, holder.attributes, issuer.msg); });
            cost.issuer_issue += timed([&] { reply = uprove::issuer_third(p, issuer, user.challenge); });
            cost.holder_issue += timed([&] { credential = uprove::user_finish(p, user, reply); });
            return credential;
        },
        [&](const Holder& holder, const uprove::Credential& item, Costs& cost) {
            const auto context = "utilization/" + std::to_string(batch) + "/" + std::to_string(cost.use_order);
            uprove::Presentation proof;
            cost.show = timed([&] { proof = uprove::present(p, item, holder.attributes, req, context); });
            bool accepted = false;
            cost.verify = timed([&] { accepted = uprove::verify(p, req, proof, context, spent); });
            require(accepted, "U-Prove consumption");
        });
    require(spent.size() == order.size(), "U-Prove workload counts");
    return result;
}
} // namespace

int main(int argc, char** argv) try {
    require(argc == 3 || argc == 5 || argc == 6 || argc == 7,
            "usage: utilization_bench PARAM BATCHES [first-v2 ATTRIBUTES [CREDENTIALS_PER_BATCH [BATCH_INDEX]]]");
    const int batches = std::stoi(argv[2]);
    require(batches >= 6 && batches % 6 == 0, "batch count must be a positive multiple of six");
    const bool first_v2 = argc >= 5;
    const int attribute_count = first_v2 ? std::stoi(argv[4]) : default_attribute_count;
    const int holder_count = argc >= 6 ? std::stoi(argv[5]) : default_holder_count;
    const int batch_index = argc == 7 ? std::stoi(argv[6]) : -1;
    require(argc != 7 || (batch_index >= 0 && batch_index < batches), "batch index out of range");
    require(holder_count >= default_candidate_count, "credentials per batch must cover the candidate list");
    if (first_v2) {
        require(std::string(argv[3]) == "first-v2" &&
                    (attribute_count == 16 || attribute_count == 32),
                "first-v2 requires 16 or 32 attributes");
    }
    init(argv[1]);
    PP common(attribute_count);
    scheme::Params otac(common);
    uprove::Params uprove_params(common);
    std::mt19937_64 rng(order_seed);
    std::array<int, 3> scheme_order{0, 1, 2};
    const std::array<std::string, 3> names{"OTAC", "ACL", "UPROVE"};

    std::cout << "batch,scheme,scheme_order,holder,use_order,holder_issue_ms,issuer_issue_ms,admit_ms,"
                 "show_ms,verify_ms,acl_holder_registration_ms,acl_issuer_registration_ms\n"
              << std::setprecision(12) << std::flush;
    const int stop = batch_index < 0 ? batches : batch_index + 1;
    for (int batch = -warmups; batch < stop; ++batch) {
        const int count = batch < 0 ? default_holder_count : holder_count;
        std::vector<size_t> order(count);
        std::iota(order.begin(), order.end(), size_t(0));
        std::shuffle(order.begin(), order.end(), rng);
        if (batch >= 0 && batch_index >= 0 && batch != batch_index) {
            // Match the serial run's permutation and holder order for the selected batch.
            std::next_permutation(scheme_order.begin(), scheme_order.end());
            continue;
        }
        const auto holders = holders_for(batch, attribute_count, count);
        const auto req = request(holders.front().attributes, match_count);

        for (size_t position = 0; position < scheme_order.size(); ++position) {
            const int scheme_id = scheme_order[position];
            if (batch >= 0) {
                std::cerr << "Paired batch " << batch + 1 << '/' << batches << ": "
                          << names[scheme_id] << " started (" << holders.size() << " credentials)\n";
            }
            std::vector<Costs> rows;
            if (scheme_id == 0) rows = otac_workload(otac, req, holders, order, first_v2);
            else if (scheme_id == 1) rows = acl_workload(common, req, holders, order);
            else rows = uprove_workload(uprove_params, req, batch, holders, order);
            if (batch < 0) continue;
            for (size_t i = 0; i < rows.size(); ++i) {
                const auto& c = rows[i];
                std::cout << batch << ',' << names[scheme_id] << ',' << position << ',' << i << ','
                          << c.use_order << ',' << c.holder_issue << ',' << c.issuer_issue << ',' << c.admit << ','
                          << c.show << ',' << c.verify << ',' << c.acl_holder_registration << ','
                          << c.acl_issuer_registration << '\n';
            }
            std::cout.flush();
        }
        if (batch < 0) std::cerr << "Warmup " << batch + warmups + 1 << '/' << warmups << " completed\n";
        else std::cerr << "Paired batch " << batch + 1 << '/' << batches << " completed\n";
        std::next_permutation(scheme_order.begin(), scheme_order.end());
    }
    require(bool(std::cout), "incomplete timing output");
    return 0;
} catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
}
