#pragma once

#include "ours.hpp"

#include <optional>

namespace otac::issuance_v2 {

// The application supplies this context from an authenticated session.
struct Context {
    std::string account;
    std::string session;
};

struct OpeningProof {
    G A_R, A_V;
    S response;
};

struct KeyProof {
    G Y, A_x;
    S response;
};

struct Request {
    G R, V;
    OpeningProof opening;
    std::optional<KeyProof> key;

    std::string payload_bytes() const {
        std::string payload;
        if (key) payload = key->Y.bytes();
        payload += R.bytes() + V.bytes() + opening.A_R.bytes() + opening.A_V.bytes() +
                   opening.response.bytes();
        if (key) payload += key->A_x.bytes() + key->response.bytes();
        return payload;
    }

    static Request from_payload(const std::string& payload, bool first) {
        scheme::Reader reader(payload);
        Request request;
        if (first) request.key.emplace().Y = reader.point();
        request.R = reader.point();
        request.V = reader.point();
        request.opening = {reader.point(), reader.point(), reader.scalar()};
        if (first) {
            request.key->A_x = reader.point();
            request.key->response = reader.scalar();
        }
        reader.done();
        return request;
    }
};

inline void bind_statement(Hash& hash, const scheme::Params& params, const Context& context,
                           bool first, const G& Y, const Request& request,
                           const std::vector<S>& attributes) {
    hash.blob(params.id);
    hash.blob(context.account);
    hash.blob(context.session);
    hash.u32(first ? 1 : 0);
    hash.point(Y);
    hash.point(request.R);
    hash.point(request.V);
    hash.u32(static_cast<uint32_t>(attributes.size()));
    for (const auto& attribute : attributes) hash.scalar(attribute);
}

inline S opening_challenge(const scheme::Params& params, const Context& context, bool first,
                           const G& Y, const Request& request, const std::vector<S>& attributes) {
    Hash hash("otac/issuance/20261108/open");
    bind_statement(hash, params, context, first, Y, request, attributes);
    hash.point(request.opening.A_R);
    hash.point(request.opening.A_V);
    return scheme::challenge128(hash);
}

inline S key_challenge(const scheme::Params& params, const Context& context, const Request& request,
                       const std::vector<S>& attributes) {
    Hash hash("otac/issuance/20261108/key");
    bind_statement(hash, params, context, true, request.key->Y, request, attributes);
    hash.point(request.key->A_x);
    return scheme::challenge128(hash);
}

inline Request cred_gen(const scheme::Params& params, const Context& context, bool first,
                        const S& secret, const std::vector<S>& attributes, scheme::Opening& opening) {
    require(secret != S() && attributes.size() == params.attrs.size(), "issuance inputs");
    opening = {attributes, S::random()};
    const G Y = pow(params.h0, secret);
    Request request;
    request.R = pow(Y, opening.r);
    request.V = pow(params.g, opening.r);

    const S nonce = S::random();
    request.opening.A_R = pow(Y, nonce);
    request.opening.A_V = pow(params.g, nonce);
    request.opening.response = nonce +
        opening_challenge(params, context, first, Y, request, attributes) * opening.r;
    if (first) {
        const S key_nonce = S::random();
        request.key = KeyProof{Y, pow(params.h0, key_nonce), S()};
        request.key->response = key_nonce + key_challenge(params, context, request, attributes) * secret;
    }
    return request;
}

// Sequential, in-process adapter. For first issuance, the application supplies
// attributes verified against the account's evidence. Only active records are modeled.
class Issuer {
public:
    Issuer(const scheme::Params& params, scheme::Ledger& ledger)
        : params_(params), ledger_(ledger) {}

    std::optional<scheme::Credential> issue(const Context& context, const std::string& payload,
                                           const std::vector<S>* audited_attributes = nullptr) {
        const bool first = records_.find(context.account) == records_.end();
        Request request;
        try {
            request = Request::from_payload(payload, first);
        } catch (const std::runtime_error&) {
            return std::nullopt;
        }
        return issue_parsed(context, request, audited_attributes);
    }

    std::optional<scheme::Credential> issue_parsed(
        const Context& context, const Request& request,
        const std::vector<S>* audited_attributes = nullptr, double* admission_ms = nullptr) {
        if (context.account.empty() || context.session.empty()) return std::nullopt;
        const auto record = records_.find(context.account);
        const bool first = record == records_.end();
        if (first != (audited_attributes != nullptr) || first != request.key.has_value()) {
            return std::nullopt;
        }
        const G& Y = first ? request.key->Y : record->second.Y;
        const auto& attributes = first ? *audited_attributes : record->second.attributes;
        if (Y.identity() || attributes.size() != params_.attrs.size()) return std::nullopt;

        const S c_r = opening_challenge(params_, context, first, Y, request, attributes);
        if (pow(Y, request.opening.response) != request.opening.A_R * pow(request.R, c_r) ||
            pow(params_.g, request.opening.response) != request.opening.A_V * pow(request.V, c_r)) {
            return std::nullopt;
        }
        if (first) {
            const S c_x = key_challenge(params_, context, request, attributes);
            if (pow(params_.h0, request.key->response) != request.key->A_x * pow(Y, c_x)) {
                return std::nullopt;
            }
        }

        const G commitment = request.V * params_.attr_product(attributes);
        scheme::Credential credential{commitment, scheme::sign(params_, commitment)};
        bool admitted;
        if (admission_ms) {
            *admission_ms = timed([&] { admitted = ledger_.register_issued(params_, credential); });
        } else {
            admitted = ledger_.register_issued(params_, credential);
        }
        if (!admitted) return std::nullopt;
        if (first) records_.emplace(context.account, Record{Y, attributes});
        return credential;
    }

private:
    struct Record {
        G Y;
        std::vector<S> attributes;
    };
    const scheme::Params& params_;
    scheme::Ledger& ledger_;
    std::map<std::string, Record> records_;
};

}  // namespace otac::issuance_v2
