#pragma once
#include "core.hpp"

namespace otac::scheme::oom_windows {

// A width-five signed representation uses odd digits from -15 to 15.
// The tables are local to one OoM call and use the existing PBC point code.
using Digits = std::vector<int8_t>;
inline constexpr size_t max_interleaved_terms = 128;
inline Digits recode(const S& scalar) {
 S remaining = scalar;
 Digits digits;
 digits.reserve(mpz_sizeinbase(remaining.v, 2) + 1);
 while (mpz_sgn(remaining.v) != 0) {
  int digit = 0;
  if (mpz_odd_p(remaining.v)) {
   digit = int(mpz_fdiv_ui(remaining.v, 32));
   if (digit >= 16) digit -= 32;
   if (digit > 0) mpz_sub_ui(remaining.v, remaining.v, unsigned(digit));
   else mpz_add_ui(remaining.v, remaining.v, unsigned(-digit));
  }
  digits.push_back(int8_t(digit));
  mpz_fdiv_q_2exp(remaining.v, remaining.v, 1);
 }
 return digits;
}

struct OddPowers {
 std::array<G, 8> positive, negative;

 explicit OddPowers(const G& base) {
  positive.front() = base;
  const G twice = base * base;
  for (size_t i = 1; i < positive.size(); ++i) positive[i] = positive[i-1] * twice;
  for (size_t i = 0; i < positive.size(); ++i) negative[i] = inv(positive[i]);
 }

 const G& at(int digit) const {
  return digit > 0 ? positive[size_t(digit / 2)] : negative[size_t(-digit / 2)];
 }
};

inline G power(const OddPowers& powers, const Digits& digits) {
 G result;
 curve_ops::Workspace scratch(result.v);
 curve_ops::Point sum(curve_ops::point_field(result.v));
 for (auto it = digits.rbegin(); it != digits.rend(); ++it) {
  sum.twice(scratch);
  if (*it != 0) sum.add_affine(powers.at(*it).v, scratch);
 }
 sum.write(result.v, scratch);
 return result;
}

template<class Lookup>
inline G interleave(const std::vector<S>& exponents, Lookup lookup) {
 std::vector<std::pair<const OddPowers*, Digits>> terms;
 terms.reserve(exponents.size());
 size_t width = 0;
 for (size_t i = 0; i < exponents.size(); ++i) {
  if (mpz_sgn(exponents[i].v) == 0) continue;
  const OddPowers* powers = lookup(i);
  if (powers == nullptr) continue;
  auto digits = recode(exponents[i]);
  width = std::max(width, digits.size());
  terms.emplace_back(powers, std::move(digits));
 }
 G result;
 curve_ops::Workspace scratch(result.v);
 curve_ops::Point sum(curve_ops::point_field(result.v));
 for (size_t bit = width; bit > 0; --bit) {
  sum.twice(scratch);
  for (const auto& [powers, digits] : terms) {
   if (bit <= digits.size() && digits[bit-1] != 0) {
    sum.add_affine(powers->at(digits[bit-1]).v, scratch);
   }
  }
 }
 sum.write(result.v, scratch);
 return result;
}

inline G product(const std::vector<G>& bases, const std::vector<S>& exponents) {
 require(bases.size() == exponents.size(), "OoM product length mismatch");
 if (bases.size() > max_interleaved_terms) return msm(bases, exponents);

 std::vector<OddPowers> powers;
 powers.reserve(bases.size());
 return interleave(exponents, [&](size_t i) -> const OddPowers* {
  if (bases[i].identity()) return nullptr;
  return &powers.emplace_back(bases[i]);
 });
}

// One proof evaluates two products with the same public attribute bases.
class AttributeProducts {
 const std::vector<G>& bases;
 std::vector<OddPowers> powers;

public:
 explicit AttributeProducts(const std::vector<G>& attributes) : bases(attributes) {
  if (bases.size() <= max_interleaved_terms) {
   powers.reserve(bases.size());
   for (const auto& base : bases) powers.emplace_back(base);
  }
 }

 G full(const std::vector<S>& exponents) const {
  require(exponents.size() == bases.size(), "attribute product length mismatch");
  if (powers.empty()) return msm(bases, exponents);
  return interleave(exponents, [&](size_t i) { return &powers[i]; });
 }

 G subset(const std::vector<int>& indices, const std::vector<S>& exponents) const {
  require(exponents.size() == indices.size(), "attribute subset length mismatch");
  if (!powers.empty()) {
   return interleave(exponents, [&](size_t i) { return &powers.at(size_t(indices[i])); });
  }
  std::vector<G> selected;
  selected.reserve(indices.size());
  for (int i : indices) selected.push_back(bases.at(size_t(i)));
  return product(selected, exponents);
 }
};

} // namespace otac::scheme::oom_windows
