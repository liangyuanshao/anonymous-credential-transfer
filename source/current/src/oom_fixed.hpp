#pragma once
#include "core.hpp"

namespace otac::scheme::oom_fixed {

// A public-base comb with eight teeth and four blocks of columns.
// Each block has its own shifted subset table so evaluation shares doublings.
class Comb {
 static constexpr size_t teeth = 8;
 static constexpr size_t blocks = 4;
 const size_t columns = (size_t(order_bits) + teeth - 1) / teeth;
 const size_t block_columns = (columns + blocks - 1) / blocks;
 std::array<std::vector<G>, blocks> table;

public:
 explicit Comb(const G& base) {
  for (auto& block : table) {
   block.reserve(size_t(1) << teeth);
   block.emplace_back();
  }
  curve_ops::Workspace workspace(base.v);
  curve_ops::Point shifted(curve_ops::point_field(base.v));
  shifted.assign(base.v);
  size_t shift = 0;
  for (size_t tooth = 0; tooth < teeth; ++tooth) {
   for (size_t block = 0; block < blocks && block * block_columns < columns; ++block) {
    const size_t target = tooth * columns + block * block_columns;
    while (shift < target) {
     shifted.twice(workspace);
     ++shift;
    }
    G anchor;
    shifted.write(anchor.v, workspace);
    auto& entries = table[block];
    const size_t previous = entries.size();
    for (size_t i = 0; i < previous; ++i) entries.push_back(entries[i] * anchor);
   }
  }
 }

 G power(const S& scalar) const {
  G result;
  curve_ops::Workspace workspace(result.v);
  curve_ops::Point accumulator(curve_ops::point_field(result.v));
  for (size_t offset = block_columns; offset-- > 0;) {
   accumulator.twice(workspace);
   for (size_t block = 0; block < blocks; ++block) {
    const size_t column = block * block_columns + offset;
    if (column >= columns) break;
    unsigned index = 0;
    for (size_t tooth = 0; tooth < teeth; ++tooth) {
     index |= unsigned(mpz_tstbit(scalar.v, tooth * columns + column)) << tooth;
    }
    accumulator.add_affine(table[block][index].v, workspace);
   }
  }
  accumulator.write(result.v, workspace);
  return result;
 }
};

} // namespace otac::scheme::oom_fixed
