#pragma once
#include <array>

namespace otac {
inline constexpr int default_candidate_count = 64;
inline constexpr int default_attribute_count = 2;
inline constexpr int default_match_count = 2;
inline constexpr int max_benchmark_attribute_count = 5;
inline constexpr int wide_match_attribute_count = 32;
inline constexpr std::array<int, 16> wide_attribute_counts{4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 56, 60, 64};
inline constexpr std::array<int, 6> wide_match_counts{1, 2, 4, 8, 16, 32};
}
