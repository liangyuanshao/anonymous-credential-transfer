"""Read the shared C++ benchmark defaults."""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
HEADER = (ROOT/"src/benchmark_defaults.hpp").read_text(encoding="utf-8")


def read_default(name):
    match = re.search(rf"\b{name}\s*=\s*(\d+)\s*;", HEADER)
    if match is None:
        raise ValueError(f"Missing benchmark default {name}")
    return int(match.group(1))


def read_counts(name):
    match = re.search(rf"\b{name}\s*\{{\s*(\d+(?:\s*,\s*\d+)*\s*,?)\s*\}}\s*;", HEADER)
    if match is None:
        raise ValueError(f"Missing benchmark counts {name}")
    counts = tuple(map(int, re.findall(r"\d+", match[1])))
    if counts[0] < 1 or counts != tuple(sorted(set(counts))):
        raise ValueError(f"Expected increasing positive counts for {name}")
    return counts


DEFAULT_ELL = read_default("default_candidate_count")
DEFAULT_N = read_default("default_attribute_count")
DEFAULT_D = read_default("default_match_count")
MAX_BENCHMARK_N = read_default("max_benchmark_attribute_count")
WIDE_MATCH_N = read_default("wide_match_attribute_count")
WIDE_ATTRIBUTE_COUNTS = read_counts("wide_attribute_counts")
WIDE_MATCH_COUNTS = read_counts("wide_match_counts")
if DEFAULT_ELL < 2 or DEFAULT_ELL & (DEFAULT_ELL-1):
    raise ValueError("Candidate count must be a power of two")
if not 1 <= DEFAULT_D <= DEFAULT_N:
    raise ValueError("Invalid default attribute counts")
if MAX_BENCHMARK_N < DEFAULT_N:
    raise ValueError("Invalid maximum attribute count")
if (WIDE_ATTRIBUTE_COUNTS[0] < DEFAULT_D
        or WIDE_MATCH_N not in WIDE_ATTRIBUTE_COUNTS
        or DEFAULT_D not in WIDE_MATCH_COUNTS
        or WIDE_MATCH_COUNTS[-1] > WIDE_MATCH_N):
    raise ValueError("Invalid wide attribute or match counts")

ATTRIBUTE_COUNTS = tuple(range(DEFAULT_N, MAX_BENCHMARK_N + 1))
MATCH_COUNTS = tuple(range(1, MAX_BENCHMARK_N + 1))
