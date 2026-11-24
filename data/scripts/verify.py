#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Verify the released CSVs with Python's standard library; write no files."""
from __future__ import annotations

import argparse
import csv
import hashlib
import itertools
import json
import math
from pathlib import Path
import re
import statistics
import sys


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_csv(path):
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def close(actual, expected, label, tolerance=1e-8):
    require(math.isfinite(actual) and abs(actual - expected) <= tolerance,
            f"{label}: got {actual!r}, expected {expected!r}")


def private_information_check(root):
    patterns = {
        "private home directory": re.compile(
            r"(?i)(?:[a-z]:[\\/](?:users|documents and settings)[\\/]"
            r"|/(?:home|users)/[a-z0-9_.-]+/)"),
        "email address": re.compile(r"[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}"),
        "SSH or SCP endpoint": re.compile(r"\b(?:ssh|scp)://", re.I),
    }
    for path in root.rglob("*"):
        require(not path.is_symlink(), f"Symlink is outside the release scope: {path.name}")
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        for label, pattern in patterns.items():
            require(not pattern.search(text), f"{label} found in {path.relative_to(root)}")


def verify_integrity(root, manifest_path=None):
    manifest = json.loads((manifest_path or root / "manifest.json").read_text(encoding="utf-8"))
    require(manifest["release_status"] in {"release-candidate", "published"}, "Unexpected release status")
    require(manifest["version"] == "1.0.0", "Unexpected dataset version")
    entries = manifest["files"]
    paths = [entry["path"] for entry in entries]
    require(len(paths) == len(set(paths)), "Duplicate manifest paths")
    expected = set(paths) | {"manifest.json", "SHA256SUMS"}
    actual = {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()}
    require(actual == expected, "Actual file inventory differs from the manifest")
    for entry in entries:
        path = root / entry["path"]
        require(path.resolve().is_relative_to(root.resolve()), "Path leaves the release directory")
        require(path.stat().st_size == entry["bytes"], f"Size mismatch: {entry['path']}")
        require(sha256(path) == entry["sha256"], f"SHA-256 mismatch: {entry['path']}")
        if entry["kind"] in {"raw_csv", "archived_processed_csv"}:
            require(entry["sha256"] == entry["original_sha256"],
                    f"Archived CSV was changed: {entry['path']}")
        if "rows" in entry:
            require(len(read_csv(path)) == entry["rows"], f"Row count mismatch: {entry['path']}")
    sums = {}
    for line in (root / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
        digest, name = line.split("  ", 1)
        require(name not in sums, "Duplicate SHA256SUMS entry")
        sums[name] = digest
    require(set(sums) == actual - {"SHA256SUMS"}, "SHA256SUMS inventory mismatch")
    for name, digest in sums.items():
        require(sha256(root / name) == digest, f"SHA256SUMS mismatch: {name}")
    raw_entries = [e for e in entries if e["kind"] == "raw_csv"]
    archived = [e for e in entries if e["kind"] == "archived_processed_csv"]
    require(len(raw_entries) == 8, "Expected eight byte-preserved raw CSVs")
    require(len(archived) == 11, "Expected eleven byte-preserved processed CSVs")
    raw = root / "data" / "raw"
    for folder in manifest["timing_runs"]:
        environment = json.loads(
            (root / "metadata" / f"{folder}.environment.json").read_text(encoding="utf-8"))
        require(environment["raw_sha256"] == sha256(raw / folder / "raw_timings.csv"),
                f"Environment/raw hash mismatch: {folder}")
    private_information_check(root)
    return {"files": len(actual), "raw_csvs": len(raw_entries),
            "archived_processed_csvs": len(archived), "private_information_scan": "passed"}


def verify_figure_2(root):
    folder = root / "data" / "raw" / "issuance-communication"
    old = read_csv(folder / "transcripts.csv")
    new = read_csv(folder / "transcripts-v2.csv")
    key = lambda row: (int(row["n"]), row["scheme"], row["mode"])
    old_map = {key(row): row for row in old}
    new_map = {key(row): row for row in new}
    expected = set(itertools.product(range(4, 65, 4),
                                     ("OTAC", "ACL", "UPROVE"), ("first", "repeat")))
    require(len(old) == len(new) == 96 and set(old_map) == set(new_map) == expected,
            "Unexpected issuance communication grid")
    for (n, scheme, mode), row in new_map.items():
        group, scalar = 66, 64
        credential = 2 * group + scalar
        acl_registration = 2 * group + (n + 2) * scalar
        if scheme == "OTAC":
            user = 6 * group + 2 * scalar if mode == "first" else 4 * group + scalar
            issuer, messages, ledger, ledger_messages, public = credential, 2, credential, 1, credential
        elif scheme == "ACL":
            user = scalar + (acl_registration if mode == "first" else 0)
            issuer, messages, ledger, ledger_messages, public = 3 * group + 6 * scalar, 4 if mode == "first" else 3, 0, 0, 2 * group + 6 * scalar + 32
        else:
            user = scalar + (n * scalar if mode == "first" else 0)
            issuer, messages, ledger, ledger_messages, public = 3 * group + scalar, 4 if mode == "first" else 3, 0, 0, 2 * group + 2 * scalar + 94
        values = (user, issuer, user + issuer, messages, ledger, ledger_messages, public)
        columns = ("user_to_issuer_bytes", "issuer_to_user_bytes", "bilateral_bytes",
                   "user_issuer_messages", "ledger_bytes", "ledger_messages", "public_credential_bytes")
        require(tuple(int(row[c]) for c in columns) == values, f"Communication formula mismatch: {n}/{scheme}/{mode}")
        if scheme != "OTAC":
            require(row == old_map[n, scheme, mode], "Archived baseline transcript changed")
    points = read_csv(root / "data" / "processed" / "figure_2_issuance.csv")
    mapping = {"otac_first": ("OTAC", "first"), "otac_repeat": ("OTAC", "repeat"),
               "acl_first": ("ACL", "first"), "acl_repeat": ("ACL", "repeat"),
               "uprove_submitted": ("UPROVE", "first"), "uprove_known": ("UPROVE", "repeat")}
    require([int(x["n"]) for x in points] == list(range(4, 65, 4)), "Figure 2 attribute grid")
    for row in points:
        for column, (scheme, mode) in mapping.items():
            require(int(row[column]) == int(new_map[int(row["n"]), scheme, mode]["bilateral_bytes"]),
                    "Figure 2 plotted payload differs from raw transcript")
    return {"transcripts_per_version": 96, "plotted_rows": len(points)}


def verify_figure_3(root):
    raw = root / "data" / "raw" / "issuance-first-v2-typef-20261117" / "raw_timings.csv"
    groups, repetitions = {}, {}
    rows = read_csv(raw)
    for row in rows:
        key = tuple(row[k] for k in ("n", "scheme", "mode", "role"))
        repetition = int(row["repetition"])
        require(0 <= repetition < 100, "Figure 3 repetition index")
        groups.setdefault(key, []).append(float(row["ms"]))
        repetitions.setdefault(key, set()).add(repetition)
    require(len(rows) == 22400 and len(groups) == 224, "Figure 3 raw grid")
    require(all(len(v) == 100 for v in groups.values()), "Figure 3 repetitions")
    require(all(v == set(range(100)) for v in repetitions.values()), "Figure 3 duplicate/missing repetitions")
    points = read_csv(root / "data" / "processed" / "figure_3_issuance_timings.csv")
    require(len(points) == 96, "Figure 3 plotted group count")
    point_keys = [tuple(r[k] for k in ("n", "scheme", "mode", "role")) for r in points]
    expected_keys = set(itertools.product(map(str, range(4, 65, 4)), ("OTAC", "ACL", "UPROVE"), ("first",), ("holder", "issuer")))
    require(len(set(point_keys)) == len(point_keys) and set(point_keys) == expected_keys, "Figure 3 duplicate/missing plotted groups")
    for row in points:
        key = tuple(row[k] for k in ("n", "scheme", "mode", "role"))
        require(row["mode"] == "first" and row["role"] in {"holder", "issuer"}, "Figure 3 selected role")
        close(statistics.median(groups[key]), float(row["median_ms"]), "Figure 3 median")
        require(row["source_csv_sha256"] == sha256(raw), "Figure 3 provenance")
    return {"raw_rows": len(rows), "medians_recomputed": len(points)}


def verify_figure_4(root):
    raw = root / "data" / "raw" / "presentation-oas3-20261110" / "raw_timings.csv"
    update = root / "data" / "raw" / "presentation-verify-window-20261116" / "raw_timings.csv"
    rows = read_csv(raw)
    changed = read_csv(update)
    require(len(rows) == 8100 and len(changed) == 1800, "Figure 4 raw row counts")
    groups = {}
    for row in rows:
        if row["implementation"] == "OAS2":
            continue
        scheme = "OTAC" if row["implementation"] == "OAS3" else row["implementation"]
        ell = row["ell"] if scheme == "OTAC" else ""
        key = row["n"], scheme, ell
        groups.setdefault(key + ("show",), []).append(float(row["sample_ms"]) + float(row["prove_ms"]))
        groups.setdefault(key + ("verify",), []).append(float(row["verify_ms"]))
    updates = {}
    for row in changed:
        updates.setdefault((row["n"], "OTAC", row["ell"], "verify"), []).append(float(row["verify_ms"]))
    points = read_csv(root / "data" / "processed" / "figure_4_presentation_timings.csv")
    require(len(points) == 160, "Figure 4 plotted group count")
    point_keys = [tuple(r[k] for k in ("n", "scheme", "ell", "operation")) for r in points]
    expected_keys = {(str(n), scheme, ell, operation) for n in range(4, 65, 4) for scheme, ell in [("OTAC", "32"), ("OTAC", "64"), ("OTAC", "128"), ("ACL", ""), ("UPROVE", "")] for operation in ("show", "verify")}
    require(len(set(point_keys)) == len(point_keys) and set(point_keys) == expected_keys, "Figure 4 duplicate/missing plotted groups")
    for row in points:
        key = tuple(row[k] for k in ("n", "scheme", "ell", "operation"))
        selected = update if key[1:] == ("OTAC", "64", "verify") else raw
        values = updates[key] if selected == update else groups[key]
        require(len(values) == 100, "Figure 4 repetitions")
        close(statistics.median(values), float(row["median_ms"]), "Figure 4 median")
        require(row["source_sha256"] == sha256(selected), "Figure 4 provenance")
    return {"raw_rows": len(rows), "verification_update_rows": len(changed),
            "medians_recomputed": len(points)}


def verify_table_iii(root):
    raw = root / "data" / "raw" / "attribute-scale-20261109" / "raw_timings.csv"
    groups, repetitions = {}, {}
    for row in read_csv(raw):
        if (row["experiment"] == "attributes" and row["scheme"] == "OTAC" and row["profile"] == "pbc-native"
                and row["ell"] == "64" and row["d"] == "2"
                and int(row["n"]) in range(8, 65, 8)
                and row["operation"] in {"transfer", "verify_transfer"}):
            key = int(row["n"]), row["operation"]
            groups.setdefault(key, []).append(float(row["ms"]))
            repetitions.setdefault(key, set()).add(int(row["repetition"]))
    expected = {"transfer": ["39.31", "43.23", "47.00", "50.89", "54.80", "58.59", "62.51", "66.30"],
                "verify_transfer": ["51.23", "54.36", "57.34", "60.78", "63.15", "65.39", "67.69", "69.96"]}
    rows = read_csv(root / "data" / "processed" / "table_iii_transfer.csv")
    require(len(rows) == len(groups) == 16, "Table III selected grid")
    require(all(v == set(range(100)) for v in repetitions.values()), "Table III duplicate/missing repetitions")
    selected_keys = set()
    for row in rows:
        key = int(row["n"]), row["operation"]
        require(key not in selected_keys, "Table III duplicate row")
        selected_keys.add(key)
        values = groups[key]
        require(len(values) == int(row["repetitions"]) == 100, "Table III repetitions")
        median = statistics.median(values)
        close(median, float(row["median_ms"]), "Table III median")
        require(f"{median:.2f}" == expected[key[1]][key[0] // 8 - 1], "Table III printed value")
        require(row["source_csv_sha256"] == sha256(raw), "Table III source hash")
    return {"selected_series": 16, "raw_measurements_used": 1600, "printed_cells_match": True}


def crossing(own, other):
    diff = [b - a for a, b in zip(own, other)]
    if diff[0] <= 0:
        return None, None
    for k in range(1, len(diff)):
        if diff[k] <= 0:
            value = k - 1 + diff[k - 1] / (diff[k - 1] - diff[k])
            return 100 * value / (len(diff) - 1), k - 1
    return None, None


def verify_figure_5(root, n):
    raw = root / "data" / "raw" / f"utilization-oas3-10000-20261110-n{n}" / "raw_timings.csv"
    processed = root / "data" / "processed"
    groups, count = {}, 0
    phases = ("holder_issue_ms", "issuer_issue_ms", "admit_ms", "show_ms", "verify_ms")
    with raw.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            count += 1
            key = int(row["batch"]), row["scheme"]
            group = groups.setdefault(key, {"sums": [0.0] * 5, "uses": [0.0] * 10001,
                                           "holders": [None] * 10001, "orders": set(), "registration": 0.0})
            used, holder = int(row["use_order"]), int(row["holder"])
            require(1 <= used <= 10000 and 0 <= holder < 10000, "Utilization synthetic indices")
            require(group["holders"][used] is None, "Duplicate utilization use order")
            group["holders"][used] = holder
            group["orders"].add(int(row["scheme_order"]))
            times = [float(row[k]) for k in phases]
            require(all(math.isfinite(v) and v >= 0 for v in times), "Invalid utilization timing")
            require(all(times[i] > 0 for i in (0, 1, 3, 4)), "Nonpositive utilization phase")
            require(times[2] > 0 if row["scheme"] == "OTAC" else times[2] == 0, "Unexpected admission phase")
            for i, value in enumerate(times):
                group["sums"][i] += value
            group["uses"][used] = times[3] + times[4]
            group["registration"] += float(row["acl_holder_registration_ms"]) + float(row["acl_issuer_registration_ms"])
    schemes = ("OTAC", "ACL", "UPROVE")
    require(count == 180000 and set(groups) == set(itertools.product(range(6), schemes)), "Utilization grid")
    curves = {s: [0.0] * 10001 for s in schemes}
    phase_means = {s: [0.0] * 5 for s in schemes}
    orders = set()
    registration = 0.0
    for batch in range(6):
        order = []
        reference = groups[batch, "OTAC"]["holders"]
        require(set(reference[1:]) == set(range(10000)), "Utilization holder permutation")
        for scheme in schemes:
            group = groups[batch, scheme]
            require(group["holders"] == reference, "Schemes do not share presentation order")
            require(len(group["orders"]) == 1, "Scheme order changes within a batch")
            order.append(next(iter(group["orders"])))
            running = sum(group["sums"][:3])
            for k in range(10001):
                running += group["uses"][k]
                curves[scheme][k] += running / 60000
            for i, value in enumerate(group["sums"]):
                phase_means[scheme][i] += value / 60000
            if scheme == "ACL":
                registration += group["registration"] / 60000
        orders.add(tuple(order))
    require(orders == set(itertools.permutations(range(3))), "Paired-batch execution order")
    phase_rows = read_csv(processed / f"figure_5_n{n}_phase_means.csv")
    require(len(phase_rows) == len(schemes) and {r["scheme"] for r in phase_rows} == set(schemes), "Duplicate/missing phase means")
    for row in phase_rows:
        values = phase_means[row["scheme"]]
        for column, actual in zip(phases, values):
            close(actual, float(row[column]), f"n={n} phase mean")
        close(sum(values[:3]), float(row["issuance_ms"]), "Issuance phase total")
        close(sum(values[3:]), float(row["use_ms"]), "Presentation phase total")
    points = read_csv(processed / f"figure_5_n{n}_workload_curves.csv")
    require(len(points) == 30003, "Figure 5 cumulative point count")
    seen, maximum_error = set(), 0.0
    for row in points:
        key = row["scheme"], int(row["used"])
        require(key not in seen, "Duplicate cumulative curve point")
        seen.add(key)
        actual = curves[key[0]][key[1]]
        expected = float(row["ms_per_issued"])
        close(actual, expected, f"n={n} cumulative point")
        maximum_error = max(maximum_error, abs(actual - expected))
        close(key[1] / 100, float(row["use_pct"]), "Use percentage")
        require(float(row["ci95_low_ms"]) <= expected <= float(row["ci95_high_ms"]), "Cumulative interval ordering")
    require(seen == set(itertools.product(schemes, range(10001))), "Incomplete cumulative curves")
    curves["ACL_REUSE"] = [value - registration for value in curves["ACL"]]
    threshold_rows = read_csv(processed / f"figure_5_n{n}_break_even.csv")
    require(len(threshold_rows) == 3, "Duplicate/missing threshold rows")
    thresholds = {x["baseline"]: x for x in threshold_rows}
    require(set(thresholds) == {"ACL", "UPROVE", "ACL_REUSE"}, "Break-even baseline set")
    result = {}
    for scheme, row in thresholds.items():
        pct, before = crossing(curves["OTAC"], curves[scheme])
        if pct is None:
            require(row["break_even_pct"] == "" and row["cheaper_use_count"] == "", "Unexpected crossing")
            continue
        close(pct, float(row["break_even_pct"]), f"n={n} {scheme} break-even percentage")
        require(int(row["cheaper_use_count"]) == before and int(row["next_use_count"]) == before + 1,
                "Break-even adjacent actual presentation counts")
        close(100 / pct, float(row["issued_per_used"]), "Issued-to-used ratio")
        zero = curves[scheme][0] - curves["OTAC"][0]
        final = curves[scheme][-1] - curves["OTAC"][-1]
        model = 100 * zero / (zero - final)
        close(model, float(row["model_pct"]), "Linear-model percentage")
        close(100 * zero / curves[scheme][0], float(row["saving_at_zero_pct"]), "Zero-use savings")
        if scheme in {"ACL", "UPROVE"}:
            result[scheme] = {"break_even_pct": pct, "cheaper_through": before, "exceeds_at": before + 1}
    savings = read_csv(processed / f"figure_5_n{n}_savings.csv")
    require(len(savings) == 30003, "Savings point count")
    seen_savings = set()
    for row in savings:
        baseline, k = row["baseline"], int(row["used"])
        require((baseline, k) not in seen_savings, "Duplicate savings point")
        seen_savings.add((baseline, k))
        require(baseline in thresholds and 0 <= k <= 10000, "Invalid savings grid")
        close(k / 100, float(row["use_pct"]), "Savings use percentage")
        actual = 100 * (curves[baseline][k] - curves["OTAC"][k]) / curves[baseline][k]
        close(actual, float(row["saved_pct"]), f"n={n} savings")
    require(seen_savings == set(itertools.product(thresholds, range(10001))), "Incomplete savings grid")
    return {"raw_rows": count, "paired_batches": 6, "points_per_scheme": 10001,
            "cumulative_points_recomputed": len(points), "savings_points_recomputed": len(savings),
            "maximum_cumulative_error_ms": maximum_error, "break_even": result}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-root", type=Path, help="Release directory; defaults to the parent of scripts/.")
    parser.add_argument("--manifest", type=Path, help="Explicit manifest.json in the release root.")
    args = parser.parse_args()
    root = (args.input_root or (args.manifest.parent if args.manifest else Path(__file__).resolve().parents[1])).resolve()
    manifest_path = args.manifest.resolve() if args.manifest else root / "manifest.json"
    require(manifest_path == root / "manifest.json", "Manifest must be manifest.json in the selected release root")
    report = {"status": "passed", "integrity": verify_integrity(root, manifest_path),
              "figure_2": verify_figure_2(root), "figure_3": verify_figure_3(root),
              "figure_4": verify_figure_4(root), "table_iii": verify_table_iii(root),
              "figure_5_n16": verify_figure_5(root, 16), "figure_5_n32": verify_figure_5(root, 32),
              "confidence_intervals": "Archived values are hash-checked; bootstrap intervals are not recomputed."}
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError) as error:
        print(f"FAILED: {error}", file=sys.stderr)
        sys.exit(1)
