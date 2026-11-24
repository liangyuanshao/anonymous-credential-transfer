"""Validate and summarize the P-256 single-operation measurements."""
import argparse
from collections import defaultdict
from itertools import product
import json
from pathlib import Path

import numpy as np

from result_io import load_csv, save_csv
from run_experiments import sha


def summaries(groups, expected, repetitions, seed):
    if set(groups) != expected:
        raise ValueError("Unexpected or missing measurement configurations")
    rng = np.random.default_rng(seed)
    for key in sorted(groups):
        readings = sorted(groups[key])
        if [row[0] for row in readings] != list(range(repetitions)):
            raise ValueError(f"Duplicate or missing repetitions for {key}")
        samples = np.array([row[1] for row in readings])
        if not np.all(np.isfinite(samples) & (samples > 0)):
            raise ValueError(f"Unusable measurements for {key}")
        indexes = rng.integers(0, repetitions, (10000, repetitions))
        low, high = np.percentile(np.median(samples[indexes], axis=1), [2.5, 97.5])
        yield key, dict(repetitions=repetitions, median_ms=float(np.median(samples)),
                        ci95_low_ms=float(low), ci95_high_ms=float(high))


def summarize(folder):
    env = json.loads((folder / "environment.json").read_text(encoding="utf-8"))
    data = ("issuance_timings.csv", "issuance_communication.csv", "presentation_transfer.csv")
    for name in data:
        if env["files"][name] != sha(folder / name):
            raise ValueError(f"Raw timing checksum mismatch: {name}")
    n_values = env["attribute_counts"]
    schemes = env["schemes"]
    ell_values = env["candidate_counts"]
    transfer_counts = env["transfer_attributes"]
    repetitions = env["repetitions"]
    native = env["native_parameters"]
    group, scalar = native["group_bytes"], native["scalar_bytes"]
    if (native["curve"], group, scalar) != ("prime256v1", 33, 32):
        raise ValueError("Unexpected serialized group parameters")

    issue_groups = defaultdict(list)
    for row in load_csv(folder / "issuance_timings.csv"):
        key = int(row["n"]), row["scheme"], row["mode"], row["role"]
        issue_groups[key].append((int(row["repetition"]), float(row["ms"])))
    modes = ("first", "repeat")
    issuance_cases = set(product(n_values, schemes, modes, ("holder", "issuer")))
    issuance_cases.update(product(n_values, ("OTAC",), modes, ("admit",)))
    issuance = [dict(n=n, scheme=s, mode=m, role=r, **values)
                for (n, s, m, r), values in summaries(issue_groups, issuance_cases, repetitions, 20261117)]
    save_csv(folder / "issuance_summary.csv", issuance)

    groups = defaultdict(list)
    message_sizes = defaultdict(set)
    for row in load_csv(folder / "presentation_transfer.csv"):
        key = int(row["n"]), row["scheme"], int(row["ell"]), row["operation"]
        if int(row["d"]) != env["matched_attributes"]:
            raise ValueError("Unexpected attribute disclosure count")
        groups[key].append((int(row["repetition"]), float(row["ms"])))
        if row["operation"] in ("show", "transfer"):
            message_sizes[key].add(tuple(int(row[field]) for field in (
                "payload_bytes", "wire_bytes", "private_bytes")))
    proof_cases = set(product(n_values, ("OTAC",), ell_values, ("show", "verify")))
    proof_cases.update(product(n_values, ("ACL", "UPROVE"), (0,), ("show", "verify")))
    proof_cases.update(product(transfer_counts, ("OTAC",), (64,), ("transfer", "verify_transfer")))
    proofs = [dict(n=n, scheme=s, ell=ell, operation=op, **values)
              for (n, s, ell, op), values in summaries(groups, proof_cases, repetitions, 20261118)]
    save_csv(folder / "presentation_transfer_summary.csv", proofs)

    sizes = []
    for row in load_csv(folder / "issuance_communication.csv"):
        n, scheme, mode = int(row["n"]), row["scheme"], row["mode"]
        if scheme == "OTAC":
            expected = ((8 * group + 3 * scalar, 2, 2 * group + scalar)
                        if mode == "first" else (6 * group + 2 * scalar, 2, 2 * group + scalar))
        elif scheme == "ACL":
            expected = ((5 * group + (n + 9) * scalar, 4, 2 * group + 6 * scalar + 32)
                        if mode == "first" else (3 * group + 7 * scalar, 3, 2 * group + 6 * scalar + 32))
        elif scheme == "UPROVE":
            expected = (3 * group + (n + 2 if mode == "first" else 2) * scalar,
                        4 if mode == "first" else 3, 2 * group + 3 * scalar + 30)
        else:
            raise ValueError(f"Unexpected issuance scheme: {scheme}")
        actual = tuple(int(row[field]) for field in (
            "bilateral_bytes", "user_issuer_messages", "public_credential_bytes"))
        if actual != expected:
            raise ValueError(f"Unexpected issuance encoding: {n}, {scheme}, {mode}, {actual}")
        # Ledger column is applicable only to the OTAC adapter.
        if int(row["ledger_bytes"]) != (2 * group + scalar if scheme == "OTAC" else 0):
            raise ValueError("Unexpected ledger admission payload")
        sizes.append((n, scheme, mode))
    if len(sizes) != len(n_values) * len(schemes) * len(modes) or set(sizes) != set(product(n_values, schemes, modes)):
        raise ValueError("Incomplete issuance sizes")

    communication = []
    for (n, scheme, ell, op), values in sorted(message_sizes.items()):
        if len(values) != 1:
            raise ValueError(f"Variable encoded size: n={n}, {scheme}, ell={ell}, {op}")
        payload, wire, private = next(iter(values))
        hidden = n - env["matched_attributes"]
        m = (ell - 1).bit_length() if ell else 0
        if scheme == "OTAC":
            expected = ((ell + 8*m + 7) * group + (3*m + n + 3) * scalar if op == "transfer"
                        else (ell + 8*m + 1) * group + (3*m + hidden + 1) * scalar)
            expected_private = group + (n + 1) * scalar if op == "transfer" else 0
            if (payload, wire, private) != (expected, expected + 12, expected_private):
                raise ValueError(f"Unexpected {op} encoding for n={n}, ell={ell}")
        else:
            overhead = 32 if scheme == "ACL" else scalar + 30
            expected = (4 * group + (hidden + 10) * scalar if scheme == "ACL"
                        else 2 * group + (hidden + 4) * scalar) + overhead
            if (payload, wire, private) != (expected, 0, 0):
                raise ValueError(f"Unexpected {scheme} response size for n={n}")
        communication.append(dict(n=n, scheme=scheme, ell=ell, operation=op,
                                  payload_bytes=payload, framed_bytes=wire or "",
                                  private_bytes=private, total_payload_bytes=payload + private))
    save_csv(folder / "presentation_transfer_communication.csv", communication)
    print(f"Checked {len(issuance)} issuance timings, {len(proofs)} proof timings "
          f"and {len(communication)} proof payload configurations")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    summarize(parser.parse_args().directory)
