"""Check the single-credential issuance transcripts and render the PGFPlots figure."""

import argparse
import csv
from pathlib import Path

from benchmark_config import WIDE_ATTRIBUTE_COUNTS
from figure_support import render


ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results" / "issuance-communication"
FIGURES = ROOT / "figures" / "issuance-communication"


def read_csv(path):
    with path.open(encoding="utf-8", newline="") as source:
        return list(csv.DictReader(source))


def check_sizes(n, measurements, archived):
    group, scalar = 66, 64
    credential = 2 * group + scalar
    acl_registration = 2 * group + (n + 2) * scalar
    # User bytes, issuer bytes, bilateral messages, ledger bytes and messages, credential bytes.
    acl_core = (scalar, 3 * group + 6 * scalar, 3, 0, 0, 2 * group + 6 * scalar + 32)
    uprove_core = (scalar, 3 * group + scalar, 3, 0, 0, 2 * group + 2 * scalar + 94)
    ours_first = (6 * group + 2 * scalar, credential, 2, credential, 1, credential)
    ours_repeat = (4 * group + scalar, credential, 2, credential, 1, credential)
    expected = {
        ("OTAC", "first"): ours_first,
        ("OTAC", "repeat"): ours_repeat,
        ("ACL", "first"): (acl_core[0] + acl_registration, acl_core[1], 4, *acl_core[3:]),
        ("ACL", "repeat"): acl_core,
        ("UPROVE", "first"): (uprove_core[0] + n * scalar, uprove_core[1], 4, *uprove_core[3:]),
        ("UPROVE", "repeat"): uprove_core,
    }
    fields = ("user_to_issuer_bytes", "issuer_to_user_bytes", "user_issuer_messages",
              "ledger_bytes", "ledger_messages", "public_credential_bytes")
    totals = {}
    for (scheme, mode), sizes in expected.items():
        row = measurements[n, scheme, mode]
        actual = tuple(int(row[field]) for field in fields)
        bilateral = int(row["bilateral_bytes"])
        if actual != sizes or bilateral != sum(actual[:2]):
            raise ValueError(f"Inconsistent transcript sizes: n={n}, {scheme}, {mode}")
        if scheme != "OTAC" and row != archived[n, scheme, mode]:
            raise ValueError(f"Archived baseline mismatch: n={n}, {scheme}, {mode}")
        totals[scheme, mode] = bilateral
    return [n, totals["OTAC", "first"], totals["OTAC", "repeat"],
            totals["ACL", "first"], totals["ACL", "repeat"],
            totals["UPROVE", "first"], totals["UPROVE", "repeat"]]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--transcripts", type=Path, default=RESULTS / "transcripts-v2.csv")
    args = parser.parse_args()
    rows = read_csv(args.transcripts)
    measurements = {(int(row["n"]), row["scheme"], row["mode"]): row for row in rows}
    expected = {(n, scheme, mode) for n in WIDE_ATTRIBUTE_COUNTS
                for scheme in ("OTAC", "ACL", "UPROVE") for mode in ("first", "repeat")}
    if len(rows) != len(expected) or measurements.keys() != expected:
        raise ValueError("Expected exactly one first and one repeat transcript per scheme and attribute count")

    archived = {(int(row["n"]), row["scheme"], row["mode"]): row
                for row in read_csv(RESULTS / "transcripts.csv")}
    points = [check_sizes(n, measurements, archived) for n in WIDE_ATTRIBUTE_COUNTS]
    with (FIGURES / "issuance_plot.csv").open("w", encoding="utf-8", newline="") as target:
        writer = csv.writer(target, lineterminator="\n")
        writer.writerow(("n", "otac_first", "otac_repeat", "acl_first", "acl_repeat",
                         "uprove_submitted", "uprove_known"))
        writer.writerows(points)
    print(f"Verified {len(rows)} transcripts against the payload formulas and the previous baseline run")
    render(FIGURES, "issuance")


if __name__ == "__main__":
    main()
