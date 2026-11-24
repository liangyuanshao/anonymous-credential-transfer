"""Prepare the PGFPlots comparison of three candidate-list sizes."""

import argparse
import json
import math
from pathlib import Path

import numpy as np

from benchmark_config import DEFAULT_D, DEFAULT_ELL, WIDE_ATTRIBUTE_COUNTS
from figure_support import END, PREAMBLE, ROOT, dat, plot_table, sha
from plot_issuance_timing import read_presentation_summary
from plot_results import relative
from result_io import load_csv, save_csv


STEM = "figure_3_presentation_by_candidates"
OPERATIONS = ("show", "verify")
NEW_SIZES = (32, 128)
STYLES = (
    ("OTAC", 32, "greenSmall,densely dashed,mark=diamond*", r"This work, $\ell=32$"),
    ("ACL", None, "acl,densely dashed,mark=square*", "ACL"),
    ("OTAC", 64, "greenDefault,solid,mark=*", r"This work, $\ell=64$"),
    ("UPROVE", None, "uprove,dash dot,mark=triangle*", "U-Prove"),
    ("OTAC", 128, "greenLarge,densely dotted,mark=+", r"This work, $\ell=128$"),
)


def measure_summary(source, expected, env):
    digest = sha(source)
    if digest != env["raw_sha256"][source.name]:
        raise ValueError(f"Unexpected checksum for {source}")
    groups = {key: {} for key in expected}
    for row in load_csv(source):
        n, ell, d, repetition = (int(row[key]) for key in ("n", "ell", "d", "repetition"))
        group = groups[n, ell]
        if d != DEFAULT_D or repetition in group:
            raise ValueError(f"Duplicate repetition or mismatched request: {row}")
        group[repetition] = [float(row[op + "_ms"]) for op in OPERATIONS]
    count = env["repetitions"]
    summary = {}
    for n, ell in sorted(groups):
        group = groups[n, ell]
        if sorted(group) != list(range(count)):
            raise ValueError(f"Incomplete repetitions for n={n}, ell={ell}")
        times = np.array([group[i] for i in range(count)])
        if not np.all(np.isfinite(times) & (times > 0)):
            raise ValueError(f"Invalid timing for n={n}, ell={ell}")
        rng = np.random.default_rng(20261109 + 1000 * ell + n)
        samples = rng.integers(0, count, size=(10000, count))
        medians = np.median(times[samples], axis=1)
        low, high = np.percentile(medians, [2.5, 97.5], axis=0)
        for i, op in enumerate(OPERATIONS):
            summary[n, "OTAC", ell, op] = dict(
                n=n, scheme="OTAC", ell=ell, operation=op, d=DEFAULT_D,
                repetitions=count, median_ms=float(np.median(times[:, i])),
                ci95_low_ms=float(low[i]), ci95_high_ms=float(high[i]),
                source=relative(source), source_sha256=digest,
            )
    return summary


def archived_series(path, env):
    if sha(path.with_name("raw_timings.csv")) != env["archived_comparison_sha256"]:
        raise ValueError(f"Unexpected raw comparison archive for {path}")
    rows = {}
    for (n, scheme, op), row in read_presentation_summary(path).items():
        if row["source_csv_sha256"] != env["archived_comparison_sha256"]:
            raise ValueError(f"Unexpected archived comparison source: {(n, scheme, op)}")
        ell = DEFAULT_ELL if scheme == "OTAC" else None
        rows[n, scheme, ell, op] = dict(
            n=n, scheme=scheme, ell=ell, operation=op, d=DEFAULT_D,
            repetitions=row["repetitions"], median_ms=row["median_ms"],
            ci95_low_ms=row["ci95_low_ms"], ci95_high_ms=row["ci95_high_ms"],
            source=row["source_csv"], source_sha256=row["source_csv_sha256"],
        )
    return rows


def integrated_series(folder, env):
    source = folder / "raw_timings.csv"
    digest = sha(source)
    if digest != env["raw_sha256"]:
        raise ValueError(f"Unexpected checksum for {source}")
    counts = tuple(WIDE_ATTRIBUTE_COUNTS)
    ell_values = (32, 64, 128)
    if (tuple(env["attribute_counts"]), tuple(env["ell"])) != (counts, ell_values):
        raise ValueError("Unexpected OAS3 attribute or candidate grid")
    count = env["repetitions"]
    paired = env["paired_configuration"]
    if paired != {"n": 32, "ell": 64, "d": DEFAULT_D}:
        raise ValueError("Unexpected paired configuration")
    groups = {(n, "OAS3", ell): {} for n in counts for ell in ell_values}
    groups.update({(n, scheme, 0): {} for n in counts for scheme in ("ACL", "UPROVE")})
    groups[32, "OAS2", 64] = {}
    for row in load_csv(source):
        n, ell, d, repetition, order = (int(row[key]) for key in ("n", "ell", "d", "repetition", "order"))
        implementation = row["implementation"]
        key = n, implementation, ell
        if key not in groups or d != DEFAULT_D or repetition in groups[key]:
            raise ValueError(f"Unexpected or duplicate measurement: {row}")
        if key in ((32, "OAS2", 64), (32, "OAS3", 64)):
            expected_order = (repetition + (implementation == "OAS3")) % 2
        else:
            expected_order = -1
        if order != expected_order:
            raise ValueError(f"Unexpected measurement order: {row}")
        sample, prove, verify = (float(row[key]) for key in ("sample_ms", "prove_ms", "verify_ms"))
        if not (math.isfinite(sample) and math.isfinite(prove) and math.isfinite(verify)
                and prove > 0 and verify > 0 and (sample > 0 if ell else sample == 0)):
            raise ValueError(f"Invalid timing values: {row}")
        groups[key][repetition] = (sample, prove, verify)
    groups = {key: [group[i] for i in range(count)] if set(group) == set(range(count)) else []
              for key, group in groups.items()}
    if not all(groups.values()):
        raise ValueError("Incomplete presentation measurements")

    rows = {}
    for (n, implementation, ell), group in groups.items():
        if implementation == "OAS2":
            continue
        scheme = "OTAC" if implementation == "OAS3" else implementation
        plotted_ell = ell or None
        values = np.array([(sample + prove, verify) for sample, prove, verify in group])
        rng = np.random.default_rng(20261110 + 1000 * ell + n)
        draws = rng.integers(0, count, size=(10000, count))
        low, high = np.percentile(np.median(values[draws], axis=1), [2.5, 97.5], axis=0)
        for index, op in enumerate(OPERATIONS):
            rows[n, scheme, plotted_ell, op] = dict(
                n=n, scheme=scheme, ell=plotted_ell, operation=op, d=DEFAULT_D,
                repetitions=count, median_ms=float(np.median(values[:, index])),
                ci95_low_ms=float(low[index]), ci95_high_ms=float(high[index]),
                source=relative(source), source_sha256=digest,
            )

    old = np.array(groups[32, "OAS2", 64])
    new = np.array(groups[32, "OAS3", 64])
    if not np.array_equal(old[:, 0], new[:, 0]):
        raise ValueError("The paired implementations did not share candidate sampling")
    old = np.column_stack((old, old[:, 0] + old[:, 1]))
    new = np.column_stack((new, new[:, 0] + new[:, 1]))
    delta = old - new
    rng = np.random.default_rng(20261110)
    draws = rng.integers(0, count, size=(10000, count))
    low, high = np.percentile(np.median(delta[draws], axis=1), [2.5, 97.5], axis=0)
    paired_rows = [dict(operation=op, repetitions=count, oas2_median_ms=float(np.median(old[:, i])),
                        oas3_median_ms=float(np.median(new[:, i])),
                        paired_saving_median_ms=float(np.median(delta[:, i])),
                        ci95_saving_low_ms=float(low[i]), ci95_saving_high_ms=float(high[i]),
                        source=relative(source), source_sha256=digest)
                   for i, op in enumerate(("sample", "prove", "verify", "show"))]
    return rows, paired_rows


def updated_verification(folder, reference):
    env = json.loads((folder / "environment.json").read_text(encoding="utf-8"))
    if not env["complete"] or (env["repetitions"], env["warmups"], env["d"], env["ell"]) != (100, 3, DEFAULT_D, [DEFAULT_ELL]):
        raise ValueError("Incomplete or incompatible verification run")
    if env["previous_raw_sha256"] != reference["raw_sha256"]:
        raise ValueError("Verification rerun is linked to a different reference run")
    source = folder / "raw_timings.csv"
    digest = sha(source)
    if digest != env["raw_sha256"]:
        raise ValueError(f"Unexpected checksum for {source}")

    plotted_counts = set(WIDE_ATTRIBUTE_COUNTS)
    counts = env["attribute_counts"]
    measured_counts = set(counts)
    paired_counts = set(env["paired_attribute_counts"])
    if (len(counts) != len(measured_counts)
            or not plotted_counts <= measured_counts <= plotted_counts | {58, 59}
            or not {56, 60, 64} <= paired_counts <= measured_counts):
        raise ValueError("Unexpected verification attribute grid")

    groups = {n: {} for n in counts}
    count = env["repetitions"]
    for row in load_csv(source):
        n, ell, d, repetition, order = (int(row[key]) for key in ("n", "ell", "d", "repetition", "order"))
        if n not in groups or ell != DEFAULT_ELL or d != DEFAULT_D or repetition in groups[n]:
            raise ValueError(f"Unexpected or duplicate verification measurement: {row}")
        if order not in ((0, 1) if n in paired_counts else (-1,)):
            raise ValueError(f"Invalid verification order: {row}")
        verify = float(row["verify_ms"])
        old_verify = float(row["old_verify_ms"] or "0")
        if not (math.isfinite(verify) and verify > 0 and math.isfinite(old_verify)
                and (old_verify > 0 if n in paired_counts else old_verify == 0)):
            raise ValueError(f"Invalid verification time: {row}")
        groups[n][repetition] = (verify, order)

    rows = {}
    for n, group in sorted(groups.items()):
        if sorted(group) != list(range(count)):
            raise ValueError(f"Incomplete verification repetitions for n={n}")
        if n in paired_counts and any(group[i][1] != (group[0][1] + i) % 2 for i in range(count)):
            raise ValueError(f"Nonalternating verification order for n={n}")
        if n not in plotted_counts:
            continue
        values = np.array([group[i][0] for i in range(count)])
        rng = np.random.default_rng(20261110 + 1000 * DEFAULT_ELL + n)
        draws = rng.integers(0, count, size=(10000, count))
        low, high = np.percentile(np.median(values[draws], axis=1), [2.5, 97.5])
        rows[n, "OTAC", DEFAULT_ELL, "verify"] = dict(
            n=n, scheme="OTAC", ell=DEFAULT_ELL, operation="verify", d=DEFAULT_D,
            repetitions=count, median_ms=float(np.median(values)),
            ci95_low_ms=float(low), ci95_high_ms=float(high),
            source=relative(source), source_sha256=digest,
        )
    return rows


def draw(folder, rows):
    ticks = ",".join(map(str, WIDE_ATTRIBUTE_COUNTS))
    upper = 20 * math.ceil(max(float(r["ci95_high_ms"]) for r in rows.values()) * 1.06 / 20)
    body = [
        r"\begin{groupplot}[group style={group size=2 by 1,horizontal sep=17mm},"
        r"paper,scale only axis,width=73mm,height=44mm,xmin=1,xmax=67,"
        f"xtick={{{ticks}}},xlabel={{Total attributes, $n$}},ymin=0,ymax={upper},ytick distance=20,"
        r"xmajorgrids=false,xticklabel style={font=\tiny}]"
    ]
    for index, op in enumerate(OPERATIONS):
        title = ("Presentation generation", "Presentation verification")[index]
        options = f"title={{\\textbf{{{'ab'[index]}}}\\quad {title}}}"
        if index == 0:
            options += r",legend style={at={(0,1.23)},anchor=south west,legend columns=2}"
        body.append(f"\\nextgroupplot[{options}]")
        for scheme, ell, style, label in STYLES:
            color = style.split(",", 1)[0]
            points = []
            for n in WIDE_ATTRIBUTE_COUNTS:
                row = rows[n, scheme, ell, op]
                points.append((n, dict(median=float(row["median_ms"]),
                                       low=float(row["ci95_low_ms"]),
                                       high=float(row["ci95_high_ms"]))))
            name = f"{STEM}_{op}_{scheme}" + (f"_{ell}" if ell else "")
            body.append(plot_table(dat(folder, name, points),
                                   f"color={style},mark options={{solid,draw={color},fill={color}}},"
                                   "mark size=1.45pt,line width=.95pt,err").rstrip())
            if index == 0:
                body.append(rf"\addlegendentry{{{label}}}")
    body.append(r"\end{groupplot}")
    colors = r"""\definecolor{greenSmall}{RGB}{71,148,94}
\definecolor{greenDefault}{RGB}{32,128,79}
\definecolor{greenLarge}{RGB}{19,94,58}
"""
    preamble = PREAMBLE.replace(r"\begin{document}", colors + r"\begin{document}")
    (folder / (STEM + ".tex")).write_text(
        preamble + "\n".join(body) + "\n" + END, encoding="utf-8", newline="\n"
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--measured", type=Path, required=True)
    parser.add_argument("--archive", type=Path,
                        default=ROOT / "results/attribute-scale-20261109/summary.csv")
    parser.add_argument("--verify-update", type=Path,
                        help="Remeasurement of OTAC verification at the default candidate count")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    env = json.loads((args.measured / "environment.json").read_text(encoding="utf-8"))
    if not env["complete"] or (env["repetitions"], env["warmups"], env["d"]) != (100, 3, DEFAULT_D):
        raise ValueError("Incomplete or incompatible candidate-scale run")
    args.output.mkdir(parents=True, exist_ok=True)
    if "paired_configuration" in env:
        rows, paired = integrated_series(args.measured, env)
        if args.verify_update:
            rows.update(updated_verification(args.verify_update, env))
        else:
            save_csv(args.measured / "paired_summary.csv", paired)
    else:
        if args.verify_update:
            parser.error("--verify-update requires an integrated presentation reference run")
        rows = archived_series(args.archive, env)
        for ell in NEW_SIZES:
            expected = {(n, ell) for n in WIDE_ATTRIBUTE_COUNTS}
            rows.update(measure_summary(args.measured / f"raw_ell{ell}.csv", expected, env))
        profile = measure_summary(args.measured / "raw_oom_n32.csv", {(32, ell) for ell in (32, 64, 128)}, env)
        save_csv(args.measured / "oom_n32_summary.csv", list(profile.values()))
    save_csv(args.output / (STEM + "_source_data.csv"), list(rows.values()))
    draw(args.output, rows)


if __name__ == "__main__":
    main()
