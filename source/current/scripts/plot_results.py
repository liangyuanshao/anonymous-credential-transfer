"""Draw the credential measurements with XeLaTeX/PGFPlots.

Python validates and summarizes measured records for PGFPlots.
The candidate set size is fixed while the attribute counts vary.
"""
from pathlib import Path
from collections import defaultdict
import argparse
import datetime
import hashlib
import json
import math
import numpy as np

from benchmark_config import (ATTRIBUTE_COUNTS, DEFAULT_D, DEFAULT_ELL, DEFAULT_N,
                              MATCH_COUNTS, MAX_BENCHMARK_N, WIDE_ATTRIBUTE_COUNTS,
                              WIDE_MATCH_COUNTS, WIDE_MATCH_N)
from result_io import load_csv, save_csv
from figure_support import (ROOT, SCHEMES, COLORS, MARKERS, LABELS, OPS,
                            TITLES, dat, plot_table, write_tex, render)

REVISION = "current"
TRANSFER_OPS = ("transfer", "verify_transfer")
MAIN_ATTRIBUTES = (DEFAULT_N, DEFAULT_D)
WIDE_MAIN_ATTRIBUTES = (WIDE_ATTRIBUTE_COUNTS[0], DEFAULT_D)
ATTRIBUTE_SWEEP = tuple((n, DEFAULT_D) for n in ATTRIBUTE_COUNTS)
MATCH_SWEEP = tuple((MAX_BENCHMARK_N, d) for d in MATCH_COUNTS)
WIDE_ATTRIBUTE_SWEEP = tuple((n, DEFAULT_D) for n in WIDE_ATTRIBUTE_COUNTS)
WIDE_MATCH_SWEEP = tuple((WIDE_MATCH_N, d) for d in WIDE_MATCH_COUNTS)
WIDE_SCHEMES = ("OTAC", "ACL", "UPROVE")
GROUP_FIELDS = ("experiment", "scheme", "profile", "operation", "ell", "n", "d")


def sweep_workloads(main_attributes, attribute_sweep, match_sweep):
    return ((("algorithms", *main_attributes),)
            + tuple(("attributes", *point) for point in attribute_sweep if point != main_attributes)
            + tuple(("match_counts", *point) for point in match_sweep if point not in attribute_sweep))


def expected_points(grid, ell):
    if grid == "wide":
        schemes = WIDE_SCHEMES
        workloads = sweep_workloads(WIDE_MAIN_ATTRIBUTES, WIDE_ATTRIBUTE_SWEEP, WIDE_MATCH_SWEEP)
    elif grid == "all":
        schemes = SCHEMES
        workloads = sweep_workloads(MAIN_ATTRIBUTES, ATTRIBUTE_SWEEP, MATCH_SWEEP)
    elif grid == "default":
        schemes = SCHEMES
        workloads = (("algorithms", *MAIN_ATTRIBUTES),)
    else:
        raise ValueError(f"Unknown measurement grid: {grid}")
    return {(exp, scheme, op, ell, n, d)
            for exp, n, d in workloads for scheme in schemes
            for op in OPS+(TRANSFER_OPS if scheme == "OTAC" else ())}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def relative(path):
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return path.resolve().as_posix()


def summarize(raw_path, repetitions, ell, *, grid="all"):
    expected = expected_points(grid, ell)
    rows = load_csv(raw_path)
    if not rows:
        raise ValueError("No measured records")
    required = set(GROUP_FIELDS) | {"repetition", "ms", "bytes", "operation_complete"}
    if not required.issubset(rows[0]):
        raise ValueError(f"Raw columns missing: {required-set(rows[0])}")
    groups = defaultdict(list)
    observed = set()
    for row in rows:
        n, d, size = (int(row[k]) for k in ("n", "d", "ell"))
        exp, scheme, op = (row[k] for k in ("experiment", "scheme", "operation"))
        point = (exp, scheme, op, size, n, d)
        if point not in expected:
            raise ValueError(f"Unexpected measurement series: {point}")
        partial = scheme == "CY22" and op in OPS[:2]
        if int(row["operation_complete"]) != int(not partial):
            raise ValueError(f"Incorrect completeness flag: {row}")
        observed.add(point)
        groups[tuple(row[k] for k in GROUP_FIELDS)].append(row)
    if expected != observed:
        raise ValueError(f"Incomplete measurement grid: {sorted(expected-observed)}")
    if len(groups) != len(expected):
        raise ValueError("Multiple profiles or encodings of the same measurement series")

    digest = sha(raw_path)
    output = []
    for index, (key, measurements) in enumerate(sorted(groups.items())):
        if sorted(int(r["repetition"]) for r in measurements) != list(range(repetitions)):
            raise ValueError(f"Missing or duplicate repetitions: {key}")
        if len({r["operation_complete"] for r in measurements}) != 1:
            raise ValueError(f"Inconsistent operation completeness: {key}")
        times = np.asarray([float(r["ms"]) for r in measurements])
        if not np.all(np.isfinite(times)) or np.any(times <= 0):
            raise ValueError(f"Non-positive or non-finite timings: {key}")
        if any(int(r["bytes"]) < 0 for r in measurements):
            raise ValueError(f"Negative serialized size: {key}")
        rng = np.random.default_rng(20261107+index)
        samples = np.median(rng.choice(times, (10000, len(times))), axis=1)
        low, high = np.percentile(samples, [2.5, 97.5])
        row = dict(zip(GROUP_FIELDS, key))
        row.update(repetitions=len(times), median_ms=float(np.median(times)),
                   ci95_low_ms=float(low), ci95_high_ms=float(high),
                   operation_complete=int(measurements[0]["operation_complete"]),
                   source_csv=relative(raw_path), source_csv_sha256=digest)
        output.append(row)
    return output, len(rows)


def normalized(row):
    return dict(experiment=row["experiment"], scheme=row["scheme"],
                profile=row["profile"], operation=row["operation"],
                n=int(row["n"]), d=int(row["d"]), measured_ell=int(row["ell"]),
                ell_applies=int(row["scheme"] == "OTAC"),
                median=float(row["median_ms"]), low=float(row["ci95_low_ms"]),
                high=float(row["ci95_high_ms"]), complete=int(row["operation_complete"]),
                repetitions=row["repetitions"], origin=row["source_csv"],
                source_csv_sha256=row["source_csv_sha256"])


def prepare(data_dir, folder, repetitions, ell, *, grid="all"):
    if grid == "wide":
        attribute_counts, attribute_sweep = WIDE_ATTRIBUTE_COUNTS, WIDE_ATTRIBUTE_SWEEP
        match_counts, match_sweep = WIDE_MATCH_COUNTS, WIDE_MATCH_SWEEP
        match_n, schemes = WIDE_MATCH_N, WIDE_SCHEMES
        main_attributes = WIDE_MAIN_ATTRIBUTES
    elif grid == "all":
        attribute_counts, attribute_sweep = ATTRIBUTE_COUNTS, ATTRIBUTE_SWEEP
        match_counts, match_sweep = MATCH_COUNTS, MATCH_SWEEP
        match_n, schemes = MAX_BENCHMARK_N, SCHEMES
        main_attributes = MAIN_ATTRIBUTES
    else:
        raise ValueError(f"Cannot plot measurement grid: {grid}")
    raw_path = data_dir/"raw_timings.csv"
    summary, row_count = summarize(raw_path, repetitions, ell, grid=grid)
    folder.mkdir(parents=True, exist_ok=True)
    save_csv(data_dir/"summary.csv", summary)
    allrows = [normalized(row) for row in summary]

    def choose(scheme, op, attributes):
        found = [row for row in allrows if row["scheme"] == scheme and
                 row["operation"] == op and (row["n"], row["d"]) == attributes]
        if len(found) != 1:
            raise ValueError(f"Missing/duplicate plot point: {(scheme, op, attributes, ell)}")
        return found[0]

    line_styles = {"OTAC": "solid", "ACL": "densely dashed",
                   "UPROVE": "dash dot", "CY22": "densely dotted"}

    def line(rows, x_field, name, color, mark, dash):
        path = dat(folder, name, [(row[x_field], row) for row in rows])
        style = (f"color={color},{dash},mark={mark},"
                 f"mark options={{solid,fill={color},draw={color}}},mark size=1.4pt,line width=1pt,err,"
                 r"error bars/error mark options={rotate=90,mark size=2.5pt,line width=.45pt}")
        return plot_table(path, style)

    def attribute_axis(x_values, x_label, x_field):
        if grid == "wide" and x_field == "d":
            bounds = (f"xmode=log,log basis x=2,minor x tick num=0,"
                      f"xmin={x_values[0]*.9:.12g},xmax={x_values[-1]*1.12:.12g}")
            x_label += " (log scale)"
        elif grid == "wide":
            margin = (x_values[-1] - x_values[0]) * .05
            bounds = f"xmin={x_values[0]-margin:.12g},xmax={x_values[-1]+margin:.12g}"
        else:
            bounds = f"xmin={x_values[0]-.22:.2f},xmax={x_values[-1]+.22:.2f}"
        ticks = ",".join(str(value) for value in x_values)
        return (f"paper,{bounds},"
                f"xtick={{{ticks}}},xticklabels={{{ticks}}},xlabel={{{x_label}}}")

    def comparison_plot(operations, configurations, x_values, x_field, x_label,
                        note, stem, source_name):
        panel_rows = len(operations)//2
        axis = attribute_axis(x_values, x_label, x_field)
        body = (r"\begin{groupplot}[group style={group size=2 by "
                +str(panel_rows)+r",horizontal sep=16mm,vertical sep=20mm},"
                +axis+r",width=89.5mm,height=56mm,ymode=log,log ticks with fixed point,"
                r"minor y tick num=0,ylabel={Time (ms, log scale)}]"+"\n")
        plotted = []
        for index, op in enumerate(operations):
            series = {scheme: [choose(scheme, op, config) for config in configurations]
                      for scheme in schemes}
            points = [row for rows in series.values() for row in rows]
            plotted.extend(points)
            ymin = min(row["low"] for row in points)*.80
            ymax = max(row["high"] for row in points)*1.23
            ticks = [mantissa * 10.**decade
                     for decade in range(math.floor(math.log10(ymin)), math.ceil(math.log10(ymax))+1)
                     for mantissa in (1, 2, 5)
                     if ymin <= mantissa * 10.**decade <= ymax]
            yticks = f",ytick={{{','.join(f'{tick:g}' for tick in ticks)}}}" if len(ticks) >= 2 else ""
            legend = (r",legend style={at={(0,1.22)},anchor=south west,legend columns="
                      + str(len(schemes)) + "}"
                      if index == 0 else "")
            title = TITLES[OPS.index(op)]
            body += (f"\\nextgroupplot[title={{\\textbf{{{chr(97+index)}}}\\quad {title}}},"
                     f"ymin={ymin:.12g},ymax={ymax:.12g}{yticks}{legend}]\n")
            for scheme, rows in series.items():
                body += line(rows, x_field, f"{source_name}_{op}_{scheme}",
                             COLORS[scheme], MARKERS[scheme], line_styles[scheme])
                if index == 0:
                    label = LABELS[scheme]
                    if scheme == "CY22" and operations[0] == "holder_issue":
                        label += " (issuance core)"
                    body += f"\\addlegendentry{{{label}}}\n"
        body += "\\end{groupplot}\n"
        body += (r"\node[anchor=south east,font=\scriptsize,yshift=22pt] at (group c2r1.north east) "
                 f"{{{note}}};\n")
        write_tex(folder, stem, body)
        save_csv(folder/f"{source_name}_source_data.csv", plotted)

    # Figure 1 varies the total attributes, with a common matching policy size.
    comparison_plot(OPS, attribute_sweep, attribute_counts, "n", r"Total attributes, $n$",
                    rf"$d={DEFAULT_D}$, $\ell={ell}$ (this work)",
                    "figure_1_algorithm_costs", "comparison")

    # Figure 2 measures transfer at the same total attribute counts.
    transfer = {op: [choose("OTAC", op, config) for config in attribute_sweep]
                for op in TRANSFER_OPS}
    points = [row for rows in transfer.values() for row in rows]
    ymax = max(row["high"] for row in points)*1.18
    axis = attribute_axis(attribute_counts, r"Total attributes, $n$", "n")
    body = (r"\begin{axis}["+axis+r",name=transferPlot,width=176.5mm,height=66mm,"
            f"ymin=0,ymax={ymax:.12g},"
            r"legend style={at={(0,1.10)},anchor=south west,legend columns=2}]"+"\n")
    body += line(transfer["transfer"], "n", "transfer_n", "ours", "*", "solid")
    body += r"\addlegendentry{Transfer}"+"\n"
    body += line(transfer["verify_transfer"], "n", "verify_transfer_n", "acl", "square*", "densely dashed")
    body += r"\addlegendentry{VerifyTransfer}"+"\n"
    body += "\\end{axis}\n"
    body += (r"\node[anchor=south east,font=\scriptsize,yshift=16pt] at (transferPlot.north east) "
             f"{{$\\ell={ell}$}};\n")
    write_tex(folder, "figure_2_anonymity_set", body)
    save_csv(folder/"anonymity_source_data.csv", points)

    # Figure 3 varies the matched attributes at a common total attribute count.
    comparison_plot(("show", "verify"), match_sweep, match_counts, "d", r"Matched attributes, $d$",
                    rf"$n={match_n}$, $\ell={ell}$ (this work)",
                    "figure_3_attributes", "attributes")

    audited_files = [raw_path]
    for name in ("environment.json", "communication.csv", "setup.csv"):
        path = data_dir/name
        if path.is_file():
            audited_files.append(path)
    result = dict(revision=REVISION, grid=grid, schemes=schemes, default_ell=ell, raw_rows=row_count,
                  main_attributes=dict(n=main_attributes[0], d=main_attributes[1]),
                  fixed_ell=ell, attribute_configurations=attribute_sweep,
                  match_configurations=match_sweep,
                  series=len(summary), repetitions=repetitions, warmups=3,
                  center="median", confidence_interval="percentile bootstrap 95%",
                  bootstrap_resamples=10000, bootstrap_seed_base=20261107,
                  all_records_retained=True,
                  shared_presentation_configuration=dict(n=match_n, d=DEFAULT_D),
                  matching_security_model_or_security_bits_claimed=False,
                  source_sha256={relative(p): sha(p) for p in audited_files},
                  plot_generator_sha256=sha(Path(__file__)))
    limitations = ["No network or consensus timing",
                   "Algorithm measurements do not prove privacy or security equivalence"]
    if grid == "all":
        result["same_n5_d2_presentation_rows_reused_in_figures_1_and_3"] = True
        result["cy22_issuance"] = "honest-party core only; not complete issuance"
        limitations.insert(0, "CY22 issuance is core-only")
    (folder/"data_audit.json").write_text(json.dumps(result, indent=2)+"\n", encoding="utf-8")
    (folder/"contract.json").write_text(json.dumps(dict(
        backend="XeLaTeX/PGFPlots", python_role="validation, statistics and table preparation",
        purpose="Compare issuance, presentation and transfer costs as attribute counts vary at fixed candidate size",
        evidence="Fresh measurements of the credential protocol and baseline reimplementations run in the same batch",
        archetype="quantitative grid",
        figures={"figure_1": "Issuance and presentation versus total attributes at fixed d",
                 "figure_2": "Transfer generation and verification versus total attributes",
                 "figure_3": "Presentation versus matched attributes at fixed n"},
        plot_data="Measured medians and 10000-resample percentile-bootstrap 95% intervals; no synthetic timing points",
        exports=["tex", "pdf", "png", "csv"], width_mm_target=183,
        privacy_claim="Candidate list length is not a quantitative privacy-security guarantee",
        limitations=limitations
    ), indent=2)+"\n", encoding="utf-8")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, default=ROOT/"results"/REVISION)
    parser.add_argument("--output-dir", type=Path, default=ROOT/"figures"/REVISION)
    parser.add_argument("--ell", type=int, default=DEFAULT_ELL)
    parser.add_argument("--repetitions", type=int, default=100)
    parser.add_argument("--grid", choices=("all", "wide"), default="all")
    parser.add_argument("--prepare-only", action="store_true")
    parser.add_argument("--revision", default=datetime.datetime.now().strftime("%Y%m%d-%H%M%S"))
    args = parser.parse_args()
    if args.ell != 64:
        raise ValueError("This measured-grid contract uses default ell=64")
    if args.repetitions < 2:
        raise ValueError("At least two repetitions required")
    audit = prepare(args.data_dir, args.output_dir, args.repetitions, args.ell, grid=args.grid)
    if not args.prepare_only:
        render(args.output_dir, args.revision)
    print(json.dumps(audit, indent=2))


if __name__ == "__main__":
    main()
