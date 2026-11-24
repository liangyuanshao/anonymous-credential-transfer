"""Validate issuance timings and draw the measured series with XeLaTeX/PGFPlots."""

import argparse
import math
from pathlib import Path

import numpy as np

from benchmark_config import DEFAULT_D, DEFAULT_ELL, WIDE_ATTRIBUTE_COUNTS
from figure_support import COLORS, LABELS, MARKERS, ROOT, dat, plot_table, render, sha, write_tex
from result_io import load_csv, save_csv


SCHEMES = ("OTAC", "ACL", "UPROVE")
MODES = ("first", "repeat")
ROLES = ("holder", "issuer")
DASHES = ("solid", "densely dashed", "dash dot")
BOOTSTRAP_SAMPLES = 10000


def summarize(raw, repetitions):
    expected = {(n, scheme, mode, role)
                for n in WIDE_ATTRIBUTE_COUNTS for scheme in SCHEMES for mode in MODES
                for role in (ROLES + ("admit",) if scheme == "OTAC" else ROLES)}
    measurements = {key: {} for key in expected}
    rows = load_csv(raw)
    required = {"n", "scheme", "mode", "role", "repetition", "ms"}
    if not rows or not required.issubset(rows[0]):
        raise ValueError(f"Expected nonempty timing CSV with fields {sorted(required)}")
    for row in rows:
        key = (int(row["n"]), row["scheme"], row["mode"], row["role"])
        repetition, elapsed = int(row["repetition"]), float(row["ms"])
        if key not in expected or not 0 <= repetition < repetitions:
            raise ValueError(f"Unexpected timing measurement: {key}, repetition {repetition}")
        if repetition in measurements[key] or not math.isfinite(elapsed) or elapsed <= 0:
            raise ValueError(f"Duplicate or invalid timing: {key}, repetition {repetition}")
        measurements[key][repetition] = elapsed

    incomplete = [key for key, times in measurements.items() if len(times) != repetitions]
    if incomplete:
        raise ValueError(f"Missing repetitions for timing series: {sorted(incomplete)}")

    source = raw.resolve()
    if source.is_relative_to(ROOT):
        source = source.relative_to(ROOT)
    digest = sha(raw)
    output = []
    for index, ((n, scheme, mode, role), times) in enumerate(sorted(measurements.items())):
        values = np.asarray([times[rep] for rep in range(repetitions)])
        rng = np.random.default_rng(20261107 + index)
        samples = np.median(rng.choice(values, (BOOTSTRAP_SAMPLES, repetitions)), axis=1)
        low, high = np.percentile(samples, [2.5, 97.5])
        output.append(dict(n=n, scheme=scheme, mode=mode, role=role, repetitions=repetitions,
                           median_ms=float(np.median(values)), ci95_low_ms=float(low),
                           ci95_high_ms=float(high), source_csv=source.as_posix(),
                           source_csv_sha256=digest))
    return output, len(rows)


def read_wide_summary(source, series):
    expected = {(n, scheme, op) for n in WIDE_ATTRIBUTE_COUNTS for scheme, op in series}
    entries = {}
    for row in load_csv(source):
        n, ell, d = (int(row[key]) for key in ("n", "ell", "d"))
        key = (n, row["scheme"], row["operation"])
        if key not in expected or (ell, d) != (DEFAULT_ELL, DEFAULT_D):
            continue
        if key in entries or int(row["operation_complete"]) != 1:
            raise ValueError(f"Duplicate or incomplete archived timing series: {key}")
        median, low, high = (float(row[key]) for key in ("median_ms", "ci95_low_ms", "ci95_high_ms"))
        if not all(map(math.isfinite, (median, low, high))) or not 0 < low <= median <= high:
            raise ValueError(f"Invalid archived timing interval: {key}")
        entries[key] = row
    if entries.keys() != expected:
        raise ValueError(f"Missing archived timing series: {sorted(expected - entries.keys())}")
    return entries


def read_presentation_summary(source):
    return read_wide_summary(source, [(scheme, op) for scheme in SCHEMES
                                     for op in ("show", "verify")])


def draw_figure(folder, stem, panels, *, logarithmic=False, shared_y=False):
    """Panels are ordered by row and share limits within columns by default."""
    ticks = ",".join(map(str, WIDE_ATTRIBUTE_COUNTS))
    margin = 0.05 * (WIDE_ATTRIBUTE_COUNTS[-1] - WIDE_ATTRIBUTE_COUNTS[0])
    x_low, x_high = WIDE_ATTRIBUTE_COUNTS[0] - margin, WIDE_ATTRIBUTE_COUNTS[-1] + margin
    y_label = "Time (ms, log scale)" if logarithmic else "Time (ms)"
    body = [
        f"\\begin{{groupplot}}[group style={{group size=2 by {len(panels)//2},"
        "horizontal sep=17mm,vertical sep=18mm},paper,scale only axis,width=73mm,height=44mm,"
        f"xmin={x_low:g},xmax={x_high:g},xtick={{{ticks}}},xticklabels={{{ticks}}},"
        f"xlabel={{Total attributes, $n$}},ylabel={{{y_label}}},"
        r"xmajorgrids=false,xticklabel style={font=\tiny}]"
    ]
    limits = []
    for column in range(2):
        points = [row for _, _, series in (panels if shared_y else panels[column::2])
                  for rows in series.values()
                  for row in rows]
        lower = min(float(row["ci95_low_ms"]) for row in points) * 0.80 if logarithmic else 0
        upper = max(float(row["ci95_high_ms"]) for row in points) * 1.17
        limits.append((lower, upper))
    for index, (tag, title, series) in enumerate(panels):
        lower, upper = limits[index % 2]
        options = (f"title={{\\textbf{{{chr(97 + index)}}}\\quad {title}}},"
                   f"ymin={lower:.10g},ymax={upper:.10g}")
        if logarithmic:
            options += r",ymode=log,log ticks with fixed point,minor y tick num=0"
            log_ticks = [mantissa * 10.0**decade
                         for decade in range(math.floor(math.log10(lower)), math.ceil(math.log10(upper)) + 1)
                         for mantissa in (1, 2, 5) if lower <= mantissa * 10.0**decade <= upper]
            if len(log_ticks) >= 2:
                options += ",ytick={" + ",".join(f"{tick:g}" for tick in log_ticks) + "}"
        legend = index == 0 and len(series) > 1
        if legend:
            options += (r",legend style={at={(0,1.23)},anchor=south west,legend columns="
                        + str(len(series)) + "}")
        body.append(f"\\nextgroupplot[{options}]")
        for scheme, dash in zip(SCHEMES, DASHES):
            if scheme not in series:
                continue
            rows = series[scheme]
            points = [(int(row["n"]), dict(median=float(row["median_ms"]),
                                          low=float(row["ci95_low_ms"]),
                                          high=float(row["ci95_high_ms"]))) for row in rows]
            path = dat(folder, f"{stem}_{tag}_{scheme}", points)
            color = COLORS[scheme]
            style = (f"color={color},{dash},mark={MARKERS[scheme]},"
                     f"mark options={{solid,fill={color},draw={color}}},"
                     "mark size=1.25pt,line width=.8pt,err")
            body.append(plot_table(path, style).rstrip())
            if legend:
                body.append(f"\\addlegendentry{{{LABELS[scheme]}}}")
    body.append(r"\end{groupplot}")
    write_tex(folder, stem, "\n".join(body) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw", required=True, type=Path)
    parser.add_argument("--figures", required=True, type=Path)
    parser.add_argument("--repetitions", type=int, default=100)
    parser.add_argument("--presentation-summary", type=Path,
                        help="Include a separate show/verify figure from an archived wide summary")
    parser.add_argument("--first-issuance-figure", action="store_true",
                        help="Draw only the two first-issuance panels on a common linear scale")
    parser.add_argument("--prepare-only", action="store_true")
    args = parser.parse_args()
    if args.repetitions < 1:
        parser.error("--repetitions must be positive")

    summary, measured_count = summarize(args.raw, args.repetitions)
    archive = read_presentation_summary(args.presentation_summary) if args.presentation_summary else None
    args.figures.mkdir(parents=True, exist_ok=True)
    save_csv(args.raw.with_name("summary.csv"), summary)
    index = {(row["n"], row["scheme"], row["mode"], row["role"]): row for row in summary}
    if args.first_issuance_figure:
        first_panels = [(f"{role}_issue", f"{role.title()} issuance",
                         {scheme: [index[n, scheme, "first", role] for n in WIDE_ATTRIBUTE_COUNTS]
                          for scheme in SCHEMES}) for role in ROLES]
        draw_figure(args.figures, "figure_2_issuance_costs", first_panels, shared_y=True)
        save_csv(args.figures / "figure_2_issuance_costs_source_data.csv",
                 [row for row in summary if row["mode"] == "first" and row["role"] in ROLES])
    else:
        titles = {"first": "First issuance", "repeat": "Subsequent issuance"}
        panels = [(f"{mode}_{role}", f"{titles[mode]} ({role})",
                   {scheme: [index[n, scheme, mode, role] for n in WIDE_ATTRIBUTE_COUNTS]
                    for scheme in SCHEMES}) for mode in MODES for role in ROLES]
        draw_figure(args.figures, "figure_issuance_timing", panels)
    if archive is not None:
        panels = [(op, title, {scheme: [archive[n, scheme, op] for n in WIDE_ATTRIBUTE_COUNTS]
                               for scheme in SCHEMES})
                  for op, title in (("show", "Presentation generation"),
                                    ("verify", "Presentation verification"))]
        draw_figure(args.figures, "figure_presentation_timing", panels, logarithmic=True)
        save_csv(args.figures / "presentation_source_data.csv",
                 [archive[key] for key in sorted(archive)])
    print(f"Verified {measured_count} timing records across {len(summary)} series")
    if not args.prepare_only:
        render(args.figures, "issuance-timing")


if __name__ == "__main__":
    main()
