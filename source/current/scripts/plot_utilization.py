"""Write the utilization comparison as standalone PGFPlots source."""
import argparse
import json
import math
from pathlib import Path

from figure_support import COLORS, END, LABELS, MARKERS, PREAMBLE, ROOT
from result_io import load_csv


def coordinates(rows, x, y):
    return " ".join(f"({float(r[x]):.8f},{float(r[y]):.8f})" for r in rows)


def plot_points(rows, step, important):
    return [r for r in rows if int(r["used"]) % step == 0 or int(r["used"]) in important]


def plot_style(scheme):
    dash = {"OTAC": "solid", "ACL": "densely dashed", "UPROVE": "dash dot"}
    return f"color={COLORS[scheme]},{dash[scheme]},line width=1.05pt"


def confidence_band(rows, x, low, high, color, name):
    return [
        rf"\addplot[draw=none,forget plot,name path={name}low] coordinates "
        "{" + coordinates(rows, x, low) + "};",
        rf"\addplot[draw=none,forget plot,name path={name}high] coordinates "
        "{" + coordinates(rows, x, high) + "};",
        rf"\addplot[draw=none,fill={color},fill opacity=.16,forget plot] "
        rf"fill between[of={name}low and {name}high];",
    ]


def make_figure(directory):
    environment = json.loads((directory / "environment.json").read_text(encoding="utf-8"))
    first_v2 = environment.get("issuance_mode") == "first-v2"
    ell, n, d = (int(environment[key]) for key in ("ell", "n", "d"))
    issued = int(environment["credentials_per_batch"])
    margin = float(environment["practical_margin_pct"])
    curves = load_csv(directory / "workload_curves.csv")
    savings = load_csv(directory / "savings.csv")
    thresholds = {r["baseline"]: r for r in load_csv(directory / "break_even.csv")}
    crossings = {s: thresholds[s] for s in ("ACL", "UPROVE") if thresholds[s]["break_even_pct"]}
    # Keep the full-resolution statistics and display a tractable number of points in TeX.
    step = math.ceil(issued / 200)
    markers = {round(issued * quarter / 4) for quarter in range(5)}
    important = markers | {int(row[key]) for row in crossings.values()
                           for key in ("cheaper_use_count", "next_use_count")}
    xmax = max(40, min(100, math.ceil(max((float(r["break_even_pct"])
                                         for r in crossings.values()), default=0) / 5) * 5 + 5))
    shown = [r for r in savings if r["baseline"] in ("ACL", "UPROVE")
             and float(r["use_pct"]) <= xmax + 2]
    ymin = min(-12, math.floor(min(float(r["ci95_low_pct"]) for r in shown) / 5) * 5)
    ymax = max(margin + 5, math.ceil(max(float(r["ci95_high_pct"]) for r in shown) / 5) * 5 + 5)
    upper = math.ceil(max(float(r["ci95_high_ms"]) for r in curves) / 10) * 10

    body = [
        r"\begin{groupplot}[group style={group size=2 by 1,horizontal sep=19mm},"
        r"paper,width=86mm,height=62mm,xlabel={Issued credentials used (\%)},"
        r"tick label style={font=\scriptsize},grid=major]",
        r"\nextgroupplot[title={\textbf{a}\quad Cumulative computation},"
        r"ylabel={Time per issued credential (ms)},xmin=0,xmax=100,ymin=0,"
        f"ymax={upper}," + r"xtick={0,25,50,75,100},ytick distance=25,"
        r"legend style={at={(0.035,0.965)},anchor=north west,fill=white}]",
    ]
    for scheme in ("OTAC", "ACL", "UPROVE"):
        data = [r for r in curves if r["scheme"] == scheme]
        data = plot_points(data, step, important)
        coords = coordinates(data, "use_pct", "ms_per_issued")
        mark, color = MARKERS[scheme], COLORS[scheme]
        style = plot_style(scheme)
        if first_v2:
            body.extend(confidence_band(data, "use_pct", "ci95_low_ms", "ci95_high_ms",
                                        color, f"cumulative{scheme}"))
        body.append(rf"\addplot+[{style},no marks] coordinates {{{coords}}};")
        body.append(rf"\addlegendentry{{{LABELS[scheme]}}}")
        selected = [r for r in data if int(r["used"]) in markers]
        body.append(rf"\addplot+[only marks,mark={mark},mark size=1.7pt,"
                    rf"color={color},mark options={{solid,fill={color},draw={color}}},forget plot] coordinates "
                    "{" + coordinates(selected, "use_pct", "ms_per_issued") + "};")

    xticks = ",".join(str(x) for x in range(0, xmax + 1, 10))
    body += [
        r"\nextgroupplot[title={\textbf{b}\quad Relative savings},"
        r"ylabel={Time saved by this work (\%)},xmin=0,"
        f"xmax={xmax},ymin={ymin},ymax={ymax},xtick={{{xticks}}},ytick distance=20]",
        rf"\draw[black!58,densely dashed,line width=.55pt] (axis cs:0,0) -- (axis cs:{xmax},0);",
        rf"\draw[black!36,densely dotted,line width=.55pt] (axis cs:0,{margin}) -- (axis cs:{xmax},{margin});",
    ]
    for scheme in ("ACL", "UPROVE"):
        data = [r for r in shown if r["baseline"] == scheme]
        data = plot_points(data, step, important)
        color = COLORS[scheme]
        body.extend(confidence_band(data, "use_pct", "ci95_low_pct", "ci95_high_pct", color, scheme))
        style = plot_style(scheme)
        body.append(rf"\addplot+[{style},no marks] coordinates "
                    "{" + coordinates(data, "use_pct", "saved_pct") + "};")
    body.append(rf"\node[anchor=south east,font=\scriptsize,text=black!60] "
                rf"at (axis cs:{xmax-.4},{margin+.6}) {{{margin:g}\% saving}};")
    for scheme, row in crossings.items():
        x = float(row["break_even_pct"])
        color = COLORS[scheme]
        label_height = max(ymin + 2, -0.12 * (ymax - ymin))
        body.append(rf"\draw[{color}!70,densely dotted,line width=.55pt] "
                    rf"(axis cs:{x},0) -- (axis cs:{x},{label_height});")
        body.append(rf"\addplot[only marks,mark=*,mark size=1.9pt,{color},forget plot] "
                    rf"coordinates {{({x},0)}};")
        anchor, label_x = ("east", x-.7) if x >= 5 else ("west", x+.7)
        precision = 2 if first_v2 else 1
        body.append(rf"\node[anchor={anchor},font=\scriptsize,text={color},fill=white,"
                    rf"inner sep=1.4pt] at (axis cs:{label_x},{label_height}) {{{x:.{precision}f}\%}};")
    last = int(thresholds["ACL"]["practical_ci_through"])
    if last >= 1 and not first_v2:
        acl_rates = {int(r["used"]): float(r["use_pct"]) for r in savings if r["baseline"] == "ACL"}
        x0, x1 = acl_rates[1], acl_rates[last]
        y = ymin + .08 * (ymax - ymin)
        body.append(rf"\draw[acl,line width=.9pt,|-|] (axis cs:{x0},{y}) -- (axis cs:{x1},{y});")
        body.append(rf"\node[anchor=south west,font=\scriptsize,text=acl] "
                    rf"at (axis cs:{x0},{y+1}) {{$\geq{margin:g}\%$ vs ACL}};")
    body.append(r"\end{groupplot}")
    batch_size = f"{issued:,}".replace(",", "{,}")
    body.append(rf"\node[anchor=south east,font=\scriptsize,yshift=19pt] at (group c2r1.north east)"
                rf" {{$I={batch_size},\ \ell={ell},\ n={n},\ d={d}$}};")
    preamble = PREAMBLE.replace(r"\usepgfplotslibrary{groupplots}",
                                r"\usepgfplotslibrary{groupplots,fillbetween}")
    path = directory / "figure_4_issuance_utilization.tex"
    path.write_text(preamble + "\n".join(body) + "\n" + END, encoding="utf-8", newline="\n")
    print(path)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=ROOT / "results/utilization")
    make_figure(parser.parse_args().directory)
