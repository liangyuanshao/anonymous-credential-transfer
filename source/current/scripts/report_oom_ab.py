"""Summarize the paired OoM runs and generate their PGFPlots comparison."""
import argparse
from collections import defaultdict
import json
from pathlib import Path

import numpy as np

from figure_support import COLORS, ROOT, sha, write_tex
from result_io import load_csv, save_csv


def interval(times, rng):
    indices = rng.integers(0, len(times), size=(10000, len(times)))
    low, high = np.percentile(np.median(times[indices], axis=1), [2.5, 97.5])
    return float(np.median(times)), float(low), float(high)


def summarize(raw, settings):
    groups = defaultdict(list)
    for row in load_csv(raw):
        key = (int(row["ell"]), row["operation"], row["variant"])
        groups[key].append(row)
    results = {}
    rng = np.random.default_rng(20261107)
    reps = settings["repetitions"]
    variants = settings.get("variants", ["direct", "factored"])
    for ell in sorted(settings["ell"]):
        m = (ell - 1).bit_length()
        sizes = {"show": (ell + 8*m + 5)*66 + (3*m + 14)*64,
                 "transfer": (ell + 8*m + 7)*66 + (3*m + 19)*64}
        for operation, size in sizes.items():
            for index, variant in enumerate(variants):
                rows = sorted(groups.pop((ell, operation, variant)), key=lambda r: int(r["repetition"]))
                assert [int(r["repetition"]) for r in rows] == list(range(reps))
                assert {int(r["payload_bytes"]) for r in rows} == {size}
                assert all(int(r["order"]) == ((int(r["repetition"]) % 2) ^ index)
                           for r in rows)
                for phase in ("generation", "verification"):
                    times = np.array([float(r[phase + "_ms"]) for r in rows])
                    assert np.all(np.isfinite(times)) and np.all(times > 0)
                    median, low, high = interval(times, rng)
                    key = (ell, operation, variant, phase)
                    results[key] = dict(ell=ell, operation=operation, variant=variant, phase=phase,
                                        repetitions=reps, payload_bytes=size, median=median,
                                        low=low, high=high)
    assert not groups
    return results


def bars(points, width):
    body = ""
    for x, point in enumerate(points, 1):
        color = point["color"]
        y, low, high = (point[k] for k in ("median", "low", "high"))
        body += (f"\\addplot+[ybar,mark=none,draw={color},fill={color},fill opacity=.8,"
                 f"bar width={width}pt,bar shift=0pt,barlabel,err]"
                 " table[x=x,y=median,y error minus=minus,y error plus=plus] {\n"
                 f"x median minus plus\n{x} {y:.12g} {y-low:.12g} {high-y:.12g}\n"
                 "};\n")
    return body


def figure(folder, phases, variants, points):
    labels = [r"{This work\\(" + v + ")}" for v in variants]
    labels.extend(("ACL", "U-Prove", "CY22"))
    labels = ",".join(labels)
    common = (r"paper,height=53mm,ymin=0,xmin=.45,xmax=5.55,xtick={1,2,3,4,5},"
              r"xticklabel style={align=center},xticklabels={" + labels + "}")
    if len(phases) == 1:
        ymax = 1.23 * max(r["high"] for r in points["generation"])
        body = (r"\begin{axis}[" + common + f",width=166mm,ymax={ymax}," +
                r"title={Presentation generation ($\ell=64$)}]" + "\n")
        body += bars(points["generation"], 17) + r"\end{axis}" + "\n"
        name = "presentation_comparison"
    else:
        body = (r"\begin{groupplot}[group style={group size=2 by 1,horizontal sep=14mm}," +
                common + ",width=90mm]\n")
        for letter, phase in zip(("a", "b"), phases):
            ymax = 1.23 * max(r["high"] for r in points[phase])
            body += (f"\\nextgroupplot[ymax={ymax},"
                     f"title={{\\textbf{{{letter}}}\\quad Presentation {phase}}}]\n")
            body += bars(points[phase], 12)
        body += r"\end{groupplot}" + "\n"
        name = "presentation_comparison"
    write_tex(folder, name, body)
    return name


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=ROOT / "results/oom-factoring")
    folder = parser.parse_args().directory
    settings = json.loads((folder / "environment.json").read_text(encoding="utf-8"))
    if 64 not in settings["ell"]:
        parser.error("the chart with fixed baselines requires ell=64")
    raw = folder / "raw_timings.csv"
    assert settings["complete"] and settings["raw_sha256"] == sha(raw)
    results = summarize(raw, settings)
    save_csv(folder / "summary.csv", list(results.values()))
    previous = ROOT / "results/current"
    assert settings["fixed_baseline_raw_sha256"] == sha(previous / "raw_timings.csv")
    baselines = {(r["scheme"], r["operation"]): r for r in load_csv(previous / "summary.csv")
                 if r["experiment"] == "algorithms"}
    variants = settings.get("variants", ["direct", "factored"])
    phases = ("generation", "verification") if "variants" in settings else ("generation",)

    def point(variant, ell=64, operation="show", phase="generation"):
        return results[ell, operation, variant, phase]

    direct, factored = (point(v)["median"] for v in variants)
    points = {}
    for phase in phases:
        points[phase] = []
        for variant, color in zip(variants, ("ours!45", "ours")):
            p = point(variant, phase=phase)
            points[phase].append(dict(phase=phase, label=variant, median=p["median"], low=p["low"],
                                      high=p["high"], color=color, source_sha256=settings["raw_sha256"]))
        operation = "show" if phase == "generation" else "verify"
        for scheme in ("ACL", "UPROVE", "CY22"):
            row = baselines[scheme, operation]
            points[phase].append(dict(phase=phase, label=scheme, median=float(row["median_ms"]),
                                      low=float(row["ci95_low_ms"]), high=float(row["ci95_high_ms"]),
                                      color=COLORS[scheme], source_sha256=settings["fixed_baseline_raw_sha256"]))
    save_csv(folder / "presentation_comparison.csv", [p for rows in points.values() for p in rows])
    name = figure(folder, phases, variants, points)

    acl = float(baselines["ACL", "show"]["median_ms"])
    verify_before, verify_after = (point(v, phase="verification")["median"] for v in variants)
    report = [
        "# OoM 专项实测",
        "",
        f"默认配置为 64 个候选、16 个属性、核验其中 4 个。完整呈示生成从 {direct:.2f} ms "
        f"降至 {factored:.2f} ms，下降 {100*(1-factored/direct):.1f}%。"
        f"验证从 {verify_before:.2f} ms 变为 {verify_after:.2f} ms。以此前同一 PBC 后端的 "
        f"ACL 呈示生成 {acl:.2f} ms 为参照，耗时比从 {direct/acl:.2f} 倍降至 {factored/acl:.2f} 倍。",
        "",
        "两个版本在同一进程中交替运行，逐对使用同一份凭证及登记池。候选抽样、窗口表和新鲜随机数"
        f"都计入对应操作。每组预热 3 次、测量 {settings['repetitions']} 次，保留全部实测。"
        "图中三个基线方案沿用四方案基准批次，前后两版本文数据"
        "来自本次 A/B。误差线为 10,000 次百分位自助采样的 95% 置信区间。",
        "",
    ]
    if "setup_sha256" in settings:
        setup = folder / "setup.csv"
        assert sha(setup) == settings["setup_sha256"]
        setup_rows = load_csv(setup)
        medians = []
        for variant in variants:
            measured = [row for row in setup_rows if row["variant"] == variant]
            assert sorted(int(row["repetition"]) for row in measured) == list(range(settings["repetitions"]))
            medians.append(float(np.median([float(row["ms"]) for row in measured])))
        report += [
            f"在共用 PBC 公共参数的前提下，方案专用公共参数构造的中位数为 {medians[0]:.2f} → "
            f"{medians[1]:.2f} ms。两张梳状表的构造计入这一项。属性底数的短表在生成时构造并复用。",
            "",
            "[初始化逐次计时](setup.csv)",
            "",
        ]
    report += [
        f"![呈示耗时对比]({name}.png)",
        "",
        "| 候选数 | 操作 | 生成（ms，参考版 → 本版） | 验证（ms，参考版 → 本版） | 负载大小（B） |",
        "| ---: | --- | ---: | ---: | ---: |",
    ]
    for ell in sorted(settings["ell"]):
        for op, label in (("show", "呈示"), ("transfer", "转让")):
            b, a = (point(v, ell, op) for v in variants)
            vb, va = (point(v, ell, op, "verification")["median"] for v in variants)
            report.append(f"| {ell} | {label} | {b['median']:.2f} → {a['median']:.2f} | "
                          f"{vb:.2f} → {va:.2f} | {a['payload_bytes']:,} |")
    report += [
        "",
        "每条输出均通过验证。验证耗时、置信区间和逐次结果分别见统计表和原始数据。",
        "",
        "- [统计表](summary.csv)",
        "- [原始数据](raw_timings.csv)",
        "- [编译、计时口径和源码散列](environment.json)",
        f"- [LaTeX 图源]({name}.tex)",
        "",
    ]
    (folder / "report.md").write_text("\n".join(report), encoding="utf-8")
    print(f"Validated {len(results) * settings['repetitions'] // 2:,} rows. "
          f"Default presentation: {direct:.2f} -> {factored:.2f} ms.")


if __name__ == "__main__":
    main()
