"""Compute cumulative costs, paired intervals and break-even use rates."""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
import os
from pathlib import Path
from zipfile import ZipFile

import numpy as np

from figure_support import ROOT, sha
from result_io import load_csv, save_csv

LABELS = {"OTAC": "本文", "ACL": "ACL", "UPROVE": "U-Prove",
          "ACL_REUSE": "ACL 登记复用估算"}
PHASES = ("holder_issue_ms", "issuer_issue_ms", "admit_ms", "show_ms", "verify_ms")
BOOTSTRAP_DRAWS = 10_000
BOOTSTRAP_SEED = 20261107


def verify_measurements(folder, env, required_version):
    raw = folder / "raw_timings.csv"
    if not env["complete"] or env["raw_sha256"] != sha(raw):
        raise ValueError("Incomplete utilization measurement or raw CSV checksum mismatch")
    version = env["native_parameters"].get("show_wire_version", "OAS2")
    if version not in ("OAS2", "OAS3") or (required_version and version != required_version):
        raise ValueError(f"Unexpected presentation encoding {version!r}")
    archive = folder / "measured-source.zip"
    if version == "OAS3" or archive.exists():
        sources = env["source_sha256"]
        parameters = ("src/group_p256.hpp" if env["native_parameters"].get("curve") == "prime256v1"
                      else "parameters/type-f.param")
        if version == "OAS3" and not {"src/ours.hpp", "src/utilization.cpp", parameters} <= sources.keys():
            raise ValueError("OAS3 source manifest is missing the implementation, benchmark, or parameters")
        with ZipFile(archive) as bundle:
            for name, digest in sources.items():
                if hashlib.sha256(bundle.read(name)).hexdigest() != digest:
                    raise ValueError(f"Measured source checksum mismatch for {name}")
    return raw


def workload(raw, env):
    schemes = env["schemes"]
    batches, issued = env["paired_batches"], env["credentials_per_batch"]
    rows = defaultdict(list)
    for row in load_csv(raw):
        rows[int(row["batch"]), row["scheme"]].append(row)
    curves = np.empty((batches, len(schemes), issued + 1))
    phases = np.empty((batches, len(schemes), len(PHASES)))
    acl_registration = np.empty(batches)
    scheme_orders = Counter()
    for batch in range(batches):
        orders = []
        for s, scheme in enumerate(schemes):
            group = sorted(rows.pop((batch, scheme)), key=lambda r: int(r["use_order"]))
            assert [int(r["use_order"]) for r in group] == list(range(1, issued + 1))
            holders = [int(r["holder"]) for r in group]
            assert sorted(holders) == list(range(issued))
            if s == 0:
                reference_order = holders
            else:
                assert holders == reference_order
            positions = {int(r["scheme_order"]) for r in group}
            assert len(positions) == 1
            orders.append(positions.pop())
            times = np.array([[float(r[k]) for k in PHASES] for r in group])
            assert np.all(np.isfinite(times)) and np.all(times >= 0)
            assert np.all(times[:, (0, 1, 3, 4)] > 0)
            if scheme == "OTAC":
                assert np.all(times[:, 2] > 0)
            else:
                assert np.all(times[:, 2] == 0)
            phases[batch, s] = times.mean(axis=0)
            issue = times[:, :3].sum() / issued
            curves[batch, s, 0] = issue
            curves[batch, s, 1:] = issue + np.cumsum(times[:, 3:].sum(axis=1)) / issued
            if scheme == "ACL":
                registrations = np.array([[float(r["acl_holder_registration_ms"]),
                                           float(r["acl_issuer_registration_ms"])] for r in group])
                assert np.all(registrations > 0) and np.all(registrations <= times[:, :2])
                acl_registration[batch] = registrations.sum() / issued
        assert sorted(orders) == list(range(len(schemes)))
        scheme_orders[tuple(orders)] += 1
    assert not rows and len(scheme_orders) == 6 and set(scheme_orders.values()) == {batches // 6}
    return curves, phases, acl_registration


def prefix_crossing(diff):
    """First loss of a strict low-use advantage, interpolated between two counts."""
    if diff[0] <= 0:
        return None, None
    crossings = np.flatnonzero(diff[1:] <= 0)
    if not crossings.size:
        return None, None
    before = int(crossings[0])
    used = before + diff[before] / (diff[before] - diff[before + 1])
    return float(used / (len(diff) - 1)), before


def supported_prefix(values, margin):
    misses = np.flatnonzero(values < margin)
    return int(misses[0]) - 1 if misses.size else len(values) - 1


def bootstrap_percentiles(samples, frequencies):
    """Evaluate the ordinary resample percentiles without a full expanded array."""
    draws = np.repeat(np.arange(len(frequencies)), frequencies)
    flat = samples.reshape(len(samples), -1)
    intervals = np.empty((2, flat.shape[1]))
    for start in range(0, flat.shape[1], 256):
        columns = slice(start, start + 256)
        intervals[:, columns] = np.percentile(flat[draws, columns], [2.5, 97.5], axis=0)
    return intervals.reshape(2, *samples.shape[1:])


def crossing_summary(name, own, base, boot_own, boot_base, frequencies, margin):
    issued = len(own) - 1
    diff = base - own
    empirical, before = prefix_crossing(diff)
    boot_diff = boot_base - boot_own
    roots = np.array([prefix_crossing(d)[0] for d in boot_diff], dtype=float)
    crossed = np.isfinite(roots)
    roots = np.repeat(roots[crossed], frequencies[crossed])
    low, high = (map(float, np.percentile(roots, [2.5, 97.5])) if roots.size else (None, None))
    savings = 100 * diff / base
    s_low, s_high = bootstrap_percentiles(100 * boot_diff / boot_base, frequencies)
    extra_use = diff[0] - diff[-1]
    model = float(diff[0] / extra_use) if diff[0] > 0 and diff[-1] < 0 else None
    summary = dict(
        baseline=name,
        model_pct=None if model is None else 100 * model,
        break_even_pct=None if empirical is None else 100 * empirical,
        ci95_low_pct=None if low is None else 100 * low,
        ci95_high_pct=None if high is None else 100 * high,
        bootstrap_crossing_fraction=roots.size / int(frequencies.sum()),
        issued_per_used=None if empirical is None else 1 / empirical,
        cheaper_use_count=before, next_use_count=None if before is None else before + 1,
        positive_ci_through=supported_prefix(s_low, np.nextafter(0, 1)),
        practical_ci_through=supported_prefix(s_low, margin),
        saving_at_zero_pct=float(savings[0]), saving_at_zero_ci95_low_pct=float(s_low[0]),
    )
    points = [dict(baseline=name, used=k, use_pct=100 * k / issued, saved_pct=savings[k],
                   ci95_low_pct=s_low[k], ci95_high_pct=s_high[k])
              for k in range(issued + 1)]
    return summary, points


def fmt_crossing(row):
    if row["break_even_pct"] is None:
        return "无低使用率交叉点"
    interval = (f"（95% CI {row['ci95_low_pct']:.2f}%–{row['ci95_high_pct']:.2f}%）"
                if row["bootstrap_crossing_fraction"] >= 0.95 else "")
    return (f"{row['break_even_pct']:.2f}%{interval}，约 "
            f"{row['issued_per_used']:.2f} 张签发对应 1 张使用")


def cy22_reference(data, utilization_env):
    env = json.loads((data / "environment.json").read_text(encoding="utf-8"))
    assert env["complete"] and env["raw_sha256"] == sha(data / "raw_timings.csv")
    n, d = (str(utilization_env[key]) for key in ("n", "d"))
    rows = [r for r in load_csv(data / "raw_timings.csv")
            if (r["experiment"], r["scheme"], r["n"], r["d"]) == ("algorithms", "CY22", n, d)]
    costs = {}
    for op in ("holder_issue", "issuer_issue", "show", "verify"):
        component = [r for r in rows if r["operation"] == op]
        assert len(component) == env["repetitions"]
        assert {r["operation_complete"] for r in component} == {"0" if op.endswith("issue") else "1"}
        costs[op] = float(np.mean([float(r["ms"]) for r in component]))
    return costs["holder_issue"] + costs["issuer_issue"], costs["show"] + costs["verify"]


def write_report(folder, comparison, env, table, thresholds, savings):
    issued, margin = env["credentials_per_batch"], env["practical_margin_pct"]
    first_v2 = env.get("issuance_mode") == "first-v2"
    version = env["native_parameters"].get("show_wire_version", "OAS2")
    p256 = env["native_parameters"].get("curve") == "prime256v1"
    if "batch_cores" in env:
        schedule = (
            "每组配对批次由绑定到一个逻辑 CPU 的独立进程执行，三个方案在进程内依次运行。"
            f"每个进程预热 {env['warmup_batches_per_worker']} 批，每批 "
            f"{env['warmup_credentials_per_batch']} 张。"
        )
        if "concurrent_attribute_configurations" in env:
            configurations = "、".join(str(n) for n in env["concurrent_attribute_configurations"])
            schedule += f"属性数为 {configurations} 的配置同时调度。"
    else:
        schedule = f"预热 {env['warmup_batches']} 批。"
    report = [
        "# 签发量与使用量的累计开销",
        "",
        f"每批为 {issued} 位持有者各签发一张凭证。签发完成后按相同的随机次序逐张使用，"
        "每张凭证只接受一次。用到第 $u$ 张时的累计计算由本批全部签发耗时与前 $u$ 次实际使用耗时相加得到。"
        f"使用率为 $\\rho=u/I$，签发量与使用量的比为 $I:u$。本文的 $\\ell={env['ell']}$，"
        f"各方案均使用 {env['n']} 个属性并核验其中 {env['d']} 个。",
        "",
        f"实际测量 {env['paired_batches']} 组配对批次，三个方案按六种顺序平衡执行。"
        + schedule
        + "计时包含持有者和签发者的计算、本文的本地签名核验与承诺登记、呈示生成、验证及本地查重。"
        + ("本文采用新版首次签发。" if first_v2 else "")
        + f"本文的呈示编码版本为 {version}。"
        + "ACL 使用首次登记后签发。"
        + ("三个方案使用相同的 OpenSSL P-256 群运算后端。" if p256 else "U-Prove 使用仓库的 PBC 复现。")
        + "公参准备、网络传输、共识与外部资格核验在计时之外。",
        "",
        "## 实测分项",
        "",
        "| 方案 | 用户签发 | 签发者计算 | 单列的登记 | 每张签发合计 | 每次使用合计 |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in table:
        cells = [f"{row[k]:.2f}" for k in (*PHASES[:3], "issuance_ms", "use_ms")]
        report.append("| " + " | ".join([LABELS[row["scheme"]], *cells]) + " |")
    report += [
        "",
        "表中单位为 ms，按全部批次取算术均值。ACL 的登记生成和核验已经分别计入签发双方。",
        "",
        "## 临界点与可见的收益",
        "",
        "曲线按每张已签发凭证归一化，表示 $T_s(u)/I$。实测临界点由平均累计耗时差在相邻使用数之间插值。"
        "另用每张签发均值 $A_s$ 与每次使用均值 $B_s$ 写出 $A_s+\\rho B_s$，交点为 "
        "$\\rho^*=(A_b-A_{\\rm ours})/(B_{\\rm ours}-B_b)$。"
        "置信区间通过 10,000 次配对批次自助采样得到，节省率的区间按使用率逐点计算。",
        "",
        "| 对照 | 实测交点 | 相邻实际使用数 | 线性模型交点 |",
        "| --- | --- | --- | ---: |",
    ]
    for row in thresholds[:2]:
        bracket = (f"{row['cheaper_use_count']} → {row['next_use_count']} / {issued}"
                   if row["cheaper_use_count"] is not None else "—")
        model = f"{row['model_pct']:.2f}%" if row["model_pct"] is not None else "—"
        report.append(f"| {LABELS[row['baseline']]} | {fmt_crossing(row)} | {bracket} | {model} |")
    report += [
        "",
        f"等成本点本身的节省为零。以至少节省 {margin}% 作为实际优势的门槛，检查节省率的 95% 置信区间下界。",
    ]
    for row in thresholds[:2]:
        count = row["practical_ci_through"]
        if count >= 1:
            report.append(f"- 相对 {LABELS[row['baseline']]}，正使用量中满足该门槛的连续区间为 "
                          f"1–{count} 张，即最多使用 {100*count/issued:.2f}% 的凭证。")
        else:
            report.append(f"- 相对 {LABELS[row['baseline']]}，正使用量的测点未形成满足该门槛的低使用率区间。")
    report += ["", "下表给出实际用量点的节省率。负值表示本文耗时较长。", "",
               "| 实际使用 | 相对 ACL 节省率（95% CI） | 相对 U-Prove 节省率（95% CI） |",
               "| --- | ---: | ---: |"]
    display_counts = {round(issued * k / 64) for k in (1, 3, 4, 8, 12, 13, 16, 32, 64)}
    display_counts.update(row[key] for row in thresholds[:2]
                          for key in ("cheaper_use_count", "next_use_count")
                          if row[key] is not None)
    for k in sorted(display_counts):
        group = [savings[b, k] for b in ("ACL", "UPROVE")]
        cells = [f"{r['saved_pct']:.2f}% [{r['ci95_low_pct']:.2f}%, {r['ci95_high_pct']:.2f}%]" for r in group]
        report.append(f"| {k}/{issued}（{100*k/issued:.2f}%） | " + " | ".join(cells) + " |")
    reuse = thresholds[2]
    reuse_result = (
        "在全部实测用量点，扣除登记后的 ACL 累计计算均更低。"
        if all(savings["ACL_REUSE", k]["saved_pct"] < 0 for k in range(issued + 1))
        else f"估算交点为 {fmt_crossing(reuse)}。"
    )
    if not p256:
        report += [
            "",
            "![签发量与使用量的对比](figure_4_issuance_utilization.png)",
            "",
            "左图为实际签发和使用前缀的均值，右图为本文相对两基线的节省率。"
            "若出现等成本点，图中用圆点和竖线标记。"
            + ("短横线标出相对 ACL 的节省率下界达到 10% 的正使用率测点范围。"
               if not first_v2 and thresholds[0]["practical_ci_through"] >= 1 else ""),
        ]
    report += [
        "",
        "## 口径敏感性",
        "",
        "从 ACL 签发计算中仅扣去本批单独测得的首次登记和核验，可得到登记复用时的敏感性估算。"
        + reuse_result
        + f"零使用时本文的节省率为 {reuse['saving_at_zero_pct']:.2f}%。"
        "这是扣除登记成本的计算情形，主实验对应每位新持有者签发一张。",
        "",
    ]
    if not first_v2:
        cy_issue, cy_use = cy22_reference(comparison, env)
        cy_link = Path(os.path.relpath(comparison / "raw_timings.csv", folder)).as_posix()
        report += [
            f"相同属性配置下，Chan–Yuen 的实测均值为签发核心 {cy_issue:.2f} ms，单次 AND 使用 {cy_use:.2f} ms。"
            "它的签发复现缺少原文中的加密相关证明，以上两项单独供参考，完整生命周期临界点留空。",
            f"[Chan–Yuen 原始记录]({cy_link})",
            "",
        ]
    report += [
        "- [分项均值](phase_means.csv)",
        "- [原始计时](raw_timings.csv) · [累计曲线](workload_curves.csv) · [节省率](savings.csv) · [临界点](break_even.csv)",
        "- [环境和源码散列](environment.json) · [实测源码](measured-source.zip)"
        + ("" if p256 else " · [LaTeX 图源](figure_4_issuance_utilization.tex)"),
        "",
    ]
    if not first_v2:
        report += [
            "实验设计核对参考了 Scientific Critical Thinking 技能。[Kassis 等，Scientific Agent Skills](https://doi.org/10.48550/arXiv.2609.00065)",
            "",
        ]
    (folder / "report.md").write_text("\n".join(report), encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=ROOT / "results/utilization")
    parser.add_argument("--comparison-dir", type=Path, default=ROOT / "results/current")
    parser.add_argument("--require-show-wire-version", choices=("OAS2", "OAS3"))
    args = parser.parse_args()
    folder = args.directory
    env = json.loads((folder / "environment.json").read_text(encoding="utf-8"))
    raw = verify_measurements(folder, env, args.require_show_wire_version)
    curves, phases, registration = workload(raw, env)
    batches, schemes, counts = curves.shape
    rng = np.random.default_rng(BOOTSTRAP_SEED)
    draws = rng.multinomial(batches, np.full(batches, 1 / batches), size=BOOTSTRAP_DRAWS)
    counts_per_batch, frequencies = np.unique(draws, axis=0, return_counts=True)
    weights = counts_per_batch / batches
    boot = (weights @ curves.reshape(batches, -1)).reshape(-1, schemes, counts)
    means = curves.mean(axis=0)
    lows, highs = bootstrap_percentiles(boot, frequencies)
    phase_rows, curve_rows = [], []
    for s, scheme in enumerate(env["schemes"]):
        p = phases[:, s].mean(axis=0)
        phase_rows.append(dict(scheme=scheme, **dict(zip(PHASES, p)),
                               issuance_ms=p[:3].sum(), use_ms=p[3:].sum()))
        curve_rows.extend(dict(scheme=scheme, used=k, use_pct=100*k/(counts-1), ms_per_issued=means[s, k],
                               ci95_low_ms=lows[s, k], ci95_high_ms=highs[s, k]) for k in range(counts))
    thresholds, savings = [], {}
    for s, scheme in enumerate(env["schemes"][1:], 1):
        row, points = crossing_summary(scheme, means[0], means[s], boot[:, 0], boot[:, s],
                                       frequencies, env["practical_margin_pct"])
        thresholds.append(row)
        savings.update({(p["baseline"], p["used"]): p for p in points})
    reuse = curves[:, 1] - registration[:, None]
    row, points = crossing_summary("ACL_REUSE", means[0], reuse.mean(axis=0), boot[:, 0], weights @ reuse,
                                   frequencies, env["practical_margin_pct"])
    thresholds.append(row)
    savings.update({(p["baseline"], p["used"]): p for p in points})
    save_csv(folder / "phase_means.csv", phase_rows)
    save_csv(folder / "workload_curves.csv", curve_rows)
    save_csv(folder / "savings.csv", list(savings.values()))
    save_csv(folder / "break_even.csv", thresholds)
    write_report(folder, args.comparison_dir, env, phase_rows, thresholds, savings)
    print(f"Validated {batches * schemes * (counts-1):,} credentials and consumptions in {batches} paired batches")
    for row in thresholds:
        print(row["baseline"], fmt_crossing(row), "10% through", row["practical_ci_through"])


if __name__ == "__main__":
    main()
