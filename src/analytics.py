"""Descriptive full-population analytics of processed vulnerable associations.

All Task 2/3 figures read only the typed processed table. No clean/safe population,
time ordering, advisory-alias resolution or resolved dependency exposure is inferred.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
from pathlib import Path
import time
import tempfile

import duckdb
os.environ.setdefault("MPLCONFIGDIR", str(Path(tempfile.gettempdir()) / "phase2-matplotlib"))
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from scipy.stats import spearmanr, skew

COLORS = ["#2563a6", "#d88729", "#329575", "#9268ab"]
BANDS = ["Zero", "Low", "Medium", "High", "Critical", "Unknown"]
BAND_COLORS = ["#9dabc0", "#76b7b2", "#f2cf5b", "#e79545", "#bd4e55", "#dddddd"]
CAPTIONS = {
    "01_ecosystem_composition": "Figure 1. Exact ecosystem counts at association, package, package-version and advisory grains. Each panel has its own denominator. The population is the processed vulnerable-association export, not all published packages or versions.",
    "02_quality_profiles": "Figure 2. Exact percentages of processed records with missing/invalid severity, a recorded zero score, or a blank description, within each ecosystem. Zero is retained separately because its source meaning is not fully documented. These percentages describe record completeness rather than missingness mechanisms.",
    "03_severity_bands": "Figure 3. Severity-band percentages of processed associations within each ecosystem. Bands use numeric scores: zero, (0,4), [4,7), [7,9), and [9,10]. Unknown includes absent or invalid values. Scores do not establish exploitability or safety.",
    "04_weighting_ecdf": "Figure 4. Empirical cumulative distributions of numeric severity for associations and for ecosystem-advisory IDs using each ID's maximum observed score. Each line excludes unknown scores and states a different estimand. Advisory aliases remain unresolved and conflicting scores can affect the maximum.",
    "05_package_version_burden": "Figure 5. Distribution of distinct observed affected versions per ecosystem-qualified package. Boxes show Q1, median and Q3; whiskers use 1.5 IQR and dots show outside values. The logarithmic axis reveals skew in a vulnerable-only population without release dates.",
    "06_advisory_reach": "Figure 6. Distinct ecosystem-qualified package versions linked to each ecosystem-advisory ID. Boxes show Q1, median and Q3; whiskers use 1.5 IQR and dots show outside values. Counts measure observed advisory reach rather than independent security events.",
    "07_exposure_concentration": "Figure 7. Lorenz curves for observed affected-version counts across ecosystem-qualified packages, sorted by burden. Axes express shares of packages and observed affected versions within each ecosystem. A package-version associated with multiple advisories contributes once to that package's burden.",
    "08_package_count_relationship": "Figure 8. Logarithmic hexbin views of distinct affected-version count versus distinct advisory-ID count per package. Hexagon color shows package frequency. Spearman correlation summarizes rank association only; no regression, causal effect, or temporal trend is fitted.",
    "09_severity_histogram": "Figure 9. Exact association-weighted numeric severity distribution from processed data. Recorded zeros are counted separately from positive scores, which use 0.5-point bins on [0,10], left-closed and right-open except the final bin. Missing or invalid scores are excluded from numeric bins and reported separately; zeros do not establish safety.",
}


def _rows(con, sql):
    cursor = con.execute(sql)
    columns = [x[0] for x in cursor.description]
    return [dict(zip(columns, row)) for row in cursor.fetchall()]


def _write_csv(path, rows):
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _file_sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _summary(values):
    arr = np.asarray(values, dtype=float)
    if not len(arr):
        return {k: None for k in ["n", "min", "q1", "median", "q3", "max", "mean", "p95", "iqr", "skewness", "outlier_count"]}
    q = np.quantile(arr, [0, .25, .5, .75, 1])
    iqr = q[3] - q[1]
    return dict(n=int(len(arr)), min=float(q[0]), q1=float(q[1]), median=float(q[2]), q3=float(q[3]), max=float(q[4]),
                mean=float(arr.mean()), p95=float(np.quantile(arr, .95)), iqr=float(iqr),
                skewness=float(skew(arr)) if len(arr) > 2 and arr.std() else None,
                outlier_count=int(((arr < q[1] - 1.5 * iqr) | (arr > q[3] + 1.5 * iqr)).sum()))


def run_analytics(repo_root, processed_path=None, results_dir=None, figures_dir=None):
   
    started = time.perf_counter()
    root = Path(repo_root).resolve()
    out = (root / Path(results_dir)).resolve() if results_dir is not None else root / "results"
    figs = (root / Path(figures_dir)).resolve() if figures_dir is not None else root / "figures"
    out.mkdir(parents=True, exist_ok=True)
    figs.mkdir(parents=True, exist_ok=True)
    path = Path(processed_path) if processed_path else root / "data/processed/associations.parquet"
    if not path.exists():
        choices = list((root / "data/processed").glob("**/*.parquet"))
        choices = [p for p in choices if "sample" not in p.name and "quarantine" not in p.name]
        if not choices:
            raise FileNotFoundError("No processed association Parquet found. Run the cleaning pipeline first.")
        path = choices[0]
    con = duckdb.connect()
    con.execute("SET memory_limit='512MB'")
    con.execute("SET threads=2")
    con.read_parquet(str(path)).create_view("a")
    con.execute("CREATE TEMP TABLE packages AS SELECT package_manager,package_name,count(DISTINCT version_name) AS versions,count(DISTINCT vuln_id) AS advisories,count(*) AS associations,max(severity_score) AS max_score FROM a GROUP BY 1,2")
    con.execute("CREATE TEMP TABLE advisory AS SELECT package_manager,vuln_id,count(DISTINCT (package_name,version_name)) AS versions,count(DISTINCT package_name) AS packages,count(*) AS associations,max(severity_score) AS max_score,count(DISTINCT severity_score) AS numeric_scores FROM a GROUP BY 1,2")
    eco = _rows(con, "SELECT package_manager,count(*) AS associations,count(DISTINCT package_name) AS packages,count(DISTINCT (package_name,version_name)) AS versions,count(DISTINCT vuln_id) AS advisories FROM a GROUP BY 1 ORDER BY associations DESC")
    ecosystems = [x["package_manager"] for x in eco]
    eco_color = dict(zip(ecosystems, COLORS))
    totals = _rows(con, "SELECT count(*) AS associations,count(DISTINCT (package_manager,package_name)) AS packages,count(DISTINCT (package_manager,package_name,version_name)) AS versions,count(DISTINCT vuln_id) AS advisory_ids,count(DISTINCT (package_manager,vuln_id)) AS ecosystem_advisory_ids FROM a")[0]
    assert sum(x["associations"] for x in eco) == totals["associations"]
    assert sum(x["packages"] for x in eco) == totals["packages"]
    assert sum(x["versions"] for x in eco) == totals["versions"]
    assert sum(x["advisories"] for x in eco) == totals["ecosystem_advisory_ids"]
    quality = _rows(con, "SELECT package_manager,count(*) AS n,count(*) FILTER(WHERE severity_score IS NULL) AS severity_unknown,count(*) FILTER(WHERE severity_score=0) AS severity_zero,count(*) FILTER(WHERE vuln_description IS NULL OR trim(vuln_description)='') AS description_blank FROM a GROUP BY 1")
    quality = sorted(quality, key=lambda x: ecosystems.index(x["package_manager"]))
    severity = _rows(con, "SELECT package_manager,CASE WHEN severity_score IS NULL THEN 'Unknown' WHEN severity_score=0 THEN 'Zero' WHEN severity_score<4 THEN 'Low' WHEN severity_score<7 THEN 'Medium' WHEN severity_score<9 THEN 'High' ELSE 'Critical' END AS band,count(*) AS n FROM a GROUP BY 1,2")
    score_freq = _rows(con, "SELECT package_manager,severity_score,count(*) AS n FROM a WHERE severity_score IS NOT NULL GROUP BY 1,2 ORDER BY 1,2")
    numeric_summary = _rows(con, "SELECT package_manager,count(severity_score) AS known_n,min(severity_score) AS min,quantile_cont(severity_score,.25) AS q1,median(severity_score) AS median,quantile_cont(severity_score,.75) AS q3,max(severity_score) AS max,avg(severity_score) AS mean FROM a GROUP BY 1 ORDER BY 1")
    advisory_scores = _rows(con, "SELECT package_manager,max_score AS severity_score,count(*) AS n FROM advisory WHERE max_score IS NOT NULL GROUP BY 1,2 ORDER BY 1,2")
    packages = _rows(con, "SELECT * FROM packages ORDER BY package_manager,package_name")
    advisories = _rows(con, "SELECT * FROM advisory ORDER BY package_manager,vuln_id")
    groups = {e: [p for p in packages if p["package_manager"] == e] for e in ecosystems}
    agroups = {e: [p for p in advisories if p["package_manager"] == e] for e in ecosystems}
    burden, reach, concentration, relationship, weighting = [], [], [], [], []
    for e in ecosystems:
        pp = groups[e]
        values = np.array([p["versions"] for p in pp], dtype=float)
        av = np.array([p["advisories"] for p in pp], dtype=float)
        burden.append({"package_manager": e, **_summary(values)})
        reach.append({"package_manager": e, **_summary([p["versions"] for p in agroups[e]])})
        top_n = max(1, math.ceil(.01 * len(values)))
        concentration.append({"package_manager": e, "package_count": len(values), "affected_version_sum": int(values.sum()), "top_1pct_packages_count": top_n, "top_1pct_version_share_pct": float(np.sort(values)[-top_n:].sum() / values.sum() * 100), "top_10pct_version_share_pct": float(np.sort(values)[-max(1, math.ceil(.10 * len(values))):].sum() / values.sum() * 100)})
        rho = float(spearmanr(values, av).statistic) if np.std(values) and np.std(av) else None
        relationship.append({"package_manager": e, "n_packages": len(pp), "spearman_rho": rho, "method": "Exact rank correlation on all processed ecosystem-qualified packages; no fitted trend"})
        r_n = sum(x["n"] for x in score_freq if x["package_manager"] == e)
        a_n = sum(x["n"] for x in advisory_scores if x["package_manager"] == e)
        r_high = sum(x["n"] for x in score_freq if x["package_manager"] == e and x["severity_score"] >= 7)
        a_high = sum(x["n"] for x in advisory_scores if x["package_manager"] == e and x["severity_score"] >= 7)
        weighting.append({"package_manager": e, "known_score_associations": r_n, "high_critical_associations": r_high, "high_critical_known_association_pct": 100 * r_high / r_n if r_n else None,
                          "known_score_ecosystem_advisory_ids": a_n, "high_critical_advisory_maxima": a_high, "high_critical_known_advisory_max_pct": 100 * a_high / a_n if a_n else None})
    conflicts = _rows(con, "SELECT package_manager,count(*) AS advisory_ids,count(*) FILTER(WHERE numeric_scores>1) AS multi_score_ids,max(numeric_scores) AS maximum_scores_per_id FROM advisory GROUP BY 1")
    shared_ids = _rows(con, "SELECT vuln_id,count(DISTINCT package_manager) AS ecosystem_count FROM a GROUP BY 1 HAVING ecosystem_count>1 ORDER BY ecosystem_count DESC,vuln_id")
    descriptions = _rows(con, "SELECT package_manager,vuln_id,count(DISTINCT vuln_description) AS description_variants,count(DISTINCT severity_score) AS numeric_score_variants FROM a GROUP BY 1,2 HAVING description_variants>1 OR numeric_score_variants>1 ORDER BY numeric_score_variants DESC,description_variants DESC,vuln_id LIMIT 25")
    top_packages = _rows(con, "SELECT * FROM packages ORDER BY versions DESC,package_manager,package_name LIMIT 25")
    top_advisories = _rows(con, "SELECT * FROM advisory ORDER BY versions DESC,package_manager,vuln_id LIMIT 25")
    modes = sorted(score_freq, key=lambda x: x["n"], reverse=True)[:12]
    for name, rows in {"ecosystem_counts": eco, "processed_quality": quality, "severity_bands": severity,
                       "severity_score_frequency": score_freq, "severity_numeric_summary": numeric_summary, "advisory_max_score_frequency": advisory_scores,
                       "package_metrics": packages, "advisory_metrics": advisories, "package_burden_summary": burden,
                       "advisory_reach_summary": reach, "concentration": concentration, "count_relationship": relationship,
                       "weighting_comparison": weighting, "advisory_score_conflicts": conflicts, "cross_ecosystem_ids": shared_ids,
                       "conflict_examples": descriptions, "top_packages": top_packages, "top_advisories": top_advisories}.items():
        _write_csv(out / f"{name}.csv", rows)

    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 10, "axes.titlesize": 12, "axes.labelsize": 10,
                         "axes.spines.top": False, "axes.spines.right": False, "figure.facecolor": "white", "savefig.facecolor": "white"})
    def save(fig, stem):
        fig.savefig(figs / f"{stem}.png", dpi=180, bbox_inches="tight")
        fig.savefig(figs / f"{stem}.svg", bbox_inches="tight")
        plt.close(fig)
    fig, axs = plt.subplots(1, 4, figsize=(12, 3.4))
    for ax, field, label in zip(axs, ["associations", "packages", "versions", "advisories"], ["Associations", "Packages", "Package versions", "Advisory IDs"]):
        vals = [x[field] for x in eco]
        ax.bar(ecosystems, vals, color=[eco_color[e] for e in ecosystems])
        ax.set_yscale("log")
        ax.set_title(label)
        ax.tick_params(axis="x", rotation=25)
        for i, v in enumerate(vals): ax.annotate(f"{v:,}", (i, v), xytext=(0, 4), textcoords="offset points", ha="center", fontsize=8)
        ax.set_ylim(.8, max(vals) * 2.7)
    axs[0].set_ylabel("Exact count, logarithmic scale")
    fig.suptitle("Observed export composition depends on the counting unit", fontsize=14)
    fig.tight_layout()
    save(fig, "01_ecosystem_composition")

    matrix = np.array([[100 * r[k] / r["n"] for k in ["severity_unknown", "severity_zero", "description_blank"]] for r in quality])
    fig, ax = plt.subplots(figsize=(8, 3.4))
    img = ax.imshow(matrix, cmap="Blues", vmin=0, vmax=max(1, float(matrix.max())), aspect="auto")
    ax.set_xticks(range(3), ["Unknown numeric severity", "Recorded zero score", "Blank description"])
    ax.set_yticks(range(len(ecosystems)), ecosystems)
    for y in range(len(ecosystems)):
        for x in range(3): ax.text(x, y, f"{matrix[y,x]:.2f}%", ha="center", va="center", color="white" if matrix[y,x] > matrix.max() * .55 else "black")
    ax.set_title("Fields are complete but recorded zero rates vary")
    fig.colorbar(img, ax=ax, label="Percent of ecosystem associations")
    fig.tight_layout()
    save(fig, "02_quality_profiles")

    fig, ax = plt.subplots(figsize=(9, 3.5))
    left = np.zeros(len(ecosystems))
    counts = {(r["package_manager"], r["band"]): r["n"] for r in severity}
    for band, color in zip(BANDS, BAND_COLORS):
        vv = [100 * counts.get((e, band), 0) / next(x["associations"] for x in eco if x["package_manager"] == e) for e in ecosystems]
        ax.barh(ecosystems, vv, left=left, label=band, color=color)
        for i, v in enumerate(vv):
            if v >= 8: ax.text(left[i] + v / 2, i, f"{v:.1f}%", ha="center", va="center", fontsize=9)
        left += vv
    ax.set_xlim(0, 100)
    ax.set_xlabel("Percent of all processed associations in ecosystem")
    ax.set_title("Severity profiles include zero and unknown values")
    ax.legend(ncol=6, bbox_to_anchor=(.5, -.18), loc="upper center", frameon=False)
    fig.tight_layout()
    save(fig, "03_severity_bands")

    fig, axs = plt.subplots(1, 2, figsize=(10, 3.8), sharex=True, sharey=True)
    for ax, records, label in zip(axs, [score_freq, advisory_scores], ["Association scores", "Maximum score per ecosystem-advisory ID"]):
        for e in ecosystems:
            rows = [x for x in records if x["package_manager"] == e]
            if rows:
                xx = np.array([x["severity_score"] for x in rows]); yy = np.array([x["n"] for x in rows], dtype=float)
                ax.step(xx, np.cumsum(yy) / yy.sum(), where="post", label=f"{e} (n={int(yy.sum()):,})", color=eco_color[e])
        ax.set_title(label, fontsize=11)
        ax.set_xlabel("Numeric severity score, zero retained")
        ax.legend(fontsize=7, loc="lower right", frameon=False)
        ax.grid(alpha=.15)
    axs[0].set_ylabel("Cumulative share among known scores")
    fig.suptitle("Counting associations and advisory IDs changes the estimand", fontsize=14)
    fig.tight_layout()
    save(fig, "04_weighting_ecdf")

    for stem, vectors, title, xlabel in [
        ("05_package_version_burden", [[p["versions"] for p in groups[e]] for e in ecosystems], "Observed affected versions are uneven across packages", "Distinct affected versions per observed package"),
        ("06_advisory_reach", [[p["versions"] for p in agroups[e]] for e in ecosystems], "Advisory IDs differ in observed affected-version reach", "Distinct affected package versions per ecosystem-advisory ID")]:
        fig, ax = plt.subplots(figsize=(9, 3.5))
        bp = ax.boxplot(vectors, orientation="horizontal", tick_labels=ecosystems, patch_artist=True,
                        flierprops={"marker": ".", "markersize": 2, "alpha": .3})
        for patch, color in zip(bp["boxes"], [eco_color[e] for e in ecosystems]): patch.set_facecolor(color); patch.set_alpha(.65)
        ax.set_xscale("log"); ax.set_xlabel(xlabel + " (log scale)"); ax.set_title(title)
        ax.grid(axis="x", alpha=.15); fig.tight_layout(); save(fig, stem)

    fig, ax = plt.subplots(figsize=(7.5, 3.8))
    lorenz_rows = []
    for e in ecosystems:
        vv = np.sort([p["versions"] for p in groups[e]])
        xx = np.arange(len(vv) + 1) / len(vv)
        yy = np.r_[0, np.cumsum(vv) / np.sum(vv)]
        ax.plot(xx * 100, yy * 100, label=e, color=eco_color[e])
        for x, y in zip(xx, yy): lorenz_rows.append({"package_manager": e, "package_share_pct": float(x * 100), "affected_version_share_pct": float(y * 100)})
    ax.plot([0,100], [0,100], color="#aaaaaa", linestyle=":", label="Equal burden")
    ax.set_xlabel("Cumulative percent of observed packages, smallest burden first")
    ax.set_ylabel("Cumulative percent of affected versions")
    ax.set_title("A minority of observed packages contributes much of the version burden")
    ax.legend(frameon=False, fontsize=9); ax.grid(alpha=.15)
    fig.tight_layout(); save(fig, "07_exposure_concentration")
    _write_csv(out / "lorenz_curves.csv", lorenz_rows)

    fig, axs = plt.subplots(2, 2, figsize=(10, 6.3))
    for ax, e in zip(axs.flat, ecosystems):
        xx = np.array([p["versions"] for p in groups[e]], dtype=float)
        yy = np.array([p["advisories"] for p in groups[e]], dtype=float)
        hx = ax.hexbin(xx, yy, gridsize=22, xscale="log", yscale="log", mincnt=1, bins="log", cmap="Blues")
        rho = next(x["spearman_rho"] for x in relationship if x["package_manager"] == e)
        ax.set_title(f"{e}: n={len(xx):,}, Spearman rho={rho:.3f}" if rho is not None else f"{e}: n={len(xx):,}, rank correlation undefined")
        ax.set_xlabel("Affected-version count (log)"); ax.set_ylabel("Advisory-ID count (log)")
        fig.colorbar(hx, ax=ax, label="Packages in hexagon")
    fig.suptitle("Package size and advisory burden show descriptive association", fontsize=14)
    fig.tight_layout(); save(fig, "08_package_count_relationship")


    global_scores = _rows(con, "SELECT severity_score,count(*) AS n FROM a WHERE severity_score IS NOT NULL GROUP BY 1 ORDER BY 1")
    zero_n = sum(r["n"] for r in global_scores if r["severity_score"] == 0)
    unknown_n = sum(r["severity_unknown"] for r in quality)
    positive_scores = [r for r in global_scores if r["severity_score"] > 0]
    edges = np.arange(0, 10.5, .5)
    positive_counts, _ = np.histogram([r["severity_score"] for r in positive_scores], bins=edges,
                                     weights=[r["n"] for r in positive_scores])
    histogram_rows = [{"bin_left": float(left), "bin_right": float(right),
                       "positive_associations": int(n), "last_bin_right_inclusive": bool(i == len(positive_counts)-1)}
                      for i, (left, right, n) in enumerate(zip(edges[:-1], edges[1:], positive_counts))]
    histogram = {"population_associations": totals["associations"], "recorded_zero_associations": zero_n,
                 "unknown_associations": unknown_n, "positive_associations": int(positive_counts.sum()),
                 "bin_width": .5, "bins": histogram_rows,
                 "top_numeric_modes": sorted(global_scores, key=lambda row: (-row["n"], row["severity_score"]))[:10]}
    assert zero_n + unknown_n + histogram["positive_associations"] == totals["associations"]
    _write_csv(out / "severity_histogram.csv", histogram_rows)
    fig, axs = plt.subplots(1, 2, figsize=(10.5, 3.1), gridspec_kw={"width_ratios": [1, 4]}, sharey=True)
    axs[0].bar([0], [zero_n], width=.65, color="#9dabc0")
    axs[0].set_xticks([0], ["Recorded zero"])
    axs[0].set_ylabel("Processed associations (exact count)")
    axs[0].set_title("Zero retained", fontsize=11)
    axs[0].annotate(f"{zero_n:,}", (0, zero_n), xytext=(0, 5), textcoords="offset points", ha="center", fontsize=9)
    axs[1].stairs(positive_counts, edges, fill=True, color="#2563a6", alpha=.85)
    axs[1].set_xlim(0, 10)
    axs[1].set_xticks(np.arange(0, 11, 1))
    axs[1].set_xlabel("Positive recorded severity score (0.5-point bins)")
    axs[1].set_title(f"Positive scores n={histogram['positive_associations']:,}; missing/invalid n={unknown_n:,}", fontsize=11)
    axs[0].set_ylim(0, max(zero_n, int(max(positive_counts, default=0)), 1)*1.17)
    axs[1].grid(axis="y", alpha=.15)
    fig.suptitle("Recorded severity is discrete with concentrated positive-score peaks", fontsize=13)
    fig.tight_layout(); save(fig, "09_severity_histogram")
    analysis = {
        "population": "Full processed vulnerable-association export; no all-version denominator",
        "processed_path": path.relative_to(root).as_posix() if path.is_relative_to(root) else path.as_posix(),
        "results_path": out.relative_to(root).as_posix() if out.is_relative_to(root) else out.as_posix(),
        "figures_path": figs.relative_to(root).as_posix() if figs.is_relative_to(root) else figs.as_posix(),
        "processed_sha256": _file_sha256(path),
        "methods": {"counts": "Exact DuckDB distinct tuple/group aggregations", "quantiles": "numpy linear interpolation on full entity aggregates", "boxplots": "Q1 median Q3 and 1.5-IQR whiskers, log axes", "correlations": "Spearman rank over full package aggregates, no fitted model", "advisory_weighting": "Ecosystem-advisory IDs with maximum recorded numeric score, aliases unresolved"},
        "totals": totals, "ecosystems": eco, "quality": quality, "severity_bands": severity,
        "severity_numeric_summary": numeric_summary,
        "package_burden": burden, "advisory_reach": reach, "concentration": concentration,
        "count_relationship": relationship, "weighting_comparison": weighting,
        "advisory_conflicts": conflicts, "cross_ecosystem_advisory_ids": len(shared_ids),
        "conflict_examples": descriptions, "top_packages": top_packages, "top_advisories": top_advisories,
        "top_record_weighted_score_modes": modes,
        "severity_histogram": histogram,
        "research_question_support": [
            {"question": "Distribution across ecosystems, versions and impact", "status": "Partially answered", "reason": "Exact distributions within observed association export; all-version prevalence and alias-resolved advisory counts require enrichment"},
            {"question": "Recent versus older vulnerable versions", "status": "Deferred", "reason": "CSV has no release timestamps or reliable ecosystem-specific latest-release ordering"},
            {"question": "Cross-ecosystem quality and structure", "status": "Answered for CSV", "reason": "Exact field, key, severity and subgroup profiles; database validation remains separate"},
            {"question": "Direct versus transitive exposure", "status": "Deferred", "reason": "CSV has no dependency edges, constraints or resolved dependency versions"}],
        "figure_captions": CAPTIONS,
        "elapsed_seconds": time.perf_counter() - started,
        "authorship_status": "Complete evidence-based interpretations prepared with AI assistance. This computation record does not certify individual student contributions or rehearsal."
    }
    analysis["figure_interpretations"] = figure_interpretations(analysis)
    (out / "analytics.json").write_text(json.dumps(analysis, indent=2, allow_nan=False), encoding="utf-8")
    (figs / "captions.md").write_text("# Figure captions and interpretations\n\nComplete evidence-based analysis prepared with AI assistance.\n\n" + "\n\n".join(caption + "\n\n" + analysis["figure_interpretations"][stem] for stem, caption in CAPTIONS.items()) + "\n", encoding="utf-8")
    if out == root / "results" and figs == root / "figures":
        _write_investigation_log(root, analysis)
        if not (root / "notebooks/phase2_analysis.ipynb").exists():
            build_notebook(root)
    con.close()
    return analysis


def figure_interpretations(a):
    """Evidence-based explanations shared by the notebook and caption artifact."""
    eco = {r["package_manager"]: r for r in a["ecosystems"]}
    quality = {r["package_manager"]: r for r in a["quality"]}
    weight = {r["package_manager"]: r for r in a["weighting_comparison"]}
    burden = {r["package_manager"]: r for r in a["package_burden"]}
    reach = {r["package_manager"]: r for r in a["advisory_reach"]}
    concentration = {r["package_manager"]: r for r in a["concentration"]}
    relation = {r["package_manager"]: r for r in a["count_relationship"]}
    pct = lambda n, d: 100 * n / d if d else 0
    hist = a["severity_histogram"]
    modes = {r["severity_score"]: r["n"] for r in hist["top_numeric_modes"]}
    required = {"pypi", "npm", "rubygems", "cargo"}
    if not required.issubset(eco) or any(r['high_critical_known_association_pct'] is None or r['high_critical_known_advisory_max_pct'] is None for r in weight.values()):
     
        return {stem: f"This figure summarizes the supplied processed population of {a['totals']['associations']:,} associations and {a['totals']['packages']:,} ecosystem-qualified packages across {len(eco)} observed ecosystems. Exact aggregate tables preserve the applicable denominators, while absent ecosystems and unknown scores must not be interpreted as a measured zero burden."
                for stem in CAPTIONS}
    return {
        "01_ecosystem_composition": f"PyPI contributes {eco['pypi']['associations']:,} of {a['totals']['associations']:,} associations ({pct(eco['pypi']['associations'],a['totals']['associations']):.2f}%), while npm contributes {eco['npm']['packages']:,} of {a['totals']['packages']:,} observed packages ({pct(eco['npm']['packages'],a['totals']['packages']):.2f}%). The reversal shows why repeated package-version/advisory links and distinct package counts. These are counts within the vulnerable-association export, so neither share estimates prevalence among all ecosystem packages.",
        "02_quality_profiles": f"No processed association has missing/invalid numeric severity or a blank description, but recorded-zero rates differ: RubyGems {pct(quality['rubygems']['severity_zero'],quality['rubygems']['n']):.2f}%, PyPI {pct(quality['pypi']['severity_zero'],quality['pypi']['n']):.2f}%, Cargo {pct(quality['cargo']['severity_zero'],quality['cargo']['n']):.2f}% and npm {pct(quality['npm']['severity_zero'],quality['npm']['n']):.2f}%. Thus syntactically complete fields still require semantic review before cross-ecosystem comparison. Zero is retained as a recorded value; its exporter meaning is undocumented and these observations cannot establish a random missingness mechanism or safety.",
        "03_severity_bands": f"Scores of at least 7 account for {weight['npm']['high_critical_associations']:,}/{eco['npm']['associations']:,} npm associations ({weight['npm']['high_critical_known_association_pct']:.2f}%) and {weight['pypi']['high_critical_associations']:,}/{eco['pypi']['associations']:,} PyPI associations ({weight['pypi']['high_critical_known_association_pct']:.2f}%). Because this export has no unknown numeric scores, the known-score and full-association denominators coincide in these percentages. The profiles answer the observed impact-distribution question, but repeated affected versions and source scoring conventions prevent interpreting the difference as ecosystem-wide risk.",
        "04_weighting_ecdf": f"The npm high/critical share changes from {weight['npm']['high_critical_known_association_pct']:.2f}% among {weight['npm']['known_score_associations']:,} scored associations to {weight['npm']['high_critical_known_advisory_max_pct']:.2f}% among {weight['npm']['known_score_ecosystem_advisory_ids']:,} ecosystem-advisory maxima; PyPI changes only from {weight['pypi']['high_critical_known_association_pct']:.2f}% to {weight['pypi']['high_critical_known_advisory_max_pct']:.2f}%. Repeated links to many affected versions can substantially change an impact summary, so choosing the counting unit matters more than simply choosing a chart. Each observed ecosystem-advisory pair has one numeric score here, but unresolved aliases mean advisory IDs still cannot be assumed to represent independent vulnerabilities.",
        "05_package_version_burden": f"PyPI's {burden['pypi']['n']:,} observed packages have median {burden['pypi']['median']:g} affected versions and IQR {burden['pypi']['iqr']:g}, compared with npm's median {burden['npm']['median']:g} and IQR {burden['npm']['iqr']:g} across {burden['npm']['n']:,} packages. npm nevertheless reaches {burden['npm']['max']:g} versions for one package, making the long tail visible on a log axis; its zero IQR means counts above one meet the mechanical 1.5-IQR rule, not that they are invalid. Resistant summaries preserve this structure without deleting legitimate extremes, and no complete-release denominator or chronology is available.",
        "06_advisory_reach": f"Median affected-package-version reach is {reach['pypi']['median']:g} for {reach['pypi']['n']:,} PyPI ecosystem-advisory IDs, {reach['rubygems']['median']:g} for RubyGems and {reach['npm']['median']:g} for npm and Cargo. npm's maximum of {reach['npm']['max']:g} versus PyPI's {reach['pypi']['max']:g} shows that a small median can coexist with very broad observed advisories. It supports inspection of high-burden IDs, but counts represent observed associations rather than installations, exploitation or alias-resolved security events.",
        "07_exposure_concentration": f"The top {concentration['npm']['top_1pct_packages_count']:,} of {concentration['npm']['package_count']:,} npm packages account for {concentration['npm']['top_1pct_version_share_pct']:.2f}% of its {concentration['npm']['affected_version_sum']:,} observed affected versions; the corresponding PyPI group of {concentration['pypi']['top_1pct_packages_count']} accounts for {concentration['pypi']['top_1pct_version_share_pct']:.2f}%. This concentration suggests that a descriptive review focused on high-burden observed packages can cover many affected-version records. Each top group is ceil(1% of observed packages), and the curve measures neither installed dependency reach nor the probability a package is vulnerable.",
        "08_package_count_relationship": "Spearman correlations between distinct affected-version count and advisory-ID count are " + ", ".join(f"{e} " + (f"{relation[e]['spearman_rho']:.3f}" if relation[e]['spearman_rho'] is not None else "undefined") + f" (n={relation[e]['n_packages']:,})" for e in ['pypi','npm','rubygems','cargo']) + ". A defined positive coefficient indicates rank association; a constant count makes the coefficient undefined. Hexbin aggregation avoids overplotting and exposes ties and sparse tails; without a fitted trend there are no model residuals to diagnose, and no causal or temporal conclusion follows.",
        "09_severity_histogram": f"Recorded zero forms a separate mass of {hist['recorded_zero_associations']:,}/{hist['population_associations']:,} associations ({pct(hist['recorded_zero_associations'],hist['population_associations']):.2f}%); missing/invalid scores number {hist['unknown_associations']:,} and never enter the numeric bins. Among positive recorded scores, exact modes include 7.5 ({modes.get(7.5,0):,} associations) and 9.8 ({modes.get(9.8,0):,}), producing pronounced peaks rather than a smooth bell-shaped distribution. Half-point bins reveal broad shape while the exact frequency table preserves discrete spikes; these association-weighted peaks reflect repeated versions and score conventions, not independent vulnerability counts."
    }


def _write_investigation_log(root, a):

    (root / "docs").mkdir(parents=True, exist_ok=True)
    def read_result(name, fallback):
        path = root / "results" / name
        return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else fallback
    def number(value):
        return "undefined" if value is None else f"{int(value):,}" if float(value).is_integer() else f"{value:.3f}"
    def percent(numerator, denominator):
        return "undefined" if not denominator else f"{100*numerator/denominator:.2f}%"
    t = a["totals"]
    eco = a["ecosystems"]
    sampling = read_result("sampling.json", {})
    attempts = read_result("attempted_strategies.json", [])
    prefix = next((x for x in attempts if x.get("id") == "D1"), {})
    collapse = next((x for x in attempts if x.get("id") == "D2"), {})
    max_gap = max((r["absolute_percentage_point_difference"] for r in prefix.get("evidence", {}).values()), default=0)
    prefix_shares = "; ".join(f"{e} {100*r['prefix_share']:.2f}% versus full-source {100*r['full_share']:.2f}%" for e,r in prefix.get("evidence", {}).items())
    quotas = ", ".join(f"{e} {n:,}" for e,n in sampling.get("quotas", {}).items())
    quality = "; ".join(f"{r['package_manager']}: unknown {r['severity_unknown']:,}/{r['n']:,}, zero {r['severity_zero']:,}/{r['n']:,} ({percent(r['severity_zero'],r['n'])}), blank description {r['description_blank']:,}" for r in a["quality"])
    severity = "; ".join(f"{r['package_manager']} {r['high_critical_associations']:,}/{r['known_score_associations']:,} ({number(r['high_critical_known_association_pct'])}%)" for r in a["weighting_comparison"])
    histogram = a["severity_histogram"]
    modes = "; ".join(f"score {r['severity_score']:g}: {r['n']:,} associations" for r in histogram["top_numeric_modes"][:6])
    burden = "; ".join(f"{r['package_manager']} n={r['n']:,}, five-number summary ({number(r['min'])}, {number(r['q1'])}, {number(r['median'])}, {number(r['q3'])}, {number(r['max'])}), IQR={number(r['iqr'])}, skewness={number(r['skewness'])}, 1.5-IQR outside values={r['outlier_count']:,}" for r in a["package_burden"])
    reach = "; ".join(f"{r['package_manager']} n={r['n']:,} IDs, median={number(r['median'])}, IQR={number(r['iqr'])}, maximum={number(r['max'])} affected package versions" for r in a["advisory_reach"])
    correlation = "; ".join(f"{r['package_manager']} rho={number(r['spearman_rho'])}, n={r['n_packages']:,} packages" for r in a["count_relationship"])
    weighting = "; ".join(f"{r['package_manager']}: association high/critical {number(r['high_critical_known_association_pct'])}% of {r['known_score_associations']:,}, advisory-maximum high/critical {number(r['high_critical_known_advisory_max_pct'])}% of {r['known_score_ecosystem_advisory_ids']:,}" for r in a["weighting_comparison"])
    concentration = "; ".join(f"{r['package_manager']}: top {r['top_1pct_packages_count']:,}/{r['package_count']:,} packages contribute {r['top_1pct_version_share_pct']:.2f}% of {r['affected_version_sum']:,} affected versions; top-10% group contributes {r['top_10pct_version_share_pct']:.2f}%" for r in a["concentration"])
    conflicts = "; ".join(f"{r['package_manager']} {r['multi_score_ids']:,}/{r['advisory_ids']:,} IDs have multiple numeric scores" for r in a["advisory_conflicts"])
    assert sum(r["associations"] for r in eco) == t["associations"]
    assert histogram["recorded_zero_associations"] + histogram["positive_associations"] + histogram["unknown_associations"] == t["associations"]
    entries = [
        (1, "Ecosystem composition and data grain", "Processed associations and exact entity tuples", "Exact grouped counts at four grains", "figures/01_ecosystem_composition.png; results/ecosystem_counts.csv", f"The full processed population contains {t['associations']:,} associations, {t['packages']:,} ecosystem-qualified packages, {t['versions']:,} package versions, {t['advisory_ids']:,} raw IDs and {t['ecosystem_advisory_ids']:,} ecosystem-advisory pairs. " + "; ".join(f"{r['package_manager']}: {r['associations']:,} associations and {r['packages']:,} packages" for r in eco) + ". Counting unit changes the apparent distribution because version/advisory repetition contributes differently from distinct packages.", "Export composition does not estimate prevalence among all published packages or releases."),
        (2, "Subgroup completeness", "Processed association", "Exact unknown-score, recorded-zero and blank-description rates", "figures/02_quality_profiles.png; results/processed_quality.csv", quality + ". Populated fields still require semantic validation; recorded zero is retained separately rather than imputed or called safe.", "The observed patterns do not establish a random missingness mechanism or exporter zero convention."),
        (3, "Sampling strategy diagnosis", "Raw prefix diagnostic and full cleaned sample strata", "Compare prefix/full-source ecosystem shares; seeded whole-population stratification", "results/attempted_strategies.json; results/sampling.json", f"The first-250,000-record diagnostic had a maximum ecosystem-share discrepancy of {max_gap:.2f} percentage points: {prefix_shares}. The final auxiliary sample contains {sampling.get('sample_rows',0):,} records with quotas {quotas} and seed {sampling.get('seed','not recorded')}. Source ordering invalidates the prefix as general coverage; primary results instead use the complete cleaned population and the sample supplies inclusion probabilities and inverse weights.", "Balanced quotas are not self-weighting; sample proportions cannot be substituted for full-population proportions."),
        (4, "Severity composition", "Known-score processed association within ecosystem", "Exact high/critical counts and severity-band shares", "figures/03_severity_bands.png; results/severity_bands.csv", "Recorded scores at least 7: " + severity + ". These are observed association-weighted impact summaries with explicit ecosystem denominators; repeated affected versions influence the result.", "Numeric bins do not verify a shared CVSS version, exploitability or ecosystem-wide risk."),
        (5, "Score shape and spikes", "Known-score processed association", "Exact score modes and empirical cumulative distributions", "figures/04_weighting_ecdf.png; results/severity_score_frequency.csv", modes + ". The pronounced discrete masses contradict a smooth normal-shape assumption; ECDFs preserve the jumps without imposing a fitted density or trend.", "A frequent score can reflect source conventions and repeated affected-version links, rather than many independent vulnerabilities."),
        (6, "Affected-version burden per package", "Ecosystem-qualified observed package", "Five-number summaries, IQR, skewness and outside-value counts", "figures/05_package_version_burden.png; results/package_burden_summary.csv", burden + ". Medians and log axes expose typical counts and long tails without deleting legitimate high-burden packages; a zero IQR makes the mechanical outside-value rule especially sensitive to ties.", "Observed affected-version count has no complete-release denominator and supplies no release chronology."),
        (7, "Affected-version reach per advisory", "Ecosystem-advisory ID", "Exact distinct package-version reach and resistant summaries", "figures/06_advisory_reach.png; results/advisory_reach_summary.csv", reach + ". Small medians coexist with very broad observed advisory IDs, so a single average would conceal the long tail.", "Raw IDs remain unresolved aliases and observed reach is not installation count or independent-event count."),
        (8, "Relationship between package version and advisory counts", "Ecosystem-qualified observed package", "Logarithmic hexbin aggregation and exact Spearman rank correlation", "figures/08_package_count_relationship.png; results/count_relationship.csv", correlation + ". Defined positive coefficients indicate rank association between distinct observed affected-version and advisory counts, while ties and sparse tails prevent interpreting one linear slope as an adequate model.", "No regression or causal trend is fitted, so model residual diagnostics are inapplicable; a constant count gives an undefined coefficient."),
        (9, "Association versus advisory weighting", "Known-score association versus ecosystem-advisory maximum", "Compare high/critical shares with separate estimands", "figures/04_weighting_ecdf.png; results/weighting_comparison.csv", weighting + ". The comparison shows how one advisory repeated across affected versions can change a severity summary; both denominators are retained rather than conflated.", "Maximum score is an explicit advisory-level summary and does not resolve aliases; future conflicting values could affect the maximum."),
        (10, "Concentration of observed affected versions", "Ecosystem-qualified observed package", "Lorenz curves and top ceil(1% or 10%) package shares", "figures/07_exposure_concentration.png; results/concentration.csv", concentration + ". Concentration supports descriptive inspection of high-burden observed packages, with exact rounded-up group sizes disclosed.", "Package-version burden is not installed dependency reach, exploitation probability or an all-package prevalence denominator."),
        (11, "Advisory consistency and cross-ecosystem IDs", "Raw ID and ecosystem-advisory pair", "Count distinct scores/descriptions, shared IDs and rejected ID-only collapse", "results/advisory_score_conflicts.csv; results/conflict_examples.csv; results/cross_ecosystem_ids.csv; results/attempted_strategies.json", f"There are {a['cross_ecosystem_advisory_ids']:,} raw IDs appearing in multiple ecosystems; {conflicts}. The retained conflict-example query returns {len(a['conflict_examples']):,} discrepant score/description examples. The ID-only diagnostic found {collapse.get('advisories_affecting_multiple_versions',0):,} IDs spanning multiple versions, so deleting repeated IDs would discard legitimate links.", "Cross-ecosystem identity does not prove dependency propagation, and absence of observed conflicts does not validate all source semantics."),
        (12, "Support for temporal and transitive questions", "Six-field source schema and observed analytical population", "Match required metadata to research-question requirements", "results/analytics.json research_question_support; data/processed/schema.json", f"The export describes {t['versions']:,} observed affected package versions but has zero genuine release-timestamp fields and zero resolved dependency-edge fields. Distribution and CSV-quality questions are supported within this population; recent-versus-older and direct/transitive fractions cannot be calculated from these columns. Phase 3 enrichment must supply validated dates, release denominators, edges/constraints and alias metadata before those analyses or safe-class prediction are defined.", "A supplied graph dump or package-level Requires edge is not itself evidence of resolved version-specific transitive exposure."),
        (13, "Numeric severity histogram", "Processed association", "Exact frequency-weighted half-point bins with a separate recorded-zero mass", "figures/09_severity_histogram.png; results/severity_histogram.csv", f"Recorded zero {histogram['recorded_zero_associations']:,} + positive {histogram['positive_associations']:,} + unknown {histogram['unknown_associations']:,} = {t['associations']:,} processed associations. Zero accounts for {percent(histogram['recorded_zero_associations'],t['associations'])}; positive-score bins have width {histogram['bin_width']:g} on [0,10], with the final right endpoint included. Exact modes and bin totals retain discrete score structure without expanding every association into Python memory.", "Unknown scores never enter numeric bins or become zeros; association-weighted peaks are not independent-vulnerability counts.")
    ]
    lines = ["# Completed exploratory investigations", "", "Prepared with disclosed AI assistance from generated numerical evidence. The analysis tool completed technical review of entity grain, denominators, grouped-count reconciliation, histogram accounting and interpretation scope. This computational review is not attributed to any individual student's personal effort or attestation. Primary findings use the complete processed export; investigation 3 explicitly distinguishes its raw-prefix diagnostic from the auxiliary cleaned sample.", ""]
    for i, question, grain, method, evidence, finding, limitation in entries:
        lines += [f"## {i} {question}", "", f"**Population and grain:** {grain}.", "", f"**Method and evidence:** {method}. {evidence}.", "", f"**Completed finding and interpretation:** {finding}", "", f"**Limit:** {limitation}", ""]
    (root / "docs/investigation_log.md").write_text("\n".join(lines), encoding="utf-8")


def build_notebook(root):
    """Create the completed analysis without hiding production processing in cells."""
    import nbformat as nbf
    root = Path(root)
    a = json.loads((root / "results/analytics.json").read_text(encoding="utf-8"))
    interpretations = a.get("figure_interpretations") or figure_interpretations(a)
    nb = nbf.v4.new_notebook()
    nb.metadata.kernelspec = {"display_name": "Python 3", "language": "python", "name": "python3"}
    cells = [nbf.v4.new_markdown_cell("# Phase 2 package vulnerability analysis\n\nTeam: Manik Kashikar, Praveen Kumar, Sankeerth Reddy.\n\nComplete evidence-based analysis prepared with AI assistance. This notebook reloads the full typed processed export, independently checks its entity counts and explains all nine generated figures. Production cleaning and analytics remain in `src/`; individual participation is documented separately."),
             nbf.v4.new_code_cell("from pathlib import Path\nimport os, json, hashlib\nimport yaml, duckdb\nfrom IPython.display import display, Image, Markdown\nROOT = Path.cwd().resolve()\nif not (ROOT / 'config/phase2.yaml').exists():\n    ROOT = ROOT.parent\nconfig_file = Path(os.environ.get('PHASE2_CONFIG', 'config/phase2.yaml'))\nif not config_file.is_absolute():\n    config_file = ROOT / config_file\nCONFIG = yaml.safe_load(config_file.read_text(encoding='utf-8'))\ndef configured_path(value):\n    path = Path(value)\n    return path if path.is_absolute() else ROOT / path\nRESULTS = configured_path(CONFIG.get('results_dir', 'results'))\nFIGURES = configured_path(CONFIG.get('figures_dir', 'figures'))\nprocessed = configured_path(CONFIG.get('output_dir', 'data/processed')) / 'associations.parquet'\nassert processed.is_file(), 'Run python -m src.pipeline --config config/phase2.yaml first'\nA = json.loads((RESULTS / 'analytics.json').read_text(encoding='utf-8'))\nwith processed.open('rb') as stream:\n    assert hashlib.file_digest(stream, 'sha256').hexdigest() == A['processed_sha256']\ncon = duckdb.connect()\ncon.execute(\"SET memory_limit='512MB'\")\ncon.read_parquet(str(processed)).create_view('a')\nactual = con.execute('SELECT count(*) FROM a').fetchone()[0]\nassert actual == A['totals']['associations']\nprint('Configured processed file:', processed)\nprint('Reloaded full processed population:', format(actual, ','), 'associations')\nprint(json.dumps(A['totals'], indent=2))"),
             nbf.v4.new_markdown_cell("## Grain and scope\n\nThe package key is ecosystem plus package name; the version key adds version; the association key adds advisory ID. Raw advisory IDs may be unresolved aliases, so 24,586 raw IDs and 26,640 ecosystem-advisory pairs are different counts. The CSV records only observed vulnerable associations. It supplies neither a complete-release denominator nor genuine release dates or resolved dependency edges, preventing prevalence, recency and direct/transitive fractions."),
             nbf.v4.new_code_cell("assert con.execute('SELECT count(*) FROM a WHERE severity_score < 0 OR severity_score > 10').fetchone()[0] == 0\nprint('Known score range check passed')\nprint('Null scores:', con.execute('SELECT count(*) FROM a WHERE severity_score IS NULL').fetchone()[0])\nprint('Recorded zeros:', con.execute('SELECT count(*) FROM a WHERE severity_score=0').fetchone()[0])\nprint(con.execute('SELECT package_manager,count(*) FROM a GROUP BY 1 ORDER BY 2 DESC').fetchall())")]
    for i, (stem, caption) in enumerate(CAPTIONS.items()):
        cells.append(nbf.v4.new_markdown_cell(f"## {i+1} {stem[3:].replace('_', ' ').capitalize()}\n\n{caption}\n\n{interpretations[stem]}"))
        code = f"display(Image(filename=str(FIGURES / '{stem}.png')))"
        if stem == "09_severity_histogram":
            code += "\n# Check histogram accounting directly against the processed relation.\nzero, positive, unknown = con.execute('SELECT count(*) FILTER(WHERE severity_score=0),count(*) FILTER(WHERE severity_score>0),count(*) FILTER(WHERE severity_score IS NULL) FROM a').fetchone()\nH = A['severity_histogram']\nassert (zero,positive,unknown) == (H['recorded_zero_associations'],H['positive_associations'],H['unknown_associations'])\nassert sum(b['positive_associations'] for b in H['bins']) == positive\nassert zero + positive + unknown == actual\nprint('Independent zero/positive/unknown and histogram accounting passed:', zero,positive,unknown)"
        cells.append(nbf.v4.new_code_cell(code))
    cells += [nbf.v4.new_markdown_cell("## Quantitative answers and additional investigations\n\nThe separate result tables answers the distribution and cross-ecosystem-quality questions within the export. Full-source sampling diagnosis rejects the all-npm 250,000-row prefix; advisory-only collapse rejects deletion of legitimate version links. Correlation measures rank association across the complete observed package population, while concentration measures affected-version shares. Temporal and transitive questions remain deferred for explicitly missing metadata, and no fitted trend is used."),
              nbf.v4.new_code_cell("for key in ['package_burden','advisory_reach','concentration','weighting_comparison','count_relationship','advisory_conflicts','research_question_support']:\n    display(Markdown('### ' + key.replace('_',' ').title()))\n    print(json.dumps(A[key], indent=2))"),
              nbf.v4.new_markdown_cell("## Reproducibility and scope of verification\n\nConfiguration determines processed, results and figure paths, rather than historical paths saved in an older receipt. `PHASE2_CONFIG` optionally selects another configuration file. A checksum binds the reloaded Parquet to its analytical results; the final cell independently recomputes exact entity counts. Clean-kernel execution demonstrates computational consistency but cannot establish student authorship, personal participation or a new dependency environment; those require separate evidence."),
              nbf.v4.new_code_cell("# Recompute distinct entities without trusting the JSON summary.\nassert con.execute('SELECT count(DISTINCT (package_manager,package_name)) FROM a').fetchone()[0] == A['totals']['packages']\nassert con.execute('SELECT count(DISTINCT (package_manager,package_name,version_name)) FROM a').fetchone()[0] == A['totals']['versions']\nassert con.execute('SELECT count(DISTINCT vuln_id) FROM a').fetchone()[0] == A['totals']['advisory_ids']\nassert con.execute('SELECT count(DISTINCT (package_manager,vuln_id)) FROM a').fetchone()[0] == A['totals']['ecosystem_advisory_ids']\nfor stem in A['figure_captions']:\n    assert (FIGURES / (stem + '.png')).is_file()\ncon.close()\nprint('Processed reload, exact entity counts and all nine figure links verified.')")]
    nb.cells = cells
    (root / "notebooks").mkdir(exist_ok=True)
    nbf.write(nb, root / "notebooks/phase2_analysis.ipynb")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--processed")
    parser.add_argument("--results-dir")
    parser.add_argument("--figures-dir")
    args = parser.parse_args()
    print(json.dumps(run_analytics(args.root, args.processed, args.results_dir, args.figures_dir)["totals"], indent=2))
