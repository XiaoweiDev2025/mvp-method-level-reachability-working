"""
Reachability-adjusted exposure reduction metric.

Compares aggregate CVSS-weighted exposure under two models:
  - Package-level scanner: every (app, CVE) pair where the vulnerable
    dep is present is reported at full CVSS (no reachability info).
  - Method-level (this tool): uses the pipeline's reachability-adjusted
    risk_score = CVSS × evidence_multiplier, where:
      NOT_REACHABLE       → × 0.10  (residual uncertainty, not zero)
      UNDER_INVESTIGATION → × 0.50
      AFFECTED            → × 1.00

The multipliers are design parameters, not natural laws.  The 0.10
residual for NOT_REACHABLE represents analysis uncertainty: reflection,
invokedynamic, and dynamic class loading are not modelled by static
analysis, and unreachable code today may become reachable after a
refactor.  This metric therefore measures reachability-adjusted exposure
re-weighting, not a reduction in real-world attack probability.

Only (app, CVE) pairs where the vulnerable dep is in the app's classpath
are counted.  Cross-CVE pipeline outputs are excluded.

Usage:
  python scripts/risk_reduction.py
"""

import json
from pathlib import Path

# -----------------------------------------------------------------------
# Evaluation matrix: explicit (report, CVE) pairs where the vulnerable
# dep IS present in the app.  This mirrors what a package-level scanner
# would flag.  Cross-CVE pipeline outputs are excluded intentionally.
# -----------------------------------------------------------------------
EVALUATION_MATRIX = [
    # (report_path,                        cve_id,            app_label,                    cvss)
    ("reports/log4j.json",           "CVE-2021-44228", "vulnerable-log4j-demo",       10.0),
    ("reports/safe-log4j.json",      "CVE-2021-44228", "safe-log4j-demo",             10.0),
    ("reports/text4shell-vuln.json", "CVE-2022-42889", "vulnerable-text4shell-demo",   9.8),
    ("reports/text4shell-safe.json", "CVE-2022-42889", "safe-text4shell-demo",          9.8),
    ("reports/commons-io.json",      "CVE-2021-29425", "commons-io-demo",               4.8),
    ("reports/commons-io-safe.json", "CVE-2021-29425", "safe-commons-io-demo",           4.8),
    ("reports/plexus.json",          "CVE-2018-1002200", "plexus-demo",                 5.5),
    ("reports/plexus-safe.json",     "CVE-2018-1002200", "safe-plexus-demo",             5.5),
]

EVIDENCE_LABEL = {
    "affected":               "L4 RUNTIME_OBSERVED / AFFECTED",
    "likely_affected":        "L3 STATIC_REACHABLE / NOT_OBSERVED",
    "under_investigation":    "L3 STATIC_REACHABLE / NOT_RUN",
    "not_affected_candidate": "L2 NOT_REACHABLE",
}

# Authoritative multipliers (from fusion.py) — used for display, not back-calculated.
MULTIPLIER = {
    "affected":               1.00,
    "likely_affected":        0.75,
    "under_investigation":    0.50,
    "not_affected_candidate": 0.10,
}

ROOT = Path(__file__).parent.parent


def main() -> None:
    rows = []
    for rel_path, cve_id, app_label, cvss in EVALUATION_MATRIX:
        path = ROOT / rel_path
        if not path.exists():
            print(f"  [SKIP] {rel_path} not found")
            continue
        data = json.loads(path.read_text(encoding="utf-8"))
        finding = next((f for f in data.get("findings", []) if f["cve"] == cve_id), None)
        if finding is None:
            print(f"  [SKIP] {cve_id} not found in {rel_path}")
            continue
        risk     = finding["risk_score"]
        decision = finding["decision"]
        rows.append({
            "app":        app_label,
            "cve":        cve_id,
            "cvss":       cvss,
            "ml_risk":    risk,
            "multiplier": MULTIPLIER.get(decision, 0.50),
            "decision":   decision,
            "level":      f"L{finding['evidence_level']}",
        })

    if not rows:
        print("No data found.")
        return

    pkg_total = sum(r["cvss"]    for r in rows)
    ml_total  = sum(r["ml_risk"] for r in rows)
    reduction = (pkg_total - ml_total) / pkg_total * 100

    # -----------------------------------------------------------------------
    # Print table
    # -----------------------------------------------------------------------
    col_app = max(len(r["app"]) for r in rows) + 2
    header = (
        f"{'App':<{col_app}} {'CVE':<17} {'CVSS':>5}  "
        f"{'Pkg exposure':>13}  {'mult':>4}  {'Adj. exposure':>14}  Evidence classification"
    )
    sep = "-" * len(header)
    print(header)
    print(sep)
    for r in rows:
        label = EVIDENCE_LABEL.get(r["decision"], r["decision"])
        print(
            f"{r['app']:<{col_app}} {r['cve']:<17} {r['cvss']:>5.1f}  "
            f"{r['cvss']:>13.1f}  {r['multiplier']:>4.2f}  {r['ml_risk']:>14.1f}  "
            f"{label}"
        )
    print(sep)
    print(
        f"{'TOTAL':<{col_app}} {'':<17} {'':<5}  "
        f"{pkg_total:>13.1f}  {'':>4}  {ml_total:>14.1f}"
    )
    print()

    # -----------------------------------------------------------------------
    # Summary statistics
    # -----------------------------------------------------------------------
    n = len(rows)
    n_reachable     = sum(1 for r in rows if r["decision"] != "not_affected_candidate")
    n_not_reachable = sum(1 for r in rows if r["decision"] == "not_affected_candidate")
    n_affected      = sum(1 for r in rows if r["decision"] == "affected")

    print(f"Evaluation dataset : 8 Java Maven applications covering {n // 2} CVEs "
          f"with vulnerable and safe variants")
    print(f"  Statically reachable         : {n_reachable}/{n} "
          f"({n_reachable/n*100:.0f}%)")
    print(f"  Statically not reachable     : {n_not_reachable}/{n} "
          f"({n_not_reachable/n*100:.0f}%)  -- package-level over-approximations")
    print(f"  Runtime-confirmed (L4)       : {n_affected}/{n}  (Log4Shell with OTel trace)")
    print()
    print(f"Aggregate CVSS-weighted exposure (package-level)        : {pkg_total:.1f}")
    print(f"Aggregate reachability-adjusted exposure (this tool)    : {ml_total:.1f}")
    print(f"Exposure re-weighting reduction                         : {reduction:.1f}%")
    print()
    print("Headline (for abstract):")
    print(
        f'  "Across the {n}-application evaluation dataset, method-level reachability '
        f"analysis reduced aggregate CVSS-weighted exposure by {reduction:.1f}% compared "
        f"with package-level scanning under the proposed reachability-adjusted scoring "
        f"model. {n_not_reachable} of {n} package-level alerts were classified as "
        f'statically not reachable and assigned a residual weight of 0.10 to account '
        f'for analysis uncertainty."'
    )


if __name__ == "__main__":
    main()
