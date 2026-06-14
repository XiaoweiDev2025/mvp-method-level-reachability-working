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

DECISION_LABEL = {
    "affected":               "AFFECTED",
    "likely_affected":        "LIKELY_AFFECTED",
    "under_investigation":    "REACHABLE (no trace)",
    "not_affected_candidate": "NOT_REACHABLE",
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
        rows.append({
            "app":      app_label,
            "cve":      cve_id,
            "cvss":     cvss,
            "ml_risk":  finding["risk_score"],
            "decision": finding["decision"],
            "level":    f"L{finding['evidence_level']}",
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
        f"{'App':<{col_app}} {'CVE':<17} {'CVSS':>6}  "
        f"{'Pkg scanner':>12}  {'This tool':>10}  Result"
    )
    sep = "-" * len(header)
    print(header)
    print(sep)
    for r in rows:
        label = DECISION_LABEL.get(r["decision"], r["decision"])
        print(
            f"{r['app']:<{col_app}} {r['cve']:<17} {r['cvss']:>6.1f}  "
            f"{'VULNERABLE':>12}  {r['ml_risk']:>10.1f}  "
            f"{r['level']} {label}"
        )
    print(sep)
    print(
        f"{'TOTAL':<{col_app}} {'':<17} {pkg_total:>6.1f}  "
        f"{pkg_total:>12.1f}  {ml_total:>10.1f}"
    )
    print()

    # -----------------------------------------------------------------------
    # Summary statistics
    # -----------------------------------------------------------------------
    n = len(rows)
    n_reachable     = sum(1 for r in rows if r["decision"] not in ("not_affected_candidate",))
    n_not_reachable = sum(1 for r in rows if r["decision"] == "not_affected_candidate")
    n_affected      = sum(1 for r in rows if r["decision"] == "affected")

    print(f"Test cases  : {n} applications × CVE pairs")
    print(f"  Reachable : {n_reachable}  ({n_reachable/n*100:.0f}%)")
    print(f"  Not reach : {n_not_reachable}  ({n_not_reachable/n*100:.0f}%) — these are pkg-scanner false positives")
    print(f"  Confirmed : {n_affected}  (L4 runtime-observed)")
    print()
    print(f"Aggregate CVSS-weighted exposure (package-level) : {pkg_total:.1f}")
    print(f"Aggregate reachability-adjusted exposure         : {ml_total:.1f}")
    print(f"Exposure re-weighting reduction                  : {reduction:.1f}%")
    print()
    print(
        f'Headline: "Reachability analysis reduced aggregate CVSS-weighted exposure by '
        f'{reduction:.0f}% relative to package-level scanning across our '
        f'{n}-application evaluation dataset, by assigning a residual weight of 0.10 '
        f'to statically-unreachable findings to account for analysis uncertainty '
        f'({n_not_reachable} of {n} package-scanner alerts were statically unreachable)."'
    )


if __name__ == "__main__":
    main()
