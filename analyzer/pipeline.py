"""
Vulnerability Risk Assessment Pipeline.

Runs the full evidence chain for one or more CVEs against a given project:
  1. Load seeds (YAML)
  2. Build or load a call graph (Java extractor)
  3. Static reachability analysis (BFS + CHA)
  4. Runtime evidence (OTel trace log, if available)
  5. Evidence fusion (L0–L5 level, decision, risk score)
  6. Write JSON report to reports/

Usage:
    python analyzer/pipeline.py --help
    python analyzer/pipeline.py --project-jars a.jar b.jar --cve CVE-2021-44228
    python analyzer/pipeline.py --project-jars a.jar b.jar   # runs all seeds
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from fusion import fuse
from models import EvidenceChain
from remediation import RemediationAdvice, build_remediation
from runtime_analyzer import analyze_traces
from seed_loader import Seed, load_all_seeds
from static_analyzer import StaticAnalyzer

ROOT          = Path(__file__).parent.parent
SEEDS_DIR     = ROOT / "data" / "seeds"
REPORTS_DIR   = ROOT / "reports"
EXTRACTOR_JAR = ROOT / "tools" / "callgraph-extractor" / "target" / "callgraph-extractor-1.0.jar"
TRACES_DIR    = ROOT / "data" / "traces"


def assess_cve(
    cve_id: str,
    seed: Seed,
    project_jars: list[Path],
    project_artifact: str,
    analyzer: StaticAnalyzer,
    callgraph_cache: Path | None,
    trace_log: Path | None,
    project_prefix: str | None = None,
    extra_entry_points: list[str] | None = None,
) -> tuple[EvidenceChain, RemediationAdvice]:
    vm = seed.primary_method

    # Static analysis
    static_ev = analyzer.analyze(
        app_jars            = project_jars,
        seed_method         = vm,
        callgraph_cache     = callgraph_cache,
        project_prefix      = project_prefix,
        extra_entry_points  = extra_entry_points,
    )

    # Runtime evidence (optional)
    runtime_ev = None
    if trace_log and trace_log.exists():
        runtime_ev = analyze_traces(trace_log, vm)

    # Fuse into EvidenceChain
    chain = fuse(
        cve              = cve_id,
        project_artifact = project_artifact,
        seed             = seed,
        static           = static_ev,
        runtime          = runtime_ev,
    )

    advice = build_remediation(chain, seed, project_prefix or "")

    return chain, advice


def run(
    project_jars: list[Path],
    project_artifact: str,
    cve_filter: list[str] | None,
    callgraph_cache: Path | None,
    trace_log: Path | None,
    output_file: Path | None,
    output_vex: Path | None,
    verbose: bool,
    project_prefix: str | None = None,
    extra_entry_points: list[str] | None = None,
) -> None:

    seeds = load_all_seeds(SEEDS_DIR)
    if cve_filter:
        seeds = {k: v for k, v in seeds.items() if k in cve_filter}

    if not seeds:
        print(f"No seeds found for filter: {cve_filter}", file=sys.stderr)
        sys.exit(1)

    analyzer = StaticAnalyzer(EXTRACTOR_JAR)
    chains   = []
    advices  = []

    for cve_id, seed in seeds.items():
        if verbose:
            print(f"\n[{cve_id}]")

        chain, advice = assess_cve(
            cve_id              = cve_id,
            seed                = seed,
            project_jars        = project_jars,
            project_artifact    = project_artifact,
            analyzer            = analyzer,
            callgraph_cache     = callgraph_cache,
            trace_log           = trace_log,
            project_prefix      = project_prefix,
            extra_entry_points  = extra_entry_points,
        )
        chains.append(chain)
        advices.append(advice)

        # One-line summary to terminal
        level_tag = f"L{chain.evidence_level.value}"
        print(
            f"  {cve_id:26s}  {level_tag}  "
            f"{chain.decision.value:26s}  "
            f"risk={chain.risk_score:4.1f}  "
            f"conf={chain.decision_confidence:.2f}  "
            f"remedy={advice.priority}"
        )

    # Write JSON report
    findings = []
    for chain, advice in zip(chains, advices):
        finding = chain.to_dict()
        finding["remediation"] = {
            "priority":                advice.priority,
            "upgrade_path":            advice.upgrade_path,
            "entry_point_in_your_code": advice.entry_point_in_your_code,
            "fix_commit":              advice.fix_commit,
            "effort_estimate":         advice.effort_estimate,
            "notes":                   advice.notes,
        }
        findings.append(finding)

    report = {
        "project": project_artifact,
        "findings": findings,
        "summary": {
            "total": len(chains),
            "affected":    sum(1 for c in chains if c.decision and "affected"    in c.decision.value),
            "not_affected": sum(1 for c in chains if c.decision and "not_affected" in c.decision.value),
            "under_investigation": sum(1 for c in chains if c.decision and c.decision.value == "under_investigation"),
        },
    }

    if output_file:
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"\nReport written to {output_file}")

    if output_vex:
        write_vex(output_vex, project_artifact, chains)
        print(f"VEX written to {output_vex}")

    return None


_VEX_STATE_MAP = {
    "affected":               "exploitable",
    "likely_affected":        "in_triage",
    "under_investigation":    "in_triage",
    "not_affected_candidate": "not_affected",
    "fixed":                  "fixed",
    "mitigated":              "not_affected",
}


def write_vex(path: Path, project_artifact: str, chains: list[EvidenceChain]) -> None:
    """Write a CycloneDX 1.5 VEX document for CRA conformity assessors."""
    import datetime
    now = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    vulnerabilities = []
    for chain in chains:
        state = _VEX_STATE_MAP.get(chain.decision.value if chain.decision else "", "in_triage")
        vulnerabilities.append({
            "id": chain.cve,
            "analysis": {
                "state": state,
                "detail": chain.notes,
                "response": ["update"] if state in ("exploitable", "in_triage") else [],
            },
            "affects": [{"ref": project_artifact}],
        })

    vex_doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": now,
            "tools": [{"name": "vuln-risk-assessor", "version": "1.0"}],
        },
        "vulnerabilities": vulnerabilities,
    }

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(vex_doc, indent=2), encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(
        description="Method-level CVE risk assessment pipeline"
    )
    parser.add_argument(
        "--project-jars", nargs="+", required=True,
        help="JAR files to analyze (app JAR + dependency JARs)"
    )
    parser.add_argument(
        "--project-artifact", default="unknown:unknown:unknown",
        help="Maven coordinates of the project being assessed"
    )
    parser.add_argument(
        "--cve", nargs="*",
        help="Only assess these CVE IDs (default: all seeds)"
    )
    parser.add_argument(
        "--callgraph-cache",
        help="Reuse a previously generated call graph file"
    )
    parser.add_argument(
        "--trace-log",
        help="OTel trace log from collect_traces.py"
    )
    parser.add_argument(
        "--output",
        help="Path for JSON report (default: reports/<artifact>.json)"
    )
    parser.add_argument(
        "--extra-entry-points", nargs="*",
        help="Additional method signatures to use as BFS entry points "
             "(e.g. 'com.example.MyServlet.service(Ljavax/servlet/...')"
    )
    parser.add_argument(
        "--output-vex",
        help="Path for CycloneDX 1.5 VEX document (CRA conformity output)"
    )
    parser.add_argument(
        "--verbose", action="store_true"
    )

    args = parser.parse_args()

    project_jars = [Path(j) for j in args.project_jars]
    for jar in project_jars:
        if not jar.exists():
            print(f"ERROR: JAR not found: {jar}", file=sys.stderr)
            sys.exit(1)

    # Derive Java package prefix from Maven groupId (the part before the first ':').
    # e.g. "com.example:log4j-demo" -> "com.example"
    # This filters out library tool classes (Log4j's own Version.main, etc.)
    # from being treated as application entry points.
    project_prefix = args.project_artifact.split(":")[0] if ":" in args.project_artifact else None

    artifact_slug = args.project_artifact.replace(":", "_").replace("/", "_")
    output_file = Path(args.output) if args.output else (
        REPORTS_DIR / f"{artifact_slug}.json"
    )

    run(
        project_jars        = project_jars,
        project_artifact    = args.project_artifact,
        cve_filter          = args.cve,
        callgraph_cache     = Path(args.callgraph_cache) if args.callgraph_cache else None,
        trace_log           = Path(args.trace_log) if args.trace_log else None,
        output_file         = output_file,
        output_vex          = Path(args.output_vex) if args.output_vex else None,
        verbose             = args.verbose,
        project_prefix      = project_prefix,
        extra_entry_points  = args.extra_entry_points,
    )


if __name__ == "__main__":
    main()
