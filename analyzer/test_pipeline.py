"""
Full pipeline end-to-end test: CVE-2021-44228 (Log4Shell)

Runs the complete evidence chain:
  seed (YAML) -> static analysis -> runtime traces -> fusion -> EvidenceChain

Expected final output:
  evidence_level  : L4_RUNTIME_OBSERVED
  decision        : AFFECTED
  risk_score      : 10.0  (full CVSS-10.0 preserved since L4 AFFECTED)

Run:
    python analyzer/test_pipeline.py
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from fusion import fuse
from remediation import build_remediation
from runtime_analyzer import analyze_traces
from seed_loader import load_seed
from static_analyzer import StaticAnalyzer

ROOT        = Path(__file__).parent.parent
SEEDS_DIR   = ROOT / "data" / "seeds"
DEMO_DIR    = ROOT / "demo-projects" / "vulnerable-log4j-demo"
EXTRACTOR   = ROOT / "tools" / "callgraph-extractor" / "target" / "callgraph-extractor-1.0.jar"
CG_CACHE    = ROOT / "data" / "callgraph-log4j.txt"
TRACE_LOG   = ROOT / "data" / "traces" / "run1.log"


def run_pipeline(cve_id: str, project_artifact: str) -> dict:
    print(f"\n{'=' * 62}")
    print(f"Pipeline: {cve_id}  <- {project_artifact}")
    print(f"{'=' * 62}")

    # 1. Load seed
    seed = load_seed(SEEDS_DIR / f"{cve_id}.yaml")
    vm   = seed.primary_method
    print(f"  [L2] Seed  : {vm.full_signature}")

    # 2. Static analysis
    app_jars = [
        DEMO_DIR / "target" / "vulnerable-log4j-demo-1.0-SNAPSHOT.jar",
        DEMO_DIR / "target" / "dependency" / "log4j-core-2.14.1.jar",
        DEMO_DIR / "target" / "dependency" / "log4j-api-2.14.1.jar",
    ]
    analyzer      = StaticAnalyzer(EXTRACTOR)
    static_ev     = analyzer.analyze(app_jars, vm, callgraph_cache=CG_CACHE, project_prefix="com.example")
    print(f"  [L3] Static: {static_ev.status.value} (conf={static_ev.confidence})")
    if static_ev.call_path:
        print(f"       Path depth: {len(static_ev.call_path)} hops")

    # 3. Runtime evidence
    runtime_ev = analyze_traces(TRACE_LOG, vm)
    print(f"  [L4] Runtime: {runtime_ev.status.value} (conf={runtime_ev.confidence})")
    if runtime_ev.trace_ids:
        print(f"       Trace: {runtime_ev.trace_ids[0][:16]}...")

    # 4. Fusion
    chain = fuse(
        cve            = cve_id,
        project_artifact = project_artifact,
        seed           = seed,
        static         = static_ev,
        runtime        = runtime_ev,
    )

    print(f"\n  +- EvidenceChain -------------------------------------+")
    print(f"  |  chain_id    : {chain.chain_id}")
    print(f"  |  level       : {chain.evidence_level.name}  ({chain.evidence_level.value})")
    print(f"  |  decision    : {chain.decision.value}")
    print(f"  |  confidence  : {chain.decision_confidence:.2f}")
    print(f"  |  risk_score  : {chain.risk_score} / 10.0")
    print(f"  +------------------------------------------------------+")

    advice = build_remediation(chain, seed, project_prefix="com.example")
    print(f"  [Remedy] Priority: {advice.priority}  Effort: {advice.effort_estimate}")
    print(f"           Entry  : {advice.entry_point_in_your_code}")

    result = chain.to_dict()
    result["remediation"] = {
        "priority":                 advice.priority,
        "upgrade_path":             advice.upgrade_path,
        "entry_point_in_your_code": advice.entry_point_in_your_code,
        "fix_commit":               advice.fix_commit,
        "effort_estimate":          advice.effort_estimate,
        "notes":                    advice.notes,
    }
    return result


def main():
    result = run_pipeline(
        cve_id           = "CVE-2021-44228",
        project_artifact = "com.example:vulnerable-log4j-demo:1.0-SNAPSHOT",
    )

    print("\n  JSON output preview:")
    print(json.dumps(result, indent=2)[:1200])

    # Core assertions
    assert result["evidence_level"] == 4, f"Expected L4, got {result['evidence_level']}"
    assert result["decision"] == "affected", f"Expected affected, got {result['decision']}"
    assert result["risk_score"] == 10.0, f"Expected 10.0, got {result['risk_score']}"
    assert result["static"]["status"] == "reachable"
    assert result["runtime"]["status"] == "observed"

    # evidence_summary assertions
    es = result["evidence_summary"]
    assert es["dependency_match"] is True
    assert es["static_reachable"] is True
    assert es["runtime_observed"] is True
    assert es["entry_points"], "entry_points should be non-empty"
    assert es["call_path_depth"] > 0

    # static annotations
    assert result["static"]["analysis_fingerprint"], "fingerprint should be non-empty"
    assert result["static"]["call_path_annotated"], "annotated path should be non-empty"
    assert result["static"]["call_path_annotated"][0]["edge_type"] == "ENTRY_POINT"

    # remediation assertions
    rem = result["remediation"]
    assert rem["priority"] == "URGENT", f"Expected URGENT, got {rem['priority']}"
    assert rem["entry_point_in_your_code"].startswith("com.example"), \
        f"Entry point should be in com.example, got {rem['entry_point_in_your_code']}"
    assert rem["effort_estimate"] in ("LOW", "MEDIUM", "HIGH")

    print("\n  ALL ASSERTIONS PASSED")
    return True


if __name__ == "__main__":
    ok = main()
    sys.exit(0 if ok else 1)
