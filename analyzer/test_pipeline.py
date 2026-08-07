"""
Full pipeline end-to-end test: CVE-2021-44228 (Log4Shell)

Runs the complete evidence chain:
  seed (YAML) -> static analysis -> runtime traces -> fusion -> EvidenceChain

Expected final output:
  evidence_level  : L4_STATIC_RUNTIME_CORROBORATED
  decision        : AFFECTED
  risk_score      : 10.0  (full CVSS-10.0 preserved since L4 AFFECTED)

Run:
    python analyzer/test_pipeline.py
"""

import json
import sys
import tempfile
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from fusion import fuse
from models import Decision, EvidenceChain, EvidenceLevel
from pipeline import assess_cve, write_vex
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


def test_assess_cve_l1_short_circuit():
    """
    pipeline.py::assess_cve() integration test: a project whose only log4j-core
    JAR is at a patched version (2.17.1, outside CVE-2021-44228's vulnerable_range)
    must short-circuit to the L1 NOT_AFFECTED_CANDIDATE finding from
    fusion.fuse_component_absent(), with static/runtime analysis never invoked.
    A StaticAnalyzer pointed at a non-existent extractor JAR is passed
    deliberately: if the short-circuit didn't fire, analyzer.analyze() would
    try to run it and fail loudly, rather than this test silently passing for
    the wrong reason.
    """
    print(f"\n{'=' * 62}")
    print("Pipeline: CVE-2021-44228 <- project with only a patched log4j-core")
    print(f"{'=' * 62}")

    seed = load_seed(SEEDS_DIR / "CVE-2021-44228.yaml")

    with tempfile.TemporaryDirectory() as tmp:
        patched_jar = Path(tmp) / "log4j-core-2.17.1.jar"
        with zipfile.ZipFile(patched_jar, "w") as z:
            z.writestr(
                "META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties",
                "groupId=org.apache.logging.log4j\nartifactId=log4j-core\nversion=2.17.1\n",
            )

        chain, advice = assess_cve(
            cve_id              = "CVE-2021-44228",
            seed                = seed,
            project_jars        = [patched_jar],
            project_artifact    = "com.example:patched-app:1.0",
            analyzer            = StaticAnalyzer(Path("/nonexistent/extractor.jar")),
            callgraph_cache     = None,
            trace_log           = None,
            project_prefix      = "com.example",
        )

    print(f"  level={chain.evidence_level.name} ({chain.evidence_level.value})  "
          f"decision={chain.decision.value}  conf={chain.decision_confidence}  "
          f"risk={chain.risk_score}")
    print(f"  notes: {chain.notes}")
    print(f"  remedy: {advice.priority} -- {advice.notes}")

    assert chain.evidence_level.value == 1, f"Expected L1, got {chain.evidence_level.value}"
    assert chain.decision.value == "not_affected_candidate", chain.decision.value
    assert chain.static_evidence is None, "static analysis must have been skipped"
    assert chain.runtime_evidence is None, "runtime analysis must have been skipped"
    assert chain.risk_score == 0.5, f"Expected 0.5 (10.0 CVSS x 0.05 L1 multiplier), got {chain.risk_score}"
    assert "2.17.1" in chain.notes
    assert chain.component_evidence.status.value == "out_of_range", chain.component_evidence
    assert chain.component_evidence.matches == [(str(patched_jar), "2.17.1")], chain.component_evidence.matches
    assert advice.priority == "MONITOR", advice.priority
    assert "outside" in advice.notes.lower()

    print("\n  ALL ASSERTIONS PASSED")
    return True


def test_write_vex_state_mapping():
    """
    Regression coverage for the VEX mapping fixes:
      - "fixed" must map to CycloneDX's "resolved", not the non-existent
        state "fixed" (an earlier version of this map produced schema-invalid
        output for every FIXED-decision finding).
      - "not_affected_candidate" must map to "in_triage", not "not_affected"
        (CycloneDX's not_affected asserts unconditional non-affection, a
        stronger claim than a hedged _candidate decision is designed to make).
      - "mitigated" -> "not_affected" gets an explicit justification
        (protected_by_mitigating_control); no other decision does, since none
        of CycloneDX's other justification values accurately describe what
        this system's bounded evidence supports.
    """
    print("=" * 70)
    print("Test: write_vex() state/justification mapping")
    print("=" * 70)

    def _chain(decision: Decision, cve: str = "CVE-2021-44228") -> EvidenceChain:
        return EvidenceChain(
            chain_id=f"{cve}::test", cve=cve, project_artifact="test:app:1.0",
            vulnerable_component="g:a:range", seed_method="Foo.bar()",
            evidence_level=EvidenceLevel.L2_SEED_IDENTIFIED,
            decision=decision, decision_confidence=0.5, risk_score=1.0,
            notes="test notes",
        )

    cases = [
        (Decision.AFFECTED, "exploitable", None),
        (Decision.LIKELY_AFFECTED, "in_triage", None),
        (Decision.UNDER_INVESTIGATION, "in_triage", None),
        (Decision.NOT_AFFECTED_CANDIDATE, "in_triage", None),
        (Decision.FIXED, "resolved", None),
        (Decision.MITIGATED, "not_affected", "protected_by_mitigating_control"),
    ]

    with tempfile.TemporaryDirectory() as tmp:
        vex_path = Path(tmp) / "out.vex.json"
        chains = [_chain(d) for d, _, _ in cases]
        write_vex(vex_path, "test:app:1.0", chains)
        doc = json.loads(vex_path.read_text(encoding="utf-8"))

    assert len(doc["vulnerabilities"]) == len(cases)
    for vuln, (decision, expected_state, expected_justification) in zip(doc["vulnerabilities"], cases):
        analysis = vuln["analysis"]
        assert analysis["state"] == expected_state, \
            f"{decision.value}: expected state {expected_state!r}, got {analysis['state']!r}"
        assert analysis.get("justification") == expected_justification, \
            f"{decision.value}: expected justification {expected_justification!r}, got {analysis.get('justification')!r}"
        print(f"  {decision.value:24s} -> state={analysis['state']:12s} "
              f"justification={analysis.get('justification')} (OK)")

    print("  PASS")
    return True


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
    # run_pipeline() above calls fuse() directly without a component check
    # (see fuse()'s own component parameter, unused here), so
    # dependency_match is correctly None (unchecked), not True: this test
    # exercises the static/runtime fusion path in isolation, not the L1 gate.
    assert es["dependency_match"] is None
    assert es["component_check_status"] is None
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
    main()
    test_assess_cve_l1_short_circuit()
    test_write_vex_state_mapping()
    sys.exit(0)
