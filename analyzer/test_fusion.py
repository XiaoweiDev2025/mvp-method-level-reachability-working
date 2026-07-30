"""
Unit tests for fusion.py's _decide() branch logic.

Pure dataclass inputs, no JVM/BFS/OTel dependency -- covers every
static/runtime evidence combination _decide() branches on.

Run from the project root:
    python analyzer/test_fusion.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from fusion import fuse
from models import (
    Decision,
    EvidenceLevel,
    RuntimeEvidence,
    RuntimeReachability,
    StaticEvidence,
    StaticReachability,
)
from seed_loader import Seed, SeedPackage, VulnerableMethod

CVE = "CVE-2021-44228"  # CVSS_BASE = 10.0, makes risk_score arithmetic easy to check
PROJECT = "com.example:test-app:1.0"

SEED = Seed(
    cve=CVE,
    ecosystem="maven",
    package=SeedPackage(
        group_id="org.apache.logging.log4j",
        artifact_id="log4j-core",
        vulnerable_range="<2.15.0",
        fixed_version="2.15.0",
    ),
    vulnerable_methods=[
        VulnerableMethod(
            fqcn="org.apache.logging.log4j.core.lookup.JndiLookup",
            method="lookup",
            descriptor=None,
            confidence="high",
        )
    ],
)


def _check(name, static, runtime, expected_level, expected_decision, expected_confidence, expected_risk):
    chain = fuse(cve=CVE, project_artifact=PROJECT, seed=SEED, static=static, runtime=runtime)
    print(f"  {name}: level={chain.evidence_level.value} decision={chain.decision.value} "
          f"conf={chain.decision_confidence} risk={chain.risk_score}")
    assert chain.evidence_level == expected_level, f"{name}: expected level {expected_level}, got {chain.evidence_level}"
    assert chain.decision == expected_decision, f"{name}: expected decision {expected_decision}, got {chain.decision}"
    assert abs(chain.decision_confidence - expected_confidence) < 1e-9, \
        f"{name}: expected confidence {expected_confidence}, got {chain.decision_confidence}"
    assert abs(chain.risk_score - expected_risk) < 1e-9, \
        f"{name}: expected risk {expected_risk}, got {chain.risk_score}"


def test_all_decide_branches():
    print("=" * 70)
    print("Test: fusion._decide() covers all static/runtime combinations")
    print("=" * 70)

    # 1. No static evidence at all
    _check(
        "no static evidence",
        static=None, runtime=None,
        expected_level=EvidenceLevel.L2_SEED_IDENTIFIED,
        expected_decision=Decision.UNDER_INVESTIGATION,
        expected_confidence=0.30,
        expected_risk=5.0,
    )

    # 2. Static NOT_REACHABLE
    _check(
        "static NOT_REACHABLE",
        static=StaticEvidence(status=StaticReachability.NOT_REACHABLE, confidence=0.9),
        runtime=None,
        expected_level=EvidenceLevel.L2_SEED_IDENTIFIED,
        expected_decision=Decision.NOT_AFFECTED_CANDIDATE,
        expected_confidence=0.9 * 0.85,
        expected_risk=1.0,
    )

    # 3. Static UNKNOWN
    _check(
        "static UNKNOWN",
        static=StaticEvidence(status=StaticReachability.UNKNOWN, confidence=0.0),
        runtime=None,
        expected_level=EvidenceLevel.L2_SEED_IDENTIFIED,
        expected_decision=Decision.UNDER_INVESTIGATION,
        expected_confidence=0.50,
        expected_risk=5.0,
    )

    # 4a. Static REACHABLE, runtime absent (None)
    _check(
        "static REACHABLE, runtime=None",
        static=StaticEvidence(status=StaticReachability.REACHABLE, confidence=0.9),
        runtime=None,
        expected_level=EvidenceLevel.L3_STATIC_REACHABLE,
        expected_decision=Decision.UNDER_INVESTIGATION,
        expected_confidence=0.60,
        expected_risk=5.0,
    )

    # 4b. Static REACHABLE, runtime NOT_RUN (distinct code path from runtime=None, same branch)
    _check(
        "static REACHABLE, runtime NOT_RUN",
        static=StaticEvidence(status=StaticReachability.REACHABLE, confidence=0.9),
        runtime=RuntimeEvidence(status=RuntimeReachability.NOT_RUN, confidence=0.0),
        expected_level=EvidenceLevel.L3_STATIC_REACHABLE,
        expected_decision=Decision.UNDER_INVESTIGATION,
        expected_confidence=0.60,
        expected_risk=5.0,
    )

    # 5. Static REACHABLE, runtime NOT_OBSERVED
    _check(
        "static REACHABLE, runtime NOT_OBSERVED",
        static=StaticEvidence(status=StaticReachability.REACHABLE, confidence=0.9),
        runtime=RuntimeEvidence(status=RuntimeReachability.NOT_OBSERVED, confidence=0.6),
        expected_level=EvidenceLevel.L3_STATIC_REACHABLE,
        expected_decision=Decision.LIKELY_AFFECTED,
        expected_confidence=0.75,
        expected_risk=7.5,
    )

    # 6. Static REACHABLE, runtime OBSERVED (strongest evidence)
    _check(
        "static REACHABLE, runtime OBSERVED",
        static=StaticEvidence(status=StaticReachability.REACHABLE, confidence=0.9),
        runtime=RuntimeEvidence(status=RuntimeReachability.OBSERVED, confidence=0.95),
        expected_level=EvidenceLevel.L4_RUNTIME_OBSERVED,
        expected_decision=Decision.AFFECTED,
        expected_confidence=min(0.9, 0.95),
        expected_risk=10.0,
    )

    # 7. Static NOT_REACHABLE, runtime OBSERVED (conflict: static missed a path,
    # e.g. reflection/dynamic dispatch) — must NOT silently collapse to
    # NOT_AFFECTED_CANDIDATE just because static said no path exists.
    _check(
        "static NOT_REACHABLE, runtime OBSERVED (conflict)",
        static=StaticEvidence(status=StaticReachability.NOT_REACHABLE, confidence=0.7),
        runtime=RuntimeEvidence(status=RuntimeReachability.OBSERVED, confidence=0.95),
        expected_level=EvidenceLevel.L2_SEED_IDENTIFIED,
        expected_decision=Decision.UNDER_INVESTIGATION,
        expected_confidence=0.95 * 0.7,
        expected_risk=5.0,
    )

    print("  PASS: all 8 static/runtime combinations produced the expected level/decision/confidence/risk")
    return True


if __name__ == "__main__":
    ok = test_all_decide_branches()
    sys.exit(0 if ok else 1)
