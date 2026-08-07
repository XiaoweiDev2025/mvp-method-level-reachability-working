"""
Unit tests for audit.py::apply_audit_to_dict()'s confirm-vs-override confidence logic.

Run from the project root:
    python analyzer/test_audit.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from audit import apply_audit_to_dict
from models import AuditRecord


def _base_finding(decision: str, confidence: float) -> dict:
    return {
        "chain_id": "CVE-2021-44228::com.example:test-app:1.0",
        "cve": "CVE-2021-44228",
        "evidence_level": 2,
        "decision": decision,
        "decision_confidence": confidence,
        "risk_score": 1.0,
        "audit_history": [],
    }


def test_confirmation_raises_existing_confidence():
    """No decision_override: a plain confirmation raises the existing decision's
    own confidence by 0.20, capped at 0.98 -- unchanged behaviour."""
    print("=" * 70)
    print("Test: confirmation (no override) raises confidence by 0.20")
    print("=" * 70)

    finding = _base_finding("affected", 0.75)
    record = AuditRecord(reviewer="alice", reviewed_at="2026-08-07T00:00:00Z", justification="confirmed")
    apply_audit_to_dict(finding, record)

    assert finding["decision"] == "affected", finding["decision"]
    assert abs(finding["decision_confidence"] - 0.95) < 1e-9, finding["decision_confidence"]
    print(f"  confidence 0.75 -> {finding['decision_confidence']} (OK, 0.75+0.20)")

    # Cap at 0.98
    finding2 = _base_finding("affected", 0.90)
    record2 = AuditRecord(reviewer="alice", reviewed_at="2026-08-07T00:00:00Z", justification="confirmed")
    apply_audit_to_dict(finding2, record2)
    assert abs(finding2["decision_confidence"] - 0.98) < 1e-9, finding2["decision_confidence"]
    print(f"  confidence 0.90 -> {finding2['decision_confidence']} (OK, capped at 0.98)")
    print("  PASS")
    return True


def test_override_same_decision_is_a_confirmation():
    """decision_override naming the SAME decision the finding already has is
    treated as a confirmation, not an override -- still uses the +0.20 path."""
    print("=" * 70)
    print("Test: decision_override matching the existing decision is a confirmation")
    print("=" * 70)

    finding = _base_finding("under_investigation", 0.50)
    record = AuditRecord(
        reviewer="alice", reviewed_at="2026-08-07T00:00:00Z", justification="confirmed",
        decision_override="under_investigation",
    )
    apply_audit_to_dict(finding, record)
    assert abs(finding["decision_confidence"] - 0.70) < 1e-9, finding["decision_confidence"]
    print(f"  decision_override == existing decision -> {finding['decision_confidence']} (OK, treated as confirmation)")
    print("  PASS")
    return True


def test_override_does_not_inherit_old_confidence():
    """
    The bug this test locks in: a genuine override (decision_override names a
    DIFFERENT decision) must not compute new confidence as
    old_confidence + 0.20 -- the old confidence supported a conclusion that is
    being replaced, not the new one. Regression case: automated
    not_affected_candidate at 0.595, human overrides to affected. The old
    (unfixed) formula would produce 0.795 -- confidence in "affected" derived
    from evidence that supported "not affected".
    """
    print("=" * 70)
    print("Test: override does NOT inherit the replaced decision's confidence")
    print("=" * 70)

    finding = _base_finding("not_affected_candidate", 0.595)
    record = AuditRecord(
        reviewer="alice", reviewed_at="2026-08-07T00:00:00Z",
        justification="Manually confirmed reachable via a code path the static analyzer missed",
        decision_override="affected",
    )
    apply_audit_to_dict(finding, record)

    assert finding["decision"] == "affected", finding["decision"]
    # Must NOT be 0.595 + 0.20 = 0.795
    assert abs(finding["decision_confidence"] - 0.795) > 1e-6, \
        f"regression: override inherited the replaced decision's confidence ({finding['decision_confidence']})"
    # Falls back to the documented default (0.90) since no reviewer_confidence was given
    assert abs(finding["decision_confidence"] - 0.90) < 1e-9, finding["decision_confidence"]
    print(f"  pre-audit not_affected_candidate@0.595, override->affected, "
          f"no reviewer_confidence -> {finding['decision_confidence']} (OK, default 0.90, not 0.795)")
    print("  PASS")
    return True


def test_override_uses_explicit_reviewer_confidence():
    """A reviewer-supplied reviewer_confidence is used directly (capped at 0.98) for an override."""
    print("=" * 70)
    print("Test: override uses explicit reviewer_confidence when supplied")
    print("=" * 70)

    finding = _base_finding("not_affected_candidate", 0.595)
    record = AuditRecord(
        reviewer="alice", reviewed_at="2026-08-07T00:00:00Z",
        justification="Manually confirmed reachable via reflection",
        decision_override="affected",
        reviewer_confidence=0.99,
    )
    apply_audit_to_dict(finding, record)
    assert abs(finding["decision_confidence"] - 0.98) < 1e-9, finding["decision_confidence"]
    print(f"  reviewer_confidence=0.99 -> {finding['decision_confidence']} (OK, capped at 0.98)")

    finding2 = _base_finding("not_affected_candidate", 0.595)
    record2 = AuditRecord(
        reviewer="alice", reviewed_at="2026-08-07T00:00:00Z",
        justification="Manually confirmed reachable via reflection",
        decision_override="affected",
        reviewer_confidence=0.80,
    )
    apply_audit_to_dict(finding2, record2)
    assert abs(finding2["decision_confidence"] - 0.80) < 1e-9, finding2["decision_confidence"]
    print(f"  reviewer_confidence=0.80 -> {finding2['decision_confidence']} (OK)")
    print("  PASS")
    return True


def test_pre_audit_snapshot_still_correct():
    """The pre-audit snapshot fields must still reflect the true pre-audit state
    regardless of which confidence path was taken."""
    print("=" * 70)
    print("Test: pre-audit snapshot fields unaffected by the confidence-path fix")
    print("=" * 70)

    finding = _base_finding("not_affected_candidate", 0.595)
    finding["evidence_level"] = 2
    finding["risk_score"] = 0.5
    record = AuditRecord(
        reviewer="alice", reviewed_at="2026-08-07T00:00:00Z",
        justification="override", decision_override="affected",
    )
    apply_audit_to_dict(finding, record)

    assert record.previous_decision == "not_affected_candidate", record.previous_decision
    assert record.previous_evidence_level == 2, record.previous_evidence_level
    assert record.previous_risk_score == 0.5, record.previous_risk_score
    assert record.previous_decision_confidence == 0.595, record.previous_decision_confidence
    print("  previous_* fields correctly snapshot the pre-audit state (OK)")
    print("  PASS")
    return True


if __name__ == "__main__":
    ok = test_confirmation_raises_existing_confidence()
    ok = test_override_same_decision_is_a_confirmation() and ok
    ok = test_override_does_not_inherit_old_confidence() and ok
    ok = test_override_uses_explicit_reviewer_confidence() and ok
    ok = test_pre_audit_snapshot_still_correct() and ok
    sys.exit(0 if ok else 1)
