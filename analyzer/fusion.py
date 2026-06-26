"""
Evidence fusion engine.

Takes static + runtime evidence for one CVE against one project and
produces a complete, auditable EvidenceChain with:
  - evidence_level  (L0–L5)
  - decision        (AFFECTED / LIKELY_AFFECTED / NOT_AFFECTED_CANDIDATE / ...)
  - decision_confidence
  - risk_score      (0–10, CVSS-aligned, adjusted by evidence strength)

Design principle: NEVER discard evidence. Both static and runtime results
are preserved in the EvidenceChain. The decision is a transparent function
of the evidence, not a black box.

Decision rules (applied in priority order):
  1. Static=REACHABLE + Runtime=OBSERVED      → L4  AFFECTED            conf=0.95
  2. Static=REACHABLE + Runtime=NOT_OBSERVED  → L3  LIKELY_AFFECTED     conf=0.75
  3. Static=REACHABLE + Runtime=NOT_RUN       → L3  UNDER_INVESTIGATION conf=0.60
  4. Static=NOT_REACHABLE                     → L2  NOT_AFFECTED_CAND.  conf=0.70
  5. Static=UNKNOWN                           → L2  UNDER_INVESTIGATION conf=0.50
  6. No static evidence at all                → L2  UNDER_INVESTIGATION conf=0.30

Reachability-adjusted exposure score: base_cvss × evidence_multiplier
  L4 AFFECTED:            CVSS × 1.00
  L3 LIKELY_AFFECTED:     CVSS × 0.75
  L2 NOT_AFFECTED_CAND.:  CVSS × 0.10
  L2 UNDER_INVESTIGATION: CVSS × 0.50

Evidence multipliers are design parameters, not natural laws.
The 0.10 residual for NOT_REACHABLE reflects two sources of analysis
uncertainty: (1) static analysis is incomplete — reflection,
invokedynamic, and dynamic class loading are not modelled; (2) code
evolves — a method unreachable today may become reachable after a
refactor. The specific value 0.10 is conservative and should be
calibrated against a labelled exploit dataset in future work.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Optional

from models import (
    Decision,
    EvidenceChain,
    EvidenceLevel,
    RuntimeEvidence,
    RuntimeReachability,
    StaticEvidence,
    StaticReachability,
)
from seed_loader import Seed


# ---------------------------------------------------------------------------
# CVSS base scores for our 3 target CVEs (from NVD / OSV)
# These are stored here for the MVP. A production system would fetch from NVD API.
# ---------------------------------------------------------------------------

CVSS_BASE: dict[str, float] = {
    "CVE-2021-44228":  10.0,   # Log4Shell      — Critical
    "CVE-2021-29425":   4.8,   # commons-io     — Medium
    "CVE-2018-1002200": 5.5,   # plexus-archiver — Medium
    "CVE-2022-42889":   9.8,   # Text4Shell     — Critical
}

DEFAULT_CVSS = 7.0  # Fallback for unknown CVEs (assume High to be conservative)


# ---------------------------------------------------------------------------
# Evidence multipliers for risk score adjustment
# ---------------------------------------------------------------------------

_EVIDENCE_MULTIPLIER: dict[tuple[str, str], float] = {
    # (decision_value, evidence_level_value) → multiplier
    ("affected",               "4"): 1.00,
    ("likely_affected",        "3"): 0.75,
    ("under_investigation",    "3"): 0.50,
    ("under_investigation",    "2"): 0.50,
    ("not_affected_candidate", "2"): 0.10,
}

def _risk_multiplier(decision: Decision, level: EvidenceLevel) -> float:
    key = (decision.value, str(level.value))
    return _EVIDENCE_MULTIPLIER.get(key, 0.50)


# ---------------------------------------------------------------------------
# Core fusion function
# ---------------------------------------------------------------------------

def fuse(
    cve: str,
    project_artifact: str,      # "group_id:artifact_id:version" of the analysed app
    seed: Seed,
    static: Optional[StaticEvidence] = None,
    runtime: Optional[RuntimeEvidence] = None,
) -> EvidenceChain:
    """
    Combine static and runtime evidence into a complete EvidenceChain.

    All inputs are optional — the engine degrades gracefully:
      no static + no runtime → L2 UNDER_INVESTIGATION
    """
    vm = seed.primary_method
    seed_sig = vm.full_signature

    # Build a deterministic chain ID from CVE + project artifact
    chain_id = f"{cve}::{project_artifact}"

    # --- Determine evidence level and decision ---
    level, decision, confidence = _decide(static, runtime)

    # --- Compute risk score ---
    base_cvss = CVSS_BASE.get(cve, DEFAULT_CVSS)
    multiplier = _risk_multiplier(decision, level)
    risk_score = round(base_cvss * multiplier, 1)

    # --- Build notes for audit trail ---
    notes = _build_notes(static, runtime, decision)

    return EvidenceChain(
        chain_id=chain_id,
        cve=cve,
        project_artifact=project_artifact,
        vulnerable_component=f"{seed.package.group_id}:{seed.package.artifact_id}:{seed.package.vulnerable_range}",
        seed_method=seed_sig,
        evidence_level=level,
        static_evidence=static,
        runtime_evidence=runtime,
        decision=decision,
        decision_confidence=confidence,
        risk_score=risk_score,
        notes=notes,
    )


# ---------------------------------------------------------------------------
# Decision logic
# ---------------------------------------------------------------------------

def _decide(
    static: Optional[StaticEvidence],
    runtime: Optional[RuntimeEvidence],
) -> tuple[EvidenceLevel, Decision, float]:
    """
    Returns (evidence_level, decision, confidence).

    Why confidence < 1.0 even for AFFECTED?
    CHA may produce false-positive reachability (REACHABLE is a conservative over-
    approximation). Runtime evidence is limited to observed test coverage. Neither
    alone is conclusive; together they approach but don't reach certainty.
    """
    if static is None:
        return (
            EvidenceLevel.L2_SEED_IDENTIFIED,
            Decision.UNDER_INVESTIGATION,
            0.30,
        )

    s = static.status

    if s == StaticReachability.NOT_REACHABLE:
        # Static analysis found no path. Not safe to call "safe" (reflection could
        # be present), but it's our best current evidence.
        return (
            EvidenceLevel.L2_SEED_IDENTIFIED,
            Decision.NOT_AFFECTED_CANDIDATE,
            static.confidence * 0.85,  # reduce: CHA may have missed a path
        )

    if s == StaticReachability.UNKNOWN:
        return (
            EvidenceLevel.L2_SEED_IDENTIFIED,
            Decision.UNDER_INVESTIGATION,
            0.50,
        )

    # s == REACHABLE — now look at runtime evidence
    if runtime is None or runtime.status == RuntimeReachability.NOT_RUN:
        return (
            EvidenceLevel.L3_STATIC_REACHABLE,
            Decision.UNDER_INVESTIGATION,
            0.60,
        )

    if runtime.status == RuntimeReachability.NOT_OBSERVED:
        # Static says reachable, but runtime didn't observe it.
        # This is the "false positive" candidate: static over-approximation.
        # However, NOT_OBSERVED only covers the observed test execution — not all
        # possible inputs. We cannot reduce to NOT_AFFECTED_CANDIDATE.
        return (
            EvidenceLevel.L3_STATIC_REACHABLE,
            Decision.LIKELY_AFFECTED,
            0.75,
        )

    # runtime.status == OBSERVED — strongest evidence
    return (
        EvidenceLevel.L4_RUNTIME_OBSERVED,
        Decision.AFFECTED,
        min(static.confidence, runtime.confidence),
    )


def apply_audit(chain: EvidenceChain, audit_record: "AuditRecord") -> EvidenceChain:
    """
    Promote a finding to L5 AUDITED after human review.

    The automated evidence (static, runtime) is preserved unchanged.
    Only evidence_level, audit_record, and optionally decision are updated.
    decision_confidence is capped at 0.98 — even human review is not infallible.
    """
    from copy import copy
    from models import AuditRecord  # local import to avoid circular at module level

    updated = copy(chain)
    updated.audit_record = audit_record
    updated.evidence_level = EvidenceLevel.L5_AUDITED

    if audit_record.decision_override:
        updated.decision = Decision(audit_record.decision_override)

    updated.decision_confidence = min(0.98, chain.decision_confidence + 0.20)
    return updated


def _build_notes(
    static: Optional[StaticEvidence],
    runtime: Optional[RuntimeEvidence],
    decision: Decision,
) -> str:
    parts = []
    if static:
        parts.append(f"Static: {static.status.value} (conf={static.confidence})")
        if static.call_path:
            parts.append(f"Path depth: {len(static.call_path)} hops")
        if static.uncertain_features:
            parts.append(f"Uncertain features: {static.uncertain_features}")
    if runtime:
        parts.append(f"Runtime: {runtime.status.value} (conf={runtime.confidence})")
        if runtime.observed_call_count:
            parts.append(f"Observed {runtime.observed_call_count} call(s)")
        if runtime.trace_ids:
            parts.append(f"Trace IDs: {runtime.trace_ids[:3]}")
    return " | ".join(parts)
