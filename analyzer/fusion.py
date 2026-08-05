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
  4. Static=NOT_REACHABLE + Runtime=OBSERVED  → L2  UNDER_INVESTIGATION conf=min(static.confidence, runtime.confidence)*0.7
     (static/runtime conflict: the seed method executed despite no static path being
     found — flagged for review rather than scored as either AFFECTED or NOT_AFFECTED,
     since this signals a static-model blind spot, most likely reflection or dynamic
     dispatch not visible to CHA+BFS.)
  5. Static=NOT_REACHABLE (runtime otherwise) → L2  NOT_AFFECTED_CAND.  conf=0.70
  6. Static=UNKNOWN                           → L2  UNDER_INVESTIGATION conf=0.50
  7. No static evidence at all                → L2  UNDER_INVESTIGATION conf=0.30

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

L5 AUDITED findings no longer map to a static/runtime evidence tier, so
their risk_score is recomputed from DECISION_BASE_MULTIPLIER (keyed by
decision alone) whenever a human reviewer overrides the decision — see
audit.py::apply_audit_to_dict. FIXED = 0.00 (confirmed remediated),
MITIGATED = 0.10 (compensating controls reduce but don't eliminate exposure).
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

# Fallback multiplier keyed by decision alone (not evidence level). Used whenever
# (decision, level) isn't in _EVIDENCE_MULTIPLIER above — most notably for L5
# AUDITED findings, where the level no longer maps to a static/runtime evidence
# tier but the decision (possibly reviewer-overridden) still needs a multiplier.
DECISION_BASE_MULTIPLIER: dict[str, float] = {
    "affected":               1.00,
    "likely_affected":        0.75,
    "under_investigation":    0.50,
    "not_affected_candidate": 0.10,
    "fixed":                  0.00,  # confirmed remediated — no residual exposure
    "mitigated":              0.10,  # compensating controls reduce but don't eliminate exposure
}

def risk_score_for_decision(cve: str, decision_value: str) -> float:
    """
    CVSS base × decision multiplier, ignoring evidence_level.

    Used by audit.py to recompute risk_score for L5 AUDITED findings, where the
    pre-audit evidence_level no longer determines exposure — only the (possibly
    reviewer-overridden) decision does. Centralised here so the formula and the
    multiplier table have exactly one definition; audit.py must not reimplement
    this inline.
    """
    base_cvss = CVSS_BASE.get(cve, DEFAULT_CVSS)
    multiplier = DECISION_BASE_MULTIPLIER.get(decision_value, 0.50)
    return round(base_cvss * multiplier, 1)


def _risk_multiplier(decision: Decision, level: EvidenceLevel) -> float:
    key = (decision.value, str(level.value))
    if key in _EVIDENCE_MULTIPLIER:
        return _EVIDENCE_MULTIPLIER[key]
    return DECISION_BASE_MULTIPLIER.get(decision.value, 0.50)


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
        if runtime is not None and runtime.status == RuntimeReachability.OBSERVED:
            # Runtime evidence contradicts the static result: the seed method was
            # observed executing despite no static path being found. This is
            # consistent with a static-model blind spot (reflection, dynamic
            # proxy, or other dispatch invisible to CHA+BFS) -- but runtime
            # evidence is not inherently more trustworthy than static evidence:
            # an OBSERVED match may itself rest on the weaker heuristic
            # span-name fallback rather than an exact match, or on a test
            # payload that only coincidentally resembles a real trigger. Neither
            # channel is privileged, so confidence is anchored on whichever of
            # the two is *more* uncertain (matching L4's own min(...) below),
            # then further discounted for the disagreement itself.
            return (
                EvidenceLevel.L2_SEED_IDENTIFIED,
                Decision.UNDER_INVESTIGATION,
                min(static.confidence, runtime.confidence) * 0.7,
            )
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
    if (
        static and runtime
        and static.status == StaticReachability.NOT_REACHABLE
        and runtime.status == RuntimeReachability.OBSERVED
    ):
        parts.append(
            "CONFLICT: static analysis found no path but the seed method executed at "
            "runtime -- static analysis may have missed a path (reflection/dynamic "
            "dispatch suspected)"
        )
    if not parts:
        # static and runtime are both None -- decision defaulted to
        # UNDER_INVESTIGATION with no evidence to describe. Say so explicitly
        # rather than leaving notes empty, which would look like a silent
        # decision with no basis.
        parts.append("No static or runtime evidence provided")
    return " | ".join(parts)
