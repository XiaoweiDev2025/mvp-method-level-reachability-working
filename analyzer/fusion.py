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

L1 component check (fuse_component_absent, called separately from _decide()
below): before static/runtime analysis runs at all, pipeline.py checks
whether the analysed project's own JARs actually carry the seed's
vulnerable_component at a version inside vulnerable_range
(component_check.py, reading each supplied JAR's own embedded Maven
coordinates -- a check bounded to the JARs actually supplied, not a resolved
Maven/Gradle dependency tree). A seed only records which package and version
range a CVE affects in general; it does not by itself establish that *this*
project depends on an affected version. This check produces one of three
ComponentCheckStatus outcomes, not a present/absent boolean: IN_RANGE (at
least one matching JAR's version falls inside vulnerable_range),
OUT_OF_RANGE (every matching JAR's version was confirmed outside
vulnerable_range), or INCONCLUSIVE (no matching JAR found, or a matching
JAR's version could not be confidently compared -- see component_check.py's
own docstring). Only OUT_OF_RANGE short-circuits: fuse_component_absent()
returns a L1 NOT_AFFECTED_CANDIDATE finding and static/runtime analysis is
skipped, since the seed's package-and-version model makes method-level
analysis for this seeded vulnerability unnecessary. IN_RANGE and
INCONCLUSIVE both proceed exactly as before through _decide() below, but
unlike an earlier version of this design, the resolved status and its full
supporting match list are not simply discarded once the pipeline moves past
it -- fuse() records them on the returned EvidenceChain as
component_evidence, so an IN_RANGE or INCONCLUSIVE result, and which JAR(s)
and version(s) produced it, are still visible in the final report, not just
the OUT_OF_RANGE short-circuit case. An
inconclusive check is never treated as evidence of absence.

Decision rules (applied in priority order):
  1. Static=REACHABLE + Runtime=OBSERVED      → L4  AFFECTED            conf=min(static.confidence, runtime.confidence)
  2. Static=REACHABLE + Runtime=NOT_OBSERVED  → L3  LIKELY_AFFECTED     conf=0.75
  3. Static=REACHABLE + Runtime=NOT_RUN       → L3  UNDER_INVESTIGATION conf=0.60
  4. Static=NOT_REACHABLE + Runtime=OBSERVED  → L2  UNDER_INVESTIGATION conf=min(static.confidence, runtime.confidence)*0.7
     (static/runtime conflict: the seed method executed despite no static path being
     found — flagged for review rather than scored as either AFFECTED or NOT_AFFECTED,
     since this signals a static-model blind spot, most likely reflection or dynamic
     dispatch not visible to CHA+BFS.)
  5. Static=NOT_REACHABLE (runtime otherwise) → L2  NOT_AFFECTED_CAND.  conf=static.confidence*0.85
  6a. Static=UNKNOWN + Runtime=OBSERVED       → L2  UNDER_INVESTIGATION conf=runtime.confidence*0.7
  6b. Static=UNKNOWN (runtime otherwise)      → L2  UNDER_INVESTIGATION conf=0.50
  7a. No static evidence + Runtime=OBSERVED   → L2  UNDER_INVESTIGATION conf=runtime.confidence*0.7
  7b. No static evidence (runtime otherwise)  → L2  UNDER_INVESTIGATION conf=0.30

  Rules 6a and 7a exist for the same reason as rule 4: a positive runtime
  observation is never allowed to be silently dropped just because the static
  channel was absent or inconclusive rather than actively contradictory. The
  discount is the same 0.7 factor used in rule 4, applied to runtime.confidence
  alone (there is no static.confidence to take a min() against — UNKNOWN carries
  confidence 0.0, which would zero out the result if used, and None means no
  static reading was taken at all). This is a workflow heuristic reusing an
  already-established discount, not a separately calibrated value.

Reachability-adjusted exposure score: base_cvss × evidence_multiplier
  L4 AFFECTED:            CVSS × 1.00
  L3 LIKELY_AFFECTED:     CVSS × 0.75
  L2 NOT_AFFECTED_CAND.:  CVSS × 0.10
  L2 UNDER_INVESTIGATION: CVSS × 0.50
  L1 NOT_AFFECTED_CAND.:  CVSS × 0.05

Evidence multipliers are design parameters, not natural laws.
The 0.10 residual for NOT_REACHABLE reflects two sources of analysis
uncertainty: (1) static analysis is incomplete — reflection,
invokedynamic, and dynamic class loading are not modelled; (2) code
evolves — a method unreachable today may become reachable after a
refactor. The specific value 0.10 is conservative and should be
calibrated against a labelled exploit dataset in future work.

The 0.05 residual for an OUT_OF_RANGE component (L1) is lower than the 0.10
NOT_REACHABLE residual because it reflects a narrower source of uncertainty.
component_check.py checks every supplied JAR carrying matching Maven
coordinates, not just the first one found, and only reaches OUT_OF_RANGE when
every one of them is confirmed outside vulnerable_range with no ambiguous
comparison among them -- so the residual is not about a second, undetected
matching JAR at a different version, which the check does account for. It is
about what a metadata-only check cannot see at all: an independently-vendored
or shaded copy of the vulnerable code under different, non-matching Maven
coordinates. It is not 0.00 because "every matching JAR we found is out of
range" is not the same claim as "no copy of the vulnerable code exists
anywhere in this build."

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

from component_check import ComponentCheckResult
from models import (
    ComponentCheckStatus,
    ComponentEvidence,
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
    ("not_affected_candidate", "1"): 0.05,
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

def _to_component_evidence(component: Optional[ComponentCheckResult]) -> Optional[ComponentEvidence]:
    """
    Converts a component_check.py ComponentCheckResult into the ComponentEvidence
    stored on an EvidenceChain, carrying every matching JAR/version forward
    rather than collapsing to a bare status.
    """
    if component is None:
        return None
    return ComponentEvidence(
        status=component.status,
        matches=[(str(jar_path), version) for jar_path, version in component.matches],
    )


def fuse(
    cve: str,
    project_artifact: str,      # "group_id:artifact_id:version" of the analysed app
    seed: Seed,
    static: Optional[StaticEvidence] = None,
    runtime: Optional[RuntimeEvidence] = None,
    component: Optional[ComponentCheckResult] = None,
) -> EvidenceChain:
    """
    Combine static and runtime evidence into a complete EvidenceChain.

    All inputs are optional — the engine degrades gracefully:
      no static + no runtime → L2 UNDER_INVESTIGATION

    component, when supplied, is the ComponentCheckResult the L1 check
    resolved to before this call was reached (always status IN_RANGE or
    INCONCLUSIVE here -- an OUT_OF_RANGE result never reaches fuse() at all,
    since pipeline.py routes it to fuse_component_absent() instead). Its
    status and full match list (every JAR/version the check found, not just
    whichever one determined the outcome) are recorded on the returned chain
    as component_evidence, so the L1 outcome and its supporting evidence are
    not silently discarded once analysis proceeds past it -- consistent with
    this module's own "never discard evidence" design principle above.
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
        component_evidence=_to_component_evidence(component),
        static_evidence=static,
        runtime_evidence=runtime,
        decision=decision,
        decision_confidence=confidence,
        risk_score=risk_score,
        notes=notes,
    )


def fuse_component_absent(
    cve: str,
    project_artifact: str,
    seed: Seed,
    component: ComponentCheckResult,
) -> EvidenceChain:
    """
    Short-circuit fusion for a component check that resolved to
    ComponentCheckStatus.OUT_OF_RANGE: every supplied JAR carrying
    seed.package's group_id:artifact_id was confirmed at a version outside
    seed.package.vulnerable_range. Static and runtime analysis are skipped
    entirely: under the seed's package-and-version model, an exact
    coordinate match outside the declared vulnerable range makes
    method-level analysis for this seeded vulnerability unnecessary. The
    result still stays a *candidate* finding, not a plain NOT_AFFECTED, since
    a metadata check does not exclude repackaged code, incomplete
    coordinates, or errors in the seed's own affected-version range. Caller
    is responsible for only invoking this when component.status is
    OUT_OF_RANGE; see this module's own docstring for the
    IN_RANGE/INCONCLUSIVE cases, which proceed through fuse()/_decide() as
    before.
    """
    level = EvidenceLevel.L1_COMPONENT_ASSESSED
    decision = Decision.NOT_AFFECTED_CANDIDATE
    confidence = 0.90

    base_cvss = CVSS_BASE.get(cve, DEFAULT_CVSS)
    multiplier = _risk_multiplier(decision, level)
    risk_score = round(base_cvss * multiplier, 1)

    versions_found = ", ".join(f"{v} ({p.name})" for p, v in component.matches)
    notes = (
        f"Component check: every JAR supplying {seed.package.coordinates} "
        f"coordinates ({versions_found}) was outside the vulnerable range "
        f"{seed.package.vulnerable_range}. Static/runtime analysis skipped "
        "for this seeded vulnerability, but the check does not exclude "
        "repackaged/relocated copies of the vulnerable code under different "
        "coordinates."
    )

    return EvidenceChain(
        chain_id=f"{cve}::{project_artifact}",
        cve=cve,
        project_artifact=project_artifact,
        vulnerable_component=f"{seed.package.group_id}:{seed.package.artifact_id}:{seed.package.vulnerable_range}",
        seed_method=seed.primary_method.full_signature,
        evidence_level=level,
        component_evidence=_to_component_evidence(component),
        static_evidence=None,
        runtime_evidence=None,
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
        if runtime is not None and runtime.status == RuntimeReachability.OBSERVED:
            # No static reading was taken at all, but runtime directly observed
            # the seed method executing. This positive signal must not be
            # silently dropped just because there is no static result to
            # compare it against -- see rules 6a/7a above.
            return (
                EvidenceLevel.L2_SEED_IDENTIFIED,
                Decision.UNDER_INVESTIGATION,
                runtime.confidence * 0.7,
            )
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
        if runtime is not None and runtime.status == RuntimeReachability.OBSERVED:
            # Static analysis could not be trusted to answer the reachability
            # question at all (no entry points found), but runtime directly
            # observed the seed method executing. As with the static=None case
            # above, this positive signal must not be dropped -- see rule 6a.
            # static.confidence is 0.0 for UNKNOWN by construction, so anchoring
            # on min(static.confidence, runtime.confidence) as rule 4 does would
            # zero out a genuine observation; runtime.confidence alone is used.
            return (
                EvidenceLevel.L2_SEED_IDENTIFIED,
                Decision.UNDER_INVESTIGATION,
                runtime.confidence * 0.7,
            )
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
        EvidenceLevel.L4_STATIC_RUNTIME_CORROBORATED,
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
    elif (
        runtime is not None
        and runtime.status == RuntimeReachability.OBSERVED
        and (static is None or static.status == StaticReachability.UNKNOWN)
    ):
        parts.append(
            "NOTE: runtime observed the seed method executing, but static analysis "
            "was absent or inconclusive (no entry points identified); the runtime "
            "signal is retained and discounted rather than dropped"
        )
    if not parts:
        # static and runtime are both None -- decision defaulted to
        # UNDER_INVESTIGATION with no evidence to describe. Say so explicitly
        # rather than leaving notes empty, which would look like a silent
        # decision with no basis.
        parts.append("No static or runtime evidence provided")
    return " | ".join(parts)
