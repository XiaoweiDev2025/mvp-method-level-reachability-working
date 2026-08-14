"""
Core data models for the evidence chain.

Every module in this system produces or consumes these structures.
Defining them here ensures all modules speak the same language.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class StaticReachability(str, Enum):
    """
    Result of static call graph analysis.

    NOT_REACHABLE does not mean "safe" — it means no path was found
    within the analysis scope. Reflection, dynamic proxy, and dynamic
    class-loading gaps do not produce the UNKNOWN status below; on a
    NOT_REACHABLE result they are instead recorded via residual_risk_reason
    (invokedynamic_not_modelled is also duplicated into uncertain_features).
    A REACHABLE result carries neither, since a path was already found --
    its own uncertain_features is used for match-quality signals instead
    (e.g. relocated_package_suspected). UNKNOWN is reserved for a narrower
    failure: the search could not be run at all (currently: no entry points
    found). An incomplete classpath (a dependency JAR simply not supplied)
    is not itself tracked as a per-finding reason anywhere below; it is a
    known scope boundary, not a flagged one.
    """
    REACHABLE     = "reachable"       # A call path from entry point to seed method exists
    NOT_REACHABLE = "not_reachable"   # No path found within analysis scope
    UNKNOWN       = "unknown"         # No entry points found at all, so the search never ran.
                                       # NOT for reflection/dynamic-proxy/dynamic-class-loading gaps,
                                       # which are recorded via residual_risk_reason on a NOT_REACHABLE
                                       # result instead (see static_analyzer.py's StaticAnalyzer.analyze()).


class RuntimeReachability(str, Enum):
    """
    Result of runtime trace observation.

    NOT_OBSERVED does not prove the method is unreachable —
    it only means it was not called during the observed test execution.
    """
    OBSERVED     = "observed"       # Method appeared in runtime trace
    NOT_OBSERVED = "not_observed"   # Method absent from runtime trace
    NOT_RUN      = "not_run"        # Runtime collection was not executed


class ComponentCheckStatus(str, Enum):
    """
    Outcome of component_check.py::check_component_present() -- a metadata-based
    check of whether the seed's vulnerable component appears, at an affected
    version, among the JARs supplied to the pipeline. Deliberately three-valued
    rather than a present/absent boolean, since "no matching coordinates found"
    and "matching coordinates found, confirmed outside the vulnerable range" are
    different claims with different confidence, and must not be collapsed into one.
    """
    IN_RANGE     = "in_range"     # a matching JAR was found at a version inside vulnerable_range
    OUT_OF_RANGE = "out_of_range" # every matching JAR found was confirmed outside vulnerable_range
    INCONCLUSIVE = "inconclusive" # no matching JAR found, or a matching JAR's version could not
                                   # be confidently compared -- never treated as evidence of absence


class EvidenceLevel(int, Enum):
    """
    L0-L5 evidence states, grouped into three kinds rather than one single
    cumulative chain:

    - L0-L2 are scope-and-prerequisite facts: a CVE exists; a metadata-based
      component check has been run against the supplied JARs; a specific
      vulnerable method has been validated. These are not a dependency chain
      on each other -- L2's seed identification is CVE-global knowledge,
      established independently of any specific project's L1 outcome, and the
      pipeline reaches L2 regardless of whether L1 comes back IN_RANGE or
      INCONCLUSIVE (see ComponentCheckStatus above; only a confirmed
      OUT_OF_RANGE result short-circuits before L2 is reached). This makes
      evidence_level an evidentiary-STAGE marker, not an exhaustive record of
      every fact already established: check_component_present() always takes
      an already-validated Seed as a required argument, so the fact L2 records
      (that a specific vulnerable method has been identified for this CVE) is
      already true before L1 even runs, for every finding including an L1
      OUT_OF_RANGE one -- the level records which stage's evidence determined
      this particular finding, not which facts happen to hold.
    - L3-L4 are application-specific automated evidence, and this half
      genuinely is cumulative: L3 (STATIC_REACHABLE) presupposes a validated
      seed method to search a call path for, and L4 additionally requires L3
      to already hold -- a positive runtime observation without a preceding
      static path does not, by itself, reach L4 (see fusion.py's
      NOT_REACHABLE+OBSERVED branch).
    - L5 is a human-review overlay that can be applied to a finding at any of
      the preceding levels, not a further automated observation.

    Higher levels do tend to correspond to stronger evidence, but this is not
    a strict guarantee across the ladder: a finding can only be assigned a
    level consistent with how its evidence was actually established, so a
    NOT_REACHABLE finding stays at L2 even when directly contradicted by a
    positive runtime observation -- evidence that is, in one sense, stronger
    than a higher L3 finding's static-only path with no runtime check yet
    attempted. evidence_level therefore
    records which state was established, not how much concern a finding
    warrants: decision and risk_score carry the resulting prioritisation, and
    confidence records how strong the supporting evidence is -- related but
    distinct judgments, not interchangeable with evidence_level or with each
    other.
    """
    L0_CVE_EXISTS                  = 0  # A public CVE record exists for the vulnerability
    L1_COMPONENT_ASSESSED          = 1  # A metadata-based component-version check has been run
                                         # against the supplied JARs; does not by itself mean an
                                         # affected version was found -- see ComponentCheckStatus
    L2_SEED_IDENTIFIED             = 2  # Vulnerable method has been identified (seed confirmed)
    L3_STATIC_REACHABLE            = 3  # Static call graph shows path to seed method
    L4_STATIC_RUNTIME_CORROBORATED = 4  # Static reachability and a matching runtime
                                         # observation both hold
    L5_AUDITED                     = 5  # Human review has confirmed or closed the finding


class Decision(str, Enum):
    """Final risk decision for a CVE against a specific project."""
    AFFECTED               = "affected"
    LIKELY_AFFECTED        = "likely_affected"
    NOT_AFFECTED_CANDIDATE = "not_affected_candidate"  # Evidence suggests safe, pending confirmation
    UNDER_INVESTIGATION    = "under_investigation"
    FIXED                  = "fixed"
    MITIGATED              = "mitigated"


@dataclass
class StaticEvidence:
    status: StaticReachability
    confidence: float           # 0.0 – 1.0
    call_path: list[str] = field(default_factory=list)   # Method FQCN chain from entry to seed
    call_path_annotated: list[dict] = field(default_factory=list)  # Same path, each hop tagged with edge_type
    uncertain_features: list[str] = field(default_factory=list)  # e.g. ["reflection", "spring_proxy"]
    residual_risk_reason: list[str] = field(default_factory=list)  # Why NOT_REACHABLE is not zero-risk
    engine: str = ""            # e.g. "java-callgraph-2.0", "soot-4.4"
    analysis_scope: str = ""    # JARs that were included in analysis
    entry_points_used: list[str] = field(default_factory=list)   # Entry points BFS was seeded from
    analysis_fingerprint: str = ""  # SHA256[:16] of callgraph file — makes report reproducible/verifiable


@dataclass
class RuntimeEvidence:
    status: RuntimeReachability
    confidence: float           # 0.0 – 1.0
    trace_ids: list[str] = field(default_factory=list)   # OTel trace IDs where method was observed
    test_environment: str = ""  # e.g. "unit-tests", "integration-tests", "manual"
    observed_call_count: int = 0


@dataclass
class ComponentEvidence:
    """
    Result of the L1 component check (component_check.py), in the same
    full-object-on-the-chain shape as StaticEvidence/RuntimeEvidence above,
    rather than a bare status string. matches is the complete audit trail
    behind status: every JAR that carried Maven coordinates matching the
    seed's group_id:artifact_id, paired with the version found in it --
    without this, a reviewer has no way to see *which* JAR and version
    actually produced an IN_RANGE or INCONCLUSIVE result (the OUT_OF_RANGE
    case's matches were already visible via free-text notes, but the other
    two outcomes -- the majority of findings -- previously carried no
    persisted evidence at all beyond the bare status).
    """
    status: ComponentCheckStatus
    matches: list[tuple[str, str]] = field(default_factory=list)  # (jar_path, version) pairs


@dataclass
class AuditRecord:
    """
    Structured reviewer sign-off for L5 AUDITED evidence.

    CRA relevance: the timestamp on a report containing L4 AFFECTED marks when this
    system's own automated evidence first reached its strongest finding for this CVE.
    This is not itself a CRA Article 14 "actively exploited vulnerability" determination
    (Article 3(42) requires reliable evidence of real, unauthorised exploitation by a
    malicious actor -- a stronger, separate claim from reachability plus instrumented
    execution evidence). AuditRecord captures the subsequent human review: who
    confirmed it, when, and on what basis -- the record a producer would actually rely
    on when separately judging whether an Article 14 report is warranted.
    """
    reviewer: str
    reviewed_at: str                       # ISO 8601 — treated as immutable once set
    decision_override: Optional[str] = None  # If reviewer overrides the automated decision
    justification: str = ""
    waiver_expires: Optional[str] = None   # ISO 8601 — if risk is temporarily accepted
    compensating_controls: str = ""        # Required when waiver_expires is set
    reviewer_confidence: Optional[float] = None  # 0.0-1.0, reviewer's own stated confidence
                                            # in an overriding decision. Only meaningful when
                                            # decision_override actually changes the decision
                                            # (see audit.py::apply_audit_to_dict): the pre-audit
                                            # automated confidence was evidence for the decision
                                            # being replaced, not the new one, so it cannot be
                                            # inherited as a baseline the way a confirmation's
                                            # confidence bump can.

    # Pre-audit snapshot, filled in by audit.py::apply_audit_to_dict before it
    # overwrites the finding's top-level fields. Without this, the automated
    # decision/score that held immediately before this audit is not recoverable
    # from the report alone (evidence_level/decision/risk_score/decision_confidence
    # are all overwritten in place, not versioned elsewhere).
    previous_decision: Optional[str] = None
    previous_evidence_level: Optional[int] = None
    previous_risk_score: Optional[float] = None
    previous_decision_confidence: Optional[float] = None

    def to_dict(self) -> dict:
        return {
            "reviewer":                    self.reviewer,
            "reviewed_at":                 self.reviewed_at,
            "decision_override":           self.decision_override,
            "justification":               self.justification,
            "waiver_expires":               self.waiver_expires,
            "compensating_controls":        self.compensating_controls,
            "reviewer_confidence":          self.reviewer_confidence,
            "previous_decision":            self.previous_decision,
            "previous_evidence_level":      self.previous_evidence_level,
            "previous_risk_score":          self.previous_risk_score,
            "previous_decision_confidence": self.previous_decision_confidence,
        }


@dataclass
class EvidenceChain:
    """
    The complete evidence record for one CVE against one project.
    This is the central output of the system.
    """
    chain_id: str               # Unique ID, e.g. "CVE-2021-44228::com.example:myapp:1.0"
    cve: str
    project_artifact: str       # group_id:artifact_id:version of the analysed project
    vulnerable_component: str   # group_id:artifact_id:version of the vulnerable library
    seed_method: str            # Full signature of the seed method

    evidence_level: EvidenceLevel
    component_evidence: Optional[ComponentEvidence] = None  # L1 check result -- status plus every
                                                    # matching JAR/version, set by every assess_cve()
                                                    # call, not just the OUT_OF_RANGE short-circuit --
                                                    # so the L1 outcome and its supporting matches are
                                                    # never silently discarded once analysis proceeds
                                                    # past it. See fusion.py.
    static_evidence: Optional[StaticEvidence] = None
    runtime_evidence: Optional[RuntimeEvidence] = None

    decision: Optional[Decision] = None
    decision_confidence: float = 0.0     # 0.0 – 1.0, overall confidence in the decision
    risk_score: Optional[float] = None   # 0.0 – 10.0 (CVSS-aligned scale)

    notes: str = ""
    audit_record: Optional[AuditRecord] = None   # latest audit, kept for backward compatibility
    audit_history: list[AuditRecord] = field(default_factory=list)  # full reviewer sign-off trail

    def to_dict(self) -> dict:
        """Serialise to a plain dict for JSON/YAML output."""
        ce = self.component_evidence
        se = self.static_evidence
        rt = self.runtime_evidence
        component_status_value = ce.status.value if ce else None
        # True only for a confirmed IN_RANGE match, False only for a confirmed
        # OUT_OF_RANGE match; INCONCLUSIVE (checked, but couldn't confirm
        # either way) and None (not checked at all) both map to None here
        # rather than True -- collapsing "confirmed present" and "not
        # confirmed absent" into the same True value would let a machine
        # consumer read an unconfirmed component as a confirmed one.
        dependency_match = {"in_range": True, "out_of_range": False}.get(component_status_value)
        return {
            "chain_id": self.chain_id,
            "cve": self.cve,
            "project": self.project_artifact,
            "vulnerable_component": self.vulnerable_component,
            "seed_method": self.seed_method,
            "evidence_level": self.evidence_level.value,
            "evidence_summary": {
                "component_check_status": component_status_value,
                "dependency_match": dependency_match,
                "static_reachable": se.status.value == "reachable" if se else False,
                "runtime_observed": rt.status.value == "observed" if rt else False,
                "entry_points": se.entry_points_used if se else [],
                "call_path_depth": len(se.call_path) if se else 0,
                "trace_ids": rt.trace_ids if rt else [],
            },
            "component": {
                "status": ce.status.value,
                "matches": [{"jar": jar, "version": version} for jar, version in ce.matches],
            } if ce else None,
            "static": {
                "status": se.status.value,
                "confidence": se.confidence,
                "analysis_fingerprint": se.analysis_fingerprint,
                "entry_points_used": se.entry_points_used,
                "call_path": se.call_path,
                "call_path_annotated": se.call_path_annotated,
                "uncertain_features": se.uncertain_features,
                "residual_risk_reason": se.residual_risk_reason,
                "engine": se.engine,
            } if se else None,
            "runtime": {
                "status": rt.status.value,
                "confidence": rt.confidence,
                "trace_ids": rt.trace_ids,
                "observed_call_count": rt.observed_call_count,
                "test_environment": rt.test_environment,
            } if rt else None,
            "decision": self.decision.value if self.decision else None,
            "decision_confidence": self.decision_confidence,
            "risk_score": self.risk_score,
            "notes": self.notes,
            "audit_record": self.audit_record.to_dict() if self.audit_record else None,
            "audit_history": [a.to_dict() for a in self.audit_history],
        }
