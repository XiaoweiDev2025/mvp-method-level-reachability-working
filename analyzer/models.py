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
    within the analysis scope. Unknown static features (reflection,
    dynamic proxy, missing classpath) are reported separately.
    """
    REACHABLE     = "reachable"       # A call path from entry point to seed method exists
    NOT_REACHABLE = "not_reachable"   # No path found within analysis scope
    UNKNOWN       = "unknown"         # Analysis incomplete due to reflection / dynamic proxy / JNI / missing jars


class RuntimeReachability(str, Enum):
    """
    Result of runtime trace observation.

    NOT_OBSERVED does not prove the method is unreachable —
    it only means it was not called during the observed test execution.
    """
    OBSERVED     = "observed"       # Method appeared in runtime trace
    NOT_OBSERVED = "not_observed"   # Method absent from runtime trace
    NOT_RUN      = "not_run"        # Runtime collection was not executed


class EvidenceLevel(int, Enum):
    """
    L0–L5 evidence ladder. Higher = stronger evidence of exploitability.
    Each level is a necessary (but not sufficient) condition for the next.
    """
    L0_CVE_EXISTS       = 0  # CVE alert exists for a dependency version
    L1_COMPONENT_PRESENT = 1  # Vulnerable package is in the dependency tree
    L2_SEED_IDENTIFIED  = 2  # Vulnerable method has been identified (seed confirmed)
    L3_STATIC_REACHABLE = 3  # Static call graph shows path to seed method
    L4_RUNTIME_OBSERVED = 4  # Seed method was observed during runtime execution
    L5_AUDITED          = 5  # Human review has confirmed or closed the finding


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
class AuditRecord:
    """
    Structured reviewer sign-off for L5 AUDITED evidence.

    CRA Article 14 implication: the timestamp on a report containing L4 AFFECTED
    is legally "when the manufacturer became aware". AuditRecord captures the
    subsequent human review: who confirmed it, when, and on what basis.
    """
    reviewer: str
    reviewed_at: str                       # ISO 8601 — treated as immutable once set
    decision_override: Optional[str] = None  # If reviewer overrides the automated decision
    justification: str = ""
    waiver_expires: Optional[str] = None   # ISO 8601 — if risk is temporarily accepted
    compensating_controls: str = ""        # Required when waiver_expires is set


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
    static_evidence: Optional[StaticEvidence] = None
    runtime_evidence: Optional[RuntimeEvidence] = None

    decision: Optional[Decision] = None
    decision_confidence: float = 0.0     # 0.0 – 1.0, overall confidence in the decision
    risk_score: Optional[float] = None   # 0.0 – 10.0 (CVSS-aligned scale)

    notes: str = ""
    audit_record: Optional[AuditRecord] = None

    def to_dict(self) -> dict:
        """Serialise to a plain dict for JSON/YAML output."""
        se = self.static_evidence
        re = self.runtime_evidence
        return {
            "chain_id": self.chain_id,
            "cve": self.cve,
            "project": self.project_artifact,
            "vulnerable_component": self.vulnerable_component,
            "seed_method": self.seed_method,
            "evidence_level": self.evidence_level.value,
            "evidence_summary": {
                "dependency_match": True,
                "static_reachable": se.status.value == "reachable" if se else False,
                "runtime_observed": re.status.value == "observed" if re else False,
                "entry_points": se.entry_points_used if se else [],
                "call_path_depth": len(se.call_path) if se else 0,
                "trace_ids": re.trace_ids if re else [],
            },
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
                "status": re.status.value,
                "confidence": re.confidence,
                "trace_ids": re.trace_ids,
                "observed_call_count": re.observed_call_count,
            } if re else None,
            "decision": self.decision.value if self.decision else None,
            "decision_confidence": self.decision_confidence,
            "risk_score": self.risk_score,
            "notes": self.notes,
            "audit_record": {
                "reviewer": self.audit_record.reviewer,
                "reviewed_at": self.audit_record.reviewed_at,
                "decision_override": self.audit_record.decision_override,
                "justification": self.audit_record.justification,
                "waiver_expires": self.audit_record.waiver_expires,
                "compensating_controls": self.audit_record.compensating_controls,
            } if self.audit_record else None,
        }
