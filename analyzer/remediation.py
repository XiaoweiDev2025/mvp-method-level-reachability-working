"""
Remediation advice generator.

Given a completed EvidenceChain and its originating Seed, produces a
RemediationAdvice that tells the developer:
  - How urgent the fix is (URGENT / RECOMMENDED / MONITOR)
  - What to upgrade and to which version
  - Where in their own code the vulnerable call originates
  - A link to the upstream fix commit
  - An estimated effort level based on call path depth
"""

from __future__ import annotations

from dataclasses import dataclass, field

from models import Decision, EvidenceChain
from seed_loader import Seed

_PRIORITY_MAP = {
    Decision.AFFECTED:               "URGENT",
    Decision.LIKELY_AFFECTED:        "RECOMMENDED",
    Decision.UNDER_INVESTIGATION:    "MONITOR",
    Decision.NOT_AFFECTED_CANDIDATE: "MONITOR",
    Decision.FIXED:                  "MONITOR",
    Decision.MITIGATED:              "MONITOR",
}

_PRIORITY_NOTES = {
    "URGENT":      "Vulnerable method is statically reachable and observed at runtime. Fix before next release.",
    "RECOMMENDED": "Vulnerable method is statically reachable. Increase test coverage or upgrade proactively.",
    "MONITOR":     "No confirmed reachability. Increase test coverage to determine actual exposure, or upgrade when convenient.",
}


@dataclass
class RemediationAdvice:
    cve: str
    priority: str                    # URGENT / RECOMMENDED / MONITOR
    upgrade_path: list[dict]         # [{"artifact": "g:a", "from_version": "...", "to_version": "..."}]
    entry_point_in_your_code: str    # First method in call_path that belongs to the project
    fix_commit: str                  # URL to the upstream fix commit
    effort_estimate: str             # LOW / MEDIUM / HIGH (proxy: call path depth)
    notes: str


def build_remediation(
    chain: EvidenceChain,
    seed: Seed,
    project_prefix: str,
) -> RemediationAdvice:
    """
    Derive remediation advice from a completed EvidenceChain.

    project_prefix — Maven groupId used as Java package prefix (e.g. "com.example").
    Used to locate the first application-owned method on the call path,
    which is the most actionable location for a developer.
    """
    decision = chain.decision
    priority = _PRIORITY_MAP.get(decision, "MONITOR") if decision else "MONITOR"

    call_path: list[str] = []
    if chain.static_evidence:
        call_path = chain.static_evidence.call_path

    entry_point = _find_entry_point_in_project(call_path, project_prefix)
    effort = _estimate_effort(len(call_path))

    upgrade_path = [{
        "artifact": seed.package.coordinates,
        "from_version": seed.package.vulnerable_range,
        "to_version": seed.package.fixed_version,
    }]

    base_note = _PRIORITY_NOTES.get(priority, "")
    if priority == "MONITOR" and decision == Decision.UNDER_INVESTIGATION:
        base_note = _PRIORITY_NOTES["MONITOR"]

    return RemediationAdvice(
        cve=chain.cve,
        priority=priority,
        upgrade_path=upgrade_path,
        entry_point_in_your_code=entry_point,
        fix_commit=seed.fix_commit,
        effort_estimate=effort,
        notes=base_note,
    )


def _find_entry_point_in_project(call_path: list[str], project_prefix: str) -> str:
    """
    Walk the call path from the front and return the first method whose
    class belongs to the project (starts with project_prefix).
    Falls back to call_path[0] if no project-owned method is found, or
    empty string if the path is empty.
    """
    if not call_path:
        return ""
    if not project_prefix:
        return call_path[0]

    prefix = project_prefix + "."
    for sig in call_path:
        if sig.startswith(prefix):
            return sig
    return call_path[0]


def _estimate_effort(depth: int) -> str:
    """
    Proxy for upgrade effort based on call path depth.
    Short paths usually mean the vulnerable call is in a direct dependency;
    longer paths suggest it is buried in transitive dependencies.
    """
    if depth <= 5:
        return "LOW"
    if depth <= 10:
        return "MEDIUM"
    return "HIGH"
