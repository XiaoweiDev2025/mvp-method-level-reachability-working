"""
Audit subcommand: promote a finding to L5 AUDITED after human review.

Reads an existing JSON report produced by pipeline.py, applies a reviewer's
sign-off to one finding, and writes the updated report back.

CRA Article 14 relevance:
  The timestamp on a report containing L4 AFFECTED marks when the manufacturer
  became aware. AuditRecord captures the subsequent human review: who confirmed
  it, when, and on what basis — satisfying the "addressed in a timely manner"
  documentation requirement.

Usage:
    python analyzer/audit.py \\
        --report reports/vulnerable-log4j-demo.json \\
        --chain-id "CVE-2021-44228::com.example:vulnerable-log4j-demo:1.0-SNAPSHOT" \\
        --reviewer alice@example.com \\
        --justification "Confirmed reachable via 15-hop call path. Upgrade scheduled." \\
        [--decision-override fixed] \\
        [--waiver-expires 2026-09-01T00:00:00Z] \\
        [--compensating-controls "WAF rule blocking outbound JNDI active"]

    # List available chain_ids in a report:
    python analyzer/audit.py --report reports/foo.json --list
"""

from __future__ import annotations

import argparse
import datetime
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from models import AuditRecord, Decision


def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")


def list_chain_ids(report: dict) -> None:
    findings = report.get("findings", [])
    if not findings:
        print("No findings in report.")
        return
    print(f"{'chain_id':<60}  {'level':>5}  decision")
    print("-" * 90)
    for f in findings:
        print(
            f"{f.get('chain_id', '?'):<60}  "
            f"L{f.get('evidence_level', '?'):>1}     "
            f"{f.get('decision', '?')}"
        )


def apply_audit_to_dict(finding: dict, audit_record: AuditRecord) -> dict:
    """
    Upgrade a finding dict in-place to L5 AUDITED.
    Operates on the raw dict (not EvidenceChain) to avoid reconstructing
    the full dataclass from JSON.
    """
    finding["evidence_level"] = 5  # EvidenceLevel.L5_AUDITED

    if audit_record.decision_override:
        finding["decision"] = audit_record.decision_override

    # Human review raises confidence, capped at 0.98
    prev_conf = finding.get("decision_confidence", 0.5)
    finding["decision_confidence"] = round(min(0.98, prev_conf + 0.20), 4)

    finding["audit_record"] = {
        "reviewer":              audit_record.reviewer,
        "reviewed_at":           audit_record.reviewed_at,
        "decision_override":     audit_record.decision_override,
        "justification":         audit_record.justification,
        "waiver_expires":        audit_record.waiver_expires,
        "compensating_controls": audit_record.compensating_controls,
    }
    return finding


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Promote a CVE finding to L5 AUDITED after human review"
    )
    parser.add_argument("--report", required=True,
                        help="Path to existing JSON report from pipeline.py")
    parser.add_argument("--list", action="store_true",
                        help="List available chain_ids in the report and exit")
    parser.add_argument("--chain-id",
                        help="chain_id of the finding to audit")
    parser.add_argument("--reviewer", default="",
                        help="Reviewer identity (email or name)")
    parser.add_argument("--justification", default="",
                        help="Human-readable rationale for the audit decision")
    parser.add_argument("--decision-override",
                        choices=[d.value for d in Decision],
                        default=None,
                        help="Override the automated decision (optional)")
    parser.add_argument("--waiver-expires", default=None,
                        help="ISO 8601 timestamp if risk is temporarily accepted")
    parser.add_argument("--compensating-controls", default="",
                        help="Controls in place when a waiver is granted")
    parser.add_argument("--output", default=None,
                        help="Output path (default: overwrite the input report)")

    args = parser.parse_args()

    report_path = Path(args.report)
    if not report_path.exists():
        print(f"ERROR: Report not found: {report_path}", file=sys.stderr)
        sys.exit(1)

    report = json.loads(report_path.read_text(encoding="utf-8"))

    if args.list:
        list_chain_ids(report)
        return

    # Validate required args for audit operation
    if not args.chain_id:
        parser.error("--chain-id is required (use --list to see available ids)")
    if not args.reviewer:
        parser.error("--reviewer is required")
    if not args.justification:
        parser.error("--justification is required")
    if args.waiver_expires and not args.compensating_controls:
        parser.error("--compensating-controls is required when --waiver-expires is set")

    # Find the target finding
    findings = report.get("findings", [])
    target_idx = next(
        (i for i, f in enumerate(findings) if f.get("chain_id") == args.chain_id),
        None,
    )

    if target_idx is None:
        print(f"ERROR: chain_id not found: {args.chain_id}", file=sys.stderr)
        print("Run with --list to see available chain_ids.", file=sys.stderr)
        sys.exit(1)

    audit_record = AuditRecord(
        reviewer=args.reviewer,
        reviewed_at=_now_iso(),
        decision_override=args.decision_override,
        justification=args.justification,
        waiver_expires=args.waiver_expires,
        compensating_controls=args.compensating_controls,
    )

    report["findings"][target_idx] = apply_audit_to_dict(
        report["findings"][target_idx], audit_record
    )

    output_path = Path(args.output) if args.output else report_path
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    f = report["findings"][target_idx]
    print(f"  chain_id:          {f['chain_id']}")
    print(f"  evidence_level:    L{f['evidence_level']} (AUDITED)")
    print(f"  decision:          {f['decision']}")
    print(f"  decision_confidence: {f['decision_confidence']}")
    print(f"  reviewer:          {audit_record.reviewer}")
    print(f"  reviewed_at:       {audit_record.reviewed_at}")
    print(f"  Report written to  {output_path}")


if __name__ == "__main__":
    main()
