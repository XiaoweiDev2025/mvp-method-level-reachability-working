"""
Runtime evidence analyzer.

Parses OpenTelemetry span logs produced by the LoggingSpanExporter
and answers: "Was the seed method observed during execution?"

Input  : a .log file from scripts/collect_traces.py
Output : RuntimeEvidence with status OBSERVED / NOT_OBSERVED / NOT_RUN

OTel LoggingSpanExporter line format (1.32.0):
  [otel.javaagent TIMESTAMP] [THREAD] INFO ...LoggingSpanExporter - 'SpanName' : <traceId> <spanId> <KIND>
  ... AttributesMap{data={code.function=<method>, code.namespace=<fqcn>, ...}}

When method instrumentation is used (otel.instrumentation.methods.include),
OTel adds two attributes that are perfect for seed matching:
  code.namespace  — the Fully Qualified Class Name
  code.function   — the method name
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from models import RuntimeEvidence, RuntimeReachability
from seed_loader import VulnerableMethod


# ---------------------------------------------------------------------------
# Parsed span record
# ---------------------------------------------------------------------------

@dataclass
class SpanRecord:
    """One span extracted from the OTel log output."""
    span_name: str
    trace_id: str
    span_id: str
    kind: str
    code_namespace: str = ""   # FQCN from code.namespace attribute
    code_function: str = ""    # method name from code.function attribute
    raw_line: str = ""


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

# Matches the main part of a LoggingSpanExporter line:
#   'SpanName' : traceId spanId KIND
_SPAN_HEADER = re.compile(
    r"LoggingSpanExporter\s+-\s+'([^']+)'\s*:\s*([0-9a-f]{32})\s+([0-9a-f]{16})\s+(\w+)"
)

# Matches key=value pairs inside AttributesMap{data={...}}
# e.g. code.namespace=org.apache.logging.log4j.core.lookup.JndiLookup
_ATTR = re.compile(r"([\w.]+)=([^,}]+)")


def parse_trace_log(path: Path) -> list[SpanRecord]:
    """
    Parse an OTel logging exporter output file.
    Returns a list of SpanRecord, one per completed span found.
    """
    spans: list[SpanRecord] = []

    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = _SPAN_HEADER.search(line)
            if not m:
                continue

            span = SpanRecord(
                span_name=m.group(1),
                trace_id=m.group(2),
                span_id=m.group(3),
                kind=m.group(4),
                raw_line=line.rstrip(),
            )

            # Extract individual attributes from the AttributesMap section
            attr_section = line[m.end():]
            for attr_m in _ATTR.finditer(attr_section):
                key, val = attr_m.group(1), attr_m.group(2).strip()
                if key == "code.namespace":
                    span.code_namespace = val
                elif key == "code.function":
                    span.code_function = val

            spans.append(span)

    return spans


# ---------------------------------------------------------------------------
# Seed matching
# ---------------------------------------------------------------------------

def _span_matches_seed(span: SpanRecord, seed: VulnerableMethod) -> bool:
    """
    Check whether a span corresponds to the seed method.

    Primary match: code.namespace == seed.fqcn AND code.function == seed.method
    These attributes are always present for otel.instrumentation.methods.include spans.

    Fallback match: span_name contains the simple class name + method name.
    Used when the OTel agent version doesn't emit code.* attributes.
    """
    # Primary: exact FQCN + method name from OTel attributes
    if span.code_namespace and span.code_function:
        return span.code_namespace == seed.fqcn and span.code_function == seed.method

    # Fallback: span name heuristic
    # OTel names method spans as "SimpleClassName.method", e.g. "JndiLookup.lookup"
    simple_class = seed.fqcn.rsplit(".", 1)[-1]
    return span.span_name == f"{simple_class}.{seed.method}"


# ---------------------------------------------------------------------------
# Main analyzer function
# ---------------------------------------------------------------------------

def _otel_agent_was_active(trace_log: Path) -> bool:
    """
    Check whether the OTel Java agent was actually running during the captured execution.

    The agent always prints a version banner to stderr on startup:
      [otel.javaagent ...] INFO ...VersionLogger - opentelemetry-javaagent - version: X.Y.Z

    If this line is absent, the agent was not attached — spans being absent may mean
    the agent wasn't running, not that the method was unreachable.
    """
    with open(trace_log, encoding="utf-8", errors="replace") as f:
        for line in f:
            if "otel.javaagent" in line and "VersionLogger" in line:
                return True
    return False


def analyze_traces(trace_log: Path, seed_method: VulnerableMethod) -> RuntimeEvidence:
    """
    Parse a trace log file and return RuntimeEvidence for a seed method.

    Status logic:
      OBSERVED     — at least one span matching the seed was found
      NOT_OBSERVED — OTel was running but no matching span found
                     (NOT proof of safety: the test may not have triggered the path)
      NOT_RUN      — trace file missing/empty OR OTel agent was not active
    """
    if not trace_log.exists() or trace_log.stat().st_size == 0:
        return RuntimeEvidence(
            status=RuntimeReachability.NOT_RUN,
            confidence=0.0,
            test_environment="",
        )

    # Check agent was active before concluding NOT_OBSERVED vs NOT_RUN
    agent_active = _otel_agent_was_active(trace_log)

    spans = parse_trace_log(trace_log)

    if not spans and not agent_active:
        # No spans AND no agent banner — agent was not attached
        return RuntimeEvidence(
            status=RuntimeReachability.NOT_RUN,
            confidence=0.0,
            test_environment="otel-logging",
        )

    matching = [s for s in spans if _span_matches_seed(s, seed_method)]

    if matching:
        return RuntimeEvidence(
            status=RuntimeReachability.OBSERVED,
            confidence=0.95,
            trace_ids=[s.trace_id for s in matching],
            observed_call_count=len(matching),
            test_environment="otel-logging-javaagent-1.32.0",
        )
    else:
        return RuntimeEvidence(
            status=RuntimeReachability.NOT_OBSERVED,
            confidence=0.6,    # 0.6: NOT_OBSERVED only within the observed test runs
            trace_ids=[],
            observed_call_count=0,
            test_environment="otel-logging-javaagent-1.32.0",
        )


# ---------------------------------------------------------------------------
# Summary helper
# ---------------------------------------------------------------------------

def print_trace_summary(spans: list[SpanRecord], seed_method: VulnerableMethod) -> None:
    print(f"  Total spans parsed : {len(spans)}")
    matching = [s for s in spans if _span_matches_seed(s, seed_method)]
    print(f"  Matching seed      : {len(matching)}")
    if matching:
        for s in matching:
            print(f"    - trace={s.trace_id[:16]}...  "
                  f"span={s.span_id}  ns={s.code_namespace}  fn={s.code_function}")
