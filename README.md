# Vulnerability Risk Assessor

A prototype tool for assessing the **actual risk** of vulnerable open-source dependencies in Java Maven projects by combining static reachability analysis, runtime execution evidence, and CVSS-weighted risk scoring.

Inspired by: *Shen et al., "Beyond Package-Level: Method-Level Vulnerability Reachability Analysis," ESE 2025.*

Designed with EU Cyber Resilience Act (CRA) compliance in mind: the output is structured to serve as evidence in a conformity assessment, not just a scan result.

---

## Problem Statement

Package-level vulnerability scanners (e.g., Dependabot, OWASP Dependency-Check) report every CVE in every transitive dependency — regardless of whether the vulnerable code path is actually reachable from your application. This tool narrows that down using call-graph reachability so you can prioritize fixes based on actual exposure rather than theoretical presence.

---

## Prerequisites

| Tool | Minimum version | Purpose |
|---|---|---|
| Python | 3.10+ | Analyzer pipeline |
| Java | 11+ | Call graph extractor + demo apps |
| Maven | 3.6+ | Building JARs |
| PyYAML | any | `pip install pyyaml` |

---

## Evidence Levels

| Level | Name | Description |
|-------|------|-------------|
| L0 | CVE_EXISTS | CVE is known and has a CVSS score |
| L1 | COMPONENT_PRESENT | Vulnerable component version is in the dependency tree |
| L2 | SEED_IDENTIFIED | The specific vulnerable method has been mapped from the fix commit |
| L3 | STATIC_REACHABLE | A call path from your code to the vulnerable method exists in the call graph |
| L4 | RUNTIME_OBSERVED | The vulnerable method was observed executing during testing |
| L5 | AUDITED | A human security engineer has reviewed and confirmed the finding |

---

## CVE Coverage

| CVE | Component | Vulnerable Method | Call Depth | Demo Result |
|-----|-----------|-------------------|------------|-------------|
| CVE-2021-44228 (Log4Shell) | log4j-core 2.14.1 | `JndiLookup.lookup()` | 15 hops | L4 AFFECTED (risk=10.0) |
| CVE-2021-29425 | commons-io 2.6 | `FilenameUtils.getPrefixLength()` | 3 hops | L3 UNDER_INVESTIGATION (risk=2.4) |
| CVE-2018-1002200 (Zip-Slip) | plexus-archiver 3.5 | `AbstractUnArchiver.extractFile()` | 4 hops | L3 UNDER_INVESTIGATION (risk=2.75) |

---

## Architecture

```
demo-projects/          Java Maven apps that use vulnerable libraries
tools/
  callgraph-extractor/  ASM-based Java call graph extractor (fat JAR)
  otel/                 OpenTelemetry Java agent for runtime instrumentation
scripts/
  collect_traces.py     Runs demo app with OTel agent, saves span logs
analyzer/
  seed_loader.py        Loads CVE seed YAML files (vulnerable method definitions)
  static_analyzer.py    Call graph parser + CHA + BFS reachability
  runtime_analyzer.py   OTel span log parser -> OBSERVED/NOT_OBSERVED/NOT_RUN
  fusion.py             Evidence fusion engine -> decision + risk score
  pipeline.py           Top-level CLI orchestrator + JSON/VEX report writer
  remediation.py        Remediation advice generator (priority, upgrade path)
  light_cvemapping.py   Semi-automated seed extraction from fix commits (git diff)
  models.py             Shared dataclasses (StaticEvidence, AuditRecord, etc.)
data/
  seeds/                CVE-*.yaml: vulnerable method definitions
  callgraph-*.txt       Pre-computed call graphs (cached)
  traces/               OTel span logs from demo runs
reports/                JSON + VEX risk reports (generated output)
```

---

## Quick Start

### Step 1 — Install Python dependency

```bash
pip install pyyaml
```

### Step 2 — Build the call graph extractor

```bash
cd tools/callgraph-extractor
mvn package -q
# Produces: target/callgraph-extractor-1.0.jar
```

### Step 3 — Build a demo project

```bash
cd demo-projects/vulnerable-log4j-demo
mvn package -q
mvn dependency:copy-dependencies -DoutputDirectory=target/dependency -q
```

### Step 4 — Run the risk assessment pipeline

The pre-computed call graphs in `data/` let you skip the extraction step. Use `--callgraph-cache` to reuse them.

```bash
cd <project-root>

python analyzer/pipeline.py \
  --project-jars demo-projects/vulnerable-log4j-demo/target \
  --project-artifact com.example:log4j-demo \
  --callgraph-cache data/callgraph-log4j.txt \
  --trace-log data/traces/run1.log \
  --output reports/log4j.json \
  --output-vex reports/log4j.vex.json \
  --verbose
```

**Key flags:**

| Flag | Required | Description |
|---|---|---|
| `--project-jars` | yes | Directory or JAR files to analyze |
| `--project-artifact` | recommended | Maven `groupId:artifactId` — filters entry points to your code only |
| `--callgraph-cache` | no | Reuse a previously extracted call graph (skips Java extraction) |
| `--trace-log` | no | OTel span log from `collect_traces.py` — enables L4 evidence |
| `--output` | no | Path for JSON report (default: `reports/<artifact>.json`) |
| `--output-vex` | no | Path for CycloneDX 1.5 VEX document (CRA conformity output) |
| `--cve` | no | Restrict analysis to specific CVE IDs |
| `--extra-entry-points` | no | Additional BFS entry points (e.g. servlet handlers) |

### Step 5 — Collect runtime traces (Log4Shell only)

```bash
python scripts/collect_traces.py
# Writes: data/traces/run1.log (JNDI payload), data/traces/run2.log (benign)
```

Then re-run the pipeline with `--trace-log data/traces/run1.log` to upgrade to L4.

### Step 6 — Semi-automated seed extraction from a fix commit

```bash
python analyzer/light_cvemapping.py \
  --commit https://github.com/apache/logging-log4j2/commit/c77b3cb7 \
  --package org.apache.logging.log4j.core.lookup
```

---

## Running the Three Demo CVEs

**Log4Shell** (L4 — runtime observed):
```bash
python analyzer/pipeline.py \
  --project-jars demo-projects/vulnerable-log4j-demo/target \
  --project-artifact com.example:log4j-demo \
  --callgraph-cache data/callgraph-log4j.txt \
  --trace-log data/traces/run1.log \
  --output reports/log4j.json \
  --output-vex reports/log4j.vex.json
```

**Zip-Slip** (L3 — static reachable, no trace):
```bash
python analyzer/pipeline.py \
  --project-jars demo-projects/plexus-demo/target \
  --project-artifact com.example:plexus-demo \
  --callgraph-cache data/callgraph-plexus.txt \
  --output reports/plexus.json
```

**commons-io** (L3 — static reachable, no trace):
```bash
python analyzer/pipeline.py \
  --project-jars demo-projects/commons-io-demo/target \
  --project-artifact com.example:commons-io-demo \
  --callgraph-cache data/callgraph-commons-io.txt \
  --output reports/commons-io.json
```

---

## Running Tests

```bash
python analyzer/test_static.py      # BFS reachability + CHA correctness + annotated path
python analyzer/test_runtime.py     # OTel span log parsing
python analyzer/test_pipeline.py    # Full end-to-end: evidence chain + remediation assertions
```

---

## Report Format

Each finding explains *why* the decision was reached:

```json
{
  "project": "com.example:log4j-demo",
  "findings": [
    {
      "cve": "CVE-2021-44228",
      "evidence_level": 4,
      "evidence_summary": {
        "dependency_match": true,
        "static_reachable": true,
        "runtime_observed": true,
        "entry_points": ["com.example.App.main(...)"],
        "call_path_depth": 15,
        "trace_ids": ["50b93a0c..."]
      },
      "static": {
        "status": "reachable",
        "analysis_fingerprint": "95d861e0abd06a0b",
        "call_path": ["com.example.App.main(...)", "...", "JndiLookup.lookup(...)"],
        "call_path_annotated": [
          {"sig": "com.example.App.main(...)", "edge_type": "ENTRY_POINT"},
          {"sig": "AbstractLogger.error(...)", "edge_type": "CHA_EXPANSION[Logger->AbstractLogger]"},
          {"sig": "JndiLookup.lookup(...)", "edge_type": "CHA_EXPANSION[StrLookup->JndiLookup]"}
        ]
      },
      "runtime": {
        "status": "observed",
        "trace_ids": ["50b93a0c550dd9e980d2d7675cf93544"],
        "observed_call_count": 1
      },
      "decision": "affected",
      "risk_score": 10.0,
      "remediation": {
        "priority": "URGENT",
        "upgrade_path": [{"artifact": "org.apache.logging.log4j:log4j-core", "to_version": "2.17.0"}],
        "entry_point_in_your_code": "com.example.App.main(...)",
        "fix_commit": "https://github.com/apache/logging-log4j2/commit/...",
        "effort_estimate": "HIGH"
      },
      "audit_record": null
    }
  ]
}
```

The `audit_record` field is populated when a security engineer promotes a finding to L5 AUDITED.

---

## Decision Rules

| Static | Runtime | Decision | Evidence Level |
|--------|---------|----------|----------------|
| REACHABLE | OBSERVED | affected | L4 |
| REACHABLE | NOT_OBSERVED | likely_affected | L3 |
| REACHABLE | NOT_RUN | under_investigation | L3 |
| NOT_REACHABLE | any | not_affected_candidate | L2 |
| UNKNOWN | any | under_investigation | L1 |

**Risk score** = CVSS base score × evidence multiplier (L4=1.0, L3 likely=0.75, L3 under=0.50, L2=0.10)

**Remediation priority** = URGENT (affected) / RECOMMENDED (likely_affected) / MONITOR (others)

---

## Key Design Decisions

**CHA (Class Hierarchy Analysis)** is used during BFS to handle polymorphic dispatch. When a call to `Logger.error()` (an interface method) is encountered, the BFS is expanded to include all known concrete implementations. The CHA closure is computed via BFS over both EXTENDS and IMPLEMENTS edges — interface-extends-interface relationships are stored as IMPLEMENTS edges in ASM bytecode, not as EXTENDS.

**Upward method resolution**: When bytecode contains `INVOKEVIRTUAL ZipUnArchiver.extract()`, the call graph extractor records the static receiver type, but `ZipUnArchiver` may not define `extract()` — it may be inherited from `AbstractUnArchiver`. The analyzer walks up the EXTENDS chain when a method has no outgoing edges to find the declaring superclass.

**Entry point filtering**: The `--project-artifact` groupId is used as a Java package prefix to restrict BFS entry points to application-owned classes only. Without this, library tool classes (e.g. `log4j-core`'s own `Version.main`) would be treated as entry points and inflate reachability results.

**Annotated call path**: Each hop in the call path is tagged with its edge type (`CALL`, `CHA_EXPANSION[X->Y]`, `INHERITED`, `ENTRY_POINT`), making it auditable which steps relied on conservative CHA assumptions versus direct bytecode edges.

**NOT_OBSERVED != NOT_REACHABLE**: Runtime evidence only covers the execution paths taken in the test suite. `NOT_OBSERVED` means the method was not seen in the observed runs, not that it is unreachable. The OTel agent's `VersionLogger` startup line is used to distinguish `NOT_OBSERVED` (agent ran, method not called) from `NOT_RUN` (agent was not attached at all).

**Light CVE mapping** parses git diff hunk headers (`@@ -a,b +c,d @@ function_context`) to identify which method was modified in the fix commit. This is more reliable than scanning for `+` lines alone because the hunk header names the enclosing function even when the fix is purely additive (no removed lines).

---

## CRA Compliance Notes

This tool is designed to produce evidence suitable for EU Cyber Resilience Act (CRA) conformity assessment:

- **`analysis_fingerprint`** makes each report reproducible: given the same callgraph file and seed, the result is verifiable.
- **`--output-vex`** produces a CycloneDX 1.5 VEX document. VEX is the standard format for per-CVE exploitability status and is directly consumable by conformity assessors.
- **`AuditRecord`** (populated at L5) captures reviewer identity, timestamp, justification, and waiver expiry — the chain-of-custody elements a conformity assessor will look for.
- **`generated_at`** on a report containing an L4 AFFECTED finding is legally significant under CRA Article 14 (24-hour notification obligation for actively exploited vulnerabilities).

---

## Limitations

- Only Java bytecode is analyzed (no Kotlin, Scala, Groovy).
- Reflection, `invokedynamic`, and runtime class loading are not modeled — a NOT_REACHABLE result has ~70% confidence, not 100%.
- Runtime evidence only covers execution paths in the attached test suite.
- CHA is conservative (sound but not complete): it may report REACHABLE for dispatch targets that are dead in practice.
- Light CVE mapping is a best-effort heuristic; all seeds should be reviewed by a security engineer before use in production.
- Single-project analysis only. Ecosystem-scale analysis (Maven Central-wide) would require a persistent graph database backend; the BFS logic is designed to be storage-agnostic.
