# Vulnerability Risk Assessor

A prototype tool for assessing whether known vulnerable methods in Java Maven dependencies are reachable from application code. It combines bytecode-level call graph analysis, runtime OpenTelemetry evidence, and CVSS-weighted exposure scoring, and emits JSON and CycloneDX VEX-style reports for evidence-supported vulnerability impact assessment.

Inspired by: *Shen et al., "Beyond Package-Level: Method-Level Vulnerability Reachability Analysis," ESE 2025.*

Designed with EU Cyber Resilience Act (CRA) compliance in mind: the output is structured to serve as evidence in a conformity assessment, not just a scan result.

---

## Problem Statement

Package-level vulnerability scanners (e.g., Dependabot, OWASP Dependency-Check) report every CVE in every transitive dependency — regardless of whether the vulnerable code path is actually reachable from your application. This tool narrows that down using call-graph reachability so you can prioritize fixes based on actual exposure rather than theoretical presence.

---

## Key Result

Across 8 app-CVE evaluation cases covering 4 CVEs and their safe variants, package-level scanners would report all 8 applications as vulnerable (affected dependency version present). This prototype classified 4 of those findings as statically not reachable from the application entry point. Under the proposed reachability-adjusted scoring model, aggregate CVSS-weighted exposure was reduced from 60.2 to 23.2 — a 61.5% exposure re-weighting reduction.

> This metric quantifies how method-level reachability changes vulnerability prioritisation under the scoring model. It is not a claim that real-world attack probability was reduced by 61.5%.

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

> **L2 in NOT_REACHABLE findings**: when a finding carries `evidence_level: 2`, it means the seed method was successfully identified (SEED_IDENTIFIED) but no call path from the application entry points to that method was found in the static call graph. The decision `not_affected_candidate` is therefore a statement about the *absence of a static path*, not a confirmed absence of risk.

---

## CVE Coverage

| CVE | Component | Vulnerable Method | Call Depth | Demo Result |
|-----|-----------|-------------------|------------|-------------|
| CVE-2021-44228 (Log4Shell) | log4j-core 2.14.1 | `JndiLookup.lookup()` | 15 hops | L4 AFFECTED (risk=10.0) |
| CVE-2021-29425 | commons-io 2.6 | `FilenameUtils.getPrefixLength()` | 3 hops | L3 UNDER_INVESTIGATION (risk=2.4) |
| CVE-2018-1002200 (Zip-Slip) | plexus-archiver 3.5 | `AbstractUnArchiver.extractFile()` | 4 hops | L3 UNDER_INVESTIGATION (risk=2.75) |
| CVE-2022-42889 (Text4Shell) | commons-text 1.9 | `StringSubstitutor.replace()` | 2 hops | L3 UNDER_INVESTIGATION (risk=4.9) |

---

## Evaluation Matrix

Package-level scanners over-approximate: they report every (app, CVE) pair where the vulnerable dependency version is present, regardless of whether the vulnerable code path is reachable. The table below tests where method-level reachability narrows that set: for each CVE, one application actively uses the vulnerable method (`vulnerable-*-demo`) and one uses the same dependency version without calling it (`safe-*-demo`).

| CVE | App | Dep version | This tool | Dependabot / OWASP DC | Correct? |
|-----|-----|-------------|-----------|----------------------|---------|
| CVE-2021-44228 | vulnerable-log4j-demo | log4j-core 2.14.1 | L4 AFFECTED (risk=10.0) | VULNERABLE | ✓ TP |
| CVE-2021-44228 | safe-log4j-demo | log4j-core 2.14.1 | L2 NOT_REACHABLE (risk=1.0) | VULNERABLE | ✓ TN (pkg FP) |
| CVE-2022-42889 | vulnerable-text4shell-demo | commons-text 1.9 | L3 REACHABLE (risk=4.9) | VULNERABLE | ✓ TP |
| CVE-2022-42889 | safe-text4shell-demo | commons-text 1.9 | L2 NOT_REACHABLE (risk=1.0) | VULNERABLE | ✓ TN (pkg FP) |
| CVE-2021-29425 | commons-io-demo | commons-io 2.6 | L3 REACHABLE (risk=2.4) | VULNERABLE | ✓ TP |
| CVE-2021-29425 | safe-commons-io-demo | commons-io 2.6 | L2 NOT_REACHABLE (risk=0.5) | VULNERABLE | ✓ TN (pkg FP) |
| CVE-2018-1002200 | plexus-demo | plexus-archiver 3.5 | L3 REACHABLE (risk=2.8) | VULNERABLE | ✓ TP |
| CVE-2018-1002200 | safe-plexus-demo | plexus-archiver 3.5 | L2 NOT_REACHABLE (risk=0.6) | VULNERABLE | ✓ TN (pkg FP) |

**Summary (8 test cases, 4 CVE × 2 apps):**
- This tool: 4 findings statically reachable, 4 statically not reachable under method-level ground truth
- Package-level scanners: all 8 reported at full CVSS; 4 of those cases have no static call path to the seeded vulnerable method

> Ground truth: REACHABLE = the demo application's entry point directly or transitively calls the seeded vulnerable method (verified by call graph inspection). NOT_REACHABLE means no path exists from the configured application entry points to the seeded vulnerable method in the extracted static call graph.

**Reachability-adjusted exposure reduction** (`python scripts/risk_reduction.py`):

| Metric | Value |
|--------|-------|
| Aggregate CVSS-weighted exposure — package-level | 60.2 (all 8 findings at full CVSS) |
| Aggregate reachability-adjusted exposure — this tool | 23.2 (CVSS × evidence multiplier) |
| **Exposure re-weighting reduction** | **61.5%** |
| Statically-unreachable findings | 4 / 8 (50%) |
| L4 runtime-confirmed findings | 1 / 8 (Log4Shell with OTel trace) |

> "Reachability analysis reduced aggregate CVSS-weighted exposure by **62%** relative to package-level scanning across our 8-application evaluation dataset, by assigning a residual weight of 0.10 to statically-unreachable findings to account for analysis uncertainty (4 of 8 package-scanner alerts were statically unreachable)."

**On the evidence multipliers:** The values (1.00 / 0.50 / 0.10) are design parameters, not CVSS-official standards. The 0.10 residual for NOT_REACHABLE findings is intentionally non-zero: it represents two sources of analysis uncertainty — (1) static analysis does not model reflection, `invokedynamic`, or dynamic class loading; (2) a method unreachable today may become reachable after a future refactor. This metric therefore quantifies *reachability-adjusted exposure re-weighting*, not a reduction in real-world attack probability. The specific multiplier values should be calibrated against a labelled exploit dataset in future work.

---

## Related Work

Existing tools for open-source dependency vulnerability management fall into two broad categories: package-level scanners and method-level static analyzers. This work sits between them, and adds a runtime evidence tier absent from both.

| Tool | Analysis level | Reachability | Runtime trace | VEX output | Audit chain | CRA-targeted |
|------|---------------|-------------|--------------|------------|-------------|-------------|
| OWASP Dependency-Check [1] | Package (JAR) | None | — | — | — | — |
| GitHub Dependabot [2] | Package | None | — | — | — | — |
| Google OSV-Scanner [3] | Package | None | — | — | — | — |
| Snyk (paid tier) [4] | Package + partial method | Static (limited, Java) | — | — | — | — |
| Joern [5] | Method (CPG) | Custom QL queries | — | — | — | — |
| CodeQL [6] | Method (data flow) | Taint tracking | — | SARIF | — | — |
| **This work** | **Method (bytecode BFS+CHA)** | **Static + Runtime (OTel)** | **✓** | **CycloneDX 1.5** | **✓ (L5)** | **✓** |

**Package-level scanners** (Dependency-Check, Dependabot, OSV-Scanner) flag every dependency version that appears in a vulnerability database, regardless of whether the vulnerable code path is reachable from the application. Our 8-case evaluation matrix shows that 4 of 8 such alerts are statically unreachable — a 50% over-approximation rate on this dataset.

**Snyk** introduced a reachability feature for Java Maven projects (paid tier, ~2020). However, the feature covers a limited vulnerability pattern set, produces neither VEX output nor an audit trail, and is not designed around the CRA evidence model.

**Joern** [5] and **CodeQL** [6] operate at method or data-flow level and can express reachability as custom queries. Both require non-trivial per-CVE query authoring, produce no VEX output, and are not structured for CRA conformity assessment. CodeQL produces SARIF rather than VEX-style exploitability statements; additional transformation would be required for VEX-oriented vulnerability status reporting.

This work differs along four axes: (1) it combines static BFS reachability with runtime OpenTelemetry trace evidence under a unified L0–L5 evidence ladder, directly addressing the limitation Shen et al. acknowledge — "checking whether the vulnerable condition can be satisfied requires dynamic information, which is hard to obtain and not scalable"; (2) CHA (Class Hierarchy Analysis) is applied explicitly via BFS over both EXTENDS and IMPLEMENTS edges, covering interface-extends-interface chains that Shen et al. identify as a precision gap in prior work; (3) it produces CycloneDX 1.5 VEX with per-finding `not_affected_justification` and `residual_risk_reason`; (4) the `AuditRecord` structure and `analysis_fingerprint` are designed to satisfy the independently-verifiable conformity evidence requirement implied by CRA Article 13(4). The scope of this work is complementary to Shen et al. [7]: they study vulnerability propagation breadth across 1,280 real client projects (ecosystem scale); this work focuses on depth and compliance auditability for a single project under analysis.

**References**

[1] OWASP Foundation. *OWASP Dependency-Check*. https://owasp.org/www-project-dependency-check/

[2] GitHub. *Dependabot documentation*. https://docs.github.com/en/code-security/dependabot

[3] Google. *OSV-Scanner*. https://google.github.io/osv-scanner/

[4] Snyk Ltd. *Reachable vulnerabilities*. https://docs.snyk.io/scan-using-snyk/snyk-open-source/manage-vulnerabilities/reachable-vulnerabilities

[5] Yamaguchi, F. et al. *Modeling and Discovering Vulnerabilities with Code Property Graphs.* IEEE S&P 2014.

[6] GitHub / Semmle. *CodeQL*. https://codeql.github.com/

[7] Shen, X. et al. *Beyond Package-Level: Method-Level Vulnerability Reachability Analysis.* ESE 2025.

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

`light_cvemapping.py` is a **candidate generator**, not an automatic seed generator.
Output goes into `candidate_methods:` — a separate block from `vulnerable_methods:`.
Only after manual validation (descriptor completion, evidence review) should a candidate
be promoted to a trusted seed YAML.

```bash
python analyzer/light_cvemapping.py \
  --commit https://github.com/apache/logging-log4j2/commit/c77b3cb7 \
  --cve CVE-2021-44228 \
  --group-id org.apache.logging.log4j \
  --artifact-id log4j-core \
  --advisory GHSA-jfh8-c2jp-5v3q \
  --package org.apache.logging.log4j.core.lookup \
  --output /tmp/cve-2021-44228-candidates.yaml
```

**Key flags:**

| Flag | Description |
|---|---|
| `--commit` | GitHub fix commit URL (required) |
| `--cve` | CVE ID to embed in output YAML |
| `--group-id` / `--artifact-id` | Maven coordinates of the vulnerable library |
| `--advisory` | Advisory IDs or URLs (GHSA-xxx, https://...) — space-separated |
| `--package` | Java package prefix to filter candidates (reduces noise for large commits) |
| `--output` | Write YAML to file; if omitted, prints to stdout |

**Output structure:**

```yaml
candidate_methods:          # NOT vulnerable_methods — requires manual promotion
  - fqcn: org.apache.logging.log4j.core.lookup.JndiLookup
    method: lookup
    descriptor: null        # always null — requires manual JVM type resolution
    descriptor_hint: "(?Ljava/lang/String;)Ljava/lang/String;"  # best-effort; ? = unknown type
    patch_semantic: method_deleted
    evidence_terms: [jndi, lookup]
    confidence: high
    reason: "Method was deleted by the security patch. Security-relevant terms in diff: jndi, lookup."
```

---

## Running the Demo Projects

### Vulnerable apps (expected: REACHABLE)

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

**Text4Shell** (L3 — static reachable, no trace):
```bash
python analyzer/pipeline.py \
  --project-jars demo-projects/vulnerable-text4shell-demo/target \
  --project-artifact com.example:vulnerable-text4shell-demo \
  --callgraph-cache data/callgraph-text4shell-vuln.txt \
  --output reports/text4shell-vuln.json --cve CVE-2022-42889
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

### Safe apps — same dep version, different code path (expected: NOT_REACHABLE)

```bash
python analyzer/pipeline.py \
  --project-jars demo-projects/safe-log4j-demo/target \
  --project-artifact com.example:safe-log4j-demo \
  --callgraph-cache data/callgraph-safe-log4j.txt \
  --output reports/safe-log4j.json --cve CVE-2021-44228

python analyzer/pipeline.py \
  --project-jars demo-projects/safe-text4shell-demo/target \
  --project-artifact com.example:safe-text4shell-demo \
  --callgraph-cache data/callgraph-text4shell-safe.txt \
  --output reports/text4shell-safe.json --cve CVE-2022-42889

python analyzer/pipeline.py \
  --project-jars demo-projects/safe-commons-io-demo/target \
  --project-artifact com.example:safe-commons-io-demo \
  --callgraph-cache data/callgraph-commons-io-safe.txt \
  --output reports/commons-io-safe.json --cve CVE-2021-29425

python analyzer/pipeline.py \
  --project-jars demo-projects/safe-plexus-demo/target \
  --project-artifact com.example:safe-plexus-demo \
  --callgraph-cache data/callgraph-plexus-safe.txt \
  --output reports/plexus-safe.json --cve CVE-2018-1002200
```

### Reflection false negative demo (expected: NOT_REACHABLE — known analysis limitation)

```bash
python analyzer/pipeline.py \
  --project-jars demo-projects/reflection-log4j-demo/target \
  --project-artifact com.example:reflection-log4j-demo \
  --callgraph-cache data/callgraph-reflection-log4j.txt \
  --output reports/reflection-log4j.json --cve CVE-2021-44228
```

This app invokes `Logger.error()` entirely through `Class.forName()` + `Method.invoke()`.
The ASM extractor records only static bytecode edges and cannot follow runtime dispatch
through reflection. The pipeline reports `not_affected_candidate` — a **false negative**:
the vulnerable method is reachable at runtime if the input contains `${jndi:...}`.

The `static.residual_risk_reason` field in the output documents why NOT_REACHABLE retains
a residual weight of 0.10 rather than zero:
```json
"residual_risk_reason": [
  "reflection_not_modelled",
  "invokedynamic_not_modelled",
  "future_code_change_not_modelled"
]
```

### Reachability-adjusted exposure metric

```bash
python scripts/risk_reduction.py
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
- **`generated_at`** on a report containing an L4 AFFECTED finding can support time-sensitive vulnerability management workflows, including regulatory reporting obligations such as CRA Article 14 (24-hour notification for actively exploited vulnerabilities).
- **`evidence_terms`** in seed candidate output are drawn from a predefined, CWE-keyed vocabulary — not a machine-learning model. Every term is traceable to a specific keyword match in the diff, satisfying the CRA requirement that conformity evidence be independently verifiable.

### Seed pipeline reproducibility boundary

The analysis pipeline (`pipeline.py` → `static_analyzer.py` → `fusion.py`) is **fully local and reproducible**: given the same `data/seeds/*.yaml`, call graph cache, and trace log, the output is deterministic and verifiable without any network calls.

`seed_ingestor.py` (and `light_cvemapping.py`) operate **upstream** of this boundary — they are offline preparation tools for creating new seeds, not part of the runtime analysis. Their outputs (`candidate_methods`) require human validation before promotion to `vulnerable_methods` in a trusted seed file. This validation step is enforced by convention:

- `candidate_methods` ≠ `vulnerable_methods` — the pipeline only reads `vulnerable_methods`
- `requires_manual_validation: true` is an explicit machine-readable assertion in every candidate output
- `status: NEEDS_VALIDATION` must be manually changed to `VALIDATED` by a security engineer

External API calls (OSV, GitHub) only occur during seed preparation, never during analysis. A conformity assessor auditing a report can reproduce it from the seed files and call graph alone, without network access.

---

## Limitations

- Only Java bytecode is analyzed (no Kotlin, Scala, Groovy).
- Reflection, `invokedynamic`, and runtime class loading are not modeled — a NOT_REACHABLE result should be interpreted as a not-affected candidate under the current analysis boundary, not as proof of absence of risk.
- Runtime evidence only covers execution paths in the attached test suite.
- CHA over-approximates polymorphic dispatch — it expands virtual calls to all known subtypes, which may include implementations never instantiated at runtime. The overall analysis is not sound: reflection, `invokedynamic`, and dynamic class loading can create call paths invisible to static analysis.
- Light CVE mapping is a best-effort heuristic; all seeds should be reviewed by a security engineer before use in production.
- Single-project analysis only. Ecosystem-scale analysis (Maven Central-wide) would require a persistent graph database backend; the BFS logic is designed to be storage-agnostic.
