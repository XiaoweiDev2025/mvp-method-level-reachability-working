# Vulnerability Risk Assessor

A prototype framework for assessing whether known vulnerable methods in Java Maven dependencies are reachable from application code. It combines bytecode-level call graph analysis with runtime OpenTelemetry execution traces to produce a graduated evidence chain (L0–L5), CVSS-weighted exposure scores, and CycloneDX VEX output — structured for EU Cyber Resilience Act (CRA) conformity assessment workflows, not just dependency scanning.

Inspired by: *Shen et al., "Beyond Package-Level: Method-Level Vulnerability Reachability Analysis," ESE 2025.*

**What this tool does:**
- Extracts a bytecode-level call graph from application JARs using a custom ASM-based extractor
- Applies BFS reachability with CHA (Class Hierarchy Analysis) to determine whether a vulnerable method is callable from application entry points
- Correlates static reachability with runtime OpenTelemetry span evidence to distinguish observed exploitation paths from theoretical ones
- Fuses both evidence types into a six-level evidence ladder (L0–L5) with explicit confidence scores and residual-risk reasoning
- Emits JSON evidence chains and CycloneDX 1.5 VEX documents suitable for CRA vulnerability-handling documentation
- Supports human sign-off via `AuditRecord` (L5), closing the loop from automated detection to auditable decision

---

## Key Result

Across 8 app-CVE evaluation cases covering 4 CVEs and their safe variants, package-level scanners would report all 8 applications as vulnerable (affected dependency version present). This prototype classified 4 of those findings as statically not reachable from the configured application entry points. Under the proposed reachability-adjusted scoring model, aggregate CVSS-weighted exposure was reduced from 60.2 to 23.2 — a 61.5% exposure re-weighting reduction.

> This metric quantifies how method-level reachability changes vulnerability prioritisation under the scoring model. It is not a claim that real-world attack probability was reduced by 61.5%.

---

## Quick Demo

Pre-computed call graphs and OTel traces are included. No build step needed to run the Log4Shell case:

```bash
pip install pyyaml

python analyzer/pipeline.py \
  --project-jars demo-projects/vulnerable-log4j-demo/target \
  --project-artifact com.example:log4j-demo \
  --callgraph-cache data/callgraph-log4j.txt \
  --trace-log data/traces/run1.log \
  --output reports/log4j.json \
  --output-vex reports/log4j.vex.json \
  --verbose
```

Expected: `L4  affected  risk=10.0  conf=0.90  remedy=URGENT` — 15-hop call path confirmed at runtime.

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
  audit.py              L5 human sign-off entry point
  light_cvemapping.py   Semi-automated seed extraction from fix commits (git diff)
  models.py             Shared dataclasses (StaticEvidence, AuditRecord, etc.)
data/
  seeds/                CVE-*.yaml: vulnerable method definitions
  callgraph-*.txt       Pre-computed call graphs (cached)
  traces/               OTel span logs from demo runs
reports/                JSON + VEX risk reports (generated output)
docs/
  SDD-v1.0.pdf          Software Design Document (system design, data model, module pseudocode)
```

> **Implementation note (SDD vs. actual code):** The SDD (Section 4.1.3) lists WALA, Soot, and SootUp as candidate static analysis frameworks. The implementation instead uses a custom ASM-based call graph extractor (`tools/callgraph-extractor/`) with a lightweight Python BFS engine. This choice was made during implementation to avoid JVM tool startup overhead and to allow precise control over edge types (CALL / EXTENDS / IMPLEMENTS) needed for the annotated call path feature. The design intent — bytecode-level CHA + BFS reachability — is unchanged.

---

## Third-Party Validation

To verify that the pipeline generalises beyond its own demo projects, it was applied to [`christophetd/log4shell-vulnerable-app`](https://github.com/christophetd/log4shell-vulnerable-app) — a Spring Boot application widely used in Log4Shell security research, with no shared code or call graph data with the bundled demos.

| | |
|---|---|
| JARs analysed | 29 |
| Call graph edges extracted | 222,576 |
| Static result | REACHABLE (entry point → `JndiLookup.lookup()`) |
| Runtime result | OBSERVED (OTel span captured on JNDI payload request) |
| Final decision | **L4 AFFECTED, risk=10.0, conf=0.90** |

The pipeline produced the same evidence structure as on the bundled demos, from a fully independent extraction. See [Applying the Pipeline to an External Project](#applying-the-pipeline-to-an-external-project) for the full reproduction steps.

---

## Evaluation

Package-level scanners over-approximate: they report every (app, CVE) pair where the vulnerable dependency version is present, regardless of whether the vulnerable code path is reachable. The table below tests where method-level reachability narrows that set: for each CVE, one application actively uses the vulnerable method (`vulnerable-*-demo`) and one uses the same dependency version without calling it (`safe-*-demo`).

| CVE | App | Dep version | Package-level scanner | This tool | Reachability outcome |
|-----|-----|-------------|----------------------|-----------|----------------------|
| CVE-2021-44228 | vulnerable-log4j-demo | log4j-core 2.14.1 | VULNERABLE | L4 AFFECTED (risk=10.0) | Reachable vulnerable method |
| CVE-2021-44228 | safe-log4j-demo | log4j-core 2.14.1 | VULNERABLE | L2 NOT_REACHABLE (risk=1.0) | Package-level alert; method not statically reachable |
| CVE-2022-42889 | vulnerable-text4shell-demo | commons-text 1.9 | VULNERABLE | L3 UNDER_INVESTIGATION (risk=4.9) | Reachable vulnerable method |
| CVE-2022-42889 | safe-text4shell-demo | commons-text 1.9 | VULNERABLE | L2 NOT_REACHABLE (risk=1.0) | Package-level alert; method not statically reachable |
| CVE-2021-29425 | commons-io-demo | commons-io 2.6 | VULNERABLE | L3 UNDER_INVESTIGATION (risk=2.4) | Reachable vulnerable method |
| CVE-2021-29425 | safe-commons-io-demo | commons-io 2.6 | VULNERABLE | L2 NOT_REACHABLE (risk=0.5) | Package-level alert; method not statically reachable |
| CVE-2018-1002200 | plexus-demo | plexus-archiver 3.5 | VULNERABLE | L3 UNDER_INVESTIGATION (risk=2.8) | Reachable vulnerable method |
| CVE-2018-1002200 | safe-plexus-demo | plexus-archiver 3.5 | VULNERABLE | L2 NOT_REACHABLE (risk=0.6) | Package-level alert; method not statically reachable |

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

### CVE Coverage

| CVE | Component | Vulnerable Method | Call Depth | Demo Result |
|-----|-----------|-------------------|------------|-------------|
| CVE-2021-44228 (Log4Shell) | log4j-core 2.14.1 | `JndiLookup.lookup()` | 15 hops | L4 AFFECTED (risk=10.0) |
| CVE-2021-29425 | commons-io 2.6 | `FilenameUtils.getPrefixLength()` | 3 hops | L3 UNDER_INVESTIGATION (risk=2.4) |
| CVE-2018-1002200 (Zip-Slip) | plexus-archiver 3.5 | `AbstractUnArchiver.extractFile()` | 4 hops | L3 UNDER_INVESTIGATION (risk=2.75) |
| CVE-2022-42889 (Text4Shell) | commons-text 1.9 | `StringSubstitutor.replace()` | 2 hops | L3 UNDER_INVESTIGATION (risk=4.9) |

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
- **`--output-vex`** produces a CycloneDX 1.5 VEX document. VEX is a machine-readable format for communicating per-CVE exploitability status and can support vulnerability management and conformity-assessment workflows.
- **`AuditRecord`** (populated at L5) captures reviewer identity, timestamp, justification, and waiver expiry — the chain-of-custody elements a conformity assessor will look for.
- **`generated_at`** on a report containing an L4 AFFECTED finding can support time-sensitive vulnerability management and regulatory reporting workflows.
- **`evidence_terms`** in seed candidate output are drawn from a predefined, CWE-keyed vocabulary — not a machine-learning model. Every term is traceable to a specific keyword match in the diff, supporting independently verifiable conformity evidence.

### Seed pipeline reproducibility boundary

The analysis pipeline (`pipeline.py` → `static_analyzer.py` → `fusion.py`) is **fully local and reproducible**: given the same `data/seeds/*.yaml`, call graph cache, and trace log, the output is deterministic and verifiable without any network calls.

`seed_ingestor.py` (and `light_cvemapping.py`) operate **upstream** of this boundary — they are offline preparation tools for creating new seeds, not part of the runtime analysis. Their outputs (`candidate_methods`) require human validation before promotion to `vulnerable_methods` in a trusted seed file. This validation step is enforced by convention:

- `candidate_methods` ≠ `vulnerable_methods` — the pipeline only reads `vulnerable_methods`
- `requires_manual_validation: true` is an explicit machine-readable assertion in every candidate output
- `status: NEEDS_VALIDATION` must be manually changed to `VALIDATED` by a security engineer

External API calls (OSV, GitHub) only occur during seed preparation, never during analysis. A conformity assessor auditing a report can reproduce it from the seed files and call graph alone, without network access.

---

## Related Work

Existing tools for open-source dependency vulnerability management fall into two broad categories: package-level scanners and method-level static analyzers. This work sits between them and adds an explicit runtime evidence tier to the prototype's evidence model.

| Tool | Analysis level | Reachability | Runtime trace | VEX output | Audit chain | CRA-oriented evidence |
|------|---------------|-------------|--------------|------------|-------------|----------------------|
| OWASP Dependency-Check [1] | Package (JAR) | None | — | — | — | — |
| GitHub Dependabot [2] | Package | None | — | — | — | — |
| Google OSV-Scanner [3] | Package | None | — | — | — | — |
| Snyk (paid tier) [4] | Package + partial method | Static (limited, Java) | — | — | — | — |
| Joern [5] | Method (CPG) | Custom QL queries | — | — | — | — |
| CodeQL [6] | Method (data flow) | Taint tracking | — | SARIF | — | — |
| **This work** | **Method (bytecode BFS+CHA)** | **Static + Runtime (OTel)** | **✓** | **CycloneDX 1.5 VEX** | **✓ (L5)** | **✓** |

**Package-level scanners** (Dependency-Check, Dependabot, OSV-Scanner) flag every dependency version that appears in a vulnerability database, regardless of whether the vulnerable code path is reachable from the application. Our 8-case evaluation matrix shows that 4 of 8 such alerts are statically unreachable — a 50% over-approximation rate on this dataset.

**Snyk** provides reachability analysis for some ecosystems and vulnerability patterns (paid tier). Its implementation details, evidence model, and audit trail are platform-specific and not directly reproducible in this prototype's sense; it produces neither VEX output nor an audit chain structured for CRA conformity assessment.

**Joern** [5] and **CodeQL** [6] operate at method or data-flow level and can express reachability as custom queries. Both require non-trivial per-CVE query authoring, produce no VEX output, and are not structured for CRA conformity assessment. CodeQL produces SARIF rather than VEX-style exploitability statements; additional transformation would be required for VEX-oriented vulnerability status reporting.

This work differs along four axes: (1) it combines static BFS reachability with runtime OpenTelemetry trace evidence under a unified L0–L5 evidence ladder, addressing a limitation discussed by Shen et al.: determining whether vulnerable conditions are satisfied often requires dynamic information, which is difficult to obtain at scale; (2) CHA is applied explicitly via BFS over both EXTENDS and IMPLEMENTS edges, covering interface-extends-interface chains that Shen et al. identify as a precision gap in prior work; (3) it produces CycloneDX 1.5 VEX output with per-finding `not_affected_justification` and `residual_risk_reason`; (4) the `AuditRecord` structure and `analysis_fingerprint` are designed to support independently verifiable conformity evidence in CRA-oriented workflows. The scope of this work is complementary to Shen et al. [7]: they study vulnerability propagation breadth across 1,280 real client projects (ecosystem scale); this work focuses on depth and compliance auditability for a single project under analysis.

**References**

[1] OWASP Foundation. *OWASP Dependency-Check*. https://owasp.org/www-project-dependency-check/

[2] GitHub. *Dependabot documentation*. https://docs.github.com/en/code-security/dependabot

[3] Google. *OSV-Scanner*. https://google.github.io/osv-scanner/

[4] Snyk Ltd. *Reachable vulnerabilities*. https://docs.snyk.io/scan-using-snyk/snyk-open-source/manage-vulnerabilities/reachable-vulnerabilities

[5] Yamaguchi, F. et al. *Modeling and Discovering Vulnerabilities with Code Property Graphs.* IEEE S&P 2014.

[6] GitHub / Semmle. *CodeQL*. https://codeql.github.com/

[7] Shen, X. et al. *Beyond Package-Level: Method-Level Vulnerability Reachability Analysis.* ESE 2025.

---

## Limitations

- Only Java bytecode is analyzed (no Kotlin, Scala, Groovy).
- Reflection, `invokedynamic`, and runtime class loading are not modeled — a NOT_REACHABLE result should be interpreted as a not-affected candidate under the current analysis boundary, not as proof of absence of risk.
- Runtime evidence only covers execution paths in the attached test suite.
- CHA over-approximates polymorphic dispatch — it expands virtual calls to all known subtypes, which may include implementations never instantiated at runtime. The analysis should not be interpreted as a whole-program soundness guarantee: reflection, `invokedynamic`, and dynamic class loading can create call paths invisible to the current static model.
- Light CVE mapping is a best-effort heuristic; all seeds should be reviewed by a security engineer before use in production.
- Single-project analysis only. Ecosystem-scale analysis (Maven Central-wide) would require a persistent graph database backend; the BFS logic is designed to be storage-agnostic.

---

## Prerequisites

| Tool | Minimum version | Purpose |
|---|---|---|
| Python | 3.10+ | Analyzer pipeline |
| Java | 11+ | Call graph extractor + demo apps |
| Maven | 3.6+ | Building JARs |
| PyYAML | any | `pip install pyyaml` |

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
through reflection. The pipeline reports `not_affected_candidate` under the current static model, even though the vulnerable method can be reached at runtime through reflection if the input contains `${jndi:...}`. This demonstrates a known false-negative boundary of the prototype.

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

## Applying the Pipeline to an External Project

The pipeline is not limited to the bundled demo projects. Any Java application can be analysed by providing its compiled JARs directly. This section documents how to apply it to an external codebase and records the common obstacles encountered when doing so, using `christophetd/log4shell-vulnerable-app` — a Spring Boot application widely cited in Log4Shell security research — as a worked example.

### Project Selection Criteria

Three criteria were applied when selecting an external project for validation:

1. **Seed compatibility** — the project must depend on a library version already covered by an existing seed in `data/seeds/`, so no new seed authoring is required.
2. **Active exploit path** — the application must pass user-controlled input into the vulnerable method, creating a statically traceable and runtime-triggerable call path, not merely a transitive dependency with no reachable call site.
3. **Independence** — no shared code or call graph data with the bundled demo projects; the result must come from a fully independent extraction.

`christophetd/log4shell-vulnerable-app` satisfies all three: it depends on `log4j-core:2.14.1` (matched by `data/seeds/CVE-2021-44228.yaml`), its `MainController` passes the `X-Api-Version` HTTP header directly to `logger.info()`, and it shares no code with any bundled demo project.

### Maven Project (Simple Case)

For a standard Maven project, two commands produce all the JARs needed:

```bash
mvn package -DskipTests
mvn dependency:copy-dependencies -DoutputDirectory=target/deps
```

Then pass the application JAR and all dependency JARs to the pipeline:

```bash
python analyzer/pipeline.py \
  --project-jars target/myapp.jar target/deps/*.jar \
  --project-artifact "com.example:myapp:1.0" \
  --cve CVE-2021-44228
```

### Spring Boot / Gradle Project (Fat JAR Extraction)

Spring Boot's default Gradle build produces a **nested JAR**: application classes live in `BOOT-INF/classes/` and dependency JARs in `BOOT-INF/lib/` inside the fat JAR. The ASM-based call graph extractor reads root-level `.class` files and does not recurse into nested JARs, so the fat JAR cannot be passed directly.

Extract its contents first:

```bash
# Build
./gradlew build -x test

# Extract app classes and dependency JARs from the fat JAR
cd build/libs
jar xf myapp.jar
jar cf app-classes.jar -C BOOT-INF/classes .
```

This produces:
- `build/libs/app-classes.jar` — application classes only
- `build/libs/BOOT-INF/lib/*.jar` — all dependency JARs (including the vulnerable library)

Pass both to the pipeline:

```bash
python analyzer/pipeline.py \
  --project-jars build/libs/app-classes.jar build/libs/BOOT-INF/lib/*.jar \
  --project-artifact "com.example:myapp:1.0-SNAPSHOT"
```

### Runtime Evidence Collection (OTel) for External Projects

To reach L4, the application must be run with the OTel Java agent attached and the vulnerable method instrumented. On Windows, use the provided batch script rather than PowerShell redirection (see pitfalls below):

```bat
.\run-christophetd-demo.bat
```

The script starts the app and writes all output to `data/traces/christophetd.log`. Once the app is running, send a request that exercises the vulnerable call path from a second terminal:

```powershell
Invoke-WebRequest -Uri http://localhost:8080/ `
    -Headers @{"X-Api-Version" = '${jndi:ldap://127.0.0.1:1389/test}'} `
    -UseBasicParsing
```

The JNDI payload causes log4j to call `JndiLookup.lookup()`. No LDAP server is required — the connection fails safely, but the OTel agent captures the span. Stop the app with Ctrl+C, then re-run the pipeline with `--trace-log data/traces/christophetd.log`.

### Worked Example: christophetd/log4shell-vulnerable-app

**Step 1 — Clone and fix Gradle/Java compatibility**

```powershell
git clone https://github.com/christophetd/log4shell-vulnerable-app `
    demo-projects/log4shell-vulnerable-app
```

The project targets Gradle 7.3.1, which does not support Java 21. Update `gradle/wrapper/gradle-wrapper.properties`:
```
distributionUrl=https\://services.gradle.org/distributions/gradle-8.8-bin.zip
```

Spring Boot 2.6.x uses Gradle 7.x internal APIs and fails under Gradle 8. Update `build.gradle`:
```groovy
id 'org.springframework.boot' version '2.7.18'
id 'io.spring.dependency-management' version '1.1.4'
```

Spring Boot 2.7.x manages log4j at a patched version. Pin the vulnerable version explicitly:
```groovy
ext['log4j2.version'] = '2.14.1'
```

**Step 2 — Build and extract JARs**

```powershell
cd demo-projects/log4shell-vulnerable-app
.\gradlew build -x test
cd build/libs
jar xf log4shell-vulnerable-app-0.0.1-SNAPSHOT.jar
jar cf app-classes.jar -C BOOT-INF/classes .
cd C:\project\vuln_risk_assessor
```

**Step 3 — Assign JAR paths (required at the start of each new PowerShell session)**

```powershell
$appJar = "demo-projects/log4shell-vulnerable-app/build/libs/app-classes.jar"
$depJars = (Get-ChildItem demo-projects/log4shell-vulnerable-app/build/libs/BOOT-INF/lib/*.jar |
    ForEach-Object { $_.FullName })
```

**Step 4 — Static-only run (produces L3)**

```powershell
python analyzer/pipeline.py `
    --project-jars $appJar $depJars `
    --project-artifact "fr.christophetd.log4shell:log4shell-vulnerable-app:0.0.1-SNAPSHOT" `
    --cve CVE-2021-44228 `
    --output reports/christophetd-log4shell.json `
    --output-vex reports/christophetd-log4shell.vex.json `
    --verbose
```

Expected: `L3  under_investigation  risk=5.0  conf=0.60` — static reachability confirmed, no runtime evidence yet.

**Step 5 — Collect OTel trace and re-run (upgrades to L4)**

In a new terminal, start the app:
```powershell
.\run-christophetd-demo.bat
```

Once the Spring Boot startup banner appears, send a request from the original terminal:
```powershell
Invoke-WebRequest -Uri http://localhost:8080/ `
    -Headers @{"X-Api-Version" = '${jndi:ldap://127.0.0.1:1389/test}'} `
    -UseBasicParsing
```

Stop the app (Ctrl+C in the second terminal), then re-run with the captured trace:
```powershell
python analyzer/pipeline.py `
    --project-jars $appJar $depJars `
    --project-artifact "fr.christophetd.log4shell:log4shell-vulnerable-app:0.0.1-SNAPSHOT" `
    --cve CVE-2021-44228 `
    --trace-log data/traces/christophetd.log `
    --output reports/christophetd-log4shell.json `
    --output-vex reports/christophetd-log4shell.vex.json `
    --verbose
```

Expected output:
```
[CVE-2021-44228]
  [extractor] Processed 29 JAR(s), wrote 222576 edges to callgraph.tmp.txt
  [INFO] Loaded 213911 edges, 2510 CHA type entries
  [INFO] Entry points (1): ['fr.christophetd.log4shell.vulnerableapp.VulnerableAppApplication.main(...)']
  CVE-2021-44228   L4  affected   risk=10.0  conf=0.90  remedy=URGENT
```

### Common Pitfalls

| Problem | Cause | Fix |
|---|---|---|
| `Unsupported class file major version 65` | Gradle 7.x does not support Java 21 | Update `gradle-wrapper.properties` to `gradle-8.8-bin.zip` |
| Spring Boot plugin fails under Gradle 8 | Spring Boot 2.6.x depends on Gradle 7.x internal APIs | Upgrade to `spring-boot:2.7.18` + `dependency-management:1.1.4` in `build.gradle` |
| Spring Boot BOM upgrades log4j to a patched version | Spring Boot 2.7.x manages log4j 2.17.x by default | Add `ext['log4j2.version'] = '2.14.1'` to `build.gradle` |
| `--project-jars: expected at least one argument` | `$appJar` / `$depJars` are lost between PowerShell sessions | Reassign both variables at the start of each new terminal session (Step 3 above) |
| Trace log is unreadable / Python encoding error | PowerShell `*>` writes UTF-16 LE; the runtime analyzer reads UTF-8 | Use `run-christophetd-demo.bat` instead of direct PowerShell stream redirection |
| Extractor finds 0 entry points | Spring Boot fat JAR passed directly; app classes not at JAR root | Extract `BOOT-INF/lib/*.jar` and create `app-classes.jar` from `BOOT-INF/classes/` first |

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
