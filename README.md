# Vulnerability Risk Assessor

A prototype framework for assessing whether known vulnerable methods in Java Maven dependencies are reachable from application code. It combines bytecode-level call graph analysis with runtime OpenTelemetry execution traces to produce a graduated evidence chain (L0–L5), CVSS-weighted exposure scores, and CycloneDX VEX output, structured for EU Cyber Resilience Act (CRA) conformity assessment workflows rather than dependency scanning alone, building on the method-level reachability framing of Shen et al. (ESE 2025).

**What this tool does:**
- Extracts a bytecode-level call graph from application JARs using a custom ASM-based extractor
- Applies BFS reachability with CHA (Class Hierarchy Analysis) to determine whether a vulnerable method is callable from application entry points
- Correlates static reachability with OpenTelemetry runtime evidence to distinguish runtime-observed vulnerable-method execution from statically inferred reachability
- Fuses both evidence types into a six-level evidence ladder (L0–L5) with explicit confidence scores and residual-risk reasoning
- Emits JSON evidence chains and CycloneDX 1.5 VEX documents intended to support CRA vulnerability-handling documentation
- Supports human sign-off via `AuditRecord` (L5), closing the loop from automated detection to auditable decision

---

## Key Result

Across 8 app-CVE evaluation cases covering 4 CVEs and their non-reachable control variants, package-level scanners would report all 8 applications as vulnerable (affected dependency version present). This prototype classified 4 of those findings as statically not reachable from the configured application entry points. Under the proposed reachability-adjusted scoring model, aggregate CVSS-weighted exposure was reduced from 60.2 to 23.2, a 61.5% exposure re-weighting reduction.

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

Expected: `L4  affected  risk=10.0  conf=0.90  remedy=URGENT` (15-hop call path confirmed at runtime).

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
  Software Design Document.pdf   System design, data model, module pseudocode
```

> **Implementation note (SDD vs. actual code):** The SDD (Section 4.1.3) lists WALA, Soot, and SootUp as candidate static analysis frameworks. The implementation instead uses a custom ASM-based call graph extractor (`tools/callgraph-extractor/`) with a lightweight Python BFS engine. This choice was made during implementation to avoid JVM tool startup overhead and to allow precise control over edge types (CALL / EXTENDS / IMPLEMENTS) needed for the annotated call path feature. The design intent, bytecode-level CHA + BFS reachability, is unchanged.

---

## Third-Party Validation

To verify that the pipeline generalises beyond its own demo projects, it was applied to [`christophetd/log4shell-vulnerable-app`](https://github.com/christophetd/log4shell-vulnerable-app), a Spring Boot application widely used in Log4Shell security research, with no shared code or call graph data with the bundled demos.

| | |
|---|---|
| JARs analysed | 29 |
| Call graph edges extracted | 222,576 |
| Static result | REACHABLE (entry point → `JndiLookup.lookup()`) |
| Runtime result | OBSERVED (OTel span captured on JNDI payload request) |
| Final decision | **L4 AFFECTED, risk=10.0, conf=0.90** |

The pipeline produced the same evidence structure as on the bundled demos, from a fully independent extraction. See [Applying the Pipeline to an External Project](#applying-the-pipeline-to-an-external-project) for the full reproduction steps.

To complement this reachable case with a genuine non-reachable one, the pipeline was also applied to a specific historical release of [`yangzongzhuan/RuoYi`](https://github.com/yangzongzhuan/RuoYi) (tag `v4.5.1`), a widely-used open-source Java administration framework. At that tag its `pom.xml` pins `commons-io:2.5` (vulnerable to CVE-2021-29425); the project has since upgraded past the fixed version, so this is a historical snapshot, not a claim about its current security posture. Source is not vendored for this case — see [`demo-projects/ruoyi-external-validation/README.md`](demo-projects/ruoyi-external-validation/README.md) for full provenance and reproduction steps; only the built JARs used as pipeline input are kept in this repo.

| | |
|---|---|
| JARs analysed | 127 (6 module JARs + 121 dependencies) |
| Call graph edges extracted | 874,611 |
| Entry points | `RuoYiApplication.main`, `EscapeUtil.main`, `CommonController.uploadFile` (real file-upload endpoint) |
| Static result | NOT_REACHABLE (only call site into `FilenameUtils` is `getExtension()`, which never reaches `getPrefixLength()`) |
| Final decision | **L2 NOT_AFFECTED_CANDIDATE, risk=0.5, conf=0.595** |

No live runtime instrumentation was captured for this case (RuoYi requires a MySQL-backed deployment); the exhaustive call-site count already gives a stronger guarantee than a runtime trace bounded to whichever payloads happen to be sent.

---

## Evaluation

Package-level scanners over-approximate: they report every (app, CVE) pair where the vulnerable dependency version is present, regardless of whether the vulnerable code path is reachable. The table below tests where method-level reachability narrows that set: for each CVE, one application actively uses the vulnerable method (`vulnerable-*-demo`) and one uses the same dependency version without calling it, serving as a non-reachable control variant (`safe-*-demo`).

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
| Aggregate CVSS-weighted exposure (package-level) | 60.2 (all 8 findings at full CVSS) |
| Aggregate reachability-adjusted exposure (this tool) | 23.2 (CVSS × evidence multiplier) |
| **Exposure re-weighting reduction** | **61.5%** |
| Statically-unreachable findings | 4 / 8 (50%) |
| L4 runtime-confirmed findings | 1 / 8 (Log4Shell with OTel trace) |

> "Reachability analysis reduced aggregate CVSS-weighted exposure by **62%** relative to package-level scanning across our 8-application evaluation dataset, by assigning a residual weight of 0.10 to statically-unreachable findings to account for analysis uncertainty (4 of 8 package-scanner alerts were statically unreachable)."

> **Design note:** The evidence multiplier values (1.00 / 0.50 / 0.10) are design parameters, not CVSS-official standards. The 0.10 residual for NOT_REACHABLE findings is intentionally non-zero: it represents two sources of analysis uncertainty: (1) static analysis does not model reflection, `invokedynamic`, or dynamic class loading; (2) a method unreachable today may become reachable after a future refactor. This metric therefore quantifies *reachability-adjusted exposure re-weighting*, not a reduction in real-world attack probability. The specific multiplier values should be calibrated against a labelled exploit dataset in future work.

---

## Evidence Levels

| Level | Name | Description |
|-------|------|-------------|
| L0 | CVE_EXISTS | CVE is known and has a CVSS score |
| L1 | COMPONENT_ASSESSED | A metadata-based component-version check has been run against the supplied JARs |
| L2 | SEED_IDENTIFIED | The specific vulnerable method has been mapped from the fix commit |
| L3 | STATIC_REACHABLE | A call path from your code to the vulnerable method exists in the call graph |
| L4 | STATIC_RUNTIME_CORROBORATED | Static reachability and a matching runtime observation both hold |
| L5 | AUDITED | A human security engineer has reviewed and confirmed the finding |

> **The six levels are not one single cumulative ladder.** L0-L2 are scope-and-prerequisite facts that are not a dependency chain on each other; L3-L4 are application-specific evidence that genuinely is cumulative (L4 requires L3); L5 is a human-review overlay distinct from either. In particular, **L1 does not mean "component present."** It means a metadata-based check has been *run* — the outcome can be `IN_RANGE`, `OUT_OF_RANGE`, or `INCONCLUSIVE` (see [L1 component check](#l1-component-check) below), and reaching L1 says nothing by itself about which of the three it was. A validated seed records which package and version range a CVE affects *in general*; it says nothing about whether the specific project being analysed actually depends on an affected version, which is exactly the gap this check closes.
>
> **L2 in NOT_REACHABLE findings**: when a finding carries `evidence_level: 2`, it means the seed method was successfully identified (SEED_IDENTIFIED) but no call path from the application entry points to that method was found in the static call graph. The decision `not_affected_candidate` is therefore a statement about the *absence of a static path*, not a confirmed absence of risk.
>
> **`evidence_level` is not a pure "how worried should I be" scale.** It records how far a finding progressed through the required sequence, not the finding's overall risk. Two `evidence_level: 2` findings can carry very different risk: an ordinary NOT_REACHABLE finding (`not_affected_candidate`, risk multiplier 0.10) versus the static/runtime conflict case below (`under_investigation`, risk multiplier 0.50) -- both stay at L2 because runtime evidence without a corresponding static path can't be certified as having passed through L3, but they represent very different levels of concern. `decision` and `risk_score` carry that prioritisation; `decision_confidence` separately records how strong the supporting evidence is. Read all three, not `evidence_level` alone.

### CVE Coverage

| CVE | Component | Vulnerable Method | Call Depth | Demo Result |
|-----|-----------|-------------------|------------|-------------|
| CVE-2021-44228 (Log4Shell) | log4j-core 2.14.1 | `JndiLookup.lookup()` | 15 hops | L4 AFFECTED (risk=10.0) |
| CVE-2021-29425 | commons-io 2.6 | `FilenameUtils.getPrefixLength()` | 3 hops | L3 UNDER_INVESTIGATION (risk=2.4) |
| CVE-2018-1002200 (Zip-Slip) | plexus-archiver 3.5 | `AbstractUnArchiver.extractFile()` | 4 hops | L3 UNDER_INVESTIGATION (risk=2.8) |
| CVE-2022-42889 (Text4Shell) | commons-text 1.9 | `StringSubstitutor.replace()` | 2 hops | L3 UNDER_INVESTIGATION (risk=4.9) |

---

## Decision Rules

| Static | Runtime | Decision | Evidence Level |
|--------|---------|----------|----------------|
| *(component check resolves OUT_OF_RANGE — see [L1 component check](#l1-component-check))* | not run | not_affected_candidate | **L1** |
| REACHABLE | OBSERVED | affected | L4 |
| REACHABLE | NOT_OBSERVED | likely_affected | L3 |
| REACHABLE | NOT_RUN / absent | under_investigation | L3 |
| NOT_REACHABLE | OBSERVED | under_investigation *(static/runtime conflict — see below)* | L2 |
| NOT_REACHABLE | NOT_OBSERVED / NOT_RUN / absent | not_affected_candidate | L2 |
| UNKNOWN | OBSERVED | under_investigation *(runtime-only positive — see below)* | L2 |
| UNKNOWN | NOT_OBSERVED / NOT_RUN / absent | under_investigation | L2 |
| absent | OBSERVED | under_investigation *(runtime-only positive — see below)* | L2 |
| absent | NOT_OBSERVED / NOT_RUN / absent | under_investigation | L2 |

> `REACHABLE` / `NOT_REACHABLE` are the result of the static call-graph model under the current analysis scope (see [Limitations](#limitations)), not a general claim about the deployed application's real-world exposure.

**Risk score** = CVSS base score × evidence multiplier (L4 affected=1.0, L3 likely=0.75, L3/L2 under_investigation=0.50, L2 not_affected_candidate=0.10, L1 not_affected_candidate=0.05). The multiplier is keyed on (decision, evidence level) together, not on evidence level alone — both `under_investigation` and `not_affected_candidate` can appear at L2 with different multipliers, since they represent different evidence, not different levels. The L1 multiplier is lower than L2's 0.10 because it reflects a narrower residual uncertainty (component_check.py's own version-comparator limitations — see below) rather than the broader "static analysis can't see reflection/invokedynamic" reasoning behind the L2 value.

**Remediation priority** = URGENT (affected) / RECOMMENDED (likely_affected, the NOT_REACHABLE+OBSERVED conflict case, and the UNKNOWN/absent+OBSERVED runtime-only-positive cases above) / MONITOR (others)

---

## Key Design Decisions

**CHA (Class Hierarchy Analysis)** is used during BFS to handle polymorphic dispatch. When a call to `Logger.error()` (an interface method) is encountered, the BFS is expanded to include all known concrete implementations. The CHA closure is computed via BFS over both EXTENDS and IMPLEMENTS edges. Interface-extends-interface relationships are stored as IMPLEMENTS edges in ASM bytecode, not as EXTENDS.

**Upward method resolution**: When bytecode contains `INVOKEVIRTUAL ZipUnArchiver.extract()`, the call graph extractor records the static receiver type, but `ZipUnArchiver` may not define `extract()`; it may be inherited from `AbstractUnArchiver`. The analyzer walks up the EXTENDS chain when a method has no outgoing edges to find the declaring superclass.

**Entry point filtering**: The `--project-artifact` groupId is used as a Java package prefix to restrict BFS entry points to application-owned classes only. Without this, library tool classes (e.g. `log4j-core`'s own `Version.main`) would be treated as entry points and inflate reachability results.

**Annotated call path**: Each hop in the call path is tagged with its edge type (`CALL`, `CHA_EXPANSION[X->Y]`, `INHERITED`, `ENTRY_POINT`), making it auditable which steps relied on conservative CHA assumptions versus direct bytecode edges.

**NOT_OBSERVED != NOT_REACHABLE**: Runtime evidence only covers the execution paths taken in the test suite. `NOT_OBSERVED` means the method was not seen in the observed runs, not that it is unreachable. The OTel agent's `VersionLogger` startup line is used to distinguish `NOT_OBSERVED` (agent ran, method not called) from `NOT_RUN` (agent was not attached at all).

**Static/runtime conflict detection**: if static analysis reports NOT_REACHABLE but runtime evidence shows the seed method OBSERVED executing anyway, `fusion.py` does not let the static result silently win. This combination is flagged as `under_investigation` (not `not_affected_candidate`) with an explicit `CONFLICT:` note, and `remediation.py` raises its priority to `RECOMMENDED` rather than the default `MONITOR` — because two independently-produced evidence sources actively disagreeing is itself a stronger signal that something needs review than an ordinary "haven't tested yet" finding, regardless of which of the two sources turns out to be right. Confidence for this case is `min(static.confidence, runtime.confidence) * 0.7`: neither source is assumed more trustworthy than the other going in (runtime's own confidence is itself tiered by match quality — see below — not an infallible direct measurement), so the formula anchors on whichever of the two is currently the more uncertain, then discounts further for the disagreement itself. In practice this combination is the signature of a static-model blind spot (reflection, dynamic proxy, or other dispatch invisible to CHA+BFS); see the [reflection false negative demo](#reflection-false-negative-demo-expected-not_reachable-known-analysis-limitation) below for a worked example.

**Runtime-only positive evidence**: a distinct case from the conflict above — static evidence is `UNKNOWN` (no entry points could be identified) or absent entirely (no static analysis was run), but runtime still reports `OBSERVED`. Earlier versions of `fusion.py` fell through both of these branches without ever inspecting `runtime.status`, so a genuine positive runtime observation was silently discarded and the finding scored as if no evidence existed at all (confidence 0.50 or 0.30, same as if runtime had never run). This is now handled explicitly: confidence is `runtime.confidence * 0.7` (not `min(static.confidence, runtime.confidence)`, since `UNKNOWN` carries confidence 0.0 by construction and would zero out a genuine observation), `remediation.py` raises priority to `RECOMMENDED`, and the finding's notes record that runtime observed execution despite static evidence being absent or inconclusive — distinct wording from the `CONFLICT:` note above, since there is no static result here to actively disagree with.

**L1 component check**: before static or runtime analysis runs at all, `pipeline.py` calls `component_check.py::check_component_present()` to check whether the project's own JARs actually carry the seed's vulnerable component at a version inside `vulnerable_range`, by reading embedded Maven coordinates (`META-INF/maven/<groupId>/<artifactId>/pom.properties`) from every supplied JAR whose Maven packaging process retained that metadata — a check bounded to the JARs actually supplied to the pipeline, not a resolved Maven/Gradle dependency tree. This closes a real gap: earlier versions of this pipeline went straight from a validated seed to static analysis, implicitly trusting that whoever supplied `--project-jars` had already confirmed the vulnerable component was actually present at an affected version — `L1_COMPONENT_ASSESSED` was defined in the `EvidenceLevel` enum from the start but no code path ever independently produced it. The check returns a `ComponentCheckStatus`, not a present/absent boolean:
- **`OUT_OF_RANGE`** — every JAR carrying matching coordinates was confirmed at a version outside `vulnerable_range`. `fusion.py::fuse_component_absent()` short-circuits directly to an `L1 not_affected_candidate` finding; static/runtime analysis is skipped, since under the seed's package-and-version model an exact coordinate match outside the declared range makes method-level analysis for that seeded vulnerability unnecessary. The finding stays a *candidate*, not a plain `not_affected`, because this metadata check cannot exclude a repackaged or relocated copy of the vulnerable code under different coordinates.
- **`IN_RANGE`** — at least one matching JAR's version falls inside `vulnerable_range`. Analysis proceeds exactly as before, through static/runtime analysis and `fusion.py::_decide()`.
- **`INCONCLUSIVE`** — no JAR with matching Maven coordinates was found at all (e.g. a non-Maven build, or a shaded JAR with its coordinate metadata stripped), *or* a matching JAR's version could not be confidently compared against `vulnerable_range` (see the comparator note below). Also proceeds exactly as before. This is deliberate: neither missing metadata nor an unparseable version is the same claim as the component being absent, so an inconclusive check must never be treated as a confident negative.

Neither the resolved status nor the evidence behind it is discarded once the pipeline moves past this check. Every report carries a top-level `"component"` object — `{"status": ..., "matches": [{"jar": ..., "version": ...}, ...]}` — mirroring the `"static"`/`"runtime"` objects already in the report, for every finding, not just the `OUT_OF_RANGE` short-circuit case: a reviewer can always see which JAR(s) and version(s) the L1 check actually found, even for a finding that went on to `AFFECTED` via static/runtime evidence. Earlier versions of this pipeline only attached a bare status string to the finding (nothing at all for the OUT_OF_RANGE case beyond free-text `notes`), which fell short of the full-object, fully-auditable pattern `StaticEvidence`/`RuntimeEvidence` already use. `evidence_summary.component_check_status` (a convenience copy of `component.status`) and `evidence_summary.dependency_match` are still present alongside the full `"component"` object. `dependency_match` is deliberately three-valued, not a plain boolean: `true` only for a confirmed `IN_RANGE` match, `false` only for a confirmed `OUT_OF_RANGE` match, and `null` for `INCONCLUSIVE` (checked, but nothing confirmed either way) as well as for a chain with no component check at all — collapsing "confirmed present" and "not confirmed absent" into the same `true` would let a machine consumer read an unconfirmed component as a confirmed one.

Every JAR carrying matching coordinates is checked, not just the first one found — a classpath can genuinely contain more than one version of the same component (e.g. a patched direct dependency alongside an old vendored copy bundled inside a third-party JAR), and an earlier version of this check risked a false `OUT_OF_RANGE` verdict by only inspecting the first match. The combination rule across all matches: any `IN_RANGE` match wins outright; failing that, any unparseable match forces `INCONCLUSIVE`; only when every match is confirmed out of range, with none ambiguous, does the check resolve `OUT_OF_RANGE`.

The version comparator (`_compare_versions`/`_version_satisfies_range`) is a deliberately narrow implementation, not a full Maven `ComparableVersion` algorithm. Two numeric segments are compared numerically; two qualifier segments (an alphabetic prefix plus an optional numeric suffix, e.g. `"beta9"` → `("beta", 9)`) are compared numerically on that suffix when their prefixes match, which is enough to correctly order `"beta2"` before `"beta10"` — a case plain lexical string comparison gets backwards. Two qualifiers with *different* prefixes (e.g. `"beta9"` vs `"rc1"`) would need Maven's own qualifier-ordering table (`alpha < beta < milestone < rc < snapshot < (release) < sp`) to resolve correctly; rather than guess via string order, this comparator fails open and reports the comparison as unparseable, which propagates to `INCONCLUSIVE` rather than a silently-possibly-wrong verdict. This is why the L1 `OUT_OF_RANGE` multiplier (0.05) is non-zero rather than treating that outcome as absolute proof of safety: the residual reflects a relocated/shaded copy under non-matching coordinates, which a metadata-only check cannot see at all.

**Light CVE mapping** parses git diff hunk headers (`@@ -a,b +c,d @@ function_context`) to identify which method was modified in the fix commit. This is more reliable than scanning for `+` lines alone because the hunk header names the enclosing function even when the fix is purely additive (no removed lines).

---

## CRA Compliance Notes

This prototype is designed to produce technical evidence that may support EU Cyber Resilience Act (CRA) conformity assessment workflows:

- **`analysis_fingerprint`** makes each report reproducible: given the same callgraph file and seed, the result is verifiable.
- **`--output-vex`** produces a CycloneDX 1.5 VEX document. VEX is a machine-readable format for communicating per-CVE exploitability status and can support vulnerability management and conformity-assessment workflows. `analysis.state` is deliberately not a direct decision-name rename: `not_affected_candidate` maps to `in_triage`, not CycloneDX's `not_affected`, since `not_affected`'s own specification asserts unconditional non-affection and requires a justification, a stronger claim than a hedged candidate finding is designed to make. `mitigated` is the only decision that reaches `not_affected`, and gets an explicit `analysis.justification: "protected_by_mitigating_control"` — no other decision does, since none of CycloneDX's other justification values accurately describe what this system's bounded evidence supports.
- **`AuditRecord`** (populated at L5) captures reviewer identity, timestamp, justification, and waiver expiry, together with a snapshot of the pre-audit decision, evidence level, risk score, and confidence: audit metadata that may be relevant to conformity assessment, letting a reviewer's change be reconstructed from the report alone rather than requiring separate before/after file versioning. `audit.py` distinguishes **confirmation** from **override**: a reviewer *confirming* the existing automated decision (no `--decision-override`, or one naming the same decision) raises that decision's own confidence by a flat 0.20, capped at 0.98, same as before. A genuine **override** (`--decision-override` naming a *different* decision) does not inherit the replaced decision's confidence via that same formula — the old confidence was evidence for the conclusion just discarded, not the new one. Confidence in an override instead comes from `--reviewer-confidence` if supplied, or a fixed 0.90 default otherwise.
- **`generated_at`** on a report containing an L4 AFFECTED finding can support time-sensitive vulnerability management and regulatory reporting workflows.
- **`evidence_terms`** in seed candidate output are drawn from a predefined, CWE-keyed vocabulary, not a machine-learning model. Every term is traceable to a specific keyword match in the diff, supporting independently verifiable conformity evidence.

> This prototype does not determine CRA compliance and is not a substitute for legal, regulatory, or accredited conformity assessment.

### Seed pipeline reproducibility boundary

The analysis pipeline (`pipeline.py` → `static_analyzer.py` → `fusion.py`) is **fully local and reproducible**: given the same `data/seeds/*.yaml`, call graph cache, and trace log, the output is deterministic and verifiable without any network calls.

`seed_ingestor.py` (and `light_cvemapping.py`) operate **upstream** of this boundary: they are offline preparation tools for creating new seeds, not part of the runtime analysis. Their outputs (`candidate_methods`) require human validation before promotion to `vulnerable_methods` in a trusted seed file. This validation step is enforced by convention:

- `candidate_methods` ≠ `vulnerable_methods`: the pipeline only reads `vulnerable_methods`
- `requires_manual_validation: true` is an explicit machine-readable assertion in every candidate output
- `status: NEEDS_VALIDATION` must be manually changed to `VALIDATED` by a security engineer

External API calls (OSV, GitHub) only occur during seed preparation, never during analysis. A conformity assessor auditing a report can reproduce it from the seed files and call graph alone, without network access.

---

## Related Work

Existing tools for open-source dependency vulnerability management fall into two broad categories: package-level scanners and method-level static analyzers. This work sits between them and adds an explicit runtime evidence tier to the prototype's evidence model.

| Tool | Analysis level | Reachability | Runtime trace | VEX output | Audit chain | CRA-oriented evidence |
|------|---------------|-------------|--------------|------------|-------------|----------------------|
| OWASP Dependency-Check [1] | Package (JAR) | None | – | – | – | – |
| GitHub Dependabot [2] | Package | None | – | – | – | – |
| Google OSV-Scanner [3] | Package | None | – | – | – | – |
| Snyk (paid tier) [4] | Package + partial method | Static (limited, Java) | – | – | – | – |
| Joern [5] | Method (CPG) | Custom QL queries | – | – | – | – |
| CodeQL [6] | Method (data flow) | Taint tracking | – | SARIF | – | – |
| **This work** | **Method (bytecode BFS+CHA)** | **Static + Runtime (OTel)** | **✓** | **CycloneDX 1.5 VEX** | **✓ (L5)** | **✓** |

**Package-level scanners** (Dependency-Check, Dependabot, OSV-Scanner) flag every dependency version that appears in a vulnerability database, regardless of whether the vulnerable code path is reachable from the application. Our 8-case evaluation matrix shows that 4 of 8 such alerts are statically unreachable, a 50% over-approximation rate on this dataset.

**Snyk** provides reachability analysis for some ecosystems and vulnerability patterns (paid tier). Its implementation details, evidence model, and audit trail are platform-specific and not directly reproducible in this prototype's sense; it produces neither VEX output nor an audit chain structured for CRA conformity assessment.

**Joern** [5] and **CodeQL** [6] operate at method or data-flow level and can express reachability as custom queries. Both require non-trivial per-CVE query authoring, produce no VEX output, and are not structured for CRA conformity assessment. CodeQL produces SARIF rather than VEX-style exploitability statements; additional transformation would be required for VEX-oriented vulnerability status reporting.

This work differs along four axes: (1) it combines static BFS reachability with runtime OpenTelemetry trace evidence under a unified L0–L5 evidence ladder, addressing a limitation discussed by Shen et al.: determining whether vulnerable conditions are satisfied often requires dynamic information, which is difficult to obtain at scale; (2) CHA is applied explicitly via BFS over both EXTENDS and IMPLEMENTS edges, covering interface-extends-interface chains that Shen et al. identify as a precision gap in prior work; (3) it produces CycloneDX 1.5 VEX output, carrying a per-finding `analysis.justification` where CycloneDX's own vocabulary has an accurate value for it (currently `mitigated` findings only, via `protected_by_mitigating_control`), alongside the underlying `residual_risk_reason` retained in the full JSON report; (4) the `AuditRecord` structure and `analysis_fingerprint` are designed to support independently verifiable conformity evidence in CRA-oriented workflows. The scope of this work is complementary to Shen et al. [7]: they study vulnerability propagation breadth across 1,280 real client projects (ecosystem scale); this work focuses on depth and compliance auditability for a single project under analysis.

**References**

[1] OWASP Foundation. *OWASP Dependency-Check*. https://owasp.org/www-project-dependency-check/

[2] GitHub. *Dependabot documentation*. https://docs.github.com/en/code-security/dependabot

[3] Google. *OSV-Scanner*. https://google.github.io/osv-scanner/

[4] Snyk Ltd. *Reachable vulnerabilities*. https://docs.snyk.io/scan-using-snyk/snyk-open-source/manage-vulnerabilities/reachable-vulnerabilities

[5] Yamaguchi, F. et al. *Modeling and Discovering Vulnerabilities with Code Property Graphs.* IEEE S&P 2014.

[6] GitHub / Semmle. *CodeQL*. https://codeql.github.com/

[7] Shen, Y., Gao, X., Sun, H., Guo, Y. *Understanding vulnerabilities in software supply chains.* Empirical Software Engineering, 30(1), Article 20, 2025.

---

## Limitations

- Only Java bytecode is analyzed (no Kotlin, Scala, Groovy).
- Reflection, `invokedynamic`, and runtime class loading are not modeled. A NOT_REACHABLE result should be interpreted as a not-affected candidate under the current analysis boundary, not as proof of absence of risk.
- Runtime evidence only covers execution paths in the attached test suite.
- CHA over-approximates polymorphic dispatch: it expands virtual calls to all known subtypes, which may include implementations never instantiated at runtime. The analysis should not be interpreted as a whole-program soundness guarantee: reflection, `invokedynamic`, and dynamic class loading can create call paths invisible to the current static model.
- Light CVE mapping is a best-effort heuristic; all seeds should be reviewed by a security engineer before use in production.
- Single-project analysis only. Ecosystem-scale analysis (Maven Central-wide) would require a persistent graph database backend; the BFS logic is designed to be storage-agnostic.
- Seed matching is exact on fully-qualified class name, method name, and JVM descriptor, with a narrow fallback for simple Maven package relocation (e.g. `maven-shade-plugin` relocations, which rewrite only the package prefix): if the FQCN does not match but the simple class name, method name, and descriptor do, the match is reported as `REACHABLE` at reduced confidence (0.6) and flagged as `relocated_package_suspected` in `uncertain_features`. Genuine class renaming or obfuscation is not detected; that would require bytecode-level clone detection, which is out of scope.
- CVEs whose fix is a configuration change rather than a code change (no vulnerable method exists to seed) are recognized but not yet scored: a seed YAML can declare `fix_type: configuration_only`, which `load_seed()` reports as an explicit out-of-scope case rather than a malformed file, but the pipeline does not yet produce a package-level evidence path for these.

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

### Step 1: Install Python dependency

```bash
pip install pyyaml
```

### Step 2: Build the call graph extractor

```bash
cd tools/callgraph-extractor
mvn package -q
# Produces: target/callgraph-extractor-1.0.jar
```

### Step 3: Build a demo project

```bash
cd demo-projects/vulnerable-log4j-demo
mvn package -q
mvn dependency:copy-dependencies -DoutputDirectory=target/dependency -q
```

### Step 4: Run the risk assessment pipeline

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
| `--project-artifact` | recommended | Maven `groupId:artifactId` (filters entry points to your code only) |
| `--callgraph-cache` | no | Reuse a previously extracted call graph (skips Java extraction) |
| `--trace-log` | no | OTel span log from `collect_traces.py` (enables L4 evidence) |
| `--output` | no | Path for JSON report (default: `reports/<artifact>.json`) |
| `--output-vex` | no | Path for CycloneDX 1.5 VEX document (CRA conformity output) |
| `--cve` | no | Restrict analysis to specific CVE IDs |
| `--extra-entry-points` | no | Additional BFS entry points (e.g. servlet handlers) |

### Step 5: Collect runtime traces (Log4Shell only)

```bash
python scripts/collect_traces.py
# Writes: data/traces/run1.log (JNDI payload), data/traces/run2.log (benign)
```

Then re-run the pipeline with `--trace-log data/traces/run1.log` to upgrade to L4.

### Step 6: Semi-automated seed extraction from a fix commit

`light_cvemapping.py` is a **candidate generator**, not an automatic seed generator.
Output goes into `candidate_methods:`, a separate block from `vulnerable_methods:`.
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
| `--advisory` | Advisory IDs or URLs (GHSA-xxx, https://...), space-separated |
| `--package` | Java package prefix to filter candidates (reduces noise for large commits) |
| `--output` | Write YAML to file; if omitted, prints to stdout |

**Output structure:**

```yaml
candidate_methods:          # NOT vulnerable_methods, requires manual promotion
  - fqcn: org.apache.logging.log4j.core.lookup.JndiLookup
    method: lookup
    descriptor: null        # always null, requires manual JVM type resolution
    descriptor_hint: "(?Ljava/lang/String;)Ljava/lang/String;"  # best-effort; ? = unknown type
    patch_semantic: method_deleted
    evidence_terms: [jndi, lookup]
    confidence: high
    reason: "Method was deleted by the security patch. Security-relevant terms in diff: jndi, lookup."
```

---

## Running the Demo Projects

### Vulnerable apps (expected: REACHABLE)

**Log4Shell** (L4, runtime observed):
```bash
python analyzer/pipeline.py \
  --project-jars demo-projects/vulnerable-log4j-demo/target \
  --project-artifact com.example:log4j-demo \
  --callgraph-cache data/callgraph-log4j.txt \
  --trace-log data/traces/run1.log \
  --output reports/log4j.json \
  --output-vex reports/log4j.vex.json
```

**Text4Shell** (L3, static reachable, no trace):
```bash
python analyzer/pipeline.py \
  --project-jars demo-projects/vulnerable-text4shell-demo/target \
  --project-artifact com.example:vulnerable-text4shell-demo \
  --callgraph-cache data/callgraph-text4shell-vuln.txt \
  --output reports/text4shell-vuln.json --cve CVE-2022-42889
```

**Zip-Slip** (L3, static reachable, no trace):
```bash
python analyzer/pipeline.py \
  --project-jars demo-projects/plexus-demo/target \
  --project-artifact com.example:plexus-demo \
  --callgraph-cache data/callgraph-plexus.txt \
  --output reports/plexus.json
```

**commons-io** (L3, static reachable, no trace):
```bash
python analyzer/pipeline.py \
  --project-jars demo-projects/commons-io-demo/target \
  --project-artifact com.example:commons-io-demo \
  --callgraph-cache data/callgraph-commons-io.txt \
  --output reports/commons-io.json
```

### Safe apps (non-reachable control variants): same dep version, different code path (expected: NOT_REACHABLE)

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

### Reflection false negative demo (expected: NOT_REACHABLE, known analysis limitation)

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

**With a captured runtime trace, this blind spot is caught rather than silently absorbed.**
Attaching the OTel agent to this same demo and sending the JNDI payload through the reflective
call path (`Class.forName` + `Method.invoke`) produces a span for `JndiLookup.lookup()` even
though no static path was found:

```bash
java -javaagent:tools/otel/opentelemetry-javaagent-1.32.0.jar \
  -Dotel.service.name=vuln-demo-reflection \
  -Dotel.traces.exporter=logging -Dotel.metrics.exporter=none -Dotel.logs.exporter=none \
  -Dotel.instrumentation.methods.include=org.apache.logging.log4j.core.lookup.JndiLookup[lookup] \
  -cp "demo-projects/reflection-log4j-demo/target/reflection-log4j-demo-1.0-SNAPSHOT.jar;demo-projects/reflection-log4j-demo/target/dependency/*" \
  com.example.App '${jndi:ldap://127.0.0.1/x}' \
  > data/traces/reflection-run1.log 2>&1

python analyzer/pipeline.py \
  --project-jars demo-projects/reflection-log4j-demo/target \
  --project-artifact com.example:reflection-log4j-demo \
  --callgraph-cache data/callgraph-reflection-log4j.txt \
  --trace-log data/traces/reflection-run1.log \
  --output reports/reflection-log4j.json --cve CVE-2021-44228
```

Expected: `L2  under_investigation  risk=5.0  conf=0.49  remedy=RECOMMENDED`, with the report's
`notes` field carrying an explicit conflict message: *"CONFLICT: static analysis found no path but
the seed method executed at runtime -- static analysis may have missed a path (reflection/dynamic
dispatch suspected)."* The fusion engine (`fusion.py::_decide`) treats a static/runtime
disagreement as a signal requiring review rather than letting the NOT_REACHABLE static result
silently override direct execution evidence, and `remediation.py` raises this case's priority
above the default MONITOR given to an ordinary "haven't tested yet" UNDER_INVESTIGATION finding.
This case is reported separately from the 8-case evaluation matrix above: it demonstrates evidence
fusion catching a single-source blind spot, a different property from that matrix's
vulnerable/safe discrimination test.

### Reachability-adjusted exposure metric

```bash
python scripts/risk_reduction.py
```

---

## Applying the Pipeline to an External Project

The pipeline is not limited to the bundled demo projects. Any Java application can be analysed by providing its compiled JARs directly. This section documents how to apply it to an external codebase and records the common obstacles encountered when doing so, using `christophetd/log4shell-vulnerable-app`, a Spring Boot application widely cited in Log4Shell security research, as a worked example.

### Project Selection Criteria

Three criteria were applied when selecting an external project for validation:

1. **Seed compatibility**: the project must depend on a library version already covered by an existing seed in `data/seeds/`, so no new seed authoring is required.
2. **Active exploit path**: the application must pass user-controlled input into the vulnerable method, creating a statically traceable and runtime-triggerable call path, not merely a transitive dependency with no reachable call site.
3. **Independence**: no shared code or call graph data with the bundled demo projects; the result must come from a fully independent extraction.

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
- `build/libs/app-classes.jar`: application classes only
- `build/libs/BOOT-INF/lib/*.jar`: all dependency JARs (including the vulnerable library)

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

The JNDI payload causes log4j to call `JndiLookup.lookup()`. No LDAP server is required; the connection fails safely, but the OTel agent captures the span. Stop the app with Ctrl+C, then re-run the pipeline with `--trace-log data/traces/christophetd.log`.

### Worked Example: christophetd/log4shell-vulnerable-app

**Step 1: Clone and fix Gradle/Java compatibility**

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

**Step 2: Build and extract JARs**

```powershell
cd demo-projects/log4shell-vulnerable-app
.\gradlew build -x test
cd build/libs
jar xf log4shell-vulnerable-app-0.0.1-SNAPSHOT.jar
jar cf app-classes.jar -C BOOT-INF/classes .
cd C:\project\vuln_risk_assessor
```

**Step 3: Assign JAR paths (required at the start of each new PowerShell session)**

```powershell
$appJar = "demo-projects/log4shell-vulnerable-app/build/libs/app-classes.jar"
$depJars = (Get-ChildItem demo-projects/log4shell-vulnerable-app/build/libs/BOOT-INF/lib/*.jar |
    ForEach-Object { $_.FullName })
```

**Step 4: Static-only run (produces L3)**

```powershell
python analyzer/pipeline.py `
    --project-jars $appJar $depJars `
    --project-artifact "fr.christophetd.log4shell:log4shell-vulnerable-app:0.0.1-SNAPSHOT" `
    --cve CVE-2021-44228 `
    --output reports/christophetd-log4shell.json `
    --output-vex reports/christophetd-log4shell.vex.json `
    --verbose
```

Expected: `L3  under_investigation  risk=5.0  conf=0.60` (static reachability confirmed, no runtime evidence yet).

**Step 5: Collect OTel trace and re-run (upgrades to L4)**

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
  "generated_at": "2026-08-07T14:05:51.703179Z",
  "findings": [
    {
      "cve": "CVE-2021-44228",
      "evidence_level": 4,
      "evidence_summary": {
        "component_check_status": "in_range",
        "dependency_match": true,
        "static_reachable": true,
        "runtime_observed": true,
        "entry_points": ["com.example.App.main(...)"],
        "call_path_depth": 15,
        "trace_ids": ["50b93a0c..."]
      },
      "component": {
        "status": "in_range",
        "matches": [{"jar": "demo-projects/vulnerable-log4j-demo/target/dependency/log4j-core-2.14.1.jar", "version": "2.14.1"}]
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

## AI Assistance Disclosure

AI tools, including Claude, were used during this project as development aids for code drafting, debugging support, documentation editing, and implementation planning.

The research question, system design, evidence model, evaluation methodology, and interpretation of results were conceived and directed by the author. All generated code and text were manually reviewed, tested, revised, and integrated by the author.

This project's implementation was developed with AI coding assistance. This reflects tool-assisted implementation activity, not academic co-authorship or independent project ownership.

AI assistance should therefore be understood as tool-supported implementation assistance, not as independent authorship or a substitute for human design, validation, or academic responsibility.
