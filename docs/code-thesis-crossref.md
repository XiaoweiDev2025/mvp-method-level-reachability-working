# Code ↔ Thesis cross-reference (walkthrough checklist)

Study aid for the code-audit sessions: for each code file, the thesis section(s) that describe it, the
specific things to cross-check between code and prose, and a box to tick when covered. Walk the files in
the order below (runtime execution flow), not directory order. Thesis section numbers are from Chapter 3
(Methodology): 3.1.x = design rationale, 3.2.x = implementation detail. Chapter numbers refer to
`Thesis_template.tex` on the Desktop.

For every file: as we read it, also read how the thesis frames it, and flag any place where the code now
does something the prose does not describe (this session found several such drifts already).

**Status: every file below has now been walked at least twice** — once for the original code/thesis
pairing walkthrough, once for a full docstring-accuracy audit, and once for a code-redundancy/design-
consistency audit. See **Audit History** at the bottom for what each pass actually found. Checkboxes below
are ticked for items verified consistent as of the most recent pass; re-open (untick) any item touched by a
future code change.

---

## 0. `models.py` — the shared vocabulary (read first)

The dataclasses and enums every other module passes around. No single thesis section "is" models.py;
its pieces are described wherever the concept they carry is introduced.

- [x] `EvidenceLevel` (L0–L5 enum) ↔ **3.1.3 The Evidence Ladder** (`sec:evidence_ladder`) — the six levels
  and the "not one cumulative axis" framing.
- [x] `ComponentCheckStatus` / `ComponentEvidence` ↔ **3.1.3** (L1 component check part).
- [x] `StaticEvidence` fields (status, confidence, call_path, call_path_annotated, residual_risk_reason) ↔
  **3.1.4 Static Reachability Analysis Design** (`sec:static`). Audited 2026-08-14: the field that actually
  carries reflection/invokedynamic/dynamic-class-loading gaps is `residual_risk_reason`, not
  `uncertain_features` — both `models.py` and `static_analyzer.py` docstrings wrongly claimed the latter
  until fixed; the thesis text itself was already correct (§3.1.4 line ~414).
- [x] `RuntimeEvidence` (status, confidence, trace_ids, test_environment) ↔ **3.1.5 Runtime Evidence
  Design** (`sec:runtime`).
- [x] `EvidenceChain`, `Decision` enum, risk score ↔ **3.1.6 Evidence Fusion and Scoring**
  (`sec:evidence_fusion_and_scoring`).
- [x] `AuditRecord` (+ `reviewer_confidence`) ↔ **3.1.7 CRA-Aligned Output Design** (`sec:output_design`).
- [x] The fully worked `to_dict()` output ↔ **Appendix B** (byte-accurate JSON example). Note:
  `EvidenceChain.audit_record`/`audit_history` are real dataclass fields with a `to_dict()` projection, but
  no constructor call in the current codebase (`fusion.fuse()`, `fuse_component_absent()`) ever populates
  them — the actual audit read-modify-write path (`audit.py`) works entirely on raw JSON dicts and never
  reconstructs an `EvidenceChain` object. Not a bug, just two representations of the same audit data that
  currently never intersect at runtime; worth knowing for viva if asked about the audit data flow.

## 1. `pipeline.py` — entry point / orchestration

- [x] `assess_cve()` control flow (L1 first, short-circuit on OUT_OF_RANGE, else static→runtime→fusion) ↔
  **3.1.2 System Overview** (`sec:sys_overview`, incl. Figure 3.1) and **3.2.1 Pipeline and Module Map**
  (`sec:pipeline`). Module docstring's numbered step list was missing the L1 check and remediation steps;
  fixed 2026-08-14 (was 6 steps, now 7).
- [x] `run()` batch loop, `generated_at`, batch summary ↔ **3.2.1**. The report's `summary` block only
  counted 3 of 6 `Decision` values (`affected`/`not_affected_candidate`/`under_investigation`), silently
  dropping `likely_affected`/`fixed`/`mitigated` from the count — fixed 2026-08-14 to cover all six.
  Additive-only JSON change; neither README nor thesis Appendix B show the `summary` block, so nothing
  downstream needed updating.
- [x] `write_vex()` + `_VEX_STATE_MAP` / `_VEX_JUSTIFICATION` ↔ **3.1.7** (VEX mapping) and **3.2.6 Report
  and VEX Generation** (`sec:report_generation`). Cross-checked the exact state map against the prose
  (`fixed`→`resolved`, `not_affected_candidate`→`in_triage`, `mitigated`→`not_affected`+justification) —
  matches; `test_pipeline.py`'s VEX mapping test also passes for all six decisions.

## 2. `seed_loader.py` — seed model & matching

- [x] `Seed` / `SeedPackage` / `VulnerableMethod` dataclasses, required-field validation ↔ **3.2.2 Seed
  Model and Matching Logic** (`sec:seed`).
- [x] `OutOfScopeSeedError` for config-only-fix CVEs ↔ **3.2.2** and **3.1.9 Applicability** (`sec:applicability`,
  the "third class: no seed method" case).
- [x] Single `group_id`/`artifact_id` per seed (multi-artifact advisory limitation) ↔ **6.3 Limitations**
  (Chapter 6) — stated limitation, prose matches. Separately, `Seed.primary_method`'s docstring claimed
  "(most confident)" as a guarantee; the code only ever takes `vulnerable_methods[0]` with no confidence
  sort. Vacuously true today (every current seed has exactly one method) but not code-enforced — docstring
  corrected 2026-08-14 to describe it as a convention, not a guarantee.

## 3. `component_check.py` — L1 component check

- [x] `check_component_present()`, multi-JAR checking, IN_RANGE/OUT_OF_RANGE/INCONCLUSIVE combination rule
  ↔ **3.1.3 The Evidence Ladder** (`sec:evidence_ladder`, L1 paragraphs).
- [x] Fail-open version comparator (`_compare_segments` etc., returns None on ambiguity) ↔ **3.1.3** (the
  "refused and reported as unparseable → INCONCLUSIVE" claim) and its own module docstring. One inline
  example comment was attached to the wrong branch (illustrated `_compare_versions`' length-mismatch
  handling next to `_compare_segments`' same-position branch); fixed 2026-08-14.
- [x] `pom.properties`-only scope, shaded/relocated copy blind spot ↔ **6.3 Limitations** (L1 scope boundary).

## 4. `static_analyzer.py` — CHA + BFS (longest core file, most JVM detail)

- [x] `compute_cha()` walking both EXTENDS and IMPLEMENTS upward ↔ **3.1.4** (`sec:static`, the Log4Shell
  Logger→ExtendedLogger→AbstractLogger→Logger dispatch-chain example).
- [x] `cha_targets()` — downward subtype expansion; note the `sorted()` (determinism fix, 2026-08-07) ↔
  **3.1.4** + **3.1.8 Design Tradeoffs** (`sec:tradeoffs`, CHA over-approximation) + **3.2.3 Static
  Analyzer** (`sec:static_analyzer`). Also **6.4 Future Work** (applies-to-set refinement). Note for viva:
  the UP-resolution proxy (`callee_sig not in self.callers`) treats "no outgoing edges" as equivalent to
  "method not defined in base_class," but a genuinely-defined leaf method that calls nothing would also
  trigger it — harmless (adds a sound but redundant BFS candidate), not fixed, just worth knowing if asked.
- [x] `bfs_reachable()` — BFS-for-shortest-path, upward inherited-body resolution, the `sorted()` on callees
  ↔ **3.1.4**.
- [x] Entry-point filtering by project prefix, `extra_entry_points` ↔ **3.1.4** + IoC discussion in **3.1.8**.
- [x] Match tiers (`exact` / `relocated_package_suspected`) ↔ **3.1.4**.
- [x] Edge-type annotation (ENTRY_POINT / CALL / CHA_EXPANSION / INHERITED) ↔ **3.1.4** (annotated call path).
- [x] `residual_risk_reason` list (reflection / invokedynamic / dynamic-class-loading / future-code-change)
  ↔ **3.1.4** and design goal G1 in **3.1.1**. See models.py entry above re: `uncertain_features` mixup.
- [x] `StaticReachability.UNKNOWN` vs `NOT_REACHABLE` distinction ↔ **3.1.4**.
- [x] The Java ASM extractor being a separate component ↔ **3.2.3** (`sec:static_analyzer`).
- [x] `CallGraph`'s own docstring claimed edges are stored in both a forward (`callers`) and reverse
  (`callees`) index; the dataclass never actually had a `callees` field — leftover/aspirational comment,
  fixed 2026-08-14 to describe the real one-directional structure.
- [x] `analyze()`'s `callgraph_cache` docstring said "if provided, skip extraction"; actually only skips
  when the file already exists, otherwise extraction still runs and writes there for later reuse — fixed
  2026-08-14.

## 5. `runtime_analyzer.py` — OpenTelemetry trace parsing

- [x] Three outcomes OBSERVED / NOT_OBSERVED / NOT_RUN, agent-banner check ↔ **3.1.5 Runtime Evidence
  Design** (`sec:runtime`). `analyze_traces()`'s NOT_RUN bullet listed its two triggers as OR when the code
  actually requires them together (AND) — fixed 2026-08-14.
- [x] Two match tiers (code.namespace+code.function vs span-name fallback), confidence values (0.95 / 0.70 /
  0.6 / none) ↔ **3.1.5**.
- [x] OTel agent 1.32.0 log-format binding, two-regex parser ↔ **3.2.4 Runtime Analyzer** (`sec:runtime_analyzer`).
- [x] No-sampler / rely-on-default choice ↔ **3.2.4**.
- [x] Method-identity ambiguity (no JVM descriptor) + instrumentation-config blind spot ↔ **6.3 Limitations**.
- Note: `SpanRecord.raw_line` is populated on every parsed span but never read anywhere in the codebase
  (not by `analyze_traces()`, not by `print_trace_summary()`, not by any test). Plausibly kept as audit-
  trail/debug material; flagged, not removed.

## 6. `fusion.py` — evidence fusion & scoring

- [x] `fuse()` decision table (all static×runtime combinations → decision/level/confidence) ↔ **3.1.6
  Evidence Fusion and Scoring** (`sec:evidence_fusion_and_scoring`) + **3.2.5 Fusion and Scoring**
  (`sec:fusion_and_scoring`). Module docstring's rule table had two stale confidence formulas: rule 1
  (`REACHABLE`+`OBSERVED`) said a fixed `conf=0.95`, actually `min(static.confidence, runtime.confidence)`;
  rule 5 (`NOT_REACHABLE`) said `conf=0.70`, actually `static.confidence*0.85`. Both fixed 2026-08-14 and
  re-verified against `test_fusion.py`'s 10 static/runtime combinations, which all pass.
- [x] `risk_score = round(base_cvss * multiplier, 1)`, multiplier table keyed on (decision, level) ↔ **3.1.6**.
  Every multiplier value checked against the prose's ordering argument — matches. Minor completeness note
  (not fixed): the module docstring's exposure-score summary table omits the `L3 UNDER_INVESTIGATION ×
  0.50` row even though `_EVIDENCE_MULTIPLIER` has it.
- [x] Conflict case confidence `min(static, runtime) * 0.7` ↔ **3.1.6** (the conflict-formula caveat).
- [x] "Never discard evidence" — full component/static/runtime objects stored on chain ↔ **3.1.6**.
- [x] CVSS-ordinal-×-multiplier construct-validity caveat ↔ **3.1.6**, **5.6 Threats to Validity**, **6.3/6.4**.
- Code-quality note (2026-08-14): `fuse()` and `fuse_component_absent()` independently built identical
  `chain_id`/`vulnerable_component` strings and an identical 3-line risk-score formula. Consolidated into
  `_chain_id()`, `_vulnerable_component_label()`, `_compute_risk_score()` helpers; behaviour-preserving,
  confirmed via `test_fusion.py`. Also removed three now-unused imports (`hashlib`, `Path`,
  `ComponentCheckStatus`).

## 7. `remediation.py` — remediation advice

- [x] Priority mapping (URGENT/RECOMMENDED/MONITOR), runtime-observation override, first-project-package
  call-site selection, effort-from-depth proxy ↔ **3.2.6 Report and VEX Generation** (`sec:report_generation`).
  Found a dead no-op `if` branch (`priority == "MONITOR" and decision == UNDER_INVESTIGATION`) that
  reassigned `base_note` to the exact value it already held — almost certainly a vestige of a distinct
  UNDER_INVESTIGATION note that got consolidated into the generic MONITOR text during a refactor. Removed
  2026-08-14 at the user's direction (no replacement note written — that would be a content decision, not
  a bug fix). Practical effect: `UNDER_INVESTIGATION` and `NOT_AFFECTED_CANDIDATE` findings still share one
  generic MONITOR remediation note; flagged here in case a distinct one is ever wanted.

## 8. `audit.py` — L5 human audit

- [x] `apply_audit_to_dict()`, confirm-vs-override confidence logic (+0.20 confirm path vs reviewer_confidence
  / 0.90 override path), pre-audit snapshot, `audit_history` ↔ **3.1.7 CRA-Aligned Output Design**
  (`sec:output_design`, the L5 / audit paragraphs). Fully audited 2026-08-14, both for docstring accuracy
  and code redundancy — clean, no findings. `test_audit.py` passes.
- [x] `--reviewer-confidence` CLI flag ↔ **3.1.7**.
- [x] No tamper-evidence / no cryptographic provenance ↔ **6.3 Limitations**.

## 9. Lower priority — seed-authoring tools (outside trusted runtime boundary)

The pipeline never reads these at runtime and the thesis places them outside its reproducibility guarantee.
Both fully docstring- and redundancy-audited 2026-08-14.

- [x] `light_cvemapping.py` — candidate-method generation from a fix-commit diff, CWE-keyed vocabulary,
  `candidate_methods`/`descriptor_hint` (one-level generic nesting limitation) ↔ **3.2.2 Seed Model and
  Matching Logic** (`sec:seed`, candidate-generation paragraph) + reproducibility boundary in **3.1.2**. A
  comment pointed to "see module docstring" for the generic-nesting limit, but the module docstring never
  actually stated it (only the thesis did) — fixed by adding the note to the module docstring.
- [x] `seed_ingestor.py` — (same trusted-boundary framing). `fetch_osv()`'s docstring undersold its GHSA-
  alias retry (said "fetch the first," code tries up to two) — fixed. `enhance_candidates()`'s CWE-term
  matching runs once over the whole commit diff, not per-candidate — docstring clarified.
- Minor, not fixed: both files independently define a near-identical private `_dump_yaml()` helper (~4-5
  lines). `seed_ingestor.py` already imports from `light_cvemapping.py`, so this could be shared, but given
  both are meant to remain independently runnable CLI tools and the duplication is tiny, left as-is.

## 10. `scripts/` — evaluation and demo tooling

- [x] `collect_traces.py` — launches the demo app with the OTel agent, captures combined stdout+stderr ↔
  **4.2 Controlled Evaluation Design**. Docstring and comments checked against code line-by-line — clean.
- [x] `risk_reduction.py` — aggregate exposure-reduction metric, `EVIDENCE_LABEL`/`MULTIPLIER` tables ↔
  **Table 5.1**, **5.1 Controlled Evaluation Results**. `EVIDENCE_LABEL`'s per-decision label mapping and
  the `n_reachable`/`n_not_reachable` statistics were checked against the 8 real report JSON files in
  `reports/`, not just read — every decision/evidence_level/static-status combination matched exactly.

---

## Where the code's behaviour shows up in Chapters 4–5 (for viva prep)

- Controlled 8-case results, Table 5.1, 60.2→23.2 / 61.5% ↔ `fusion.py` + `scripts/risk_reduction.py`;
  design in **4.2 Controlled Evaluation Design**, results in **5.1**.
- Reflection diagnostic (static NOT_REACHABLE → conflict on runtime add) ↔ `static_analyzer.py` blind spot +
  `fusion.py` conflict case; **4.2 / 5.1**.
- External validation (christophetd L4, RuoYi NOT_REACHABLE) ↔ whole pipeline; **4.3 / 5.2**.
- Published-analysis cross-check (plexus-archiver vs Shen et al.) ↔ `seed_loader.py` seed identification +
  `static_analyzer.py` reachability; **4.4 / 5.4**.
- Performance/tractability numbers ↔ `static_analyzer.py` extraction+CHA+BFS cost; **4.5 / 5.3**.
- Tool comparison table ↔ whole design; **5.5**.

---

## Audit History

**2026-08-14, full-project docstring audit** — every `analyzer/` file's docstrings read against the code
directly beneath them (not skimmed). Real drifts found and fixed: two stale confidence formulas in
`fusion.py`'s rule table; a two-file `uncertain_features`/`residual_risk_reason` mixup in `models.py` and
`static_analyzer.py`; an inaccurate `callgraph_cache` skip-extraction claim; an OR/AND mixup in
`runtime_analyzer.py`'s NOT_RUN condition; an unenforced "most confident" claim on `Seed.primary_method`; a
misplaced illustrative example in `component_check.py`; an incomplete `pipeline.py` step list; a broken
"see module docstring" cross-reference in `light_cvemapping.py`; an understated GHSA-alias retry
description in `seed_ingestor.py`. Also removed a dead no-op `if` branch in `remediation.py`. Thesis text
was checked against the most substantive of these (`uncertain_features`/`residual_risk_reason`) and found
already correct — the drift was code-only. Commit `2160aee`.

**2026-08-14, code-redundancy / design-consistency audit** — same files, this time reading for dead code,
duplicated logic, and code inconsistent with the system's own stated design principles rather than for
docstring accuracy. Found and fixed: 6 unused imports across 4 files (`fusion.py`, `remediation.py`,
`runtime_analyzer.py`, `seed_loader.py`); a `CallGraph` docstring describing a `callees` reverse-index
field that was never actually implemented; a report `summary` block that silently dropped 3 of 6 `Decision`
categories from its counts (inconsistent with the system's own "never discard evidence" principle);
duplicated `chain_id`/`vulnerable_component`/risk-score logic between `fusion.py`'s two entry functions,
consolidated into three small helpers. All fixes verified against the project's own test suite
(`test_fusion.py`, `test_pipeline.py`, `test_static.py`, `test_seed_loader.py`, `test_component_check.py`,
`test_audit.py`, `test_runtime.py`) — all passing both before and after. Flagged but not changed:
`EvidenceChain.audit_record`/`audit_history` dataclass fields are never populated by any constructor call
in the current codebase (the real audit flow works on raw dicts); `SpanRecord.raw_line` is written but
never read; `light_cvemapping.py`/`seed_ingestor.py` each define a near-identical `_dump_yaml()` helper.
