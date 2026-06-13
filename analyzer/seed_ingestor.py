"""
CVE Seed Ingestor — automated advisory metadata ingestion and seed skeleton generation.

Composes with light_cvemapping.py:

  OSV/GHSA API  →  advisory metadata + fix commit URL
       ↓
  light_cvemapping  →  candidate_methods   (if fix commit found)
       ↓
  CWE keyword scoring  →  adjusted confidence
       ↓
  seed skeleton YAML  →  manual validation  →  trusted seed YAML

Data source priority:
  1. OSV API (https://api.osv.dev) — primary; covers GHSA, Maven, and CVE aliases
  2. NVD — CVSS/CWE cross-check only; not called automatically (rate-limited)

Pipeline status (machine-readable):
  NEEDS_FIX_COMMIT     — advisory ingested; no commit URL found in references
  NEEDS_METHOD_MAPPING — fix commit found; light_cvemapping not yet run
  NEEDS_VALIDATION     — candidate_methods generated; awaiting human review
  VALIDATED            — human-confirmed vulnerable_methods present

CWE keyword vocabulary (dual-direction):
  vuln_terms: searched in removed lines  → corroborates "this IS the vulnerable method"
  fix_terms:  searched in added lines    → corroborates "this is where the fix was applied"
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent))

from light_cvemapping import MethodCandidate, fetch_diff, parse_diff

try:
    import yaml as _yaml
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False

try:
    import requests as _requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False


# ---------------------------------------------------------------------------
# Pipeline states
# ---------------------------------------------------------------------------

NEEDS_FIX_COMMIT     = "NEEDS_FIX_COMMIT"
NEEDS_METHOD_MAPPING = "NEEDS_METHOD_MAPPING"
NEEDS_VALIDATION     = "NEEDS_VALIDATION"
VALIDATED            = "VALIDATED"


# ---------------------------------------------------------------------------
# CWE-keyed keyword vocabulary
# ---------------------------------------------------------------------------

_CWE_KEYWORDS: dict[str, dict[str, list[str]]] = {
    "CWE-22":  {  # Path Traversal
        "vuln_terms": ["../", "traversal", "getPath", "getName"],
        "fix_terms":  ["canonical", "normalize", "getCanonicalPath", "getCanonicalFile", "startsWith"],
    },
    "CWE-20":  {  # Improper Input Validation
        "vuln_terms": [],
        "fix_terms":  ["validate", "verify", "sanitize", "check("],
    },
    "CWE-502": {  # Deserialization of Untrusted Data
        "vuln_terms": ["ObjectInputStream", "readObject", "deserializ"],
        "fix_terms":  ["allowlist", "blocklist", "ClassResolver", "filter"],
    },
    "CWE-917": {  # EL Injection (Log4Shell)
        "vuln_terms": ["lookup", "JndiLookup", "substitut", "Interpolator", "${"],
        "fix_terms":  ["disableJndi", "JNDI_ENABLE_PROPERTY", "allowedClasses"],
    },
    "CWE-611": {  # XXE
        "vuln_terms": ["DocumentBuilder", "SAXParser", "XMLReader"],
        "fix_terms":  ["setFeature", "FEATURE_EXTERNAL", "disallow"],
    },
    "CWE-78":  {  # OS Command Injection
        "vuln_terms": ["Runtime.exec", "ProcessBuilder", "exec("],
        "fix_terms":  ["sanitize", "allowlist"],
    },
    "CWE-400": {  # Uncontrolled Resource Consumption / ReDoS
        "vuln_terms": ["Pattern.compile", "matches(", "replaceAll("],
        "fix_terms":  ["timeout", "interrupt", "limit"],
    },
}


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class AdvisoryMetadata:
    cve_id:           str
    osv_id:           str              = ""
    aliases:          list[str]        = field(default_factory=list)
    summary:          str              = ""
    cwe_ids:          list[str]        = field(default_factory=list)
    cvss_vector:      Optional[str]    = None
    group_id:         str              = ""
    artifact_id:      str              = ""
    ecosystem:        str              = ""
    vulnerable_range: str              = ""
    fixed_version:    str              = ""
    commit_urls:      list[str]        = field(default_factory=list)
    pr_urls:          list[str]        = field(default_factory=list)
    advisory_urls:    list[str]        = field(default_factory=list)


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

_OSV_QUERY = "https://api.osv.dev/v1/query"
_OSV_VULNS = "https://api.osv.dev/v1/vulns"

_COMMIT_RE = re.compile(r"github\.com/[^/]+/[^/]+/commit/[0-9a-f]{7,40}")
_PR_RE     = re.compile(r"github\.com/[^/]+/[^/]+/pull/\d+")


def _get(url: str) -> dict:
    hdrs = {"Accept": "application/json", "User-Agent": "vuln-risk-assessor/1.0"}
    if _HAS_REQUESTS:
        r = _requests.get(url, headers=hdrs, timeout=30)
        r.raise_for_status()
        return r.json()
    from urllib.request import Request, urlopen
    with urlopen(Request(url, headers=hdrs), timeout=30) as r:
        return json.loads(r.read().decode())


def _post(url: str, body: dict) -> dict:
    payload = json.dumps(body).encode()
    hdrs    = {"Content-Type": "application/json", "User-Agent": "vuln-risk-assessor/1.0"}
    if _HAS_REQUESTS:
        r = _requests.post(url, data=payload, headers=hdrs, timeout=30)
        r.raise_for_status()
        return r.json()
    from urllib.request import Request, urlopen
    with urlopen(Request(url, data=payload, headers=hdrs), timeout=30) as r:
        return json.loads(r.read().decode())


# ---------------------------------------------------------------------------
# OSV ingestion
# ---------------------------------------------------------------------------

def _fetch_one(id_: str) -> dict:
    url = f"{_OSV_VULNS}/{id_}"
    print(f"  [seed-ingestor] OSV → {url}", file=sys.stderr)
    return _get(url)


def fetch_osv(cve_id: str) -> dict:
    """
    Fetch the full OSV record for any identifier (CVE, GHSA, OSV-xxx).

    NVD-primary CVE records often lack Maven package metadata — that data lives in
    the GHSA-primary alias record. When the primary record has no ECOSYSTEM-type
    affected[] entry for Maven, we fetch the first GHSA alias and merge:
      - Maven affected[] ranges
      - references (new URLs only)
      - database_specific.cwe_ids

    This two-record strategy is necessary because OSV does not consolidate
    package metadata across alias records.
    """
    primary = _fetch_one(cve_id)

    has_maven = any(
        e.get("package", {}).get("ecosystem", "").lower() == "maven"
        and any(r.get("type") == "ECOSYSTEM" for r in e.get("ranges", []))
        for e in primary.get("affected", [])
    )

    if not has_maven:
        ghsa_aliases = [a for a in primary.get("aliases", []) if a.startswith("GHSA-")]
        for ghsa_id in ghsa_aliases[:2]:   # try up to 2 GHSA aliases
            try:
                ghsa = _fetch_one(ghsa_id)
            except Exception:
                continue

            # Merge Maven affected[] ranges
            maven_entries = [
                e for e in ghsa.get("affected", [])
                if e.get("package", {}).get("ecosystem", "").lower() == "maven"
                and any(r.get("type") == "ECOSYSTEM" for r in e.get("ranges", []))
            ]
            if maven_entries:
                primary.setdefault("affected", []).extend(maven_entries)

            # Merge references (deduplicated)
            existing = {r.get("url") for r in primary.get("references", [])}
            for ref in ghsa.get("references", []):
                if ref.get("url") not in existing:
                    primary.setdefault("references", []).append(ref)
                    existing.add(ref.get("url"))

            # Merge CWE IDs from GHSA's database_specific
            ghsa_cwes = ghsa.get("database_specific", {}).get("cwe_ids", [])
            if ghsa_cwes:
                primary.setdefault("database_specific", {})["cwe_ids"] = ghsa_cwes

            if maven_entries:
                break   # found what we needed

    return primary


def _maven_package(affected: list[dict]) -> tuple[str, str]:
    for entry in affected:
        pkg = entry.get("package", {})
        if pkg.get("ecosystem", "").lower() == "maven":
            name = pkg.get("name", "")
            if ":" in name:
                return name.split(":", 1)
    return "", ""


def _version_ranges(affected: list[dict], group_id: str, artifact_id: str) -> tuple[str, str]:
    target = f"{group_id}:{artifact_id}"
    parts: list[str] = []
    fixed = ""
    for entry in affected:
        if entry.get("package", {}).get("name") != target:
            continue
        for r in entry.get("ranges", []):
            if r.get("type") != "ECOSYSTEM":
                continue
            introduced = fixed_ver = ""
            for ev in r.get("events", []):
                if "introduced" in ev:
                    introduced = ev["introduced"]
                if "fixed" in ev:
                    fixed_ver = ev["fixed"]
            if introduced and fixed_ver:
                parts.append(f">={introduced},<{fixed_ver}")
            elif introduced:
                parts.append(f">={introduced}")
            elif fixed_ver:
                parts.append(f"<{fixed_ver}")
            if fixed_ver and not fixed:
                fixed = fixed_ver
    return (" || ".join(parts) if parts else ""), fixed


def _split_references(refs: list[dict]) -> tuple[list[str], list[str], list[str]]:
    """
    Split OSV references into commit URLs, PR URLs, and advisory URLs.
    FIX-typed references are checked first — they are the most reliable source
    of fix commit URLs.
    """
    commit_urls: list[str] = []
    pr_urls:     list[str] = []
    adv_urls:    list[str] = []
    seen: set[str] = set()
    for ref in sorted(refs, key=lambda r: 0 if r.get("type") == "FIX" else 1):
        url = ref.get("url", "")
        if not url or url in seen:
            continue
        seen.add(url)
        if _COMMIT_RE.search(url):
            commit_urls.append(url)
        elif _PR_RE.search(url):
            pr_urls.append(url)
        else:
            adv_urls.append(url)
    return commit_urls, pr_urls, adv_urls


def parse_osv_record(osv: dict) -> AdvisoryMetadata:
    cve_id  = osv.get("id", "")
    aliases = [a for a in osv.get("aliases", []) if a != cve_id]
    summary = (osv.get("summary") or osv.get("details") or "")[:300].strip()

    affected               = osv.get("affected", [])
    group_id, artifact_id  = _maven_package(affected)
    vuln_range, fixed      = _version_ranges(affected, group_id, artifact_id)

    commit_urls, pr_urls, adv_urls = _split_references(osv.get("references", []))

    cwe_ids  = osv.get("database_specific", {}).get("cwe_ids", [])
    cvss_vec = next(
        (s.get("score") for s in osv.get("severity", []) if s.get("type", "").startswith("CVSS_V")),
        None,
    )

    return AdvisoryMetadata(
        cve_id           = cve_id,
        osv_id           = cve_id,
        aliases          = aliases,
        summary          = summary,
        cwe_ids          = cwe_ids,
        cvss_vector      = cvss_vec,
        group_id         = group_id,
        artifact_id      = artifact_id,
        ecosystem        = "maven" if group_id else "",
        vulnerable_range = vuln_range,
        fixed_version    = fixed,
        commit_urls      = commit_urls,
        pr_urls          = pr_urls,
        advisory_urls    = adv_urls,
    )


# ---------------------------------------------------------------------------
# Confidence enhancement
# ---------------------------------------------------------------------------

def _cwe_hits(diff_text: str, cwe_ids: list[str]) -> tuple[list[str], list[str]]:
    """Return (vuln_terms_hit, fix_terms_hit) based on CWE keyword vocabulary."""
    removed = "\n".join(l[1:] for l in diff_text.splitlines() if l.startswith("-") and not l.startswith("---"))
    added   = "\n".join(l[1:] for l in diff_text.splitlines() if l.startswith("+") and not l.startswith("+++"))
    vuln_hit: list[str] = []
    fix_hit:  list[str] = []
    for cwe in cwe_ids:
        for term in _CWE_KEYWORDS.get(cwe, {}).get("vuln_terms", []):
            if term.lower() in removed.lower() and term not in vuln_hit:
                vuln_hit.append(term)
        for term in _CWE_KEYWORDS.get(cwe, {}).get("fix_terms", []):
            if term.lower() in added.lower() and term not in fix_hit:
                fix_hit.append(term)
    return vuln_hit, fix_hit


def _regression_test_added(diff_text: str, method_name: str) -> bool:
    """Return True if the diff adds test code that references method_name."""
    in_test = False
    for line in diff_text.splitlines():
        if line.startswith("diff --git") and len(line.split()) >= 4:
            path    = line.split()[-1].lstrip("b/")
            in_test = (
                "src/test/java/" in path
                or path.endswith("Test.java")
                or path.endswith("Tests.java")
            )
        elif in_test and line.startswith("+") and method_name in line:
            return True
    return False


def enhance_candidates(
    candidates: list[MethodCandidate],
    cwe_ids:    list[str],
    diff_text:  str,
) -> list[MethodCandidate]:
    """
    Adjust candidate confidence using CWE keyword matching and regression test detection.

    Upgrade rules (applied in order, stops at first that fires):
      1. regression test added that references the method → high  (strongest signal)
      2. CWE vuln_term in removed lines AND fix_term in added lines → medium → high
      3. any CWE term (vuln or fix) present in diff → low → medium

    New terms found via CWE matching are appended to evidence_terms.
    """
    if not candidates:
        return candidates

    vuln_hit, fix_hit = _cwe_hits(diff_text, cwe_ids)

    for c in candidates:
        if _regression_test_added(diff_text, c.method):
            c.confidence = "high"
            if "regression_test_added" not in c.evidence_terms:
                c.evidence_terms.append("regression_test_added")
            continue

        if c.confidence == "high":
            continue

        if c.confidence == "medium" and vuln_hit and fix_hit:
            c.confidence = "high"
        elif c.confidence == "low" and (vuln_hit or fix_hit):
            c.confidence = "medium"

        for term in vuln_hit + fix_hit:
            if term not in c.evidence_terms:
                c.evidence_terms.append(term)

    return candidates


# ---------------------------------------------------------------------------
# Output document builder
# ---------------------------------------------------------------------------

def _status(meta: AdvisoryMetadata, candidates: list[MethodCandidate], commit_url: str) -> str:
    if candidates:
        return NEEDS_VALIDATION
    if commit_url:
        return NEEDS_METHOD_MAPPING
    return NEEDS_FIX_COMMIT


def build_output_doc(
    meta:       AdvisoryMetadata,
    candidates: list[MethodCandidate],
    commit_url: str,
) -> dict:
    ghsa_ids  = [a for a in meta.aliases if a.startswith("GHSA")]
    ghsa_urls = [f"https://github.com/advisories/{a}" for a in ghsa_ids]
    adv_type  = "ghsa" if ghsa_ids else ("osv" if meta.osv_id else None)

    doc: dict = {
        "status":    _status(meta, candidates, commit_url),
        "cve":       meta.cve_id or None,
        "aliases":   meta.aliases,
        "ecosystem": meta.ecosystem or "maven",
        "package": {
            "group_id":        meta.group_id        or None,
            "artifact_id":     meta.artifact_id     or None,
            "vulnerable_range": meta.vulnerable_range or None,
            "fixed_version":   meta.fixed_version   or None,
        },
        "cwe_ids":  meta.cwe_ids,
        "cvss":     {"vector": meta.cvss_vector},
        "summary":  meta.summary or None,
        "seed_source": {
            "advisory_source": {
                "type": adv_type,
                "ids":  ghsa_ids,
                "urls": ghsa_urls,
            },
            "method_source": {
                "type":                       "light_patch_mapping" if candidates else None,
                "fix_commit":                 commit_url or None,
                "confidence":                 "medium"  if candidates else None,
                "requires_manual_validation": True      if candidates else None,
            },
        },
        "candidate_methods":  [c.to_dict() for c in candidates],
        "vulnerable_methods": [],
    }

    if meta.pr_urls and not commit_url:
        doc["notes"] = (
            "Fix commit not found automatically. "
            "The following PRs may contain the merge commit:\n"
            + "\n".join(f"  - {u}" for u in meta.pr_urls)
        )

    return doc


def _dump_yaml(doc: dict) -> str:
    if _HAS_YAML:
        return _yaml.dump(doc, allow_unicode=True, default_flow_style=False, sort_keys=False)
    return json.dumps(doc, indent=2, default=str)


# ---------------------------------------------------------------------------
# High-level API
# ---------------------------------------------------------------------------

def ingest(
    cve_id:         str,
    run_mapping:    bool          = True,
    package_filter: Optional[str] = None,
    commit_override: str          = "",
) -> tuple[AdvisoryMetadata, list[MethodCandidate], str]:
    """
    Fetch OSV record, optionally run light_cvemapping on the fix commit.

    commit_override: supply the fix commit URL when OSV references don't contain one.
    Returns (metadata, candidates, commit_url).
    """
    osv        = fetch_osv(cve_id)
    meta       = parse_osv_record(osv)
    candidates: list[MethodCandidate] = []

    commit_url = commit_override or (meta.commit_urls[0] if meta.commit_urls else "")

    if commit_url and run_mapping:
        print(f"  [seed-ingestor] Diff  → {commit_url}", file=sys.stderr)
        try:
            diff_text  = fetch_diff(commit_url)
            candidates = parse_diff(diff_text, package_filter)
            # Exclude test-class candidates — they are regression tests, not vulnerable methods.
            # The regression_test_added signal is already propagated to the production candidates.
            candidates = [c for c in candidates if "src/test/java/" not in c.source_file]
            candidates = enhance_candidates(candidates, meta.cwe_ids, diff_text)
        except Exception as exc:
            print(f"  [seed-ingestor] Diff fetch failed: {exc}", file=sys.stderr)
            print(f"  [seed-ingestor] Continuing with skeleton only (status: NEEDS_METHOD_MAPPING)", file=sys.stderr)

    return meta, candidates, commit_url


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "CVE Seed Ingestor: fetch advisory metadata from OSV and generate a\n"
            "seed skeleton YAML with candidate_methods extracted from the fix commit.\n"
            "\n"
            "Output status field:\n"
            "  NEEDS_FIX_COMMIT     — no commit URL found in references\n"
            "  NEEDS_METHOD_MAPPING — commit found; run without --no-mapping to extract candidates\n"
            "  NEEDS_VALIDATION     — candidates generated; human review required\n"
            "  VALIDATED            — after manual vulnerable_methods promotion"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--cve",        required=True, help="CVE ID (e.g. CVE-2021-44228)")
    parser.add_argument("--commit",     default="",    help="Fix commit URL (override when not found in OSV)")
    parser.add_argument("--package",    default="",    help="Java package prefix to filter candidates")
    parser.add_argument("--no-mapping", action="store_true", help="Skip light_cvemapping; emit skeleton only")
    parser.add_argument("--output",     default="",    help="Write YAML to file (default: stdout)")

    args = parser.parse_args()

    meta, candidates, commit_url = ingest(
        cve_id          = args.cve,
        run_mapping     = not args.no_mapping,
        package_filter  = args.package or None,
        commit_override = args.commit,
    )

    doc      = build_output_doc(meta, candidates, commit_url)
    yaml_str = _dump_yaml(doc)

    if args.output:
        Path(args.output).write_text(yaml_str, encoding="utf-8")
        print(f"  [seed-ingestor] Written to {args.output}", file=sys.stderr)
        print(f"\n  status           : {doc['status']}")
        print(f"  package          : {meta.group_id}:{meta.artifact_id}")
        print(f"  vulnerable_range : {meta.vulnerable_range}")
        print(f"  fixed_version    : {meta.fixed_version}")
        print(f"  cwe_ids          : {meta.cwe_ids}")
        print(f"  fix_commit       : {commit_url or '(not found)'}")
        print(f"  candidates found : {len(candidates)}")
        for i, c in enumerate(candidates):
            print(f"    [{i+1}] {c.class_and_method}  patch_semantic={c.patch_semantic}  conf={c.confidence}")
    else:
        print(yaml_str)


if __name__ == "__main__":
    main()
