"""
Light CVE Mapping — semi-automated seed identification from fix commits.

Positioning: candidate generator + confidence annotator.

  advisory / CVE / fix commit
          ↓
  light_cvemapping.py
          ↓
  candidate_methods  (confidence-annotated, descriptor_hint provided)
          ↓
  manual validation  (fill descriptor, confirm fqcn, review reason)
          ↓
  trusted seed YAML  (vulnerable_methods: [...])
          ↓
  reachability analysis

Output uses `candidate_methods:` — NOT `vulnerable_methods:`.
Only after human review and JVM descriptor completion should a candidate
be promoted to a trusted seed's `vulnerable_methods:` block.

Why descriptor: null?
  JVM descriptors require resolving the full import chain, class hierarchy,
  and generic type erasure — information that a patch diff does not contain.
  This is a structural limitation, not an implementation gap. `descriptor_hint`
  provides a best-effort approximation from types visible in the diff itself;
  '?' marks fields that require import resolution.

Why evidence_terms from a predefined vocabulary?
  In a CRA compliance context, the basis for each candidate claim must be
  auditable and reproducible. A fixed keyword set is transparent; an NLP
  model is a black box whose outputs cannot be independently verified.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

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
# Security evidence vocabulary
# Each category maps to a list of substrings searched case-insensitively
# against the diff content around the changed method.
# ---------------------------------------------------------------------------

_SECURITY_TERMS: dict[str, list[str]] = {
    "path_traversal":  ["canonical", "traversal", "normalize", "getAbsolutePath", "resolve", "prefix", "relativize"],
    "injection":       ["jndi", "lookup", "expression", "interpolat", "evaluate", "StrSubstit", "MessageFormat"],
    "deserialization": ["readObject", "deserializ", "ObjectInputStream"],
    "zip_slip":        ["extractFile", "ZipEntry", "unzip", "unarchiv"],
    "validation":      ["validate", "sanitize", "escape", "encode", "allowlist", "denylist", "restrict"],
    "rce":             ["Runtime.exec", "ProcessBuilder", "ScriptEngine", "groovy"],
    "xxe":             ["DocumentBuilder", "SAXParser", "XMLReader", "FEATURE_EXTERNAL", "DOCTYPE"],
    "ssrf":            ["openConnection", "HttpClient", "HttpURLConnection"],
    "sql_injection":   ["prepareStatement", "createQuery", "nativeQuery"],
}


def _match_evidence_terms(text: str) -> list[str]:
    """Return security vocabulary terms found in text, deduplicated, order-preserved."""
    found: list[str] = []
    seen: set[str] = set()
    lower = text.lower()
    for terms in _SECURITY_TERMS.values():
        for term in terms:
            if term.lower() in lower and term not in seen:
                seen.add(term)
                found.append(term)
    return found


# ---------------------------------------------------------------------------
# JVM descriptor hints — best-effort only
# Cannot resolve imports without a full compiler; '?' marks unknown types.
# ---------------------------------------------------------------------------

_JVM_PRIMITIVES: dict[str, str] = {
    "void": "V", "boolean": "Z", "byte": "B", "char": "C",
    "short": "S", "int": "I", "long": "J", "float": "F", "double": "D",
}

_JVM_COMMON: dict[str, str] = {
    "String":        "Ljava/lang/String;",
    "Object":        "Ljava/lang/Object;",
    "CharSequence":  "Ljava/lang/CharSequence;",
    "StringBuilder": "Ljava/lang/StringBuilder;",
    "File":          "Ljava/io/File;",
    "Path":          "Ljava/nio/file/Path;",
    "InputStream":   "Ljava/io/InputStream;",
    "OutputStream":  "Ljava/io/OutputStream;",
    "byte[]":        "[B",
    "char[]":        "[C",
    "int[]":         "[I",
    "String[]":      "[Ljava/lang/String;",
}


def _java_type_to_jvm(java_type: str) -> str:
    t = java_type.strip()
    is_array = t.endswith("[]")
    base = (t[:-2] if is_array else t).split("<")[0]
    if base in _JVM_PRIMITIVES:
        desc = _JVM_PRIMITIVES[base]
    elif base in _JVM_COMMON:
        desc = _JVM_COMMON[base]
    else:
        desc = "?"
    return f"[{desc}" if (is_array and desc != "?") else desc


def _build_descriptor_hint(return_type: str, param_types: list[str]) -> Optional[str]:
    if not return_type and not param_types:
        return None
    params = "".join(_java_type_to_jvm(p) for p in param_types)
    ret    = _java_type_to_jvm(return_type) if return_type else "?"
    hint   = f"({params}){ret}"
    return None if hint == "()??" or hint == "()" else hint


def _parse_param_types(param_str: str) -> list[str]:
    """Extract simple type names from a Java parameter list string."""
    if not param_str.strip():
        return []
    types: list[str] = []
    for param in param_str.split(","):
        tokens = [
            t for t in re.split(r"\s+", param.strip())
            if t and not t.startswith("@") and t not in ("final", "...")
        ]
        if len(tokens) >= 2:
            types.append(tokens[-2].split("<")[0].rstrip("."))
        elif tokens:
            types.append(tokens[0].split("<")[0])
    return types


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class HunkStats:
    lines_removed: int = 0
    lines_added:   int = 0


_PATCH_SEMANTIC_DESC = {
    "class_removed":    "Class was entirely removed by the security patch (highest suspicion).",
    "method_deleted":   "Method was deleted by the security patch.",
    "logic_replaced":   "Method logic was replaced or significantly modified by the patch.",
    "validation_added": "Input validation or sanitization was added to this method by the patch.",
}

_PATCH_SEMANTIC_ORDER = {"class_removed": 0, "method_deleted": 1, "logic_replaced": 2, "validation_added": 3}


@dataclass
class MethodCandidate:
    """One candidate vulnerable method extracted from a fix commit diff."""
    fqcn:            str
    method:          str
    descriptor_hint: Optional[str]  = None
    source_file:     str            = ""
    diff_hunk:       str            = ""
    hunk_stats:      HunkStats      = field(default_factory=HunkStats)
    patch_semantic:  str            = "logic_replaced"
    evidence_terms:  list[str]      = field(default_factory=list)
    confidence:      str            = "medium"
    reason:          str            = ""

    @property
    def class_and_method(self) -> str:
        return f"{self.fqcn}.{self.method}"

    def _build_reason(self) -> str:
        parts = [_PATCH_SEMANTIC_DESC.get(self.patch_semantic, "Method was modified by the security patch.")]
        if self.evidence_terms:
            parts.append(f"Security-relevant terms in diff: {', '.join(self.evidence_terms)}.")
        s = self.hunk_stats
        if s.lines_removed > s.lines_added:
            parts.append(f"{s.lines_removed} lines removed vs {s.lines_added} added.")
        return " ".join(parts)

    def to_dict(self) -> dict:
        return {
            "fqcn":            self.fqcn,
            "method":          self.method,
            "descriptor":      None,
            "descriptor_hint": self.descriptor_hint,
            "source_file":     self.source_file,
            "diff_hunk":       self.diff_hunk,
            "hunk_stats": {
                "lines_removed": self.hunk_stats.lines_removed,
                "lines_added":   self.hunk_stats.lines_added,
            },
            "patch_semantic":  self.patch_semantic,
            "evidence_terms":  self.evidence_terms,
            "confidence":      self.confidence,
            "reason":          self.reason or self._build_reason(),
        }


# ---------------------------------------------------------------------------
# File context tracker
# ---------------------------------------------------------------------------

@dataclass
class _FileContext:
    path:       str       = ""
    package:    str       = ""
    classes:    list[str] = field(default_factory=list)
    is_deleted: bool      = False

    def set_path(self, path: str, is_deleted: bool = False) -> None:
        self.path       = path
        self.is_deleted = is_deleted
        derived         = _package_from_path(path)
        if derived:
            self.package = derived
        self.classes = [Path(path).stem]

    @property
    def fqcn(self) -> str:
        cls = self.classes[-1] if self.classes else Path(self.path).stem
        return f"{self.package}.{cls}" if self.package else cls


def _package_from_path(path: str) -> str:
    for prefix in ("src/main/java/", "src/test/java/"):
        if prefix in path:
            rest  = path[path.index(prefix) + len(prefix):]
            parts = rest.replace("\\", "/").split("/")
            return ".".join(parts[:-1])
    return ""


# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

_MODS  = r"(?:(?:public|private|protected|static|final|synchronized|native|abstract|default|strictfp)\s+)*"
_GENS  = r"(?:<[^>]+>\s*)?"
_TYRE  = r"(?:[\w$]+(?:\[\])*(?:<[^>]*>)?)"
_SKIP  = frozenset(["if", "for", "while", "switch", "catch", "try", "new", "return", "throw", "assert"])

# Full method declaration with closing brace — Strategy B (removed lines)
_METHOD_FULL = re.compile(
    rf"(?:^|[\s]){_MODS}{_GENS}"
    rf"({_TYRE})\s+"       # group 1: return type
    rf"(\w+)\s*"           # group 2: method name
    rf"\(([^)]*)\)\s*"     # group 3: parameter list
    rf"(?:throws\s+[\w,\s]+)?\s*\{{"
)

# Relaxed — for @@ hunk headers (truncated, no closing paren/brace)
_METHOD_HEADER = re.compile(
    rf"(?:^|[\s]){_MODS}{_GENS}"
    rf"(?:{_TYRE}\s+)+"    # return type token(s)
    rf"(\w+)\s*"           # group 1: method name
    rf"\("                 # opening paren only
)

_PACKAGE    = re.compile(r"^\+?-?\s*package\s+([\w.]+)\s*;")
_CLASS_DECL = re.compile(
    r"(?:^|[\s+\-])(?:public\s+)?(?:abstract\s+|final\s+)?"
    r"(?:class|interface|enum)\s+(\w+)"
)
_HUNK_HDR   = re.compile(r"^@@[^@]+@@\s*(.*)")


# ---------------------------------------------------------------------------
# Diff parser
# ---------------------------------------------------------------------------

def parse_diff(diff_text: str, package_filter: Optional[str] = None) -> list[MethodCandidate]:
    """
    Parse a unified diff and return ranked candidate vulnerable methods.

    Strategy A — Hunk headers (primary):
      The @@ header carries a function context string naming the enclosing method.
      More reliable than body scanning because it is emitted even when the diff
      is purely additive (no removed lines — e.g. a validation guard inserted).

    Strategy B — Removed line declarations:
      Scans '-' lines for full method declarations. Catches deleted methods
      and provides full parameter lists for descriptor_hint computation.
      When Strategy A already found the method, Strategy B enriches it with
      a descriptor_hint rather than creating a duplicate.

    package_filter: if set, only return candidates whose FQCN starts with this prefix.
    """
    candidates: list[MethodCandidate] = []
    seen: set[str] = set()

    ctx             = _FileContext()
    removed_lines:  list[str] = []
    added_lines:    list[str] = []
    context_lines:  list[str] = []
    current_hdr     = ""

    def _semantic(removed: list[str], added: list[str]) -> str:
        if ctx.is_deleted:
            return "class_removed"
        nr, na = len(removed), len(added)
        if nr > 0 and na == 0:
            return "method_deleted"
        if na > nr * 2 and nr < 5:
            return "validation_added"
        return "logic_replaced"

    def _confidence(semantic: str, has_terms: bool) -> str:
        if semantic in ("class_removed", "method_deleted"):
            return "high"
        return "medium" if has_terms else "low"

    def flush_hunk() -> None:
        if not (removed_lines or added_lines):
            return

        stats    = HunkStats(len(removed_lines), len(added_lines))
        semantic = _semantic(removed_lines, added_lines)
        all_text = "\n".join(removed_lines + added_lines + context_lines)
        terms    = _match_evidence_terms(all_text)

        # Strategy A — method name from hunk header
        if current_hdr:
            m = _METHOD_HEADER.search(current_hdr)
            if m:
                mname = m.group(1)
                if mname not in _SKIP:
                    key = f"{ctx.fqcn}.{mname}"
                    if key not in seen:
                        seen.add(key)
                        candidates.append(MethodCandidate(
                            fqcn           = ctx.fqcn,
                            method         = mname,
                            source_file    = ctx.path,
                            diff_hunk      = current_hdr,
                            hunk_stats     = stats,
                            patch_semantic = semantic,
                            evidence_terms = terms,
                            confidence     = _confidence(semantic, bool(terms)),
                        ))

        # Strategy B — full declarations in removed lines
        removed_text = "\n".join(removed_lines)
        added_text   = "\n".join(added_lines)
        for m in _METHOD_FULL.finditer(removed_text):
            ret_type  = m.group(1)
            mname     = m.group(2)
            param_str = m.group(3)
            if mname in _SKIP:
                continue
            key  = f"{ctx.fqcn}.{mname}"
            hint = _build_descriptor_hint(ret_type, _parse_param_types(param_str))
            if key in seen:
                # Enrich existing candidate with descriptor_hint
                for c in candidates:
                    if c.fqcn == ctx.fqcn and c.method == mname and c.descriptor_hint is None:
                        c.descriptor_hint = hint
                        break
                continue
            seen.add(key)
            is_deleted_method = not re.search(rf"\b{re.escape(mname)}\s*\(", added_text)
            this_sem = semantic if ctx.is_deleted else ("method_deleted" if is_deleted_method else semantic)
            candidates.append(MethodCandidate(
                fqcn            = ctx.fqcn,
                method          = mname,
                descriptor_hint = hint,
                source_file     = ctx.path,
                diff_hunk       = current_hdr,
                hunk_stats      = stats,
                patch_semantic  = this_sem,
                evidence_terms  = terms,
                confidence      = _confidence(this_sem, bool(terms)),
            ))

    for line in diff_text.splitlines():
        if line.startswith("diff --git"):
            flush_hunk()
            removed_lines, added_lines, context_lines = [], [], []
            current_hdr = ""
            parts = line.split()
            if len(parts) >= 4:
                ctx = _FileContext()
                ctx.set_path(parts[3].lstrip("b/"))
            continue

        if line.startswith("deleted file mode"):
            ctx.is_deleted = True
            continue

        src   = line.lstrip("+-").strip()
        pkg_m = _PACKAGE.match(src)
        if pkg_m:
            ctx.package = pkg_m.group(1)
        cls_m = _CLASS_DECL.search(src)
        if cls_m and cls_m.group(1) not in _SKIP:
            ctx.classes = [cls_m.group(1)]

        hh = _HUNK_HDR.match(line)
        if hh:
            flush_hunk()
            removed_lines, added_lines, context_lines = [], [], []
            current_hdr = hh.group(1).strip()
            continue

        if line.startswith("-") and not line.startswith("---"):
            removed_lines.append(line[1:])
        elif line.startswith("+") and not line.startswith("+++"):
            added_lines.append(line[1:])
        else:
            context_lines.append(line)

    flush_hunk()

    candidates.sort(key=lambda c: (_PATCH_SEMANTIC_ORDER.get(c.patch_semantic, 9), c.fqcn, c.method))

    if package_filter:
        candidates = [c for c in candidates if c.fqcn.startswith(package_filter)]

    return candidates


# ---------------------------------------------------------------------------
# HTTP fetch
# ---------------------------------------------------------------------------

def fetch_diff(commit_url: str) -> str:
    """Download the unified diff for a GitHub commit."""
    url = commit_url.rstrip("/")
    if not url.endswith(".diff"):
        url += ".diff"
    print(f"  [light-cvemap] Fetching: {url}", file=sys.stderr)
    headers = {"User-Agent": "vuln-risk-assessor/1.0"}
    if _HAS_REQUESTS:
        resp = _requests.get(url, headers=headers, timeout=30, allow_redirects=True)
        resp.raise_for_status()
        return resp.text
    from urllib.request import Request, urlopen
    req = Request(url, headers=headers)
    with urlopen(req, timeout=30) as resp:
        return resp.read().decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# High-level API
# ---------------------------------------------------------------------------

def map_commit(commit_url: str, package_filter: Optional[str] = None) -> list[MethodCandidate]:
    """Fetch a fix commit diff and return ranked candidate methods."""
    return parse_diff(fetch_diff(commit_url), package_filter)


def build_output_doc(
    candidates:    list[MethodCandidate],
    commit_url:    str,
    cve_id:        str       = "",
    group_id:      str       = "",
    artifact_id:   str       = "",
    advisory_ids:  list[str] = None,
    advisory_urls: list[str] = None,
) -> dict:
    """Build the full structured output document."""
    advisory_ids  = advisory_ids  or []
    advisory_urls = advisory_urls or []
    adv_type = None
    if any(i.startswith("GHSA") for i in advisory_ids):
        adv_type = "ghsa"
    elif any("osv.dev" in u for u in advisory_urls):
        adv_type = "osv"
    elif advisory_ids or advisory_urls:
        adv_type = "nvd"

    return {
        "cve":       cve_id or None,
        "ecosystem": "maven",
        "package": {
            "group_id":        group_id    or None,
            "artifact_id":     artifact_id or None,
            "vulnerable_range": None,
            "fixed_version":    None,
        },
        "seed_source": {
            "advisory_source": {
                "type": adv_type,
                "ids":  advisory_ids,
                "urls": advisory_urls,
            },
            "method_source": {
                "type":                       "light_patch_mapping",
                "fix_commit":                 commit_url,
                "confidence":                 "medium",
                "requires_manual_validation": True,
            },
        },
        "candidate_methods": [c.to_dict() for c in candidates],
    }


def _dump_yaml(doc: dict) -> str:
    if _HAS_YAML:
        return _yaml.dump(doc, allow_unicode=True, default_flow_style=False, sort_keys=False)
    import json
    return "# PyYAML not installed — falling back to JSON\n" + json.dumps(doc, indent=2, default=str)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Light CVE Mapping: extract candidate vulnerable methods from a fix commit.\n"
            "Output is a YAML stub with candidate_methods — requires manual validation\n"
            "before promoting any entry to a trusted seed's vulnerable_methods block."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--commit",      required=True, help="GitHub fix commit URL")
    parser.add_argument("--cve",         default="",    help="CVE ID (e.g. CVE-2021-44228)")
    parser.add_argument("--group-id",    default="",    help="Maven groupId of the vulnerable library")
    parser.add_argument("--artifact-id", default="",    help="Maven artifactId of the vulnerable library")
    parser.add_argument("--advisory",    nargs="*",     help="Advisory IDs or URLs (GHSA-xxx, https://...)")
    parser.add_argument("--package",     default="",    help="Java package prefix to filter candidates (e.g. org.apache.commons.io)")
    parser.add_argument("--output",      default="",    help="Write YAML to this file (default: stdout)")

    args = parser.parse_args()

    advisory_ids  = [a for a in (args.advisory or []) if not a.startswith("http")]
    advisory_urls = [a for a in (args.advisory or []) if a.startswith("http")]

    candidates = map_commit(args.commit, package_filter=args.package or None)
    doc        = build_output_doc(
        candidates    = candidates,
        commit_url    = args.commit,
        cve_id        = args.cve,
        group_id      = args.group_id,
        artifact_id   = args.artifact_id,
        advisory_ids  = advisory_ids,
        advisory_urls = advisory_urls,
    )
    yaml_str = _dump_yaml(doc)

    if args.output:
        Path(args.output).write_text(yaml_str, encoding="utf-8")
        print(f"  [light-cvemap] Written to {args.output}", file=sys.stderr)
        print(f"\n  {len(candidates)} candidate(s) found:")
        for i, c in enumerate(candidates):
            print(f"  [{i+1}] {c.class_and_method}  patch_semantic={c.patch_semantic}  conf={c.confidence}")
    else:
        print(yaml_str)


if __name__ == "__main__":
    main()
