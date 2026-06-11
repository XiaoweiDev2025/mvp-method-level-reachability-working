"""
Light CVE Mapping — semi-automated seed identification from fix commits.

Given a GitHub fix commit URL, downloads the patch diff and extracts
candidate vulnerable methods by analyzing which Java methods were
deleted or significantly modified.

This is "light" because:
  - Heuristic-only (no full Java AST parsing)
  - Returns CANDIDATES — human review still required to confirm seeds
  - Does not compute JVM descriptors (that requires resolving imports)

Why this helps:
  A typical fix commit touches 1–5 files. Without this tool, a researcher
  must manually read the diff and map changes to method signatures.
  This module cuts that from 30 minutes to 30 seconds.

Output: a list of MethodCandidate objects ranked by suspicion score.
  Most suspicious: methods DELETED in the fix (the whole method was removed).
  Also suspicious: methods MODIFIED in the fix (logic was changed).
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

try:
    import requests as _requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False
    from urllib.request import Request, urlopen

# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class MethodCandidate:
    """One candidate vulnerable method extracted from a fix commit diff."""
    fqcn: str                   # Best-effort FQCN (may lack inner class info)
    method: str                 # Method name
    change_type: str            # "deleted" | "modified" | "added_to_fix"
    confidence: str             # "high" | "medium" | "low"
    source_file: str            # Java source file path in the repo
    context_lines: list[str] = field(default_factory=list)

    @property
    def class_and_method(self) -> str:
        return f"{self.fqcn}.{self.method}"

    def to_yaml_stub(self) -> str:
        """Generate a partially-filled seed YAML entry for manual completion."""
        return (
            f"  - fqcn: {self.fqcn}\n"
            f"    method: {self.method}\n"
            f"    descriptor: null  # TODO: add JVM descriptor\n"
            f"    confidence: {self.confidence}\n"
            f"    evidence: \"TODO: add evidence rationale\"\n"
        )


# ---------------------------------------------------------------------------
# GitHub URL helpers
# ---------------------------------------------------------------------------

def _make_diff_url(commit_url: str) -> str:
    """
    Convert a GitHub commit URL to its raw .diff URL.
    e.g. https://github.com/apache/log4j2/commit/c77b3cb
      -> https://github.com/apache/log4j2/commit/c77b3cb.diff
    """
    url = commit_url.rstrip("/")
    if not url.endswith(".diff"):
        url = url + ".diff"
    return url


def fetch_diff(commit_url: str) -> str:
    """Download the unified diff for a commit from GitHub."""
    diff_url = _make_diff_url(commit_url)
    print(f"  [light-cvemap] Fetching diff: {diff_url}", file=sys.stderr)

    headers = {"User-Agent": "vuln-risk-assessor/1.0"}
    if _HAS_REQUESTS:
        resp = _requests.get(diff_url, headers=headers, timeout=30, allow_redirects=True)
        resp.raise_for_status()
        return resp.text
    else:
        from urllib.request import Request, urlopen
        req = Request(diff_url, headers=headers)
        with urlopen(req, timeout=30) as resp:
            return resp.read().decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Diff parser
# ---------------------------------------------------------------------------

# Matches a Java method declaration in diff body lines (requires closing brace).
# Groups: method_name
_METHOD_DECL = re.compile(
    r'(?:^|[\s+\-])'
    r'(?:(?:public|private|protected|static|final|'
    r'synchronized|native|abstract|default)\s+)*'
    r'(?:<[^>]+>\s*)?'
    r'(?:[\w\[\]<>,?\s]+?)\s+'
    r'(\w+)\s*'
    r'\([^)]*\)\s*'
    r'(?:throws\s+[\w,\s]+)?\s*'
    r'\{'
)

# Relaxed version for git hunk headers which may be truncated (no ')' or '{').
# Used ONLY for @@ header context extraction.
# Groups: method_name
_METHOD_IN_HEADER = re.compile(
    r'(?:^|[\s])'
    r'(?:(?:public|private|protected|static|final|'
    r'synchronized|native|abstract|default)\s+)*'
    r'(?:<[^>]+>\s*)?'
    r'(?:[\w\[\]<>,\[\]?]+\s+)+'     # return type: one or more type tokens
    r'(\w+)\s*'                       # method name (group 1)
    r'\('                             # opening paren only — params may be truncated
)

# Matches a Java package declaration
_PACKAGE = re.compile(r'^\+?-?\s*package\s+([\w.]+)\s*;')

# Matches a top-level class declaration
_CLASS = re.compile(
    r'(?:^|[\s+\-])'
    r'(?:public\s+)?(?:abstract\s+|final\s+)?(?:class|interface|enum)\s+'
    r'(\w+)'
)


def _package_from_path(path: str) -> str:
    """
    Derive Java package name from a Maven-style source path.
    src/main/java/org/apache/commons/io/FilenameUtils.java -> org.apache.commons.io
    """
    for prefix in ("src/main/java/", "src/test/java/"):
        if prefix in path:
            rest = path[path.index(prefix) + len(prefix):]
            parts = rest.replace("\\", "/").split("/")
            return ".".join(parts[:-1])   # drop filename
    return ""


@dataclass
class _FileContext:
    path: str = ""
    package: str = ""
    classes: list[str] = field(default_factory=list)

    def set_path(self, path: str) -> None:
        self.path = path
        # Derive package from path immediately — the package declaration may not
        # appear in the diff if only the method body was changed.
        derived = _package_from_path(path)
        if derived:
            self.package = derived
        self.classes = [Path(path).stem]   # default class = filename stem

    @property
    def fqcn(self) -> str:
        if self.classes:
            return f"{self.package}.{self.classes[-1]}" if self.package else self.classes[-1]
        stem = Path(self.path).stem
        return f"{self.package}.{stem}" if self.package else stem


def parse_diff(diff_text: str) -> list[MethodCandidate]:
    """
    Parse a unified diff and extract candidate vulnerable methods.

    Two complementary extraction strategies:

    Strategy A — Hunk headers (primary, most reliable):
      Git diff hunk headers carry a "function context" showing which method
      the hunk belongs to:
        @@ -676,7 +680,9 @@ public static int getPrefixLength(final String fileName) {
      We extract the method name from this context string.
      A hunk with removed lines → method was MODIFIED (vulnerable version had this logic).
      A hunk with only added lines → method was ADDED in the fix → SKIP (not vulnerable).

    Strategy B — Method declarations in removed lines:
      Scan lines starting with '-' for full method declarations.
      This catches cases like file deletion (entire class removed, like Log4Shell's JndiLookup).
      Deleted methods → highest confidence.

    Deduplication: both strategies add to the same set; fqcn.method is the key.
    """
    candidates: list[MethodCandidate] = []
    seen: set[str] = set()

    ctx = _FileContext()
    removed_lines: list[str] = []
    added_lines:   list[str] = []
    current_hunk_fn: str = ""   # function name from the @@ header

    def flush_hunk() -> None:
        has_removed = bool(removed_lines)
        has_added   = bool(added_lines)
        removed_text = "\n".join(removed_lines)
        added_text   = "\n".join(added_lines)

        # Strategy A: use hunk function context.
        # Accept both "has removed lines" (code replaced) AND "only added lines" (check
        # added inside existing method). New methods added entirely in '+' lines will also
        # match, but that's acceptable — human review filters false positives.
        if current_hunk_fn and (has_removed or has_added):
            fn_m = _METHOD_IN_HEADER.search(current_hunk_fn)
            if fn_m:
                method_name = fn_m.group(1)
                if method_name not in ("if", "for", "while", "switch", "catch", "try"):
                    key = f"{ctx.fqcn}.{method_name}"
                    if key not in seen:
                        seen.add(key)
                        candidates.append(MethodCandidate(
                            fqcn        = ctx.fqcn,
                            method      = method_name,
                            change_type = "modified",
                            confidence  = "high",
                            source_file = ctx.path,
                        ))

        # Strategy B: deleted method declarations
        for m in _METHOD_DECL.finditer(removed_text):
            method_name = m.group(1)
            if method_name in ("if", "for", "while", "switch", "catch", "try"):
                continue
            key = f"{ctx.fqcn}.{method_name}"
            if key in seen:
                continue
            seen.add(key)
            # Deleted (not in added_text) → highest suspicion
            if not re.search(rf'\b{re.escape(method_name)}\s*\(', added_text):
                change_type, confidence = "deleted", "high"
            else:
                change_type, confidence = "modified", "medium"
            candidates.append(MethodCandidate(
                fqcn        = ctx.fqcn,
                method      = method_name,
                change_type = change_type,
                confidence  = confidence,
                source_file = ctx.path,
            ))

    # Regex for hunk header function context: @@ -a,b +c,d @@ <function_context>
    _HUNK_HEADER = re.compile(r'^@@[^@]+@@\s*(.*)')

    for line in diff_text.splitlines():
        if line.startswith("diff --git"):
            flush_hunk()
            removed_lines, added_lines = [], []
            current_hunk_fn = ""
            parts = line.split()
            if len(parts) >= 4:
                path = parts[3].lstrip("b/")
                ctx = _FileContext()
                ctx.set_path(path)
            continue

        # Track package / class from any line (context, added, removed)
        src = line.lstrip("+-").strip()
        pkg_m = _PACKAGE.match(src)
        if pkg_m:
            ctx.package = pkg_m.group(1)
        cls_m = _CLASS.search(src)
        if cls_m:
            cls_name = cls_m.group(1)
            if cls_name not in ctx.classes:
                ctx.classes = [cls_name]

        hh = _HUNK_HEADER.match(line)
        if hh:
            flush_hunk()
            removed_lines, added_lines = [], []
            current_hunk_fn = hh.group(1).strip()
            continue

        if line.startswith("-") and not line.startswith("---"):
            removed_lines.append(line[1:])
        elif line.startswith("+") and not line.startswith("+++"):
            added_lines.append(line[1:])

    flush_hunk()

    # Sort: deleted first, then modified; within each group alphabetically
    candidates.sort(key=lambda c: (0 if c.change_type == "deleted" else 1, c.fqcn))
    return candidates


# ---------------------------------------------------------------------------
# Main API
# ---------------------------------------------------------------------------

def map_commit(commit_url: str) -> list[MethodCandidate]:
    """
    High-level: fetch a fix commit diff and return candidate methods.
    """
    diff = fetch_diff(commit_url)
    candidates = parse_diff(diff)
    return candidates


def print_candidates(candidates: list[MethodCandidate], cve_id: str = "") -> None:
    header = f"Light CVE Mapping results"
    if cve_id:
        header += f" for {cve_id}"
    print(f"\n  {header}")
    print(f"  {'-' * 50}")
    if not candidates:
        print("  (no method candidates found)")
        return
    for i, c in enumerate(candidates):
        print(f"  [{i+1}] {c.class_and_method}")
        print(f"       file   : {c.source_file}")
        print(f"       change : {c.change_type}  confidence: {c.confidence}")
    print()
    print("  Seed YAML stub (review and complete before use):")
    print("  vulnerable_methods:")
    for c in candidates[:3]:   # top 3
        print(c.to_yaml_stub())


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python light_cvemapping.py <github-commit-url> [cve-id]")
        sys.exit(1)

    commit_url = sys.argv[1]
    cve_id     = sys.argv[2] if len(sys.argv) > 2 else ""

    candidates = map_commit(commit_url)
    print_candidates(candidates, cve_id)
