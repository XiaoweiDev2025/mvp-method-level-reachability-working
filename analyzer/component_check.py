"""
L1 evidence: does the analysed project's own dependency set actually contain
the vulnerable component, at a version within the seed's declared vulnerable range?

This did not previously exist. assess_cve() went straight from a validated
seed to static call-graph analysis, taking on faith that whoever supplied
--project-jars had already confirmed the vulnerable component was present at
an affected version -- L1_COMPONENT_ASSESSED was defined in the EvidenceLevel
enum but never independently produced by any code path. A seed only records
which package and version range a CVE affects; it says nothing about which
JARs a *particular* analysed project actually ships.

Scope: this reads embedded Maven coordinates
(META-INF/maven/<groupId>/<artifactId>/pom.properties) from the JARs actually
supplied to the pipeline, when the Maven packaging process has retained that
metadata, rather than resolving a full Maven/Gradle dependency tree. This is a
narrower claim than "the component is/isn't in the project's dependency tree":
it can only speak to the JARs it was actually given, and a JAR built by a
non-Maven process, or one whose coordinate metadata was stripped during
shading, carries no signal either way.

Every JAR carrying matching group_id:artifact_id coordinates is checked, not
just the first one found -- a classpath can genuinely contain more than one
version of the same component (for instance a patched direct dependency
alongside an old vendored copy bundled inside a third-party JAR), and checking
only the first match risks a false OUT_OF_RANGE verdict if that JAR happens to
be the safe one. See check_component_present()'s combination rule.

The version comparator is a deliberately narrow implementation, not a full
Maven ComparableVersion algorithm: two purely numeric segments are compared
numerically, and two qualifier segments (an optional alphabetic prefix plus an
optional trailing numeric suffix, e.g. "beta9" -> ("beta", 9)) are compared
numerically on that suffix when their prefixes agree. Two qualifier segments
with *different* prefixes (e.g. "beta9" vs "rc1") would require Maven's own
qualifier-ordering table (alpha < beta < milestone < rc < snapshot < (release)
< sp) to resolve correctly, which is not implemented here; rather than guess
via lexical string order (which does not reliably match that table), such a
comparison -- and any segment containing characters outside a plain
alphanumeric token -- is refused and reported as unparseable, propagating to
an INCONCLUSIVE result rather than a silently-possibly-wrong verdict.
"""

from __future__ import annotations

import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from models import ComponentCheckStatus
from seed_loader import SeedPackage


@dataclass
class ComponentCheckResult:
    """
    Outcome of check_component_present(): a ComponentCheckStatus plus the full
    audit trail of every JAR that carried matching Maven coordinates, in the
    order encountered.

    matches -- (jar_path, version) for every supplied JAR whose own embedded
    coordinates matched the seed's group_id:artifact_id, regardless of which
    way its version compared. Empty when status is INCONCLUSIVE with no
    matching JAR found at all; non-empty when status is INCONCLUSIVE because a
    matching JAR's version could not be confidently compared.
    """
    status: ComponentCheckStatus
    matches: list[tuple[Path, str]] = field(default_factory=list)

    @property
    def found_version(self) -> Optional[str]:
        """Version of the first matching JAR, for callers that just need one representative value."""
        return self.matches[0][1] if self.matches else None

    @property
    def jar_path(self) -> Optional[Path]:
        """Path of the first matching JAR, for callers that just need one representative value."""
        return self.matches[0][0] if self.matches else None


def _read_pom_properties(jar_path: Path) -> Optional[tuple[str, str, str]]:
    """
    Read (group_id, artifact_id, version) from a JAR's own embedded
    META-INF/maven/<groupId>/<artifactId>/pom.properties, if present.
    Returns None if the JAR is not a valid zip, has no such entry, or the
    entry is missing one of the three required keys.
    """
    try:
        with zipfile.ZipFile(jar_path) as z:
            candidates = [
                n for n in z.namelist()
                if n.startswith("META-INF/maven/") and n.endswith("pom.properties")
            ]
            for name in candidates:
                props: dict[str, str] = {}
                for line in z.read(name).decode("utf-8", errors="replace").splitlines():
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    key, _, value = line.partition("=")
                    props[key.strip()] = value.strip()
                if {"groupId", "artifactId", "version"} <= props.keys():
                    return props["groupId"], props["artifactId"], props["version"]
    except (zipfile.BadZipFile, OSError):
        return None
    return None


_QUALIFIER_RE = re.compile(r"^([A-Za-z]*)(\d*)$")


def _parse_segment(segment: str):
    """
    Classifies one dot/dash/underscore-separated version segment:
      ("numeric", int)                -- segment is purely digits
      ("qualifier", (prefix, suffix)) -- an optional alphabetic prefix plus an
                                          optional trailing numeric suffix,
                                          suffix defaulting to 0 when absent
                                          (e.g. "beta9" -> ("beta", 9),
                                          "rc" -> ("rc", 0))
      ("unparseable", None)           -- neither pattern matches (unexpected
                                          characters, e.g. "1.0+build5")
    """
    if segment.isdigit():
        return ("numeric", int(segment))
    m = _QUALIFIER_RE.match(segment)
    if m and (m.group(1) or m.group(2)):
        prefix, suffix = m.group(1), m.group(2)
        return ("qualifier", (prefix, int(suffix) if suffix else 0))
    return ("unparseable", None)


def _compare_segments(a: str, b: str) -> Optional[int]:
    """
    Compares one pair of version segments. Returns -1/0/1, or None if the
    comparison cannot be made with confidence -- see this module's own
    docstring for when that happens (an unparseable segment, or two
    qualifiers with different alphabetic prefixes).
    """
    kind_a, val_a = _parse_segment(a)
    kind_b, val_b = _parse_segment(b)
    if kind_a == "unparseable" or kind_b == "unparseable":
        return None
    if kind_a == "numeric" and kind_b == "numeric":
        return (val_a > val_b) - (val_a < val_b)
    if kind_a == "qualifier" and kind_b == "qualifier":
        prefix_a, suffix_a = val_a
        prefix_b, suffix_b = val_b
        if prefix_a != prefix_b:
            return None
        return (suffix_a > suffix_b) - (suffix_a < suffix_b)
    # one numeric, one qualifier at the same position: a bare numeric segment
    # sorts above a qualifier segment (e.g. "2.7" > "2.7-beta1")
    return 1 if kind_a == "numeric" else -1


def _compare_versions(a: str, b: str) -> Optional[int]:
    """
    Returns -1, 0, or 1 for a<b, a==b, a>b, or None if any segment pair could
    not be confidently compared (see _compare_segments).
    """
    segs_a = re.split(r"[.\-_]", a)
    segs_b = re.split(r"[.\-_]", b)
    for sa, sb in zip(segs_a, segs_b):
        cmp = _compare_segments(sa, sb)
        if cmp is None:
            return None
        if cmp != 0:
            return cmp
    if len(segs_a) != len(segs_b):
        # Shorter side is missing trailing segments; treat a missing numeric
        # segment as 0 (so "2.7" == "2.7.0"), a missing qualifier segment as
        # absent-sorts-higher (so "2.7" > "2.7-beta1").
        longer, a_is_longer = (segs_a, True) if len(segs_a) > len(segs_b) else (segs_b, False)
        extra = longer[min(len(segs_a), len(segs_b)):]
        extra_kinds = [_parse_segment(s)[0] for s in extra]
        if "unparseable" in extra_kinds:
            return None
        if "qualifier" in extra_kinds:
            # whichever side carries the extra qualifier segment(s) is the
            # pre-release and sorts lower
            return -1 if a_is_longer else 1
        return 0
    return 0


_RANGE_CLAUSE = re.compile(r"(>=|<=|>|<)\s*([\w.\-]+)")


def _version_satisfies_range(version: str, range_str: str) -> Optional[bool]:
    """
    range_str is a comma-separated AND of clauses, e.g. ">=2.0,<2.7" or
    "<3.6.0" -- the only forms this thesis's own seed corpus uses. Returns
    None, rather than guessing True/False, if any clause's comparison is
    unparseable (see _compare_versions).
    """
    clauses = _RANGE_CLAUSE.findall(range_str)
    for op, bound in clauses:
        cmp = _compare_versions(version, bound)
        if cmp is None:
            return None
        if op == ">=" and not (cmp >= 0):
            return False
        if op == ">" and not (cmp > 0):
            return False
        if op == "<=" and not (cmp <= 0):
            return False
        if op == "<" and not (cmp < 0):
            return False
    return True


def _iter_jars(project_jars: list[Path]):
    """
    Yield individual JAR files from project_jars, expanding any directory
    entries by recursively globbing for *.jar underneath it -- pipeline.py's
    --project-jars accepts a directory such as a Maven target/ build output
    (see README.md's demo commands), which the Java call-graph extractor
    walks itself; this mirrors that convention on the Python side rather
    than silently finding nothing under a directory path.
    """
    for p in project_jars:
        if p.is_dir():
            yield from sorted(p.rglob("*.jar"))
        else:
            yield p


def check_component_present(
    project_jars: list[Path],
    seed_package: SeedPackage,
) -> ComponentCheckResult:
    """
    Scan project_jars for every JAR whose own embedded Maven coordinates match
    seed_package's group_id:artifact_id, and check each one's version against
    seed_package.vulnerable_range.

    Combination rule across all matches found (deliberately biased toward
    never claiming a false absence):
      - any match confirmed IN_RANGE  -> overall IN_RANGE
      - else any match unparseable    -> overall INCONCLUSIVE
      - else (all matches OUT_OF_RANGE, and at least one match exists)
                                       -> overall OUT_OF_RANGE
      - no match found at all         -> overall INCONCLUSIVE
    """
    matches: list[tuple[Path, str]] = []
    for jar_path in _iter_jars(project_jars):
        coords = _read_pom_properties(jar_path)
        if coords is None:
            continue
        group_id, artifact_id, version = coords
        if group_id == seed_package.group_id and artifact_id == seed_package.artifact_id:
            matches.append((jar_path, version))

    if not matches:
        return ComponentCheckResult(status=ComponentCheckStatus.INCONCLUSIVE, matches=[])

    verdicts = [_version_satisfies_range(version, seed_package.vulnerable_range) for _, version in matches]

    if any(v is True for v in verdicts):
        return ComponentCheckResult(status=ComponentCheckStatus.IN_RANGE, matches=matches)
    if any(v is None for v in verdicts):
        return ComponentCheckResult(status=ComponentCheckStatus.INCONCLUSIVE, matches=matches)
    return ComponentCheckResult(status=ComponentCheckStatus.OUT_OF_RANGE, matches=matches)
