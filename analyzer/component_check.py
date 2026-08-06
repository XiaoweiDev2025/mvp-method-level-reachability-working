"""
L1 evidence: does the analysed project's own dependency set actually contain
the vulnerable component, at a version within the seed's declared vulnerable range?

This did not previously exist. assess_cve() went straight from a validated
seed to static call-graph analysis, taking on faith that whoever supplied
--project-jars had already confirmed the vulnerable component was present at
an affected version -- L1_COMPONENT_PRESENT was defined in the EvidenceLevel
enum but never independently produced by any code path. A seed only records
which package and version range a CVE affects; it says nothing about which
JARs a *particular* analysed project actually ships.

Scope: this reads each JAR's own embedded Maven coordinates
(META-INF/maven/<groupId>/<artifactId>/pom.properties, written by the Maven
JAR plugin into essentially every JAR published through Maven Central) rather
than parsing a build file, since the pipeline's own input is already a flat
JAR set, not a project checkout. The version comparator is a deliberately
narrow implementation, not a full Maven ComparableVersion algorithm: it
compares dot/dash/underscore-separated segments numerically where possible,
treats a non-numeric qualifier segment as sorting below the same version
without one, and does not implement Maven's full qualifier-ordering table
(alpha < beta < milestone < rc < snapshot < (release) < sp). This is
sufficient for the plain-numeric versions and the single-qualifier lower
bound (">=2.0-beta9") this thesis's own seed corpus actually uses, and is
not offered as a general-purpose replacement for Maven's own version
comparison.
"""

from __future__ import annotations

import re
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from seed_loader import SeedPackage


@dataclass
class ComponentPresenceResult:
    """
    Outcome of checking whether a seed's vulnerable component is present,
    at what version, and whether that version falls in the vulnerable range.

    checked        — False only if no supplied JAR carried Maven coordinates
                      for this group_id:artifact_id at all. This is treated
                      as inconclusive, not as "absent": a JAR can genuinely
                      contain the component without pom.properties (a non-
                      Maven build, or metadata stripped during shading), so
                      the pipeline proceeds to static analysis rather than
                      reporting a confident negative on missing metadata.
    found_version   — the version string read from the matching JAR's own
                      pom.properties, if `checked` is True.
    in_range        — whether found_version falls within the seed's
                      vulnerable_range, if `checked` is True.
    jar_path        — which supplied JAR the coordinates were read from.
    """
    checked: bool
    found_version: Optional[str] = None
    in_range: Optional[bool] = None
    jar_path: Optional[Path] = None


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


def _version_key(segment: str) -> tuple[int, object]:
    """Sort key for one dot/dash/underscore-separated version segment."""
    if segment.isdigit():
        return (1, int(segment))
    return (0, segment)  # non-numeric qualifier sorts below a numeric segment


def _compare_versions(a: str, b: str) -> int:
    """
    Returns -1, 0, or 1 for a<b, a==b, a>b under the narrow comparator
    documented in this module's own docstring.
    """
    segs_a = re.split(r"[.\-_]", a)
    segs_b = re.split(r"[.\-_]", b)
    for sa, sb in zip(segs_a, segs_b):
        ka, kb = _version_key(sa), _version_key(sb)
        if ka != kb:
            return -1 if ka < kb else 1
    if len(segs_a) != len(segs_b):
        # Shorter side is missing trailing segments; treat a missing numeric
        # segment as 0 (so "2.7" == "2.7.0"), a missing qualifier segment as
        # absent-sorts-higher (so "2.7" > "2.7-beta1").
        longer, a_is_longer = (segs_a, True) if len(segs_a) > len(segs_b) else (segs_b, False)
        extra = longer[min(len(segs_a), len(segs_b)):]
        extra_is_qualifier = any(not s.isdigit() for s in extra)
        if extra_is_qualifier:
            # whichever side carries the extra qualifier segment(s) is the
            # pre-release and sorts lower (e.g. "2.7" > "2.7-beta1")
            return -1 if a_is_longer else 1
        return 0
    return 0


_RANGE_CLAUSE = re.compile(r"(>=|<=|>|<)\s*([\w.\-]+)")


def _version_satisfies_range(version: str, range_str: str) -> bool:
    """
    range_str is a comma-separated AND of clauses, e.g. ">=2.0,<2.7" or
    "<3.6.0" -- the only forms this thesis's own seed corpus uses.
    """
    clauses = _RANGE_CLAUSE.findall(range_str)
    for op, bound in clauses:
        cmp = _compare_versions(version, bound)
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
) -> ComponentPresenceResult:
    """
    Scan project_jars for one whose own embedded Maven coordinates match
    seed_package's group_id:artifact_id, and check its version against
    seed_package.vulnerable_range.

    If more than one supplied JAR matches (e.g. a bundled uber-JAR alongside
    its unpacked dependency), the first match encountered is used; this
    pipeline does not currently attempt to reconcile disagreeing duplicates.
    """
    for jar_path in _iter_jars(project_jars):
        coords = _read_pom_properties(jar_path)
        if coords is None:
            continue
        group_id, artifact_id, version = coords
        if group_id == seed_package.group_id and artifact_id == seed_package.artifact_id:
            return ComponentPresenceResult(
                checked=True,
                found_version=version,
                in_range=_version_satisfies_range(version, seed_package.vulnerable_range),
                jar_path=jar_path,
            )
    return ComponentPresenceResult(checked=False)
