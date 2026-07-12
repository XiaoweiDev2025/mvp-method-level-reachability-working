"""
Loads and validates vulnerable method seed definitions from YAML files.

A "seed" is the manually-confirmed entry point for a vulnerability:
the specific Java method that contains or triggers the vulnerable behaviour.
Seeds are the anchor point for both static and runtime reachability analysis.
"""

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
import yaml


@dataclass
class VulnerableMethod:
    """One vulnerable method within a CVE seed."""
    fqcn: str           # Fully Qualified Class Name, e.g. org.apache.logging.log4j.core.lookup.JndiLookup
    method: str         # Method name, e.g. lookup
    descriptor: Optional[str]  # JVM descriptor for unambiguous matching, e.g. (Ljava/lang/String;)V
    confidence: str     # high / medium / low
    evidence: str = ""  # Human-readable rationale

    @property
    def class_and_method(self) -> str:
        return f"{self.fqcn}.{self.method}"

    @property
    def full_signature(self) -> str:
        """Returns fqcn + method + descriptor if available, else just fqcn + method."""
        if self.descriptor:
            return f"{self.fqcn}.{self.method}{self.descriptor}"
        return self.class_and_method


@dataclass
class SeedPackage:
    group_id: str
    artifact_id: str
    vulnerable_range: str
    fixed_version: str
    remediation_note: str = ""  # e.g. caveats when fixed_version alone is insufficient

    @property
    def coordinates(self) -> str:
        return f"{self.group_id}:{self.artifact_id}"


@dataclass
class Seed:
    """A complete CVE seed: one vulnerability mapped to one or more vulnerable methods."""
    cve: str
    ecosystem: str
    package: SeedPackage
    vulnerable_methods: list[VulnerableMethod]
    notes: str = ""
    fix_commit: str = ""  # URL to the fix commit, from seed_source.fix_commit

    @property
    def primary_method(self) -> VulnerableMethod:
        """The first (most confident) vulnerable method."""
        return self.vulnerable_methods[0]


def load_seed(path: Path) -> Seed:
    """Load and validate a single seed YAML file."""
    with open(path, encoding="utf-8") as f:
        raw = yaml.safe_load(f)

    if not isinstance(raw, dict):
        raise ValueError(f"Seed {path} is empty or not a YAML mapping.")
    if "cve" not in raw:
        raise ValueError(f"Seed {path} is missing required top-level key 'cve'.")
    if "package" not in raw or not isinstance(raw["package"], dict):
        raise ValueError(f"Seed {path} is missing required top-level key 'package'.")

    pkg_raw = raw["package"]
    for required in ("group_id", "artifact_id"):
        if required not in pkg_raw:
            raise ValueError(f"Seed {path} package block is missing required key '{required}'.")

    package = SeedPackage(
        group_id=pkg_raw["group_id"],
        artifact_id=pkg_raw["artifact_id"],
        vulnerable_range=pkg_raw.get("vulnerable_range", ""),
        fixed_version=pkg_raw.get("fixed_version", ""),
        remediation_note=pkg_raw.get("remediation_note", ""),
    )

    methods = []
    for m in raw.get("vulnerable_methods", []):
        if "fqcn" not in m or "method" not in m:
            raise ValueError(f"Seed {path} has a vulnerable_methods entry missing 'fqcn'/'method'.")
        methods.append(VulnerableMethod(
            fqcn=m["fqcn"],
            method=m["method"],
            descriptor=m.get("descriptor"),
            confidence=m.get("confidence", "medium"),
            evidence=m.get("evidence", ""),
        ))

    if not methods:
        raise ValueError(f"Seed {path} has no vulnerable_methods defined.")

    return Seed(
        cve=raw["cve"],
        ecosystem=raw.get("ecosystem", "maven"),
        package=package,
        vulnerable_methods=methods,
        notes=raw.get("notes", ""),
        fix_commit=raw.get("seed_source", {}).get("fix_commit", ""),
    )


def load_all_seeds(seeds_dir: Path) -> dict[str, Seed]:
    """
    Load all *.yaml files from a directory.
    Returns a dict keyed by CVE ID, e.g. {"CVE-2021-44228": Seed(...), ...}

    A malformed seed file is skipped (with a warning) rather than aborting
    the whole batch — one bad file shouldn't block assessment of every other CVE.
    """
    seeds = {}
    for yaml_file in sorted(seeds_dir.glob("*.yaml")):
        try:
            seed = load_seed(yaml_file)
        except Exception as exc:
            print(f"  [WARN] Skipping malformed seed {yaml_file}: {exc}", file=sys.stderr)
            continue
        seeds[seed.cve] = seed
    return seeds


if __name__ == "__main__":
    seeds_dir = Path(__file__).parent.parent / "data" / "seeds"
    all_seeds = load_all_seeds(seeds_dir)

    for cve_id, seed in all_seeds.items():
        print(f"\n{cve_id}")
        print(f"  Package : {seed.package.coordinates}")
        print(f"  Range   : {seed.package.vulnerable_range}")
        for m in seed.vulnerable_methods:
            print(f"  Method  : {m.full_signature}")
            print(f"  Confidence: {m.confidence}")
