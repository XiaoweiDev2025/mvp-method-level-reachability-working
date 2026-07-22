"""
Loads and validates vulnerable method seed definitions from YAML files.

A "seed" is the manually-confirmed entry point for a vulnerability:
the specific Java method that contains or triggers the vulnerable behaviour.
Seeds are the anchor point for both static and runtime reachability analysis.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
import yaml

from warnlog import warn


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


class OutOfScopeSeedError(ValueError):
    """
    Raised for a CVE that is recognized but has no code-level vulnerable method to seed,
    e.g. a fix that changes only a default configuration value, not any method's logic
    (see Ponta et al. 2018, Sec. V-B-5). This is distinct from a malformed seed file: the
    YAML is well-formed and the CVE is real, but method-level reachability analysis does
    not apply to it. Callers that want to report this differently from a genuinely broken
    seed file (missing/invalid required fields) can catch this subclass specifically.
    """


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
        if raw.get("fix_type") == "configuration_only":
            raise OutOfScopeSeedError(
                f"Seed {path} declares fix_type=configuration_only (fix is a default-"
                f"configuration change, not a code change), so no vulnerable method exists "
                f"to seed. Method-level reachability analysis does not apply to this CVE; "
                f"this is a recognized scope boundary, not a malformed seed file."
            )
        raise ValueError(f"Seed {path} has no vulnerable_methods defined.")

    return Seed(
        cve=raw["cve"],
        ecosystem=raw.get("ecosystem", "maven"),
        package=package,
        vulnerable_methods=methods,
        notes=raw.get("notes", ""),
        fix_commit=raw.get("seed_source", {}).get("fix_commit", ""),
    )


def load_all_seeds_with_errors(seeds_dir: Path) -> tuple[dict[str, Seed], list[tuple[Path, str]]]:
    """
    Load all *.yaml files from a directory.

    A malformed seed file is skipped (with a warning) rather than aborting
    the whole batch — one bad file shouldn't block assessment of every other CVE.

    Returns (seeds, errors):
      seeds  — dict keyed by CVE ID, e.g. {"CVE-2021-44228": Seed(...), ...}
      errors — [(path, reason), ...] for every file that was skipped, so a caller
                can tell "no seed files matched the filter" apart from "seeds
                existed but were malformed" instead of both looking like an
                empty result.
    """
    seeds: dict[str, Seed] = {}
    errors: list[tuple[Path, str]] = []
    for yaml_file in sorted(seeds_dir.glob("*.yaml")):
        try:
            seed = load_seed(yaml_file)
        except OutOfScopeSeedError as exc:
            # Well-formed YAML, real CVE, but no code-level method to seed (e.g. a
            # configuration-only fix); distinct from a genuinely broken seed file.
            warn("seed-loader", f"Skipping out-of-scope seed {yaml_file}: {exc}")
            errors.append((yaml_file, str(exc)))
            continue
        except Exception as exc:
            warn("seed-loader", f"Skipping malformed seed {yaml_file}: {exc}")
            errors.append((yaml_file, str(exc)))
            continue
        seeds[seed.cve] = seed
    return seeds, errors


def load_all_seeds(seeds_dir: Path) -> dict[str, Seed]:
    """Load all *.yaml files from a directory. See load_all_seeds_with_errors for details."""
    return load_all_seeds_with_errors(seeds_dir)[0]


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
