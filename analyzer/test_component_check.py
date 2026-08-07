"""
Unit tests for component_check.py's version comparison, range matching,
pom.properties extraction, and multi-JAR aggregation.

Run from the project root:
    python analyzer/test_component_check.py
"""

import sys
import tempfile
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from component_check import (
    _compare_versions,
    _read_pom_properties,
    _version_satisfies_range,
    check_component_present,
)
from models import ComponentCheckStatus
from seed_loader import SeedPackage


def test_compare_versions():
    print("=" * 70)
    print("Test: _compare_versions")
    print("=" * 70)
    cases = [
        ("2.14.1", "2.15.0", -1),
        ("2.15.0", "2.15.0", 0),
        ("2.15.1", "2.15.0", 1),
        ("2.7", "2.7.0", 0),        # missing trailing numeric segment == 0
        ("2.7", "2.7-beta1", 1),    # missing trailing qualifier sorts higher
        ("2.0-beta9", "2.0", -1),   # qualifier segment sorts below no qualifier
        ("1.10.0", "1.9.0", 1),     # numeric compare, not lexicographic
        ("2.0-beta2", "2.0-beta10", -1),  # same-prefix qualifier compared numerically, not lexically
    ]
    for a, b, expected in cases:
        got = _compare_versions(a, b)
        got_sign = (got > 0) - (got < 0)
        assert got_sign == expected, f"_compare_versions({a!r}, {b!r}) = {got}, expected sign {expected}"
        print(f"  _compare_versions({a!r}, {b!r}) -> {got_sign} (OK)")

    # Cross-qualifier-prefix and unparseable comparisons must fail open (None),
    # not silently guess via lexical string order.
    ambiguous_cases = [
        ("2.0-beta9", "2.0-rc1"),    # different qualifier prefixes -- Maven's
                                      # own ordering table is not implemented
        ("1.0+build5", "1.0.0"),     # '+' is outside the supported token shape
    ]
    for a, b in ambiguous_cases:
        got = _compare_versions(a, b)
        assert got is None, f"_compare_versions({a!r}, {b!r}) = {got}, expected None (ambiguous)"
        print(f"  _compare_versions({a!r}, {b!r}) -> None (ambiguous, OK)")
    print("  PASS")


def test_version_satisfies_range():
    print("=" * 70)
    print("Test: _version_satisfies_range")
    print("=" * 70)
    cases = [
        ("2.14.1", "<2.15.0", True),
        ("2.15.0", "<2.15.0", False),
        ("2.6", ">=2.0,<2.7", True),
        ("2.7", ">=2.0,<2.7", False),
        ("1.9", ">=2.0,<2.7", False),
        ("2.0-beta9", ">=2.0-beta9,<2.15.0", True),
        ("1.9", ">=1.5,<1.10.0", True),
        ("1.10.0", ">=1.5,<1.10.0", False),
    ]
    for version, range_str, expected in cases:
        got = _version_satisfies_range(version, range_str)
        assert got == expected, f"_version_satisfies_range({version!r}, {range_str!r}) = {got}, expected {expected}"
        print(f"  _version_satisfies_range({version!r}, {range_str!r}) -> {got} (OK)")

    # An unparseable/ambiguous version must fail open to None (inconclusive),
    # never silently resolve to True or False.
    got = _version_satisfies_range("2.0-rc1", ">=2.0-beta9,<2.15.0")
    assert got is None, f"expected None (ambiguous qualifier comparison), got {got}"
    print(f"  _version_satisfies_range('2.0-rc1', '>=2.0-beta9,<2.15.0') -> None (ambiguous, OK)")
    print("  PASS")


def _make_jar(tmp_dir: Path, name: str, group_id: str, artifact_id: str, version: str) -> Path:
    jar_path = tmp_dir / name
    with zipfile.ZipFile(jar_path, "w") as z:
        z.writestr(
            f"META-INF/maven/{group_id}/{artifact_id}/pom.properties",
            f"groupId={group_id}\nartifactId={artifact_id}\nversion={version}\n",
        )
        z.writestr(f"{artifact_id.replace('-', '/')}/Marker.class", b"")
    return jar_path


def test_read_pom_properties_and_check_component_present():
    print("=" * 70)
    print("Test: _read_pom_properties / check_component_present")
    print("=" * 70)
    with tempfile.TemporaryDirectory() as tmp:
        tmp_dir = Path(tmp)

        vulnerable_jar = _make_jar(tmp_dir, "log4j-core-2.14.1.jar", "org.apache.logging.log4j", "log4j-core", "2.14.1")
        safe_jar = _make_jar(tmp_dir, "log4j-core-2.17.1.jar", "org.apache.logging.log4j", "log4j-core", "2.17.1")
        unrelated_jar = _make_jar(tmp_dir, "commons-io-2.6.jar", "commons-io", "commons-io", "2.6")

        coords = _read_pom_properties(vulnerable_jar)
        assert coords == ("org.apache.logging.log4j", "log4j-core", "2.14.1"), coords
        print(f"  _read_pom_properties(vulnerable_jar) -> {coords} (OK)")

        seed_package = SeedPackage(
            group_id="org.apache.logging.log4j",
            artifact_id="log4j-core",
            vulnerable_range="<2.15.0",
            fixed_version="2.15.0",
        )

        # Vulnerable version present -> IN_RANGE
        result = check_component_present([unrelated_jar, vulnerable_jar], seed_package)
        assert result.status == ComponentCheckStatus.IN_RANGE
        assert result.found_version == "2.14.1"
        assert result.jar_path == vulnerable_jar
        print(f"  check_component_present([...vulnerable_jar]) -> status={result.status.value} (OK)")

        # Safe version present -> OUT_OF_RANGE (the L1 short-circuit case)
        result = check_component_present([unrelated_jar, safe_jar], seed_package)
        assert result.status == ComponentCheckStatus.OUT_OF_RANGE
        assert result.found_version == "2.17.1"
        print(f"  check_component_present([...safe_jar]) -> status={result.status.value} (OK)")

        # No matching JAR at all -> INCONCLUSIVE (must NOT claim absence)
        result = check_component_present([unrelated_jar], seed_package)
        assert result.status == ComponentCheckStatus.INCONCLUSIVE
        assert result.matches == []
        print(f"  check_component_present([unrelated_jar only]) -> status={result.status.value} (OK)")

        # Both a vulnerable AND a safe copy on the classpath (an ordinary Maven
        # version conflict: a patched direct dependency alongside an older
        # version pulled in transitively): must resolve IN_RANGE, not
        # short-circuit on whichever is found first.
        # _iter_jars sorts directory contents but here we pass an explicit
        # list, so check both orderings.
        result = check_component_present([safe_jar, vulnerable_jar], seed_package)
        assert result.status == ComponentCheckStatus.IN_RANGE, \
            "a genuinely vulnerable copy elsewhere on the classpath must not be masked by a safe one found first"
        assert len(result.matches) == 2
        print(f"  check_component_present([safe_jar, vulnerable_jar]) -> status={result.status.value}, "
              f"{len(result.matches)} matches (OK)")

        result = check_component_present([vulnerable_jar, safe_jar], seed_package)
        assert result.status == ComponentCheckStatus.IN_RANGE
        print(f"  check_component_present([vulnerable_jar, safe_jar]) -> status={result.status.value} (OK)")

        # A matching JAR whose version can't be confidently compared must
        # push the whole result to INCONCLUSIVE, not silently resolve either way.
        ambiguous_jar = _make_jar(tmp_dir, "log4j-core-2.0-rc1.jar", "org.apache.logging.log4j", "log4j-core", "2.0-rc1")
        seed_with_qualifier_range = SeedPackage(
            group_id="org.apache.logging.log4j",
            artifact_id="log4j-core",
            vulnerable_range=">=2.0-beta9,<2.15.0",
            fixed_version="2.15.0",
        )
        result = check_component_present([ambiguous_jar], seed_with_qualifier_range)
        assert result.status == ComponentCheckStatus.INCONCLUSIVE
        assert len(result.matches) == 1
        print(f"  check_component_present([ambiguous_jar]) -> status={result.status.value} (OK)")

    print("  PASS")


if __name__ == "__main__":
    test_compare_versions()
    test_version_satisfies_range()
    test_read_pom_properties_and_check_component_present()
    print("\nAll component_check tests passed.")
