"""
Unit tests for seed_loader.py's validation logic.

Run from the project root:
    python analyzer/test_seed_loader.py
"""

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from seed_loader import OutOfScopeSeedError, load_seed

_BASE_SEED = """
cve: CVE-9999-00001
ecosystem: maven
package:
  group_id: com.example
  artifact_id: some-lib
  vulnerable_range: "<2.0.0"
  fixed_version: "2.0.0"
"""


def _write_seed(tmp_dir: Path, extra_yaml: str) -> Path:
    path = tmp_dir / "seed.yaml"
    path.write_text(_BASE_SEED + extra_yaml, encoding="utf-8")
    return path


def test_configuration_only_fix_is_out_of_scope_not_malformed():
    print("=" * 60)
    print("Test: fix_type=configuration_only raises OutOfScopeSeedError")
    print("=" * 60)

    with tempfile.TemporaryDirectory() as tmp:
        path = _write_seed(Path(tmp), "fix_type: configuration_only\n")

        try:
            load_seed(path)
            raise AssertionError("Expected OutOfScopeSeedError, but load_seed succeeded")
        except OutOfScopeSeedError as exc:
            print(f"  Correctly raised OutOfScopeSeedError: {exc}")
        except Exception as exc:
            raise AssertionError(
                f"Expected OutOfScopeSeedError specifically, got {type(exc).__name__}: {exc}"
            )

    print("  PASS")
    return True


def test_genuinely_empty_seed_is_still_malformed():
    print("=" * 60)
    print("Test: no vulnerable_methods AND no fix_type is still a plain ValueError")
    print("=" * 60)

    with tempfile.TemporaryDirectory() as tmp:
        path = _write_seed(Path(tmp), "")  # no vulnerable_methods, no fix_type marker

        try:
            load_seed(path)
            raise AssertionError("Expected ValueError, but load_seed succeeded")
        except OutOfScopeSeedError as exc:
            raise AssertionError(
                f"Expected plain ValueError (malformed), got OutOfScopeSeedError: {exc}"
            )
        except ValueError as exc:
            print(f"  Correctly raised plain ValueError: {exc}")

    print("  PASS")
    return True


if __name__ == "__main__":
    ok = (
        test_configuration_only_fix_is_out_of_scope_not_malformed()
        and test_genuinely_empty_seed_is_still_malformed()
    )
    sys.exit(0 if ok else 1)
