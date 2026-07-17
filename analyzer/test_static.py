"""
End-to-end test: CVE-2021-44228 (Log4Shell) should be STATIC_REACHABLE.

Run from the project root:
    python analyzer/test_static.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from seed_loader import load_seed, VulnerableMethod
from static_analyzer import StaticAnalyzer, _matches_seed

ROOT = Path(__file__).parent.parent
SEEDS_DIR = ROOT / "data" / "seeds"
DEMO_DIR = ROOT / "demo-projects" / "vulnerable-log4j-demo"
EXTRACTOR_JAR = ROOT / "tools" / "callgraph-extractor" / "target" / "callgraph-extractor-1.0.jar"
CALLGRAPH_CACHE = ROOT / "data" / "callgraph-log4j.txt"

def test_log4shell():
    print("=" * 60)
    print("Test: CVE-2021-44228 (Log4Shell) — expected: REACHABLE")
    print("=" * 60)

    seed = load_seed(SEEDS_DIR / "CVE-2021-44228.yaml")
    vm = seed.primary_method

    print(f"  Seed method : {vm.full_signature}")
    print(f"  Confidence  : {vm.confidence}")
    print()

    app_jars = [
        DEMO_DIR / "target" / "vulnerable-log4j-demo-1.0-SNAPSHOT.jar",
        DEMO_DIR / "target" / "dependency" / "log4j-core-2.14.1.jar",
        DEMO_DIR / "target" / "dependency" / "log4j-api-2.14.1.jar",
    ]

    analyzer = StaticAnalyzer(EXTRACTOR_JAR)
    evidence = analyzer.analyze(
        app_jars, vm,
        callgraph_cache=CALLGRAPH_CACHE,
        project_prefix="com.example",
    )

    print()
    print(f"  Status           : {evidence.status.value}")
    print(f"  Confidence       : {evidence.confidence}")
    print(f"  Engine           : {evidence.engine}")
    print(f"  Fingerprint      : {evidence.analysis_fingerprint}")
    print(f"  Entry points     : {evidence.entry_points_used}")

    if evidence.call_path:
        print(f"\n  Call path ({len(evidence.call_path)} hops):")
        for i, step in enumerate(evidence.call_path):
            edge = evidence.call_path_annotated[i]["edge_type"] if i < len(evidence.call_path_annotated) else "?"
            print(f"    [{i}] {step}  ({edge})")
    elif evidence.uncertain_features:
        print(f"  Uncertain        : {evidence.uncertain_features}")

    print()
    assert evidence.status.value == "reachable", f"Expected reachable, got {evidence.status.value}"
    assert evidence.analysis_fingerprint, "analysis_fingerprint should be non-empty"
    assert evidence.entry_points_used, "entry_points_used should be non-empty"
    assert evidence.call_path_annotated, "call_path_annotated should be non-empty"
    assert all("sig" in h and "edge_type" in h for h in evidence.call_path_annotated), \
        "Each annotated hop must have 'sig' and 'edge_type'"
    assert evidence.call_path_annotated[0]["edge_type"] == "ENTRY_POINT"

    print("  PASS: Log4Shell is REACHABLE — all assertions passed")
    return True


def test_seed_matching():
    print("=" * 60)
    print("Test: seed matching tiers (exact / relocated / no match)")
    print("=" * 60)

    seed = VulnerableMethod(
        fqcn="org.codehaus.plexus.archiver.AbstractUnArchiver",
        method="extractFile",
        descriptor="(Ljava/io/File;Ljava/io/File;Ljava/io/InputStream;Ljava/lang/String;"
                    "Ljava/util/Date;ZLjava/lang/Integer;Ljava/lang/String;)V",
        confidence="high",
    )

    exact_sig = (
        "org.codehaus.plexus.archiver.AbstractUnArchiver.extractFile"
        "(Ljava/io/File;Ljava/io/File;Ljava/io/InputStream;Ljava/lang/String;"
        "Ljava/util/Date;ZLjava/lang/Integer;Ljava/lang/String;)V"
    )
    relocated_sig = (
        "com.myorg.shaded.plexus.archiver.AbstractUnArchiver.extractFile"
        "(Ljava/io/File;Ljava/io/File;Ljava/io/InputStream;Ljava/lang/String;"
        "Ljava/util/Date;ZLjava/lang/Integer;Ljava/lang/String;)V"
    )
    unrelated_sig = "com.example.other.Thing.doStuff()V"
    renamed_class_sig = (
        "com.myorg.shaded.plexus.archiver.UnArchiverImpl.extractFile"
        "(Ljava/io/File;Ljava/io/File;Ljava/io/InputStream;Ljava/lang/String;"
        "Ljava/util/Date;ZLjava/lang/Integer;Ljava/lang/String;)V"
    )

    assert _matches_seed(exact_sig, seed) == "exact"
    assert _matches_seed(relocated_sig, seed) == "relocated_package_suspected"
    assert _matches_seed(unrelated_sig, seed) is None
    # A genuinely renamed class (not just relocated) must not match — that is
    # a deliberate scope boundary, not a bug: distinguishing it from relocation
    # would require bytecode clone detection, which this analyzer does not do.
    assert _matches_seed(renamed_class_sig, seed) is None

    print("  PASS: exact match, relocated-package match, and non-matches all correct")
    return True


if __name__ == "__main__":
    ok = test_log4shell() and test_seed_matching()
    sys.exit(0 if ok else 1)
