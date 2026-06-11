"""
Run the demo application with the OpenTelemetry Java agent and capture span output.

What this does:
  1. Launches the vulnerable-log4j-demo with -javaagent:opentelemetry-javaagent.jar
  2. Passes a Log4Shell payload as the user input so JndiLookup.lookup() gets called
  3. OTel instruments JndiLookup.lookup via otel.instrumentation.methods.include
  4. All stdout+stderr (including OTel span output) is written to data/traces/run1.log

Usage:
    python scripts/collect_traces.py
    python scripts/collect_traces.py --payload "hello"    # benign run (NOT_OBSERVED expected)
"""

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
DEMO_DIR   = ROOT / "demo-projects" / "vulnerable-log4j-demo"
AGENT_JAR  = ROOT / "tools" / "otel" / "opentelemetry-javaagent-1.32.0.jar"
TRACES_DIR = ROOT / "data" / "traces"

# The vulnerable method we want to observe
TARGET_METHOD = "org.apache.logging.log4j.core.lookup.JndiLookup[lookup]"

# Log4Shell payload: passes through log4j's StrSubstitutor and triggers JndiLookup.
# We use a local address to avoid network traffic. JNDI connect will fail,
# but JndiLookup.lookup() IS called before the failure — that's what we're tracking.
LOG4SHELL_PAYLOAD = "${jndi:ldap://127.0.0.1/x}"


def build_java_cmd(payload: str, output_log: Path) -> list[str]:
    demo_jar = DEMO_DIR / "target" / "vulnerable-log4j-demo-1.0-SNAPSHOT.jar"
    dep_dir  = DEMO_DIR / "target" / "dependency"

    # Windows classpath separator is ";"
    classpath = f"{demo_jar}{';'}{dep_dir}/*"

    return [
        "java",
        f"-javaagent:{AGENT_JAR}",
        # OTel configuration
        "-Dotel.service.name=vuln-demo",
        "-Dotel.traces.exporter=logging",       # write spans to JUL (goes to stderr)
        "-Dotel.metrics.exporter=none",
        "-Dotel.logs.exporter=none",
        # Instrument JndiLookup.lookup specifically
        f"-Dotel.instrumentation.methods.include={TARGET_METHOD}",
        # Classpath and main class
        "-cp", classpath,
        "com.example.App",
        payload,
    ]


def run(payload: str, output_name: str = "run1.log") -> Path:
    TRACES_DIR.mkdir(parents=True, exist_ok=True)
    output_log = TRACES_DIR / output_name

    cmd = build_java_cmd(payload, output_log)

    print(f"Running demo with payload: {payload!r}")
    print(f"Output -> {output_log}")
    print()

    # Capture both stdout and stderr. OTel's LoggingSpanExporter uses JUL (stderr).
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=30,
        cwd=str(ROOT),
    )

    # Combine stdout and stderr into one trace file so the analyzer has one input.
    combined = result.stdout + result.stderr
    output_log.write_text(combined, encoding="utf-8")

    print(f"  Exit code : {result.returncode}")
    print(f"  Output    : {len(combined.splitlines())} lines -> {output_log}")

    # Preview relevant lines
    relevant = [l for l in combined.splitlines()
                if "JndiLookup" in l or "jndi" in l.lower() or "span" in l.lower()]
    if relevant:
        print(f"\n  OTel/JndiLookup lines found ({len(relevant)}):")
        for line in relevant[:10]:
            print(f"    {line}")
    else:
        print("  (no JndiLookup / span lines found in output)")

    return output_log


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--payload", default=LOG4SHELL_PAYLOAD,
                        help="String to pass as user input to the demo app")
    parser.add_argument("--output", default="run1.log",
                        help="Output filename in data/traces/")
    args = parser.parse_args()

    if not AGENT_JAR.exists():
        print(f"ERROR: OTel agent not found: {AGENT_JAR}", file=sys.stderr)
        sys.exit(1)

    run(args.payload, args.output)
