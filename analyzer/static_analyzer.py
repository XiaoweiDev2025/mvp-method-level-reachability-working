"""
Static reachability analyzer.

Loads a call graph produced by the Java CallGraphExtractor tool and
answers the question: "Can the vulnerable seed method be reached from
any application entry point?"

Returns a StaticEvidence with one of three states:
  REACHABLE     — a call path was found
  NOT_REACHABLE — BFS exhausted with no path to the seed
  UNKNOWN       — analysis is structurally incomplete (e.g., too many
                  missing class edges to trust a NOT_REACHABLE result)

The analysis uses CHA (Class Hierarchy Analysis): when a call is made
on an interface or abstract class, we conservatively assume all known
concrete implementors might be dispatched at runtime. This is sound
(no false NOT_REACHABLEs due to missed polymorphism) but not complete
(may produce false REACHABLE results for dead dispatch targets).
"""

from __future__ import annotations

import hashlib
import subprocess
import sys
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from models import StaticEvidence, StaticReachability
from seed_loader import VulnerableMethod


# ---------------------------------------------------------------------------
# Call graph data structure
# ---------------------------------------------------------------------------

@dataclass
class CallGraph:
    """
    In-memory call graph parsed from the extractor's text output.

    Edges are stored twice:
      - callers: forward index  caller_sig -> {callee_sig, ...}
      - callees: reverse index  callee_sig -> {caller_sig, ...}  (unused for BFS but useful for debugging)

    Class hierarchy:
      - superclass:   class -> direct superclass (single inheritance)
      - interfaces:   class -> {interface, ...}  (a class can implement many)
      - _all_subtypes is computed once from the above two after loading.
    """
    # Storage backend for the call graph. At ecosystem scale (Maven Central-wide),
    # this dict could be replaced by a Neo4j-backed proxy — the BFS above is unchanged.
    callers: dict[str, set[str]] = field(default_factory=dict)
    superclass: dict[str, str] = field(default_factory=dict)
    interfaces: dict[str, set[str]] = field(default_factory=dict)
    _all_subtypes: dict[str, set[str]] = field(default_factory=dict)

    def add_call(self, caller: str, callee: str) -> None:
        self.callers.setdefault(caller, set()).add(callee)

    def add_extends(self, subclass: str, superclass: str) -> None:
        self.superclass[subclass] = superclass

    def add_implements(self, cls: str, iface: str) -> None:
        self.interfaces.setdefault(cls, set()).add(iface)

    def compute_cha(self) -> None:
        """
        Build _all_subtypes: for every type T, the set of all classes
        that are direct or indirect subclasses/implementors of T.

        Why this matters for Log4Shell:
          Logger (interface)
            <- ExtendedLogger (interface extends Logger)
               <- AbstractLogger (abstract class implements ExtendedLogger)
                  <- Logger (concrete class in log4j-core extends AbstractLogger)
          StrLookup (interface)
            <- AbstractLookup (abstract class implements StrLookup)
               <- JndiLookup (concrete class extends AbstractLookup)

        When BFS sees a call to Logger.error(...), plain edge traversal
        stops at the interface node. CHA expansion adds
        AbstractLogger.error(...) and Logger.error(...) as candidates,
        continuing the search through the concrete call chain.

        Implementation: for each type T, BFS upward through EXTENDS and
        IMPLEMENTS edges, registering T as a subtype of every ancestor found.
        We handle BOTH directions correctly:
          - class extends class        → EXTENDS edge
          - class implements interface → IMPLEMENTS edge (stored in self.interfaces)
          - interface "extends" iface  → also IMPLEMENTS edge (ASM uses interfaces[]
            for interface-to-interface inheritance, not superName)
        """
        # Collect all known TYPE names (class names only, not method signatures).
        # self.superclass and self.interfaces store pure class names.
        all_types: set[str] = set()
        for cls, sc in self.superclass.items():
            all_types.add(cls)
            all_types.add(sc)
        for cls, ifaces in self.interfaces.items():
            all_types.add(cls)
            all_types.update(ifaces)

        # For each type, BFS upward through the hierarchy and register it as
        # a subtype of every ancestor encountered.
        self._all_subtypes.clear()
        for cls in all_types:
            visited: set[str] = set()
            queue: deque[str] = deque([cls])

            while queue:
                current = queue.popleft()
                if current in visited:
                    continue
                visited.add(current)

                # Register cls as a subtype of current (skip self-registration)
                if current != cls:
                    self._all_subtypes.setdefault(current, set()).add(cls)

                # Follow EXTENDS (works for both class->class and,
                # in rare cases, interface->Object which we skip anyway)
                if current in self.superclass:
                    queue.append(self.superclass[current])

                # Follow IMPLEMENTS — this covers:
                #   • class implements interface
                #   • interface "extends" interface (stored as IMPLEMENTS by our extractor)
                for parent in self.interfaces.get(current, set()):
                    queue.append(parent)

    def cha_targets(self, callee_sig: str) -> dict[str, str]:
        """
        Given a callee signature like "org.log4j.StrLookup.lookup(...)V",
        return a dict mapping each potential dispatch target to its edge type:
          "CALL"                        — the original callee (direct bytecode call)
          "CHA_EXPANSION[Base→Subtype]" — a concrete subtype that overrides the method
          "INHERITED"                   — an ancestor class that declares the method body

        Two directions:
          DOWN (subtypes): if T.m() is called, any subclass of T that overrides
            m() is a potential target at runtime.
          UP (supertypes): if T.m() has no body in T (it's inherited), the actual
            code lives in T's superclass (or its superclass, etc.). We must include
            that declaring class in the BFS so we don't hit a dead end.

        Example: App.main calls ZipUnArchiver.extract()V.
          ZipUnArchiver does NOT define extract() — it inherits it from AbstractUnArchiver.
          Without upward resolution, the BFS sees ZipUnArchiver.extract() → no edges → dead end.
          With upward resolution, we also enqueue AbstractUnArchiver.extract() which has edges.
        """
        base_class = _class_of(callee_sig)
        method_and_desc = _method_and_desc_of(callee_sig)
        if not base_class or not method_and_desc:
            return {callee_sig: "CALL"}

        targets: dict[str, str] = {callee_sig: "CALL"}

        # DOWN: concrete subtypes that might override the method
        for subtype in self._all_subtypes.get(base_class, set()):
            targets[f"{subtype}.{method_and_desc}"] = f"CHA_EXPANSION[{base_class}->{subtype}]"

        # UP: if callee has no outgoing edges (method not defined in base_class),
        # walk up the EXTENDS chain to find the declaring superclass.
        # Add all ancestors as candidates (conservative but sound).
        if callee_sig not in self.callers:
            current = self.superclass.get(base_class)
            while current:
                ancestor_sig = f"{current}.{method_and_desc}"
                targets[ancestor_sig] = "INHERITED"
                if ancestor_sig in self.callers:
                    break  # found the declaring class; no need to go further
                current = self.superclass.get(current)

        return targets

    @property
    def total_edges(self) -> int:
        return sum(len(callees) for callees in self.callers.values())


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def parse_callgraph(path: Path) -> CallGraph:
    """
    Parse the text file produced by CallGraphExtractor.java.

    Expected line formats:
      CALL   <caller-sig>  <callee-sig>
      EXTENDS  <subclass>  <superclass>
      IMPLEMENTS  <class>  <interface>
    """
    cg = CallGraph()
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) != 3:
                continue
            kind, left, right = parts
            if kind == "CALL":
                cg.add_call(left, right)
            elif kind == "EXTENDS":
                cg.add_extends(left, right)
            elif kind == "IMPLEMENTS":
                cg.add_implements(left, right)

    cg.compute_cha()
    return cg


# ---------------------------------------------------------------------------
# BFS reachability
# ---------------------------------------------------------------------------

def bfs_reachable(
    cg: CallGraph,
    entry_points: list[str],
    seed: VulnerableMethod,
) -> tuple[bool, list[str], list[dict]]:
    """
    Breadth-first search from entry_points through the call graph.
    Returns (is_reachable, path, annotated_path) where:
      path            — list of method signatures from entry to seed
      annotated_path  — same path, each hop tagged with its edge_type:
                        ENTRY_POINT | CALL | CHA_EXPANSION[X→Y] | INHERITED

    BFS (not DFS) because:
      - It finds the SHORTEST path, which makes the evidence easier to audit.
      - It avoids pathological depth explosions in large call graphs.

    CHA expansion happens on every node we visit: for each outgoing edge
    (A calls B), we also enqueue all known concrete implementations of B.
    """
    visited: set[str] = set()
    # Queue items: (sig, plain_path, annotated_path)
    queue: deque[tuple[str, list[str], list[dict]]] = deque()

    for ep in entry_points:
        queue.append((ep, [ep], [{"sig": ep, "edge_type": "ENTRY_POINT"}]))

    while queue:
        current, path, annotated = queue.popleft()

        if current in visited:
            continue
        visited.add(current)

        # Check: does current match the seed?
        if _matches_seed(current, seed):
            return True, path, annotated

        # Get direct callees and expand via CHA (returns dict[sig, edge_type])
        for direct_callee in cg.callers.get(current, set()):
            for callee, edge_type in cg.cha_targets(direct_callee).items():
                if callee not in visited:
                    queue.append((
                        callee,
                        path + [callee],
                        annotated + [{"sig": callee, "edge_type": edge_type}],
                    ))

    return False, [], []


# ---------------------------------------------------------------------------
# Entry point detection
# ---------------------------------------------------------------------------

def find_entry_points(
    cg: CallGraph,
    project_prefix: Optional[str] = None,
    extra_entry_points: Optional[list[str]] = None,
) -> list[str]:
    """
    Find application entry points in the call graph.

    project_prefix: if provided, only main() methods whose class starts with
      this prefix are included (e.g. "com.example" keeps com.example.App.main
      but drops org.apache.logging.log4j.core.tools.CustomLoggerGenerator.main).
      Without a prefix every main() in the graph is included — this over-counts
      when dependency JARs are on the classpath, because library tool classes
      (Version.main, PluginManager.main, etc.) get treated as entry points and
      inflate reachability.

    extra_entry_points: additional method signatures to seed BFS from, regardless
      of prefix (e.g. Servlet.service, Spring @RequestMapping handlers).
    """
    entry_points = []
    for method_sig in cg.callers:
        if ".main(" in method_sig and "([Ljava/lang/String;)V" in method_sig:
            if project_prefix is None or method_sig.startswith(project_prefix + "."):
                entry_points.append(method_sig)

    if extra_entry_points:
        for ep in extra_entry_points:
            if ep in cg.callers and ep not in entry_points:
                entry_points.append(ep)

    return entry_points


# ---------------------------------------------------------------------------
# Main analyzer class
# ---------------------------------------------------------------------------

class StaticAnalyzer:
    """
    Orchestrates: run extractor -> parse graph -> find entry points -> BFS.
    """

    def __init__(self, extractor_jar: Path):
        self.extractor_jar = extractor_jar

    def run_extractor(self, app_jars: list[Path], output_file: Path) -> None:
        """Run the Java callgraph extractor as a subprocess."""
        cmd = [
            "java", "-jar", str(self.extractor_jar),
            str(output_file),
        ] + [str(j) for j in app_jars]

        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"Extractor failed:\n{result.stderr}")
        # Extractor prints stats to stderr
        print(f"  [extractor] {result.stderr.strip()}", file=sys.stderr)

    def analyze(
        self,
        app_jars: list[Path],
        seed_method: VulnerableMethod,
        callgraph_cache: Optional[Path] = None,
        project_prefix: Optional[str] = None,
        extra_entry_points: Optional[list[str]] = None,
    ) -> StaticEvidence:
        """
        Full pipeline: extract call graph, then run BFS reachability.

        callgraph_cache: if provided, skip extraction and use this file directly.
        project_prefix: Maven groupId used as Java package prefix to filter entry
          points to project-owned classes only (e.g. "com.example").
        extra_entry_points: additional method signatures to seed BFS from.
        """
        if callgraph_cache and callgraph_cache.exists():
            graph_file = callgraph_cache
            print(f"  [INFO] Using cached call graph: {graph_file}", file=sys.stderr)
        else:
            graph_file = callgraph_cache or Path("callgraph.tmp.txt")
            self.run_extractor(app_jars, graph_file)

        fingerprint = hashlib.sha256(graph_file.read_bytes()).hexdigest()[:16]

        cg = parse_callgraph(graph_file)
        print(
            f"  [INFO] Loaded {cg.total_edges} edges, "
            f"{len(cg._all_subtypes)} CHA type entries",
            file=sys.stderr
        )

        entry_points = find_entry_points(cg, project_prefix, extra_entry_points)
        if not entry_points:
            print(
                f"  [WARN] No entry points found"
                + (f" under prefix '{project_prefix}'" if project_prefix else ""),
                file=sys.stderr,
            )
            return StaticEvidence(
                status=StaticReachability.UNKNOWN,
                confidence=0.0,
                uncertain_features=["no_entry_points_found"],
                engine="asm-callgraph-1.0",
                analysis_scope=", ".join(str(j) for j in app_jars),
                analysis_fingerprint=fingerprint,
            )

        print(f"  [INFO] Entry points ({len(entry_points)}): {entry_points}", file=sys.stderr)

        reachable, path, annotated_path = bfs_reachable(cg, entry_points, seed_method)

        if reachable:
            return StaticEvidence(
                status=StaticReachability.REACHABLE,
                confidence=0.9,    # 0.9 not 1.0: CHA may have false positive dispatch targets
                call_path=path,
                call_path_annotated=annotated_path,
                entry_points_used=entry_points,
                engine="asm-callgraph-1.0",
                analysis_scope=", ".join(str(j) for j in app_jars),
                analysis_fingerprint=fingerprint,
            )
        else:
            return StaticEvidence(
                status=StaticReachability.NOT_REACHABLE,
                confidence=0.7,    # 0.7 not 1.0: reflection/invokedynamic may have been missed
                uncertain_features=["invokedynamic_not_modelled"],
                entry_points_used=entry_points,
                engine="asm-callgraph-1.0",
                analysis_scope=", ".join(str(j) for j in app_jars),
                analysis_fingerprint=fingerprint,
            )


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _class_of(sig: str) -> Optional[str]:
    """
    Extract the class name from a full method signature.
    "org.example.Foo.bar(Ljava/lang/String;)V"  ->  "org.example.Foo"

    Strategy: find the first '(' (start of descriptor), then find the last
    '.' before it — that separates class from method name.
    """
    paren = sig.find("(")
    prefix = sig[:paren] if paren != -1 else sig
    dot = prefix.rfind(".")
    if dot == -1:
        return None
    return prefix[:dot]


def _method_and_desc_of(sig: str) -> Optional[str]:
    """
    Extract 'methodName(descriptor)ReturnType' from a full signature.
    "org.example.Foo.bar(Ljava/lang/String;)V"  ->  "bar(Ljava/lang/String;)V"
    """
    paren = sig.find("(")
    prefix = sig[:paren] if paren != -1 else sig
    dot = prefix.rfind(".")
    if dot == -1:
        return None
    suffix = sig[paren:] if paren != -1 else ""
    return prefix[dot + 1:] + suffix


def _matches_seed(method_sig: str, seed: VulnerableMethod) -> bool:
    """
    Check if a call graph signature matches the seed method definition.

    Matching rules:
      1. FQCN must match exactly.
      2. Method name must match exactly.
      3. If seed has a descriptor, it must match too. If not, name match suffices.

    The call graph signature format is: "fqcn.method(descriptor)return"
    The seed.full_signature is: "fqcn.method(descriptor)return"
    So for seeds with descriptors, we just compare the full strings.
    """
    cls = _class_of(method_sig)
    method_and_desc = _method_and_desc_of(method_sig)

    if not cls or not method_and_desc:
        return False

    if cls != seed.fqcn:
        return False

    # method_and_desc looks like: "lookup(Lorg/...;)Ljava/lang/String;"
    method_name = method_and_desc.split("(")[0]
    if method_name != seed.method:
        return False

    # If seed has a descriptor, require it to match exactly.
    if seed.descriptor:
        descriptor_in_sig = "(" + method_and_desc.split("(", 1)[1] if "(" in method_and_desc else ""
        return descriptor_in_sig == seed.descriptor

    return True  # name match is enough when no descriptor is specified
