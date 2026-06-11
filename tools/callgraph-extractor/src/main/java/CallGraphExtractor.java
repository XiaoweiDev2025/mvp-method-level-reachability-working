import org.objectweb.asm.*;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.jar.*;

/**
 * Reads one or more JAR files and writes a call graph to a text file.
 *
 * Output line format (one edge per line):
 *
 *   CALL  <caller-sig>  <callee-sig>
 *   EXTENDS  <subclass>  <superclass>
 *   IMPLEMENTS  <class>  <interface>
 *
 * where <caller-sig> and <callee-sig> look like:
 *   com.example.App.main([Ljava/lang/String;)V
 *   org.apache.logging.log4j.core.lookup.JndiLookup.lookup(Lorg/apache/logging/log4j/core/LogEvent;Ljava/lang/String;)Ljava/lang/String;
 *
 * Class names use dot-notation (matching our seed YAML).
 * Descriptor type references keep slash-notation (native JVM format).
 *
 * Usage:
 *   java -jar callgraph-extractor-1.0.jar output.txt jar1.jar [jar2.jar ...]
 */
public class CallGraphExtractor {

    // Using LinkedHashSet preserves insertion order and deduplicates edges.
    private static final Set<String> edges = new LinkedHashSet<>();

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("Usage: CallGraphExtractor <output.txt> <jar1> [jar2] ...");
            System.exit(1);
        }

        String outputPath = args[0];
        int processed = 0;

        for (int i = 1; i < args.length; i++) {
            processJar(args[i]);
            processed++;
        }

        try (PrintWriter pw = new PrintWriter(
                new OutputStreamWriter(new FileOutputStream(outputPath), "UTF-8"))) {
            for (String edge : edges) {
                pw.println(edge);
            }
        }

        System.err.printf("Processed %d JAR(s), wrote %d edges to %s%n",
                processed, edges.size(), outputPath);
    }

    private static void processJar(String jarPath) throws Exception {
        try (JarFile jar = new JarFile(jarPath)) {
            Enumeration<JarEntry> entries = jar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                if (!entry.getName().endsWith(".class")) continue;

                byte[] classBytes;
                try (InputStream is = jar.getInputStream(entry)) {
                    classBytes = is.readAllBytes();
                }

                processClass(classBytes);
            }
        }
    }

    private static void processClass(byte[] classBytes) {
        ClassReader cr = new ClassReader(classBytes);
        cr.accept(new ClassVisitor(Opcodes.ASM9) {

            // currentClass is set in visit() and used by every MethodVisitor below.
            private String currentClass;

            @Override
            public void visit(int version, int access, String name, String signature,
                              String superName, String[] interfaces) {
                // Convert internal name (slashes) to external name (dots) for readability.
                currentClass = name.replace('/', '.');

                // Record class hierarchy for CHA (Class Hierarchy Analysis).
                // We skip java.lang.Object since it's the universal supertype — adding it
                // would create a massive hub node that bloats the graph without helping us.
                if (superName != null && !superName.equals("java/lang/Object")) {
                    edges.add("EXTENDS " + currentClass + " " + superName.replace('/', '.'));
                }
                if (interfaces != null) {
                    for (String iface : interfaces) {
                        edges.add("IMPLEMENTS " + currentClass + " " + iface.replace('/', '.'));
                    }
                }
            }

            @Override
            public MethodVisitor visitMethod(int access, String methodName, String descriptor,
                                              String signature, String[] exceptions) {
                // The full caller signature: "com.example.App.main([Ljava/lang/String;)V"
                // Note: descriptor keeps its native slash-notation (Ljava/lang/String; etc.)
                // because that is what our seed YAML also uses.
                final String callerSig = currentClass + "." + methodName + descriptor;

                return new MethodVisitor(Opcodes.ASM9) {
                    @Override
                    public void visitMethodInsn(int opcode, String owner, String name,
                                                String desc, boolean isInterface) {
                        // owner is in internal format (slashes) — convert class part to dots.
                        // desc keeps its native format (type refs inside still use slashes).
                        String calleeSig = owner.replace('/', '.') + "." + name + desc;
                        edges.add("CALL " + callerSig + " " + calleeSig);
                    }
                    // We deliberately skip visitInvokeDynamicInsn (lambda/invokedynamic)
                    // and visitFieldInsn (field access) for now — they can be added later.
                };
            }
        }, ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
        // SKIP_DEBUG: ignore line numbers / variable names (we don't need them)
        // SKIP_FRAMES: ignore stack frame tables (saves ~30% parse time)
    }
}
