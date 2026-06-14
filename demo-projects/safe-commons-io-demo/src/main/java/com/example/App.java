package com.example;

import org.apache.commons.io.FilenameUtils;

/**
 * Safe commons-io demo — contrasting case for NOT_REACHABLE (CVE-2021-29425).
 *
 * Same pom.xml dependency as commons-io-demo:
 *   commons-io 2.6  (CVE-2021-29425, CVSS 4.8)
 *
 * Uses FilenameUtils, but only getExtension() — which calls indexOfExtension()
 * and indexOfLastSeparator(), neither of which calls getPrefixLength().
 * The vulnerable path traversal chain is never entered.
 *
 * Call chain (vulnerable demo):
 *   App.main() -> FilenameUtils.concat() -> FilenameUtils.getPrefixLength()  <- SEEDED
 *
 * Call chain (this demo):
 *   App.main() -> FilenameUtils.getExtension()
 *              -> FilenameUtils.indexOfExtension()
 *              -> FilenameUtils.indexOfLastSeparator()
 *              (getPrefixLength never called)
 *
 * Expected pipeline result:
 *   static.status : not_reachable
 *   decision      : not_affected_candidate
 *   evidence_level: L2
 *   risk_score    : 0.5  (CVSS 4.8 x 0.10)
 *
 * Package-level scanner (Dependabot / OWASP DC): VULNERABLE
 * Method-level reachability:                     NOT_REACHABLE
 */
public class App {

    public static void main(String[] args) {
        String filename = args.length > 0 ? args[0] : "report-2024.pdf";
        String ext = FilenameUtils.getExtension(filename);
        System.out.println("File extension: " + ext);
    }
}
