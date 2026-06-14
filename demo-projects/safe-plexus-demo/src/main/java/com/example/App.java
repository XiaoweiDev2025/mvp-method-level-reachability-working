package com.example;

import org.codehaus.plexus.archiver.zip.ZipArchiver;
import java.io.File;

/**
 * Safe plexus demo — contrasting case for NOT_REACHABLE (CVE-2018-1002200).
 *
 * Same pom.xml dependencies as plexus-demo:
 *   plexus-archiver 3.5  (CVE-2018-1002200 Zip-Slip, CVSS 5.5)
 *
 * Uses plexus-archiver but only ZipArchiver (creation), not ZipUnArchiver
 * (extraction). ZipArchiver extends AbstractArchiver, NOT AbstractUnArchiver.
 * The vulnerable extractFile() method in AbstractUnArchiver is never called.
 *
 * Call chain (vulnerable demo):
 *   App.main() -> ZipUnArchiver.extract() -> AbstractUnArchiver.extractFile()  <- SEEDED
 *
 * Call chain (this demo):
 *   App.main() -> ZipArchiver.setDestFile()
 *              (AbstractUnArchiver.extractFile() never called)
 *
 * Expected pipeline result:
 *   static.status : not_reachable
 *   decision      : not_affected_candidate
 *   evidence_level: L2
 *   risk_score    : 0.6  (CVSS 5.5 x 0.10)
 *
 * Package-level scanner (Dependabot / OWASP DC): VULNERABLE
 * Method-level reachability:                     NOT_REACHABLE
 */
public class App {

    public static void main(String[] args) {
        String outputPath = args.length > 0 ? args[0] : "output.zip";
        ZipArchiver archiver = new ZipArchiver();
        archiver.setDestFile(new File(outputPath));
        System.out.println("Archiver configured for: " + outputPath);
        System.out.println("(No files added — static analysis demo only)");
    }
}
