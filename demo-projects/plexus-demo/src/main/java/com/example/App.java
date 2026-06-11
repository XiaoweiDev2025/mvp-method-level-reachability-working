package com.example;

import org.codehaus.plexus.archiver.zip.ZipUnArchiver;
import java.io.File;

/**
 * Demo app that extracts a ZIP archive using plexus-archiver.
 *
 * CVE-2018-1002200 (Zip-Slip): AbstractUnArchiver.extractFile() does not
 * validate that the extraction target path stays within the destination directory.
 * An attacker-controlled archive entry named "../../../etc/cron.d/backdoor"
 * would be extracted outside the intended directory.
 *
 * Call chain: App.main() -> ZipUnArchiver.extract() -> AbstractUnArchiver.extractFile()
 */
public class App {
    public static void main(String[] args) throws Exception {
        String archivePath = args.length > 0 ? args[0] : "archive.zip";
        String destPath    = args.length > 1 ? args[1] : "output/";

        File archive = new File(archivePath);
        File dest    = new File(destPath);

        if (!archive.exists()) {
            System.out.println("Archive not found: " + archivePath + " (expected for static analysis demo)");
            System.exit(0);
        }

        dest.mkdirs();
        ZipUnArchiver unArchiver = new ZipUnArchiver(archive);
        unArchiver.setDestDirectory(dest);
        unArchiver.extract();
        System.out.println("Extracted to: " + dest.getAbsolutePath());
    }
}
