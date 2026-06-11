package com.example;

import org.apache.commons.io.FilenameUtils;

/**
 * Demo app that calls FilenameUtils.concat() with user-controlled path.
 * This triggers FilenameUtils.getPrefixLength() internally.
 *
 * CVE-2021-29425: getPrefixLength() does not correctly validate Windows
 * drive-relative paths (e.g. "C:foo/bar"), allowing path traversal.
 *
 * Call chain: App.main() -> FilenameUtils.concat() -> FilenameUtils.getPrefixLength()
 */
public class App {
    public static void main(String[] args) {
        String base      = args.length > 0 ? args[0] : "/safe/base/";
        String userInput = args.length > 1 ? args[1] : "file.txt";

        // concat() calls getPrefixLength() on the second argument —
        // that is the vulnerable call site.
        String result = FilenameUtils.concat(base, userInput);
        System.out.println("Resolved path: " + result);
    }
}
