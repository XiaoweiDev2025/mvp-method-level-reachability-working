package com.example;

import org.apache.commons.text.WordUtils;

/**
 * Safe Text4Shell demo — contrasting case for NOT_REACHABLE (CVE-2022-42889).
 *
 * Same pom.xml dependency as vulnerable-text4shell-demo:
 *   commons-text 1.9  (CVE-2022-42889, CVSS 9.8)
 *
 * But this code never calls StringSubstitutor.replace().
 * StringSubstitutor is not imported or instantiated.
 *
 *   App.main()
 *   └── WordUtils.capitalize(input)   <- safe commons-text usage
 *       └── (no StringSubstitutor calls)
 *
 * Expected pipeline result:
 *   static.status : not_reachable
 *   decision      : not_affected_candidate
 *   evidence_level: L2
 *   risk_score    : 1.0  (CVSS 9.8 x 0.10)
 *
 * Package-level scanner (Dependabot / OWASP DC): VULNERABLE
 * Method-level reachability:                     NOT_REACHABLE
 */
public class App {

    public static void main(String[] args) {
        String input = args.length > 0 ? args[0] : "hello world";
        String result = WordUtils.capitalize(input);
        System.out.println("Result: " + result);
    }
}
