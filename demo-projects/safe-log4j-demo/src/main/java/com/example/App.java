package com.example;

/**
 * Safe log4j usage demo — contrasting case for NOT_REACHABLE.
 *
 * This project has the same pom.xml dependency as vulnerable-log4j-demo:
 *   log4j-core 2.14.1  (CVE-2021-44228, CVSS 10.0)
 *
 * But this code path never calls any log4j Logger method.
 * The JNDI lookup chain does not exist from this entry point:
 *
 *   App.main()                  ← entry point
 *   └── processInput(String)    ← only String operations, no Logger
 *       └── (no log4j calls)
 *
 * Expected pipeline result:
 *   static.status : not_reachable
 *   decision      : not_affected_candidate
 *   evidence_level: L2  (seed identified, but no call path found)
 *   risk_score    : 1.0  (CVSS 10.0 × 0.10 evidence multiplier)
 *
 * Package-level scanner (Dependabot / OWASP DC) result: VULNERABLE
 * Method-level reachability result:                     NOT_REACHABLE
 */
public class App {

    public static void main(String[] args) {
        String input = args.length > 0 ? args[0] : "hello";
        String result = processInput(input);
        System.out.println("Result: " + result);
    }

    static String processInput(String input) {
        return input.trim().toUpperCase();
    }
}
