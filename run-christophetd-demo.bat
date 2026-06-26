@echo off
chcp 65001 >nul
java ^
    -javaagent:tools/otel/opentelemetry-javaagent-1.32.0.jar ^
    -Dotel.traces.exporter=logging ^
    -Dotel.metrics.exporter=none ^
    -Dotel.logs.exporter=none ^
    -Dotel.service.name=log4shell-vulnerable-app ^
    "-Dotel.instrumentation.methods.include=org.apache.logging.log4j.core.lookup.JndiLookup[lookup]" ^
    -jar demo-projects/log4shell-vulnerable-app/build/libs/log4shell-vulnerable-app-0.0.1-SNAPSHOT.jar ^
    > data/traces/christophetd.log 2>&1
