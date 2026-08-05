# RuoYi external validation (CVE-2021-29425, NOT_REACHABLE case)

This directory holds pre-built artifacts used for a second external validation
case, complementing the `christophetd/log4shell-vulnerable-app` case (which
demonstrates a REACHABLE/AFFECTED external finding) with an independently
authored, real application that produces a genuine NOT_REACHABLE finding.

Unlike the Log4Shell case, this project's source is **not** vendored here —
only the compiled JARs used as pipeline input. RuoYi is a full multi-module
Spring application with a large static-asset tree unrelated to the analysis;
vendoring its source would add repository weight without adding anything the
pipeline actually consumes. The exact provenance below is sufficient to
rebuild these JARs from scratch.

## Provenance

- Upstream project: [`yangzongzhuan/RuoYi`](https://github.com/yangzongzhuan/RuoYi)
  — a widely used open-source Java administration framework, unrelated to
  this thesis.
- Tag: `v4.5.1`
- Commit: `680ad3a5e0c72460365387c323b241b5c707d0f8` (2020-11-18)
- Relevant dependency: `commons-io:2.5`, declared via the
  `<commons.io.version>2.5</commons.io.version>` property in the root
  `pom.xml` — within the vulnerable range for CVE-2021-29425 (`>=2.0,<2.7`).
  The project has since been upgraded past the fixed version (2.7); this tag
  is a historical snapshot of a genuinely vulnerable dependency state, not a
  claim about the project's current security posture.

## Why this project

`FilenameUtils.getExtension()` — the only call into `FilenameUtils` anywhere
in the compiled application — is used by `FileUploadUtils.upload()`
(`ruoyi-common/src/main/java/com/ruoyi/common/utils/file/FileUploadUtils.java`),
which is itself called from `CommonController.uploadFile(MultipartFile)`
(`ruoyi-admin/.../web/controller/common/CommonController.java`), a real,
publicly-routed file-upload endpoint (`POST /common/upload`) that accepts
attacker-controlled input. `getExtension()` internally uses
`indexOfExtension()`/`indexOfLastSeparator()`, not `getPrefixLength()` — the
actual vulnerable method — so this is a genuine, structural non-reachable
case rather than an untested one.

## Directory contents

```
jars/
  ruoyi-admin.jar
  ruoyi-common-4.5.1.jar
  ruoyi-framework-4.5.1.jar
  ruoyi-generator-4.5.1.jar
  ruoyi-quartz-4.5.1.jar
  ruoyi-system-4.5.1.jar
  deps/            # all 121 third-party dependency JARs, incl. commons-io-2.5.jar
```

## Reproducing from source

```bash
git clone --branch v4.5.1 https://github.com/yangzongzhuan/RuoYi.git
cd RuoYi
mvn install -DskipTests
mvn dependency:copy-dependencies -DoutputDirectory=$(pwd)/target/all-deps
```

## Running the pipeline against these JARs

```bash
python analyzer/pipeline.py \
  --project-jars demo-projects/ruoyi-external-validation/jars/*.jar \
                 demo-projects/ruoyi-external-validation/jars/deps/*.jar \
  --project-artifact "com.ruoyi:ruoyi:4.5.1" \
  --cve CVE-2021-29425 \
  --extra-entry-points "com.ruoyi.web.controller.common.CommonController.uploadFile(Lorg/springframework/web/multipart/MultipartFile;)Lcom/ruoyi/common/core/domain/AjaxResult;" \
  --output reports/ruoyi-external.json \
  --output-vex reports/ruoyi-external.vex.json
```

## Result

| | |
|---|---|
| JARs analysed | 127 (6 module JARs + 121 dependencies) |
| Call graph edges extracted | 874,611 |
| Entry points used | `RuoYiApplication.main`, `EscapeUtil.main`, `CommonController.uploadFile` |
| Static result | NOT_REACHABLE (confidence 0.7) |
| Final decision | **L2 not_affected_candidate, risk=0.5, conf=0.595** |

No live runtime instrumentation was captured for this case — see the
thesis's External Validation Results section for why that step would not
have added information here (the source-level call-site count already gives
a more exhaustive guarantee than a runtime trace bounded to whichever
payloads happen to be sent).
