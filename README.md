# Sentinel6 Phase 2

무료 로컬 스캐너를 실행하는 VS Code 확장입니다. 이 저장소는 구현 시작 시 `.git`만 존재했으므로 Phase 1 검토 대상 코드가 없었으며, 확장 기본 구조도 함께 작성했습니다.

## 실행

Node.js 20 이상, VS Code 1.90 이상을 사용합니다. 런타임 npm 의존성은 없습니다.

1. VS Code에서 이 저장소를 열고 F5 (`Run Sentinel6`)를 실행합니다.
2. Extension Development Host에서 검사할 프로젝트를 엽니다.
3. 명령 팔레트에서 `Sentinel6: Scanner Status / Installation`으로 설치 여부를 확인합니다.
4. `Sentinel6: Scan Project`를 실행합니다. 여러 작업 폴더가 있으면 하나를 선택합니다.
5. Problems 패널의 진단을 선택하면 해당 파일·줄로 이동합니다. 의존성 문제는 잠금/명세 파일 1행으로 이동합니다.
6. 알림의 Cancel 또는 `Sentinel6: Cancel Scan`으로 취소합니다.
7. `Sentinel6: Open Results`로 로컬 JSON을 엽니다. 저장 위치는 Sentinel6 출력 패널에도 표시됩니다.

검사는 저장된 파일을 사용합니다. 원본 소스 대신 임시 복사본을 검사하며 보고서는 확장의 globalStorage/reports에 저장합니다. CLI 기본 저장 위치는 사용자 홈 `.sentinel6/reports`입니다. 검사 프로젝트 내부를 보고서 경로로 지정할 수 없습니다.

```powershell
npm.cmd test
npm.cmd run check
npm.cmd run scan -- "D:\path\to\project"
```

CLI 종료 코드: 0=모든 도구 완료, 2=미설치/실패/부분 완료/취소 존재, 1=전체 실행 오류. 취약점 발견 자체는 실패가 아닙니다.

## 설치 및 오프라인 DB

스캐너 설치나 DB 다운로드는 확장이 자동 실행하지 않습니다. 스캐너는 PATH에서 찾거나 **사용자 설정**에 신뢰하는 절대 실행 파일 경로를 지정합니다. 작업 폴더의 executable/cache 설정은 무시합니다. 셸 스크립트·명령 문자열은 허용하지 않습니다.

```json
{
  "sentinel6.executables": {
    "semgrep": "D:\\tools\\semgrep\\Scripts\\semgrep.exe",
    "osv": "D:\\tools\\osv-scanner.exe",
    "gitleaks": "D:\\tools\\gitleaks.exe",
    "trivy": "D:\\tools\\trivy.exe"
  },
  "sentinel6.caches": {
    "osv": "D:\\scanner-cache\\osv",
    "trivy": "D:\\scanner-cache\\trivy"
  },
  "sentinel6.timeoutSeconds": 120
}
```

공식 설치 문서: [Semgrep CE](https://semgrep.dev/docs/getting-started/), [OSV](https://google.github.io/osv-scanner/installation/), [Gitleaks](https://github.com/gitleaks/gitleaks#installing), [Trivy](https://trivy.dev/docs/latest/getting-started/installation/).

검증에 사용한 Windows 버전은 Semgrep 1.182.1, OSV 2.7.0, Gitleaks 8.30.1, Trivy 0.76.1입니다. 테스트 도구 다운로드 스크립트 `scripts/download-test-tools.ps1`은 고정 버전 GitHub 릴리스를 `.tools`에 저장하고 공식 체크섬과 비교합니다. 체크섬 비교는 독립된 서명 검증을 대체하지 않습니다. 자동 업데이트는 없습니다.

OSV·Trivy는 사전에 무료 취약점 DB를 준비해야 합니다. DB가 없으면 **검사 실패**로 표시하며 정상/취약점 없음으로 취급하지 않습니다. DB는 오래될 수 있습니다. 갱신 시점은 사용자가 관리합니다.

OSV 2.7.0에서 실제 확인한 캐시 배치는 `<cache>/osv-scalibr/PyPI/all.zip`입니다. 공식 문서에는 `osv-scanner` 하위 디렉터리 예시도 있으므로 사용하는 버전에 맞게 확인해야 합니다. PyPI DB는 `https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip`에서 직접 받을 수 있습니다. 다른 생태계에는 해당 생태계 DB가 별도로 필요합니다. 이 다운로드는 소스나 패키지 목록을 전송하지 않습니다.

```powershell
# 로컬 DB 준비 시에만 네트워크 사용. 일반 검사는 오프라인.
trivy image --download-db-only --cache-dir "D:\scanner-cache\trivy" --timeout 5m
```

외부 AI API, 계정, API 키, 유료 서비스, 배포는 사용하지 않습니다. 무료 공개 배포 서버/DB 다운로드에 일반 인터넷 연결만 필요합니다.

## 검사 범위와 상태

| 도구 | 영역 | 실행 방식 |
|---|---|---|
| Semgrep CE | 코드 패턴 | `scan --oss-only`, 번들 로컬 규칙, metrics/version check off |
| OSV v2 | 의존성 | `scan source --recursive --offline --no-resolve --no-call-analysis=all` |
| Gitleaks | 현재 파일 비밀정보 | `dir --redact=100 --report-format=json` |
| Trivy | 의존성·비밀정보·설정 | `fs --scanners vuln,secret,misconfig`, offline 및 DB/check 갱신 금지 |

공식 CLI 옵션 근거: [Semgrep](https://docs.semgrep.dev/cli-reference), [OSV source](https://google.github.io/osv-scanner/usage/scan-source/), [OSV offline](https://google.github.io/osv-scanner/usage/offline-mode/), [Gitleaks](https://github.com/gitleaks/gitleaks#usage), [Trivy filesystem](https://trivy.dev/docs/latest/references/configuration/cli/trivy_filesystem/). 설치한 버전의 `--help` 출력과도 대조했습니다.

`not_installed`, `failed`, `cancelled`, `partial`, `completed`를 구분합니다. 실패 원인은 안전한 고정 코드(`timeout`, `scanner_exit`, `invalid_result` 등)로만 기록합니다. 설치된 도구가 실행되지 않아도 다른 도구는 계속합니다. 영역별 `coverage.completed`/`uncompleted`가 보고서와 출력 패널에 표시됩니다. completed는 아래 범위 안에서 도구 실행이 완료되었다는 뜻이며 프로젝트 전체의 안전성을 보장하지 않습니다.

- Semgrep 번들 규칙은 Python eval/shell 및 JavaScript/TypeScript eval의 3개 기본 규칙입니다. 전체 보안 규칙 모음이 아닙니다.
- Git 이력, 심볼릭 링크, 5 MiB 초과 파일, `.git`, `.tools`, `.cache`, `node_modules`, 가상환경 및 build/dist/reports 디렉터리는 제외합니다. 최대 20,000개/100 MiB를 넘으면 snapshot 실패로 표시합니다.
- 복사본에서 프로젝트의 Trivy/Gitleaks/OSV 설정을 제외하여 사용자 코드나 외부 스캐너 설정을 실행하지 않습니다. Semgrep 자체 제외 규칙 및 각 도구의 지원 언어/파일 형식도 적용됩니다.
- SCA 중복은 동일 파일·패키지·취약점 ID/별칭으로 병합합니다. 비밀정보는 동일 파일·시작 행으로 병합하므로 한 행의 여러 비밀정보는 하나로 묶일 수 있습니다. 서로 다른 파일/패키지는 유지합니다.
- 비밀값, 코드 조각, 원시 stderr, 스캐너가 생성한 설명은 로그·공통 보고서로 전달하지 않습니다. 식별자·상대 경로·위치·등급만 허용 목록으로 변환합니다. 원시 JSON은 임시 폴더에만 존재하고 검사 종료 후 삭제합니다.
- shell:false, 정제된 환경 변수, 실행 파일·인수·결과 경로 검증, 파일 이동 전 realpath 재검증, 스캐너별 시간 제한, 출력 크기 제한, 취소 시 프로세스 트리 종료를 사용합니다. 신뢰된 로컬 workspace와 공식 스캐너를 전제로 합니다.
- Windows Semgrep의 드라이브 간 경로 지연을 피하기 위해 임시 복사본은 보고서 저장소 또는 검사 프로젝트 밖의 쓰기 가능한 스캐너 설치 디렉터리에 생성합니다. 완료·실패·취소 시 정리합니다. 프로세스를 강제 종료하거나 시스템이 중단되면 임시 폴더가 남을 수 있습니다.

## 구조 / API

- `src/extension.js`: VS Code 명령, Diagnostics/Problems, 진행률 및 취소, 보고서 열기.
- `src/core.js`: `scan(root, options)`, `status(executables, signal)`, snapshot, CLI adapter, coverage, 로컬 보고서 저장.
- `src/process.js`: `executable()`, `run()`; 셸 없는 실행, timeout/abort 및 프로세스 종료.
- `src/parsers.js`: `parse()`, `merge()`, `safePath()`, `checkedFile()`; 공통 스키마, 중복 병합 및 탐색 검증.
- `rules/semgrep.yml`: 로컬 CE 규칙.
- `test/*.test.js`: 파서, 경로, 병합, 실패 격리, 원본 보존, timeout/cancel 테스트.
- `test/vscode-runner.js`: 설치된 VS Code의 실제 확장 호스트 통합 검사.
- `fixtures/vulnerable/*`, `scripts/live-test.js`: 실행하지 않는 취약 프로젝트 및 실제 스캐너 검증. 합성 토큰은 실행 시 생성합니다.

공통 JSON: schemaVersion, startedAt/finishedAt, mode, scanners, snapshot, coverage, limitations, findings. findings는 id, file(상대 경로), line/endLine(1부터), rule, aliases, severity, kind, package, scanners, 안전한 고정 message를 포함합니다.

```powershell
# .tools 도구 및 .cache DB가 준비된 상태에서
node scripts/live-test.js
# .tools/vscode-portable에 공식 ZIP을 풀거나 -CodeCli로 설치된 code.cmd 지정
.\scripts\test-vscode.ps1
```

실제 탐지 결과와 검증 범위는 `docs/phase2-validation.md`를 참고하세요.
