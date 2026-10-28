# Shared Security Core 검증 기록

날짜: 2026-10-28 (Asia/Seoul). Windows x64, Node 24.14.0, 실제 VS Code 확장 호스트 1.143.1.

## 저장소와 baseline

`git ls-remote origin refs/heads/main`과 `git rev-parse HEAD`가 모두 `144827579c35d4656ef91a47d438fc411df053f4`로 일치했습니다. 로컬 main 작업 트리는 시작 시 깨끗했습니다. 실제 package version은 **0.3.0**으로, 요청서의 0.2.0 이후 TI-1도 구현되어 있었습니다. 원격 내용을 checkout/merge/rewrite하거나 Push하지 않았습니다.

수정 전 `npm.cmd test`는 기존 **67개 모두 통과**, 실패/skip 0개였고 `npm.cmd run check`도 통과했습니다. 과거 검증 문서의 성공만 재사용하지 않고 이번 세션에서 다시 실행했습니다.

## 이번 최소 구현

- `src/security-service.js`: 기존 core.scan/status 위의 등록 workspace ID·realpath 재검증, trusted host options, strict parameter, 동시 실행/기한/취소, 생성 scan ID 조회, byte/보관 한도.
- `src/report-model.js`: schemaVersion 1을 유지하는 modelVersion 1.1, legacy finding metadata 보완.
- `src/parsers.js`: 실제 OSV/Trivy 필드로만 package/version/purl/range/fix/provenance 추가, 원시 값 제거, 충돌 관찰과 미분석 상태 보존.
- `src/core.js`: additive metadata 저장, bounded file/result read, Semgrep ID rewriting 비활성, trusted executable cwd에서 한정된 버전 probe.
- `src/extension.js`, `scripts/scan.js`: 같은 서비스 호출. 기존 UI/보고서 사용법 유지.
- `scripts/verify-shared-core.js`, `test/scan-comparison.js`, metadata/service tests, 실제 호스트 regression: 인터페이스 비교 및 보안 경계 검증.
- README/CHANGELOG/SECURITY와 구조/MCP/배포/다음 단계 문서. 라이선스·publisher 선택, packaging, CI 활성화는 하지 않았습니다.

## 테스트 결과

| 실행 | 실제 결과 |
|---|---|
| npm.cmd test | 최종 **91개 통과**, 실패/skip 0개 |
| npm.cmd run check | src/scripts/test 전체 JS 구문 통과 |
| npm.cmd audit --omit=dev --json | 현재 공개 취약점 **0건** (runtime dependency sql.js 1.15.2 유지) |
| git diff --check | 공백 오류 없음. Windows LF/CRLF 안내만 발생 |
| node scripts/live-test.js | 실제 도구 4개 완료, 80건→34건 병합, 원본 해시 유지·가짜 토큰 원문 미저장 |
| node scripts/verify-shared-core.js | 실제 CLI와 직접 scan()의 모델·ID·범위 일치, 원본 유지 |
| scripts/test-vscode.ps1 | 실제 Problems 34개·Python 4행·기본 문제 이동·보고서 열기, CLI 의미 일치 |

실제 도구 버전/원시 탐지 건수는 Semgrep CE **1.182.1 / 2건**, OSV **2.7.0 / 45건**, Gitleaks **8.30.1 / 1건**, Trivy **0.76.1 / 32건**입니다. 병합 후 코드2/의존성29/비밀정보1/설정2, 총 **34건**이고 coverage 미완료 목록은 비어 있습니다. 취약 fixture는 실행하지 않았으며 취약 의존성 설치나 Docker build도 하지 않았습니다.

CLI·VS Code 비교에서는 실행 시각·도구 duration만 제외했습니다. finding ID, 모든 새 metadata, scanner 상태/버전/건수, coverage, snapshot 범위와 limitations는 비교 대상입니다. VS Code UI는 실제 extension host의 Diagnostics와 기본 문제 이동 명령으로 검증했으며 마우스 클릭 영상을 촬영한 것은 아닙니다. 기존 TI 초기화도 호스트에서 유지됨을 확인했습니다. 이번 변경으로 공개 위협 데이터를 다시 대량 수집하지는 않았습니다.

서비스 경계 테스트는 임의 shell/args/실행 파일/출력 경로/패치 입력 거부, 허용되지 않은 root/ID 거부, 등록 symlink 재지정 차단, 상태 응답의 executable 및 비공개 필드 제거, scan ID 전용 조회, pagination/byte/메모리 한도, 결과 오염 방지, timeout/cancel/busy, 비밀값/보고서 파일 경로 미유입, 실제 미설치 처리와 원본 유지, legacy ID 보존, stat 후 성장하는 파일의 bounded read를 포함합니다.

## 실행 중 발견하고 해결한 문제

1. 새 서비스 테스트 초기 2건은 작은 byte fixture 한도와 JSON에서 undefined가 생략되는 차이로 실패했습니다. 충분히 작은 조회/큰 전체 보고서를 분리하고 serialized JSON 의미를 비교하도록 수정한 뒤 통과했습니다.
2. 실제 직접 scan/CLI 비교는 처음에 Semgrep ID만 달랐습니다. 임시 규칙 경로를 rewrite하는 기본 동작을 공식 `--no-rewrite-rule-ids`로 끄고 다시 직접→CLI→VS Code 순서로 실행해 일치를 확인했습니다. 과거 Semgrep 접두사 기반 ID는 달라질 수 있음을 호환 문서에 명시했습니다.
3. 실제 VS Code 재검증 초기에 Semgrep 버전 probe가 10초에서 timeout되었습니다. cwd를 신뢰된 실행 파일 디렉터리로 지정하고 느린 Python 초기화를 고려해 최대30초로 제한했습니다. 이후 Semgrep을 포함한 4개 도구와 34개 Diagnostics·CLI 비교가 통과했습니다. 실패를 정상/미설치로 바꿔 표시하지 않았습니다.

실제 증거 요약은 [shared-core-validation.json](shared-core-validation.json)에 있습니다. 로컬 전체 결과는 `reports/live`, `reports/shared-cli`, `reports/shared-core-cli.json`, `reports/vscode-summary.json`에 있고 Git에서 제외됩니다.

## 검증하지 않은 범위와 다음 gate

**MCP 서버는 미구현입니다.** 서비스의 MCP-shaped payload 테스트는 SDK handshake/tools/list/stdio framing/stdout 순수성/프로토콜 취소/실제 Codex 연결 테스트가 아닙니다. 공식 안정 SDK 2.4.0을 문서/npm metadata로 확인했지만 설치하지 않았습니다. 아직 MCP 도구가 동작한다고 소개하면 안 됩니다.

raw output 디스크 쿼터, 완전한 OS sandbox, kill 실패 시 hard deadline와 자손 전체 종료, 다른 OS/스캐너 버전, 실제 VSIX 생성·내용 검사·격리 설치, CI/Marketplace/공개 release/OS scheduler는 이번에 검증하지 않았습니다. [MCP 설계](mcp-server-design.md), [배포 준비](distribution-readiness.md), [다음 계획](next-development-plan.md)의 gate를 먼저 완료해야 합니다.

TI-1 수집/SQLite는 재사용 대상입니다. 프로젝트 정확 버전 비교와 근거 기반 영향 판정(TI-2), 뉴스 원본 교차 검증(TI-3), 경로/수정 지원은 미구현이며 NOT_ANALYZED를 유지합니다. 사용자 원본 수정·예약 작업 등록·외부 Push/Release/Marketplace 게시 없이 이 단계에서 작업을 마칩니다.
