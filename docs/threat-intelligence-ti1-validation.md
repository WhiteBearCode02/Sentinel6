# TI-1 검증 기록

검증일: 2026-10-28, Asia/Seoul. Node 24.14.0, Windows x64, VS Code 1.143.1.

## 구현 범위

기존 Phase 2 스캐너 API 및 Problems 기능을 유지하면서 기존 확장 내부에 CISA KEV·GitHub Reviewed Advisories·OSV npm/PyPI 수집, SQLite 캐시, 24시간 주기, 변경 추적, 초기 누락 데이터 이어받기와 기본 Threat Feed를 구현했습니다.

이 단계에서는 프로젝트와의 연관성을 평가하지 않습니다. 모든 Feed 권고는 NOT_ANALYZED입니다. 공개 데이터의 권고 건수와 현재 프로젝트 취약점 건수를 혼동하면 안 됩니다. 독립된 6개 분석 모듈, NVD/KISA/RSS/개별 공급업체 adapter, 공격 경로, 수정/패치, Windows 예약 작업, GitHub Actions, VSIX 배포는 미구현/비활성입니다.

## 실제 공개 데이터 통합 검사

`node scripts/threat-monitor.js reports\threat-live-verified` 및 `node scripts/verify-threat-live.js`를 실행했습니다. 실제 공식 HTTPS 요청만 사용했고, 모의 API·테스트 CVE로 결과를 채우지 않았습니다.

첫 수집에서 발견한 GitHub의 수정일 검색 구문 오류와 OSV 전체 색인의 행 한도 문제를 수정했습니다. GitHub는 공식 API의 날짜 구간을 사용하고, OSV는 필요한 변경 날짜까지 스트리밍합니다. 초기 요청 예산을 넘긴 분량은 partial로 남겼고, 후속 실행에서 실제로 이어받았습니다.

2026-10-28 01:11 KST 통합 검증 결과:

| 출처 | 결과 | 누락 분량 |
|---|---|---|
| CISA KEV | completed | 없음 |
| GitHub reviewed | completed | 없음 |
| OSV npm | completed | 없음 |
| OSV PyPI | completed | 없음 |

- 정규화된 고유 권고 **2,546개**.
- 변경 이력 2,855개(여러 공식 출처를 차례로 결합한 이력 포함).
- 수집 작업 3개(초기 partial 작업과 후속 완료 작업).
- 같은 날 다시 실행할 때 `not_due`로 네트워크 재수집을 하지 않는 것 확인.
- 새 Monitor 인스턴스 초기화 후 같은 권고 건수가 복원되는 것 확인.
- 일반 스케줄은 1초 간격/작은 요청 예산을 사용합니다. 명시적 검증 스크립트는 OSV 공개 API 정책을 확인하고 순차 250 ms 간격과 더 큰 record 예산으로 초기 분량을 확인했습니다. GitHub 요청은 최소 1초 간격을 유지합니다.

로컬 결과 파일:

- `reports/threat-live-verified/live-validation.json`
- `reports/threat-live-verified/latest-feed.json` (최근 200개 표시용 메타데이터)
- `reports/threat-live-verified/threat-intelligence.sqlite` (전체 캐시)

카운트·출처 상태·확장 호스트/스캐너 회귀 결과 요약은 [실제 검증 JSON](./threat-intelligence-ti1-live-validation.json)에 보존했습니다. 이 파일에는 공개 권고 메타데이터의 집계와 검사 상태만 있으며 소스코드·비밀값은 없습니다.

## 실제 VS Code 확장 호스트

`scripts/test-threat-vscode.ps1`는 시스템 사용자 설정과 별도의 테스트 프로필을 사용합니다. 검증한 **실제 공개 데이터** SQLite를 초기 캐시로 복사한 뒤, 확장 호스트 자체에서 수동 갱신을 수행했습니다. 초기 복사는 운영 mock이나 가짜 탐지가 아닙니다.

2026-10-28 01:19 KST 결과:

- VS Code 1.143.1에서 SQLite WASM 초기화 성공.
- 기본 TreeView에 최근 **200행** 생성 및 Feed 포커스 명령 확인.
- 권고 선택 명령으로 실제 공식 출처·시각·수정 이력 JSON 열기 확인.
- `Sentinel6: Refresh Threat Intelligence` 명령이 실제 API를 호출해 completed 반환.
- 네 출처 상태(CISA/GitHub/OSV npm/OSV PyPI)가 모두 completed, pending 없음.
- 갱신된 고유 권고 **2,563개**. 앞선 CLI 검사 후 새 데이터가 수집된 결과입니다.
- 분석 대상 fixture Python 파일 SHA-256이 실행 전후 일치.
- 모든 권고의 프로젝트 영향 상태 NOT_ANALYZED 유지.

수동 갱신의 첫 확장 호스트 검사에서 Windows의 DB 파일 교체 잠금을 발견했습니다. 기존 DB를 삭제하지 않는 원자적 교체 재시도와 `storage_busy` 오류 표시를 추가한 뒤 전체 수동 갱신을 통과했습니다. PowerShell 테스트 프로필 JSON에 BOM이 붙던 부분도 수정했습니다.

별도로 `scripts/test-vscode.ps1` 회귀 검사에서 기존 스캐너의 Problems **34개**, Python 4행 진단, VS Code 기본 문제 이동, 로컬 보고서 열기와 새 Threat 초기화를 확인했습니다.

실제 마우스 클릭 영상이나 24시간 장시간 방치 테스트는 수행하지 않았습니다. TreeView/명령/텍스트 편집기는 실제 확장 호스트에서 검증했고, 날짜 경과·예약 tick·재시작은 가상 시각을 사용하는 자동 테스트로 검증했습니다. 기존 시스템 VS Code의 업데이트/사용자 설정은 변경하지 않았습니다.

## 자동 검사

- `npm.cmd test`: **67개 통과**, 실패/건너뜀 0개(기존 27개 포함).
- `npm.cmd run check`: src/scripts/test 전체 JavaScript 구문 검사 통과.
- `npm.cmd audit --omit=dev --json`: 공개 취약점 **0건**. 실행 시점의 권고 DB 결과이며 미래 안전을 보장하지 않습니다.
- `git diff --check`: 공백 오류 없음.

가상 CVE와 모의 API는 테스트 전용 임시 DB에서만 사용합니다. 검증 항목은 정상/잘못된 응답, 스키마 변경, 429·cooldown, transient 백오프, 취소·timeout·응답 한도, URL/DNS/redirect 차단, 조건부 캐시/304, 비밀 형식 제거, alias와 모호한 CVE 분리, 철회/KEV/CVSS/EPSS/범위/수정 버전 변경, 날짜/중복 관찰, SQLite 재개/배타 writer/보존/삭제, Windows 파일 잠금 재시도, 하루 주기·누락 구간·수동·동시 실행·중단/재시작, 실패 데이터 보존과 오류 표시입니다.

의존성의 정확한 영향 버전 비교, 취약 기능 사용, 인증 조건, 코드 경로 및 수정 검증 테스트는 아직 대상 기능이 없어 실행하지 않았습니다. 이 항목들은 TI-2~TI-5 구현 후 추가해야 합니다.

## 보안·비용 검사

공식 고정 HTTPS 출처에서 공개 메타데이터만 GET으로 요청합니다. 프로젝트 코드/패키지 목록/비밀정보/환경변수를 전송하는 호출, 외부 문서 명령 실행, AI API 호출, 원본 코드 적용 경로가 없습니다. 기본 TreeView와 JSON 텍스트를 사용하며 Webview HTML은 없습니다. SQL 값은 binding, HTTP 응답은 필드 선택과 크기 제한, DB 저장은 기존 파일 보존을 사용합니다.

유료 API·계정·키·클라우드 저장소·원격 배포·예약 작업·외부 알림을 사용하지 않았습니다. npm 의존성은 무료 MIT sql.js 하나이고 lockfile로 고정했습니다. 기존 도구 다운로드/캐시와 실제 검증 결과는 `.tools`, `.cache`, `reports` 아래에 남아 있고 Git에서 제외됩니다.

## 다음 단계

TI-2에서 로컬 inventory 및 생태계별 정확한 버전 비교를 구현하고 `ThreatMonitor`의 새/변경 권고와 연결해야 합니다. 현재 `NOT_ANALYZED`를 유지한 상태에서 근거를 추가하고, 필수 조건이 확인된 경우에만 사용자 정의 영향 상태로 전환해야 합니다. TI-1 완료 범위에서 작업을 종료합니다.
