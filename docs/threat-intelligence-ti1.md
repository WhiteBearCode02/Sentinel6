# Threat Intelligence — TI-1

## 범위와 기존 구현

Phase 2 커밋 `d2b2318`의 스캐너 4종, `scan()` API, 프로세스 제한, 결과 파서, Problems 및 보고서 기능을 유지했습니다. 독립된 Agent 1~6 분석 모듈과 Threat Intelligence 코드는 없었습니다. TI-1은 Agent 6 역할의 **공개 위협 메타데이터 수집 기반**입니다. 다른 5개 모듈을 완성한 것처럼 표시하지 않습니다.

프로젝트 의존성·코드·설정과의 매칭, 공격 경로, 영향 판정, 수정 Diff, 패치 적용은 구현하지 않았습니다. Feed의 모든 항목은 `analysis_status: NOT_ANALYZED`이며 프로젝트 취약점 판정이 아닙니다.

## 실행

```powershell
npm.cmd ci --ignore-scripts
npm.cmd test
npm.cmd run check
```

VS Code에서 F5로 확장을 실행하고 Activity Bar의 Sentinel6 → Threat Feed를 엽니다. 또는 명령 팔레트를 사용합니다.

- `Sentinel6: Open Threat Feed`: 출처 상태와 최근 위협 목록.
- `Sentinel6: Refresh Threat Intelligence`: 공개 데이터 수동 갱신. 프로젝트 코드를 전송하지 않습니다.
- `Sentinel6: Cancel Threat Collection`: 현재 수집 취소.
- Feed 항목 선택: 정규화된 권고·출처·관찰 시각·변경 이력을 JSON 편집기로 열기.
- 출처 항목 선택: 마지막 성공 구간, 실패 코드, 재시도 시각, 미수집 상태 확인.
- `Sentinel6: Delete Local Threat Data`: 확인 후 로컬 위협 DB/캐시/이력 삭제. 스캐너 보고서와 분석 대상 원본은 건드리지 않습니다.

삭제 후에도 자동 수집을 켜 두면 다음 주기에 다시 수집합니다. 계속 비워 두려면 `threatMonitoring.enabled`를 꺼 주세요.

사용자 설정:

```json
{
  "sentinel6.threatMonitoring.enabled": true,
  "sentinel6.threatMonitoring.ecosystems": ["npm", "PyPI"],
  "sentinel6.threatMonitoring.retentionDays": 90
}
```

설정은 application 범위이고 사용자 전역 값만 읽습니다. 프로젝트 설정으로 수집 출처/주기를 변경할 수 없습니다. 생태계와 보존 기간 변경 후 창을 다시 로드합니다. 자동 수집은 신뢰된 workspace에서만 시작합니다.

기본 주기는 **성공한 수집 구간으로부터 24시간**입니다. 확장 활성화 시 지난 시각을 확인하고, 실행 중에는 1분마다 기한/미수집/재시도 상태를 확인합니다. 수집이 필요하지 않으면 네트워크 요청과 새 작업 이력을 생성하지 않습니다. 파일 저장이나 Git 이벤트와 무관합니다. 같은 확장의 동시 실행은 하나의 Promise를 공유하고 다른 창의 DB writer는 파일 잠금으로 배제합니다.

**VS Code를 닫으면 자동 수집은 중단됩니다.** Windows 예약 작업과 GitHub Actions는 TI-6 범위로 비활성 상태입니다. 예약 작업 등록, 워크플로 생성, 배포, Push/PR을 수행하지 않습니다.

## 수집 출처와 제한

| 출처 | 사용 방식 | 범위 / 체크포인트 |
|---|---|---|
| CISA KEV | 공식 JSON, 차단/연결 실패 시 cisagov 공식 미러 | 전체 카탈로그. CVE 공개일과 KEV 등록일을 구분 |
| GitHub Advisory | 인증 없는 Global Advisories REST API, reviewed | 첫 실행 최근 7일. 수정일 구간·Link cursor로 페이지 이어받기 |
| OSV | 생태계별 `modified_id.csv` + `GET /v1/vulns/{id}` | 기본 npm/PyPI, 선택 Go/Maven. 최근 변경 ID만 조회 |
| NVD / KISA / RSS / 공급업체 개별 피드 | 비활성 | 검증된 adapter가 없는 항목은 disabled로 표시 |

초기 7일은 전체 보안 데이터베이스를 내려받는 기간이 아닙니다. CISA는 전체이고 GitHub/OSV는 이 구간에 공개·수정된 권고가 대상입니다. GitHub의 날짜 단위 검색은 경계 날짜를 겹쳐 조회합니다. 중복 관찰은 새 변경 이력을 만들지 않습니다.

일반 실행의 요청 예산은 GitHub 2페이지(각 최대 100개), OSV 생태계당 20개 record입니다. 분량이 많으면 **partial**과 미수집 cursor/queue를 영속화하고 1분 후 이어받습니다. 마지막 페이지/record까지 완료하기 전에는 성공 체크포인트를 앞으로 이동하지 않습니다. 늦게 재시작해도 이전 성공 시점부터 조회하므로 중간 기간을 오늘 날짜로 덮어쓰지 않습니다.

HTTP는 HTTPS의 고정된 공식 host/path만 허용하고 DNS 결과의 사설/loopback/link-local 주소, 사용자정보·포트·임의 query·redirect를 차단합니다. 요청 총시간 15초, 본문 16 MiB, 최대 3회 및 지수 백오프를 적용합니다. 일반 요청 간격은 1초입니다. 429/제공자 cooldown은 재시도 시각으로 저장하고 수동 갱신도 우회하지 않습니다. GitHub API는 키 없이 사용하므로 IP당 공식 제한을 공유합니다. 장시간 제한 중에는 마지막 정상 캐시를 보여줍니다.

ETag/Last-Modified는 URL별로 저장하고, 304에서는 이전의 **정규화된 데이터**를 사용합니다. OSV CSV는 내림차순이라는 공식 형식에 따라 필요한 날짜 이후까지만 스트리밍합니다. 캐시가 더 좁은 기간이면 조건부 요청 대신 다시 수집합니다. 실패 시 이전 정상 데이터를 삭제하지 않고 출처에 고정된 오류 코드를 표시합니다. 마지막 완료 구간이 없거나 48시간이 지나면 STALE / incomplete로 표시합니다.

## 데이터 모델 / 인터페이스

```text
HttpClient.get() → source adapters → normalized record
                                      ↓
ThreatMonitor.refresh() → ThreatStore.ingest() → SQLite snapshot
          ↓                           ↓
scheduled/manual                 revision comparison
          └────────── ThreatFeed / evidence JSON ──────────┘
```

| SQLite 테이블 | 저장 데이터 |
|---|---|
| threat_sources | 상태, 마지막 시도/완료 구간, retryAt, cursor/queue |
| source_records | 출처별 선택된 정규화 레코드와 공식 ID |
| threat_advisories | canonical ID별 결합된 현재 메타데이터 |
| threat_revisions | 의미 있는 변경 종류·fingerprint·관찰 시각·정규화 이력 |
| http_cache | ETag/Last-Modified, 선택된 데이터, 관찰 시각 |
| monitoring_jobs | running/completed/partial/cancelled/interrupted 이력 |

SQLite WASM(sql.js 1.15.2, MIT)을 로컬 파일로 저장합니다. Native Electron ABI나 외부 DB 서버가 필요 없습니다. WASM은 설치된 npm 패키지에서 로드하며 CDN으로 요청하지 않습니다. 경로는 확장의 `globalStorageUri/threat-intelligence.sqlite`이며 원본 workspace 내부 쓰기를 차단합니다. 64 MiB 한도와 임시 파일→fsync→원자적 rename으로 이전 정상 파일을 보호합니다. SQL 값은 parameter binding을 사용합니다. active writer 잠금, 죽은 프로세스 잠금 회수, 재시작 시 interrupted 작업 처리를 구현했습니다. 보존 기간 기본 90일(7~365)보다 오래 관찰되지 않은 레코드/이력/HTTP 캐시를 정리합니다. 계속 관찰되는 CISA 항목은 유지됩니다.

Windows에서 Feed가 DB를 읽는 순간 교체가 잠깐 거부되는 경우 기존 파일을 삭제하지 않고 제한된 백오프로 재시도합니다. 잠금이 계속되면 `storage_busy`를 표시하고 마지막 정상 캐시를 유지합니다.

핵심 API:

- `HttpClient.get(url, {cache, signal, indexSince})`
- `ThreatMonitor.initialize()`, `refresh({force, signal})`, `snapshot()`, `advisory(id)`, `start()`, `stop()`, `clear()`
- `withStore(file, callback)`, `withReadStore(file, callback)`, `resetStore(file)`
- `model.cisa()`, `model.github()`, `model.osv()`, `model.combine()`

공통 advisory 필드는 canonical/source ID, title/짧은 고정 description, published/modified/first_seen/last_seen/last_changed 시각, 영향 제품·공식 범위·수정 버전, CVSS/EPSS, KEV 및 악용 상태, 공식 출처, fingerprint, change_type입니다. 조건/공격 primitive는 아직 추출하지 않으므로 빈 목록이고 영향 상태는 NOT_ANALYZED입니다. CISA dateAdded를 CVE 공개/수정 시각으로 대입하지 않습니다. 악용 확인은 CISA 근거만 사용합니다. KEV 미등록을 안전 판정으로 쓰지 않습니다.

공식적으로 명시된 alias에 한해 CVE/GHSA/OSV를 연결합니다. 여러 CVE가 들어간 모호한 record를 임의의 CVE 하나로 승격하지 않습니다. 타임스탬프만 바뀌고 내용이 같으면 revision을 생성하지 않습니다. KEV 추가/제거, 철회, CVSS/EPSS, 영향 범위, 수정 버전, 완화 조치, 다른 실질적 메타데이터 변경을 구분합니다. EPSS는 수집된 권고에 제공되는 경우만 비교하며 독립된 EPSS 전체 피드는 없습니다.

> 이후 TI-2에서 사용자 opt-in 의존성 영향 분석을 추가했습니다. 아래 TI-1의 NOT_ANALYZED는 공개 Feed 자체의 범위이며, 현재 프로젝트별 기능은 [TI-2 설계/사용법](threat-intelligence-ti2-design.md)을 따릅니다. collector와 공개 데이터 모델은 유지됩니다.

## 보호 경계

- 공개 데이터만 GET 요청합니다. 프로젝트 소스·환경변수·토큰·비밀번호·패키지 목록을 수집 서버로 보내지 않습니다.
- 전체 뉴스 본문·원시 API 응답·원시 오류 로그를 DB에 저장하지 않습니다. API 응답에서 허용한 필드만 변환합니다. 공지 요약에 알려진 토큰 형식이 있으면 제거합니다.
- 외부 문서의 명령, HTML, 프롬프트는 데이터로만 취급합니다. 명령 실행, 코드 수정, 권한 변경, 테스트 자동 실행으로 연결되는 경로가 없습니다.
- Feed는 VS Code 기본 TreeView와 JSON 텍스트 편집기를 사용합니다. Webview/HTML 렌더링이나 신뢰된 Markdown command link를 생성하지 않습니다.
- 자동 수집 결과로 프로젝트 긴급 알림을 만들지 않습니다. 프로젝트 연관성/중요도 판정과 알림 정책은 TI-2 이후입니다. 수동 갱신의 완료 요약과 Feed 상태만 제공합니다.
- 외부 유료 AI API, 로컬 LLM, 계정/토큰, 유료 저장소, 배포는 없습니다. 공개 서비스의 장애/사용 제한을 우회하지 않습니다.

## 구현 파일

- `src/threat/http.js`: URL/DNS 검증, 제한된 HTTP, 조건부 요청, 취소/재시도.
- `src/threat/model.js`: 세 공식 형식 검증·정규화, 보수적 alias, material fingerprint.
- `src/threat/store.js`: SQLite 모델, revision, cache, 보존/삭제, 원자적 저장과 writer 잠금.
- `src/threat/sources.js`: CISA/GitHub/OSV 수집 및 누락 구간 이어받기.
- `src/threat/monitor.js`: 일일 주기, 재시작·수동·중복 억제, 오류와 freshness.
- `src/threat/view.js`: 기존 확장 내부 TreeView, 상태/근거 열기, 설정·삭제 명령.
- `src/extension.js`, `package.json`, `package-lock.json`, `resources/sentinel6.svg`: 활성화·기여 항목·고정 의존성.
- `test/threat-*.test.js`, `test/threat-fixtures.js`, `test/vscode-threat-runner.js`: 자동 테스트.
- `scripts/threat-monitor.js`, `scripts/verify-threat-live.js`, `scripts/test-threat-vscode.ps1`: 실제 수집/확장 호스트 검증.
- `scripts/check.js`: 전체 런타임·검증 JavaScript 구문 검사.

## 검증과 다음 단계

단위 테스트에서는 명시적인 가상 CVE/모의 API를 사용합니다. 운영 collector에 fallback mock이 없으며 실패를 실제 발견 사항으로 대체하지 않습니다. 실제 공개 데이터 결과와 VS Code 확장 호스트 검증은 [TI-1 검증 기록](./threat-intelligence-ti1-validation.md)에 별도 기록합니다.

```powershell
# 공개 메타데이터만 수집. 별도 프로세스 실행은 수동이며 OS 예약 작업이 아닙니다.
npm.cmd run threats -- "D:\local-data\sentinel6-threats"
# 하루가 지나기 전에 수동 갱신 (서버 cooldown은 유지)
npm.cmd run threats -- "D:\local-data\sentinel6-threats" --force
```

TI-2에서는 로컬 의존성 inventory와 생태계별 버전 비교, 공식 권고의 실제 프로젝트 영향 근거를 추가해야 합니다. TI-3의 허용 RSS/공급업체 수집, TI-4 정적 경로, TI-5 승인 기반 Diff/검증, TI-6 예약 작업·Actions·VSIX는 아직 구현하지 않았습니다. 현재 NOT_ANALYZED를 CONFIRMED_AFFECTED/NOT_AFFECTED로 바꾸어 표시하면 안 됩니다.

## 공식 근거

- [CISA 공식 KEV 미러 및 JSON schema](https://github.com/cisagov/kev-data)
- [GitHub global security advisories REST API](https://docs.github.com/en/rest/security-advisories/global-advisories)
- [GitHub 인증 없는 요청과 rate limit](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api)
- [OSV 최근 변경 색인과 데이터 형식](https://google.github.io/osv.dev/data/)
- [OSV API·응답 제한 FAQ](https://google.github.io/osv.dev/faq/)
- [sql.js 공식 API](https://sql.js.org/documentation/)

공개 데이터의 출처 URL을 각 항목에 유지합니다. OSV의 원천 데이터별 라이선스가 다를 수 있으므로 외부 재배포 기능은 제공하지 않고 로컬 메타데이터·공식 링크로 제한합니다. 전체 기사 본문은 저장하지 않습니다.
