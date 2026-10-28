# TI-2 검증 기록

검증일: 2026-10-28 (KST). Windows x64, Node **24.14.0**, VS Code **1.143.1**. 시작 main/원격 main 일치: `129a754cd953237a3d93d98ed133a9a78275771c`, package **0.3.0**, 시작 작업 트리 clean. 기존 node_modules가 정상이라 baseline npm ci는 생략했고, 고정된 무료 비교 라이브러리 2개만 --ignore-scripts로 추가했습니다. Push/Release/Marketplace/예약 작업은 수행하지 않았습니다.

## 자동 테스트 및 실제 실행 명령

baseline **91/91**, 최종 **145/145 통과, 실패 0, skipped 0**입니다. 신규 54개는 inventory·version matching·correlation·impact service/SQLite 테스트입니다. 실제 VS Code/CLI/스캐너 검증은 이 145개와 **별도**이므로 테스트 수에 중복 합산하지 않습니다.

| 실행 명령 | 실제 결과 |
|---|---|
| `npm.cmd test` | 145 pass / 0 fail; 기존 91개 유지 |
| `npm.cmd run check` | src/scripts/test 전체 JS 구문 검사 통과 |
| `git diff --check` | 공백 오류 없음 (Windows LF/CRLF 안내만 발생) |
| `npm.cmd audit --omit=dev --json` | 알려진 취약점 0; Sentinel6 개발 의존성명/버전에 대한 npm 감사이며 분석 대상 목록은 보내지 않음 |
| `node scripts/live-test.js` | 실제 스캐너 4종 모두 completed, 병합 후 34건, 원본/합성 비밀값 보호 확인 |
| `node scripts/verify-shared-core.js` | 실제 CLI 34건, 기존 direct engine과 결과 의미 일치, modelVersion 1.1 유지 |
| `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/test-vscode.ps1` | 실제 확장 호스트: 19개 명령, Problems 34건, 코드 이동·JSON 열기·CLI 일치 |
| `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/test-threat-vscode.ps1` | 실제 공개 캐시/공식 HTTPS, Feed 200행, 권고 2,652개, SQLite/근거 열기/수동 갱신 유지 |
| `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/test-impact-vscode.ps1` | 격리 호스트의 **모의 권고** 4개 사례, 근거·줄 이동·KEV/중복 억제·실제 파일 watcher 2회 전환 통과 |
| `node scripts/verify-impact-migration.js` | 실제 v1 캐시 **복사본** v2 migration, 기존 3개 테이블의 모든 payload 해시/건수 일치 |
| `node scripts/verify-impact-cached.js` | 기존 공식 캐시 2,546건과 기존 Django/requests fixture 2개 비교, **연결 0건**. 전체 취약점 미존재를 의미하지 않음 |

재현에는 .tools에 준비된 공식 scanner/VS Code와 .cache의 offline scanner DB가 필요합니다. 위 native 테스트는 시스템 사용자 프로필과 분리된 테스트 프로필을 사용합니다. 공개 HTTP 테스트는 네트워크와 요청 예산에 따라 partial이 될 수 있습니다. 검사 결과를 모의 데이터로 대체하는 운영 fallback은 없습니다.

처음 제한된 실행 환경에서는 Semgrep이 Windows 인증서 저장소를 열지 못해 version_check_failed가 발생했습니다. 다른 3개 스캐너는 완료했고 미실행 SAST coverage가 명시됐습니다. Windows 인증서 저장소 접근이 가능한 실행 권한으로 같은 오프라인 테스트를 재실행해 4종 모두 완료했습니다. 이 환경 오류를 취약점 없음으로 취급하거나 제품의 검사 옵션/정책을 완화하지 않았습니다. 개발 중 SQLite multi-statement 실행 문제도 수정하고 migration/service 테스트를 다시 통과시켰습니다.

## 실제 스캐너와 기존 기능

| 도구 | 버전 | 실제 도구별 탐지 | 상태 |
|---|---|---:|---|
| Semgrep CE | 1.182.1 | 2 | completed |
| OSV-Scanner | 2.7.0 | 45 | completed |
| Gitleaks | 8.30.1 | 1 | completed |
| Trivy | 0.76.1 | 32 | completed |

도구별 수와 병합 수는 다릅니다. 공통 결과 **34건 = SAST 2 + 의존성 29 + secret 1 + misconfiguration 2**. 기존 fixture의 취약 코드를 실행하지 않았습니다. 합성 토큰 원문은 로그/공통 보고서에 없고 target 파일 hash는 동일했습니다. 실제 VS Code Problems에서 app.py 4행으로 이동하고 기존 scanner report schemaVersion 1/modelVersion 1.1 및 CLI 의미 일치를 확인했습니다.

TI-1 실제 수동 갱신 결과는 **partial**입니다. CISA completed, GitHub pending_page=true, OSV npm pending_records=18, OSV PyPI pending_records=59였으며 이전 정상 window와 continuation을 유지했습니다. 공개 권고 총 2,652개가 프로젝트 관련 취약점 2,652개라는 뜻은 아닙니다. 수집 예산/누락 분량을 숨기지 않았고 source failed는 없었습니다. 공개 Feed의 analysis_status=NOT_ANALYZED는 기존 모델대로 유지하며 프로젝트 분석과 분리했습니다.

## TI-2 시나리오 (명시적인 가상 fixture)

가상 CVE-2099 ID와 공식 JSON 형식의 축약 권고를 **별도 테스트 SQLite**에만 넣었습니다. 실제 신규 취약점이나 실제 KEV 등록이라고 보고하지 않습니다. 원격 수집·dependency 설치·공격 코드 실행은 없습니다.

| 사례 | 결과 |
|---|---|
| npm fixture-package lock 1.0.0 / 공식 형식 <2.0.0 | CONFIRMED_AFFECTED, 실제 설치/공격 경로는 미검증, 출처/범위/파일 근거 표시 |
| npm fixture-fixed 2.0.0 | NOT_AFFECTED, 긴급 알림 없음 |
| npm fixture-unknown ^1.0.0 | version=null / INSUFFICIENT_EVIDENCE |
| PyPI fixture_python 1.0rc1 / >=1.0.dev1,<2.0 | 이름 정규화 및 PEP 440 비교, CONFIRMED_AFFECTED |
| 프로젝트 파일 변경 없이 가상 CISA KEV revision 추가 | 관련 기존 inventory 재평가, KEV/위험 상승 이력 1개 추가, 반복 평가 중복 없음 |
| 항목 선택 / Open Dependency File | 공식 출처·고정 버전 후보·evidence JSON / 실제 package-lock의 해당 줄 이동 |
| test harness가 생성한 lock을 2.0.0으로 변경 후 원복 | 실제 VS Code watcher만으로 NOT_AFFECTED → CONFIRMED_AFFECTED 전환 2회; 원문 hash 원복 확인 |

최종 native 사례는 match 4개, 의미 있는 history **7개**, 중복 알림 억제입니다. 테스트 harness 이외의 제품 코드는 원본을 수정하지 않습니다. KEV monitor 이벤트 연결 자체는 단위 통합 테스트에서도 실제 ThreatStore ingest 결과를 bindMonitor에 전달해 검증했습니다. 새로운 관련 CVE, range/fix/withdrawal, 무관한 revision skip, restart/cache 재사용, GHSA→CVE promotion, dependency 제거(자동 완화 판정 금지)도 자동 테스트에 포함됩니다.

## 보안·저장소·호환성

- 실제 캐시 v1→v2 복사본에서 **advisory 2,546 / source_records 2,855 / revision 2,855**의 row 전체 해시가 동일했습니다. 원본 v1 캐시도 byte 동일합니다. hash는 [집계 JSON](threat-intelligence-ti2-validation.json)에 있습니다.
- SQLite 사용량 약 22 MiB/64 MiB를 확인했습니다. 64 MiB zeroblob으로 강제로 초과시킨 테스트에서는 database_limit가 반환되고 이전 정상 DB의 byte와 조회 결과가 유지됐습니다. 2 MiB report 제한·최근 scan 3개 보존·이력/알림 중복 억제도 통과했습니다.
- 경로 이탈·junction/symlink·안전하지 않은 -r·순환 include·미등록 workspace·조작 match ID·취소·원본 불변·manifest/lock 불일치·credentials/hash/URL 필드 제외를 검사했습니다. 정규화는 임의 문자열의 비밀성을 완벽하게 판별하는 기능이 아니므로 로컬 보고서의 비공개 패키지명도 공유 전에 검토해야 합니다.
- TI-2는 read-only 파일 API와 기존 store만 호출하며 HTTP/셸/설치 경로가 없습니다. 기존 공식 공개 수집·고정 라이브러리 설치/개발 감사 외에 프로젝트 내용을 전송하지 않았습니다. 외부 유료 AI API·원격 알림·자동 patch는 없습니다.
- 기존 scanner JSON v1/model 1.1은 유지되고 TI-2는 별도 modelVersion ti-2.0입니다. DB는 user_version 2로 업그레이드하므로 구버전 프로그램으로의 downgrade 호환성은 보장하지 않습니다.
- semver 7.8.5 / @renovatebot/pep440 4.2.4를 고정했고 무료 OSS 라이선스를 확인했습니다. 프로젝트 라이선스는 UNLICENSED 유지입니다. Node engine 변경은 README 참조.

## 한계와 미검증

- 실제 설치/deploy 버전, 런타임 marker·설정·공격 조건·정적 reachability·침해 여부·실제 완화는 검증하지 않습니다. MITIGATED를 자동 생성하지 않습니다.
- 실제 신규 KEV를 만들어 live 외부 데이터에 주입하지 않았습니다. code-unchanged KEV trigger는 명시적인 모의 데이터와 실제 service/store/UI 경로로 검증했습니다.
- 기존 공개 캐시는 초기 최근 날짜 범위 중심입니다. Django 2.0.0/requests 2.19.1의 과거 권고는 해당 캐시에 없어 TI-2 연결이 0개였으며, 전체 offline scanner DB에서는 의존성 29건이 확인됐습니다. **캐시 연결 0개를 안전으로 해석하면 안 됩니다.**
- 실제 Windows host를 검증했습니다. Linux/macOS, 선언한 최소 Node/VS Code, 대규모 monorepo 전체 탐색/미지원 manager, VSIX 설치/Marketplace 게시, MCP, 백그라운드 OS 스케줄러는 검증/구현하지 않았습니다.
- 최초 활성화 대화상자는 구현했으며 자동 native 검증은 격리 사용자 설정의 명시적 opt-in으로 실행했습니다. 사람의 대화상자 선택/알림 열람을 자동 성공으로 기록하지 않습니다.

## 로컬 증거와 변경 목록

reports/는 Git 제외이며 `ti2-tests.txt`, `impact-vscode-summary.json`, `impact-migration-summary.json`, `impact-cached-summary.json`, `impact-cached-report.json`, `live-summary.json`, `shared-core-cli.json`, `vscode-summary.json`, `threat-vscode-summary.json`에 재현 결과가 있습니다. 비밀값/절대 경로를 제외한 집계는 별도 [검증 JSON](threat-intelligence-ti2-validation.json)에 보존했습니다.

전체 수정/생성 파일과 이유, API, 저장 한도, 사용자 명령과 다음 단계는 [구현 설계](threat-intelligence-ti2-design.md)의 구현 파일 목록을 참고하세요. 다음 단계/Push/배포를 시작하지 않습니다.
