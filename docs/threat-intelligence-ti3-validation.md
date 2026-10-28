# TI-3 검증 기록

2026-10-28 KST, Windows x64 / Node 24.14.0 / VS Code 1.143.1. 시작 main/원격 main이 `19aacc82aebb1054a81de397426031b4dd080529`로 같고 작업 트리는 clean이었습니다. package 0.3.0, 기존 설치가 정상이라 baseline ci는 불필요했으며 sax 1.6.1만 --ignore-scripts로 정확히 추가했습니다.

## 실행한 검사

baseline **145/145**, 최종 **198/198 통과, 실패 0, skipped 0**입니다. 신규 53개는 수집/검증/조건/저장·프로젝트/보안 테스트입니다. 별도 CLI·실제 scanner·VS Code host 검증은 이 수에 중복 합산하지 않습니다.

| 실제 명령 | 결과 |
|---|---|
| `git status --short`, `git branch --show-current`, `git rev-parse HEAD`, `git ls-remote origin refs/heads/main` | clean/main/요청 HEAD/원격 일치 |
| `npm.cmd test` | 198 pass / 0 fail, 기존 145개 유지 |
| `npm.cmd run check`, `git diff --check` | JS 구문/공백 오류 없음. Windows line-ending 안내만 발생 |
| `npm.cmd audit --omit=dev --json` | Sentinel6 자체 개발 의존성의 알려진 취약점 0. 분석 대상 목록은 전송하지 않음 |
| `node scripts/live-test.js` | 실제 scanner 4개 completed, 병합 34건, 원본 hash 동일/합성 비밀값 제거 |
| `node scripts/verify-shared-core.js` | CLI 34건, 기존 direct core 의미 일치, scanner model 1.1 유지 |
| `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/test-vscode.ps1` | 실제 Problems 34건·4행 이동·JSON 열기·CLI 일치·명령 24개·TI-3 수집 기본 OFF |
| `… -File scripts/test-threat-vscode.ps1` | 실제 TI-1 cache/공식 수집·Feed 200행·권고 2,652개·수동 갱신 유지 |
| `… -File scripts/test-impact-vscode.ps1` | 기존 TI-2 mock fixture 4 match·이력 7·KEV 재평가·실제 watcher 2회 전환·이동·원복 유지 |
| `… -File scripts/test-intelligence-vscode.ps1` | 별도 모의 profile: 5개 TI-3 명령, 공식 형식 출처/조건, JSON/Markdown, TI-2 계약·미확인 조건·파일 이동/원본/마스킹 통과 |
| `node scripts/verify-intelligence-live.js` | 실제 Red Hat API/Talos RSS, 프로젝트 등록 없음, 선택 메타데이터 누적 19건/분석 19건 |
| `node scripts/verify-intelligence-sample.js` | 문서의 실제 과거 API 예제 CVE-2022-33980, CVSS LOW/NETWORK 구조화, 인증/미지원 유형은 UNKNOWN |
| `node scripts/verify-intelligence-migration.js` | 실제 v2 cache 복사본→v3, 기존 13개 테이블 전체 row hash 동일·원본 byte 동일 |

실제 scanner/host 재현에는 .tools의 고정 도구와 .cache의 준비된 offline DB가 필요합니다. native 테스트는 시스템 사용자 설정과 분리된 프로필을 사용합니다. 공격 코드·실제 취약 패키지의 install/script를 실행하지 않았고 remote Push/PR/Release/Marketplace/예약 작업을 하지 않았습니다.

## 실제 공개 데이터와 미완료 범위

07:54:59 UTC(16:54:59 KST) 새 출처 검증 결과, Talos **15건 completed**, Red Hat **누적 4건** 상세 저장(회당 예산 2건), 전체 선택 메타데이터/분석 **19건**입니다. Red Hat은 **partial**, 현재 page의 상세 대기 16건/다음 page가 남았고 last_success=null/STALE가 표시됐습니다. 요청 예산을 무제한으로 늘려 완료한 것처럼 표시하지 않았습니다. 기존 7일 공개일 window와 continuation이 유지됐습니다.

이 최근 표본에서는 자동 조건을 확인하지 못해 explicit prose condition 0, verified CVSS metric 0이었습니다. 이를 가짜 조건이나 모의 데이터로 채우지 않았습니다. 별도 **과거 schema 예제** CVE-2022-33980에서는 공식 verified CVSS의 required_privileges=LOW, attack_surface=NETWORK를 확인했습니다. 해당 표본의 authentication/type/상세 전제는 UNKNOWN이며, 프로젝트 적용·실제 외부 노출·공격 성공을 검증한 것은 아닙니다.

TI-1 기존 수동 수집도 **partial**입니다. CISA completed, GitHub next page, OSV npm pending 23/PyPI pending 59를 남겼고 source failed는 없었습니다. 전체 공개 권고 수는 프로젝트 관련 취약점 수가 아닙니다.

## 가상 시나리오와 보안 검사

가상 CVE-2099/fixture-package 및 공식 형식 축약 데이터만 자동 테스트/별도 UI profile에 사용했습니다. 운영 collector에 mock/fallback이 없으며 실제 새 CVE/KEV 발견이라고 주장하지 않습니다.

- SQL/Command Injection, 인증/인가 우회, SSRF, traversal, deserialization, privilege escalation, information disclosure, upload의 CWE 분류와 추가 5개 명시적 제목 taxonomy를 확인했습니다. **유형 분류를 실행 조건 확인으로 승격하지 않았습니다.**
- 명시적 인증 필요/불필요·custom authentication adapter·npm lifecycle 조건, verified/draft CVSS 구분, unknown, 부정/조건부 표현, 상충 claim의 UNKNOWN 처리를 확인했습니다.
- 공식+독립 일치/충돌·제품 scope 차이·CVE 미확인 뉴스·공식 alias·미러 중복·공개/수정/관찰 시각·PoC/reported/confirmed/미확인 구분을 검사했습니다. vendor not-confirmed가 CISA 확인을 지우지 않았습니다.
- 공식 조건 변경이 파일 변경 없이 기존 project inventory를 재평가했습니다. 취약 버전의 TI-2 CONFIRMED_AFFECTED는 유지하고 설정/제품 scope/기능 사용/노출/공격 성공은 별도로 미확인 처리했습니다. 수정 버전은 기존 NOT_AFFECTED/알림 없음으로 유지했습니다.
- `.npmrc ignore-scripts=false`와 명시된 lifecycle 조건의 **선언상 일치**를 확인했으나 실제 실행 증거라 하지 않았습니다. true로 바꿔도 MITIGATED/안전으로 자동 판정하지 않았습니다. 파일 원문/토큰은 결과에 없었습니다.
- 동일 뉴스의 200/304 재수집과 관찰 시각 변경 후 수동 조회도 analysis/history/알림을 중복 생성하지 않았습니다. 무관한 뉴스는 project scan/알림을 만들지 않았습니다.
- malformed XML/JSON, DTD/entity, 깊이/크기, 위험 URL·SSRF allowlist, HTML/스크립트·프롬프트 문자열, source authority·enum·prototype key·forged fingerprint를 차단했습니다. 뉴스/권고의 명령을 실행할 경로가 없습니다.
- 네트워크/429/cooldown/부분 queue 재시도·취소/deadline·원본 불변·dispose 이후 읽기 차단·symlink/junction·주입 경로/설정 거부·삭제/retention·이전 정상 DB 보존을 검증했습니다.

개발 중 v3 도입에 따른 기존 migration 버전 기대와 OFF 상태의 news 요약 호환을 갱신했습니다. prototype key의 enum 조회 오류를 고정된 schema 오류로 처리하도록 수정했습니다. native Markdown 검증은 실제 escape된 underscore를 확인하도록 바로잡았으며, 안전한 렌더링을 완화하지 않았습니다. 최종 실패 항목은 없습니다.

## 기존 scanner·DB 보존

| 도구 | 버전 | 도구별 실제 탐지 |
|---|---|---:|
| Semgrep CE | 1.182.1 | 2 |
| OSV | 2.7.0 | 45 |
| Gitleaks | 8.30.1 | 1 |
| Trivy | 0.76.1 | 32 |

공통 결과 **34 = SAST 2 + dependency 29 + secret 1 + misconfiguration 2**. 모든 영역 completed, original/합성 secret 보호, 기존 CLI/Problems/navigation 유지입니다. 스캐너/파서/실행 API를 중복 구현하지 않았습니다.

실제 v2→v3 복사본에서 advisory 2,546, source/revision 각각 2,855, HTTP cache 651, monitoring job 3, project inventory 1/dependency 2/scan report 2와 나머지 기존 테이블의 row 전체 hash가 동일했습니다. 이 실제 복사본의 match/evidence/history는 원래 0개였습니다. 별도 단위 migration에서는 **non-empty match/evidence/history/notification을 포함한 기존 7개 project table**을 만들고 새 테이블이 없는 v2에서 v3로 바꾼 뒤 모든 row가 동일함을 확인했습니다.

새 모델은 schemaVersion 1/modelVersion ti-3.0이며 scanner v1/1.1과 TI-2 ti-2.0의 기존 상태 의미는 유지합니다. DB user_version은 3이므로 구버전 프로그램 downgrade 호환성은 보장하지 않습니다. 기존 64 MiB 한도 초과·이전 정상 파일 보존 테스트도 함께 통과했습니다. 외부 paid AI/프로젝트 업로드/자동 패치/원격 발송은 없습니다.

## 미검증·미지원

- 새로운 source는 사용자 opt-in, 기존 scheduler ON, trusted workspace에서만 자동 수집합니다. 실제 사람의 최초 대화상자 클릭/알림 열람은 자동 검증하지 않았으며 native profile은 명시적 설정으로 실행했습니다.
- 모든 과거 CVE의 변경 feed, RSS window 밖 기사/본문·모든 공급업체·비영어 자연어·CVSS v4·draft metric을 지원하지 않습니다. 자동 패턴을 충족하지 않으면 UNKNOWN입니다.
- 공식 source/CVE 관련성은 프로젝트 제품 scope·설치/배포·특정 기능 사용·실행 조건·정확한 함수/호출 경로·실제 악용 성공을 증명하지 않습니다. TI-3가 이를 확인했다고 표시하지 않습니다.
- NVD/KISA/다른 미디어는 disabled, 임의 HTML 크롤러/LLM·MCP·TI-4·TI-5·OS 스케줄러/Actions·VSIX/Marketplace는 구현/실행하지 않았습니다.
- Windows Node 24.14.0/VS Code 1.143.1만 실제 host로 검증했습니다. 다른 OS/선언 최소 runtime/대규모 장기간 retention 부하는 배포 전 별도 검증이 필요합니다. 동기 SQL/정규화는 hard preemption을 제공하지 않습니다.

로컬 증거는 reports/ti3-tests.txt, ti3-pipeline-tests.txt, ti3-live/summary.json, ti3-sample/summary.json, intelligence-vscode-summary.json, intelligence-migration-summary.json 및 기존 scanner/CLI/TI-1/TI-2 summary에 있습니다. reports/는 Git 제외입니다. 민감한 경로·원문을 제외한 [집계 JSON](threat-intelligence-ti3-validation.json)과 [전체 파일/API/제한 목록](threat-intelligence-ti3-design.md)을 함께 제공합니다.
