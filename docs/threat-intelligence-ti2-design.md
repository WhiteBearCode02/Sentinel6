# TI-2 implementation boundary

기준 main: 129a754cd953237a3d93d98ed133a9a78275771c (원격 일치), 0.3.0. 시작 작업 트리는 깨끗했고 기존 91개 테스트/check가 통과했습니다. sql.js/WASM이 이미 설치되어 있어 baseline을 위한 재설치는 필요하지 않았습니다.

구현 순서는 inventory → ecosystem matcher → correlation/assessment → SQLite migration/history → revision-driven service → opt-in VS Code UI → 테스트/회귀입니다. 기존 스캐너/ThreatMonitor/ThreatStore/SecurityService는 재사용합니다.

- `src/inventory/`: 제한된 로컬 manifest/lockfile 읽기, exact/unknown 구분, 상대 위치·hash·coverage. 네트워크/패키지 설치/프로젝트 스크립트 없음.
- `src/impact/version-matcher.js`: npm SemVer/PyPI PEP 440, 명시 버전·범위·OSV timeline. Git/미지원은 UNKNOWN 계열.
- `src/impact/correlation.js`: 명시적인 공식 ecosystem/name 식별자만 연결. CISA 일반 제품명 추측 금지. source별 범위 충돌 보존.
- `src/impact/service.js`: 등록 workspace의 inventory/기존 snapshot 재사용, SQLite 저장·revision/파일 변경 재평가·중복 알림.
- SQLite user_version 2: 기존 advisory 보존 + project inventory/dependencies/scans/matches/evidence/history/notification 테이블. 앱 저장소만 변경.
- 기존 Threat Feed에 별도 project 영향 그룹. 최초에는 비활성이며 명시적 활성화 후 현재 열린 신뢰된 workspace만 분석. 동의·등록 root는 로컬 호스트에만 유지하고 DB에는 digest ID와 상대 위치를 기록.

판정의 범위는 **선언/잠금 파일의 구성요소 버전**입니다. CONFIRMED_AFFECTED는 정확한 의존성 버전이 공식 범위와 일치하는 증거이며, 설치·실행·도달 경로·침해 확인이 아닙니다. 환경 마커/조건/상충 범위는 불확실성을 낮추지 않습니다. MITIGATED는 실제 완화 근거가 있을 때만 가능하며 TI-2의 정적 dependency MVP는 이를 자동 생성하지 않습니다. fix availability는 별도이고 여러 분기 중 임의 단일 버전을 추천하지 않습니다.

모든 새 분석은 별도 TI-2 envelope로 저장하며 기존 scanner report schemaVersion 1/modelVersion 1.1의 의미를 바꾸지 않습니다. 취소/오류는 이전 정상 분석을 보존합니다. 분석은 로컬만 수행하고 자동 patch, MCP, OS scheduler, Actions, 원격 알림/배포를 추가하지 않습니다.

## 사용자 흐름과 데이터 흐름

`Analyze Current Project` → 명시적 최초 활성화 → SecurityService에 열린 local workspace 등록 → 읽기 전용 inventory → 기존 SQLite의 정규화된 공식 권고/출처별 범위 → correlation → 앱 전용 SQLite/history → 기존 Threat Feed의 Project Impact 그룹입니다. 설정은 사용자 전역(application scope)이므로 활성화 이후 열린 신뢰된 workspace에도 적용되며 workspace 설정만으로 활성화할 수 없습니다. 비활성화하면 watcher/작업/monitor 연결을 중단합니다.

`Check Project Impact`는 JSON, `Open Project Impact Markdown`은 Markdown, `View Impact History`는 변경 이력을 엽니다. 취약점 선택은 evidence JSON을 열고 펼친 항목의 `Open Dependency File`은 inventory에 존재하는 상대 경로를 `checkedFile()`로 재검증해 위치를 엽니다. JSON/Markdown은 사용자가 Save As로 내보낼 수 있습니다. 자동으로 대상 프로젝트에 보고서 파일을 만들지 않습니다.

기존 `Scan Project`는 계속 기존 scanner core를 사용합니다. opt-in 상태에서 완료한 안전한 공통 보고서는 메모리에만 연결해 정확한 package/ecosystem/ID 또는 purl의 scanner observation을 보조 근거로 붙입니다. 과거 scanner 버전이 현재 의존성과 다르면 재검사 필요를 표시하며 설치/공격 경로 증거로 승격하지 않습니다. 영향 분석은 스캐너·설치·프로젝트 명령을 자동 실행하지 않습니다.

## Inventory 계약

`SecurityService.inventoryWorkspace({workspaceId}, {signal, previous})`와 `workspaceIdentity({workspaceId})`는 기존 allowlist/realpath 경계를 재사용합니다. 요청에 root/명령/output 경로를 넣을 수 없습니다. `collectInventory()`는 독립된 로컬 분석 API입니다.

| 파일 | 처리 | 제한 |
|---|---|---|
| package.json | 정확 pin은 DECLARED_EXACT; 범위·URL은 version=null | 실제 설치 버전을 의미하지 않음 |
| package-lock v2/v3 | packages 직접/중첩 간접 항목, LOCKFILE_EXACT | link/alias, manifest 불일치, 누락 직접 항목은 unknown; workspace lock 해석 미지원 |
| requirements.txt, 안전한 -r | 정확 == pin, PEP 503 이름 정규화, PEP 440 버전 | -c는 해석하지 않고 관련 Python 버전 모두 unknown; marker/VCS/range/extras는 제한 표시 |
| Yarn/pnpm/Poetry/uv/Maven/Gradle | unsupported coverage issue | 안전 또는 검사 완료로 추정하지 않음 |

원시 specifier/URL/resolved/integrity/scripts/소스는 저장하지 않습니다. 필드는 project_id, package_name/normalized_name, ecosystem, version, purl, source_file/line, dependency_type, direct_or_transitive, version_confidence, inventory_timestamp, limitations입니다. project_id는 정규화 realpath의 SHA-256, 위치는 상대 경로입니다. ID는 익명성 보장이 아니라 로컬 일관성 식별자입니다.

탐색 깊이 4, 디렉터리 2,000/전체 entry 20,000(스트리밍 탐색), 파일 200, 개별 2 MiB/전체 20 MiB, 의존성 10,000 한도입니다. issue 상세는 1,000개 후 생략을 표시합니다. .git/.tools/.cache/node_modules/venv/build/dist/reports 등은 제외합니다. 심볼릭 링크, 경로 이탈·제어 문자, unsafe include를 차단합니다. 지원 파일이 없거나 잘못된 JSON/미지원 파일이 있으면 partial입니다. exact version이 없는 각 의존성도 별도 제한 사유를 가집니다. 전체 프로젝트 지원을 뜻하지 않습니다.

파일 hash·탐색 issue·parser version으로 fingerprint를 만들며 매 재평가에서 현재 파일을 읽어 변경을 확인한 뒤 동일한 파싱 결과를 재사용합니다. `checked_at`, inventory age, source 현재 상태와 평가 시점 상태를 분리합니다. 신규 분석을 건너뛰어도 현재 source 실패/STALE는 숨기지 않습니다.

## 버전 의미론 및 판정

라이브러리 버전은 **semver 7.8.5 (ISC)**, **@renovatebot/pep440 4.2.4 (Apache-2.0, 일부 코드 dual BSD/Apache)**로 고정했습니다. 최신 major 전체를 무조건 채택하지 않고 Node 지원 범위를 확인했습니다. 새 Node engine은 ^20.9.0 / ^22.11.0 / ^24.0.0입니다. 프로젝트 자체 라이선스는 UNLICENSED 유지이며 사용자의 라이선스 결정을 대신하지 않습니다.

npm 표현식은 SemVer prerelease 기본 규칙, PyPI specifier는 PEP 440을 사용합니다. 예: `<1.0`은 1.0rc1을 포함하지 않으므로 prerelease 허용 옵션만으로 취약으로 바꾸지 않습니다. OSV SEMVER/ECOSYSTEM 이벤트는 introduced inclusive, fixed/limit exclusive, last_affected inclusive, 수정 후 재도입·명시 버전 목록을 지원합니다. 불일치·겹침/짝 없는 timeline, Git 범위, 잘린 것으로 의심되는 문자열은 미지원으로 둡니다. 지원 범위의 양성 증거가 없으면 미지원 범위를 음성으로 치환하지 않습니다.

| 버전 결과 | 영향 상태 |
|---|---|
| 정확한 공식 identity + 영향 버전 일치 | CONFIRMED_AFFECTED (선언/잠금 구성요소 버전 한정) |
| 출처의 양성/음성 충돌 또는 명시된 전제 미확인 | POTENTIALLY_AFFECTED |
| 관련 공식 범위가 모두 신뢰 가능한 음성 | NOT_AFFECTED (해당 구성요소 버전 한정) |
| 버전/범위/identity 불명, 철회/모호한 alias | INSUFFICIENT_EVIDENCE |
| 분석 전 또는 이전 증거가 inventory에서 사라짐 | NOT_ANALYZED |
| 검증된 완화 증거 | MITIGATED 계약만 제공, MVP 자동 생성 안 함 |

CISA 일반 제품명은 패키지로 추측하지 않고 별도 review-only count로 둡니다. 관련 없는 명시적 identity는 unrelated로 구분합니다. 공식 CVE/GHSA/OSV alias만 기존 ThreatStore 결합을 사용하며, 나중에 GHSA에 CVE가 붙어도 같은 의존성의 이전 이력을 연결하고 신규 위험 알림을 중복 생성하지 않습니다.

match/summary는 canonical advisory × 의존성 위치 단위입니다. 같은 CVE가 여러 파일·여러 버전에 존재하면 위치별 근거를 유지하므로 match 수를 고유 CVE 수와 혼동하면 안 됩니다. 여러 출처가 같은 advisory와 의존성을 설명할 때에는 하나의 match에 source evidence를 결합합니다.

보고서는 별도 **schemaVersion 1 / modelVersion ti-2.0**이며 기존 scanner report와 별개입니다. 각 결과에 공식 URL·공개/수정 시점·별칭·범위·패키지/위치·판정 이유·출처 충돌·미확인 조건·fix_available/fixed_versions·KEV/악용/CVSS/실제 존재하는 EPSS·confidence/evidence_count·limitations·분석 시점·권장 수동 대응·재검사 여부를 제공합니다. 임의의 CVSS/EPSS/수정 버전을 생성하지 않습니다. 여러 분기의 fixed-version 후보는 모두 유지하고 단일 버전 설치 명령을 추천/실행하지 않습니다.

## 재평가와 우선순위

ProjectImpactService는 기존 ThreatMonitor.onUpdate의 최종 changed 목록만 받아 package identity/기존 match에 관련된 workspace를 재평가합니다. 신규 권고·KEV/악용·범위/fix·철회 변경은 기존 advisory revision/content_fingerprint를 사용합니다. 관련 inventory+advisory fingerprint가 동일하면 새 scan/history/알림을 만들지 않습니다. 수동 force는 분석을 저장하되 근거 fingerprint가 같은 history/위험 알림은 중복 생성하지 않습니다. dependency watcher는 600 ms debounce 후 파일 hash를 확인합니다.

활성 영향 상태에서 priority 점수는 구성요소 확정 35/가능성 20, 영향 버전 일치 15, lock 정확성 5/선언 정확성 2, KEV 25, 공식 악용 10, CVSS×2(반올림), 실제 EPSS×10(반올림), 공식 fix 5를 합쳐 100으로 제한합니다. high≥60, critical≥80이며 각 점수 이유를 공개합니다. 이는 로컬 정렬용 정책이지 CVSS/EPSS를 대체하는 확률이 아닙니다. KEV 미등록에는 안전 점수를 주지 않습니다. 음성/불충분 상태는 informational입니다.

새 high/critical 관련성, 비활성→활성 복귀, high→critical, KEV/공식 악용 상승만 알립니다. unique event key와 이전 영향 상태로 중복을 억제합니다. VS Code 로컬 표시 시도 후 delivered_at을 기록하며 실제 사람의 열람을 보장하지 않습니다. 그룹 알림에는 최대 3개 ID를 표시하고 전체 근거는 Project Impact에서 확인합니다. 원격 Issue/이메일은 없습니다.

## 저장소·취소·안전 경계

user_version 2가 project_inventory, project_dependencies, project_scans, project_threat_matches, impact_evidence, impact_history, notification_history를 추가합니다. 기존 advisory/source/revision 테이블은 유지합니다. 알 수 없는 미래 DB 버전은 거부합니다. read 경로는 메모리에서 migration을 준비하고 기존 writer checkpoint가 원자적으로 저장합니다. 구버전 Sentinel6로 DB를 되돌려 사용하는 호환성은 보장하지 않으므로 downgrade 전 별도 백업이 필요합니다.

프로젝트당 최근 scan 3개, history 1,000개(조회 100), 알림 500개(미표시 조회 20), match 2,000개, 보고서 2 MiB입니다. 기존 90일(사용자 7~365일) retention/명시적 삭제와 기존 64 MiB 파일 한도를 재사용합니다. 51 MiB부터 사용량 경고·VACUUM, 한도 초과 시 고정 오류와 마지막 유효 DB 보존을 사용합니다. 저장 실패는 조용히 새 결과를 버린 성공으로 표시하지 않습니다.

작업은 service 내 직렬화, queue 20개, 기본 60초 협력적 deadline(최대 300초), AbortSignal/수동 취소를 지원합니다. 동기 버전 비교는 입력 한도로 제한하며 프로세스 격리 hard preemption은 제공하지 않습니다. 여러 프로세스 writer 경쟁은 기존 store_busy로 실패하며 이전 snapshot이 유지됩니다. 대상 root 변경·파일 navigation은 기존 realpath 검증을 통과해야 합니다. 외부 권고는 JSON 또는 escape된 Markdown 데이터로만 열며 command link/HTML/셸로 실행하지 않습니다.

프로젝트 원본 쓰기, dependency install, 프로젝트 스크립트, 프로젝트 목록/소스/비밀값 네트워크 전송 경로를 추가하지 않았습니다. 공식 공개 수집은 기존 TI-1만 담당합니다. 외부 유료 AI API·모델·계정·예약 작업·Actions·배포는 추가하지 않았습니다.

## 구현 파일

- `src/inventory/identity.js`, `index.js`: 이름/버전/purl/ID 및 안전한 로컬 inventory.
- `src/impact/version-matcher.js`, `correlation.js`: 생태계 비교, 근거 기반 상태, 우선순위/알림 정책.
- `src/impact/storage.js`, `service.js`: migration/보존/원자적 저장 재사용, revision/캐시/이력/취소 API.
- `src/impact/view.js`: opt-in, 명령/트리/notification/의존성 watcher.
- `src/security-service.js`, `src/threat/{store,monitor,view}.js`, `src/extension.js`: 기존 경계·collector·UI·완료 scanner 결과 연결.
- `package.json`, `package-lock.json`: 명령 9개, application 설정, 고정 무료 비교 라이브러리와 Node 호환성.
- `test/{inventory,version-matcher,correlation,impact-service}.test.js`, `test/vscode-impact-runner.js`, `test/vscode-runner.js`: 신규 단위/실제 호스트 검증과 기존 회귀 유지.
- `scripts/prepare-impact-vscode.js`, `test-impact-vscode.ps1`, `verify-impact-migration.js`, `verify-impact-cached.js`: 명시적 테스트 fixture/실제 캐시 복사본 검증. 기존 test-vscode/test-threat-vscode 프로필에는 TI-2 OFF 명시.
- README/CHANGELOG/SECURITY, 이 설계 문서·검증 문서·집계 JSON, 기존 shared-core/distribution/next-plan/TI-1 문서: 현재 범위·호환성·배포 전 과제 갱신.

## 다음 단계 (이번 구현에 포함하지 않음)

TI-3은 허용된 공급업체 권고/보안 뉴스의 원문 출처·공격 전제 교차 검증을 먼저 추가합니다. 이어 동일 Security Core 위 MCP stdio adapter(별도 요청/승인), TI-4 코드 경로·실행 조건, TI-5 사용자 승인 Diff와 재검증, Marketplace 준비 게이트를 진행합니다. 스케줄러·원격 발송·게시를 자동으로 시작하지 않습니다.

## 공식 의미론과 라이선스 근거

- [node-semver 공식 API 및 ISC](https://github.com/npm/node-semver)
- [PEP 440 공식 Version specifiers](https://packaging.python.org/en/latest/specifications/version-specifiers/)
- [pep440 라이브러리 공식 저장소/라이선스](https://github.com/renovatebot/pep440)
- [OSV 공식 schema와 version ranges](https://ossf.github.io/osv-schema/)

고정 설치본의 package.json/라이선스/실제 API를 대조했으며, 검증과 미검증 항목은 [TI-2 검증 기록](threat-intelligence-ti2-validation.md)에 구분합니다.
