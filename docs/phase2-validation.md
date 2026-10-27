# Phase 2 검증 기록

검증일: 2026-10-28 (Asia/Seoul). Windows x64 / Node 24.14.0.

## 시작 상태

저장소에는 `.git`만 있고 main 브랜치에 커밋이 없었습니다. Phase 1 소스·테스트·기존 동작은 검토할 수 없었습니다. Phase 2의 실행 기반으로 VS Code 확장 구조를 함께 구현했습니다.

## 실제 도구 탐지

`node scripts/live-test.js`를 실행했습니다. 의도적으로 취약한 Python 코드, Django/Requests 고정 버전 명세, Dockerfile, 실행 시 생성한 **가짜** GitHub 토큰을 사용했습니다. 취약 코드는 실행하지 않았고 취약 의존성을 설치하거나 컨테이너를 빌드하지 않았습니다.

| 도구 | 버전 | 원시 탐지 건수 | 결과 |
|---|---|---:|---|
| Semgrep CE | 1.182.1 | 2 | 완료: eval / shell=True |
| OSV-Scanner | 2.7.0 | 45 | 완료: Django/Requests 알려진 취약점 |
| Gitleaks | 8.30.1 | 1 | 완료: 합성 토큰 |
| Trivy | 0.76.1 | 32 | 완료: 의존성·합성 토큰·Dockerfile 설정 |

80건을 동일 파일·패키지 및 CVE/GHSA/PYSEC 별칭, 비밀정보 위치 기준으로 병합한 결과 **34건**입니다.

- 코드 패턴 2건
- 의존성 29건
- 비밀정보 1건
- 설정 문제 2건

검사 전후 fixture 파일 SHA-256이 모두 일치했습니다. 생성한 가짜 토큰 원문이 공통 보고서에 포함되지 않음을 assert로 검증했습니다. 모든 영역의 coverage.uncompleted가 빈 배열임을 확인했습니다. 실제 정제 보고서는 [phase2-sample-report.json](./phase2-sample-report.json)에 보존했습니다. OSV에서 등급이 없는 항목은 unknown으로 보존하고, Trivy 중복 결과에 등급이 있으면 높은 등급으로 병합합니다.

## 자동 검사

- `npm.cmd test`: 27개 통과, 실패/건너뜀 0개.
- `npm.cmd run check`: 런타임 JavaScript 구문 검사 통과.
- `git diff --check`: 통과.
- 파서 네 종류, 비밀정보 제거, 잘못된 JSON 구조, 경로 이탈, 심볼릭 링크 우회, 보고서/캐시의 원본 내부 쓰기 차단, 중복 병합, 미설치 상태, 검사 실패 격리, 원본 복사, 인수 처리, timeout, 실행 중 및 실행 전 취소를 검증했습니다.
- 런타임 npm 패키지 의존성은 0개입니다. 유료 API/AI 연동·배포는 없습니다.

## 구현 중 확인하고 수정한 문제

- Windows Semgrep: 실행 파일과 검사 임시 폴더의 드라이브가 다르면 Python/native bridge가 정지하는 현상을 최소 fixture로 재현했습니다. 임시 작업 위치를 조정하고 로컬 규칙도 복사했습니다. jobs=1 및 규칙별 timeout/메모리 한도도 적용했습니다.
- OSV 2.7.0: 공식 문서의 osv-scanner 하위 폴더 예시와 달리 실제 캐시는 osv-scalibr 하위 폴더에서 읽었습니다. 공식 이슈/변경 기록 및 실제 실행으로 확인해 사용 안내에 반영했습니다.
- OSV: 임시 폴더의 상위 gitignore가 탐지를 제외하는 경우 `--no-ignore`를 사용해 해결했습니다.
- Windows taskkill이 실패할 때 직접 프로세스 종료도 시도하도록 보완했습니다.

## VS Code 확장 호스트

`test/vscode-runner.js`는 실제 스캐너 결과로 Diagnostics 생성, Problems 위치, marker 이동 명령, 보고서 JSON 열기를 검사합니다. 기존 VS Code 1.142.0은 시스템 업데이트 mutex가 30초 이상 유지되어 새 인스턴스 시작이 종료되었습니다. 기존 설치/업데이트 프로세스는 변경하지 않았습니다.

별도 공식 ZIP 버전 검증 결과는 아래에 기록합니다.

VS Code **1.143.1**의 공식 Windows x64 ZIP을 내려받아 Microsoft update API의 SHA-256과 일치하는지 확인했습니다. 시스템 설치와 별개인 `.tools/vscode-portable` 및 격리 사용자 프로필을 사용했고 자동 업데이트/확장 자동 갱신/telemetry를 껐습니다.

`scripts/test-vscode.ps1` 실행 결과:

- Sentinel6 명령 4개 등록 확인.
- 네 실제 도구 결과로 Problems Diagnostics **34개** 생성.
- Python eval 진단이 **4행**을 가리키는 것 확인.
- VS Code `editor.action.marker.next` 실행 후 실제 편집기 선택 위치가 코드 행으로 이동함을 assert로 확인.
- Open Results 실행 후 활성 편집기에 로컬 JSON 보고서가 열리는 것 확인.
- 최종 보고서의 coverage와 scanner 4개 항목 확인.

실제 마우스로 Problems 항목을 클릭하는 자동화는 하지 않았습니다. VS Code 기본 Diagnostics 위치와 기본 문제 이동 명령을 통해 같은 소스 위치로 이동하는 경로를 검증했습니다. 임의의 사용자 프로젝트·모든 OS/언어·다른 도구 버전에서의 탐지까지 검증한 것은 아닙니다.
