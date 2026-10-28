# Next development gates

이번 단계의 완료 지점은 공유 서비스·additive 메타데이터·인터페이스 일관성 검증과 MCP/배포 설계입니다. 아래 작업을 이번 승인 범위에서 자동으로 시작하지 않습니다.

## 1. Local MCP stdio adapter

1. 구현 시점의 공식 stable SDK/Node/보안 권고를 다시 확인하고 정확한 버전 고정.
2. SDK를 호출하는 작은 ESM adapter와 로컬 시작 config/허용 workspace ID 등록 구현. 분석 엔진은 기존 SecurityService만 호출.
3. 초기 4개 도구 strict input/outputSchema, bounded structured response, fixed stderr 오류와 stdout 프로토콜 분리.
4. worker 격리/전체 hard deadline/자손 종료 실패 테스트와 SDK modern/legacy stdio 테스트.
5. 별도 승인 후 host 설정에 로컬 stdio 프로세스 등록하고 실제 호출/취소 검증. 임의 shell, 원격 HTTP, 자동 패치/티켓 생성은 포함하지 않음.

완료 기준: 허용 root만 검사, 부적절한 파라미터/경로/프레임 차단, 미설치/실패 구분, 원본 불변, 비밀값 없는 bounded 응답, API/CLI와 같은 모델, 취소·단절 시 작업 종료. 그 뒤에도 Marketplace 게이트와 별개입니다.

## 2. Threat Intelligence: 수집을 중복 구현하지 않고 TI-2부터

현재 CISA/GitHub/OSV 수집과 SQLite/변경 추적/TI-1 Feed는 이미 구현됐습니다. 다시 만들지 않습니다.

1. 로컬 dependency inventory에 정확한 name/ecosystem/version/purl, 잠금 파일/직접·간접 여부·위치 근거를 수집. 비밀값/원본 내용 저장 금지.
2. 생태계별 검증된 버전 규칙으로 영향 범위를 비교. npm SemVer, PyPI PEP 440, Maven 규칙을 하나의 문자열 비교로 대체하지 않음. Git commit 범위·알 수 없는 버전은 확정 판정 금지.
3. 기존 scanner observation과 threat source alias를 보수적으로 연결. 프로젝트 영향 상태와 fix availability를 분리. 조건을 모르면 INSUFFICIENT_EVIDENCE/미검증을 유지.
4. SQLite에 project inventory, scan/match/evidence를 migration으로 추가하고 before/after를 기록. source revision과 version evidence를 재현 가능하게 연결.
5. 공식 공급업체 권고와 허용 RSS/API 교차 검증은 그 다음(TI-3). 뉴스 주장만으로 악용/취약성 확정하지 않음.
6. 이후 정적 도달 경로(TI-4), 승인 기반 Diff/테스트/재검사(TI-5). 현재 전역 호출 그래프나 자동 수정은 없음.

코드 변경이 없더라도 source revision/KEV 변경이 들어오면 관련 프로젝트만 재평가하고, 알림은 새 고위험 연관성/의미 있는 상태 상승에 한해 중복 억제합니다. 이는 앞으로 구현할 목표이지 현재 기능 설명이 아닙니다.

## 3. Marketplace: Primary product

[배포 준비 상태](distribution-readiness.md)의 Publisher·라이선스·PNG icon·사용자 문서·metadata·패키지 목록 게이트를 먼저 해결합니다. 라이선스는 사용자 선택 없이 확정하지 않습니다. 로컬 VSIX 생성/내용 검사/격리 설치/원본 불변 검증 후 별도 게시 승인을 받아야 합니다.

CI는 우선 읽기 전용의 npm ci/test/check 및 보안 검사로 설계하되, repository visibility와 runner/Actions 요금·spending 정책을 확인하고 비용이 발생할 수 있으면 사용자 동의 후 활성화합니다. 자동 publish job은 초기 CI에 넣지 않습니다. 실제 Push/Release/Marketplace 게시/예약 작업 등록은 별도 명시적 요청이 필요합니다.

## 4. Future desktop

이번 범위에서 Electron/Tauri UI나 installer를 만들지 않습니다. UI가 필요해질 때 동일 서비스와 모델을 호출하며 scanner adapter/parser/TI store를 복제하지 않습니다.
