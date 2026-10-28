# Changelog

이 파일은 구현 이력입니다. Marketplace에 공개된 릴리스 목록을 뜻하지 않습니다.

## Unreleased

- TI-3: Red Hat 공식 보안 API/Cisco Talos 연구 RSS의 별도 opt-in 수집 adapter와 기존 daily monitor 연결.
- 출처별 주장·공식 alias·독립 출처/미러 구분·충돌·PoC/악용 확인 수준, 명시적 조건/CWE/검증된 CVSS 분석 추가.
- 기존 TI-2 결과에 별도 ti-3.0 조건 envelope와 제한된 읽기 전용 .npmrc 근거 연결. 설치·기능 사용·외부 노출·공격 성공은 미확인 유지.
- SQLite user_version 3의 뉴스·분석·revision 저장, 기존 데이터 보존, 정규화 cache version/중복 억제·보존/삭제 추가.
- VS Code 상세/조건/출처 검증/Markdown/뉴스 갱신 명령 5개 추가. XML 파서 sax 1.6.1 (BlueOak-1.0.0) 고정, 본문 크롤링/AI/자동 수정 없음.

- TI-2: npm/PyPI 의존성 inventory, 고정 SemVer/PEP 440 비교, 공식 패키지 식별자 기반 영향 판정·근거·수정 버전 후보·우선순위 추가.
- SQLite v1→v2 무손실 마이그레이션, 프로젝트 snapshot·이력·알림 중복 억제 및 관련 revision/의존성 변경 재평가 추가.
- 기본 OFF인 프로젝트 분석 opt-in, 기존 Threat Feed 내 영향 분류, JSON/Markdown 근거·의존성 위치 이동·재평가/취소 명령 추가.
- 기존 scanner schemaVersion 1/modelVersion 1.1과 CLI/Problems를 유지. TI-2 보고서는 별도 modelVersion ti-2.0. 설치/실행/공격 경로는 미검증.
- 고정 PEP 440 라이브러리의 지원 범위에 맞춰 Node engine을 20.9+/20.x, 22.11+/22.x, 24.x로 명시. 프로젝트 라이선스는 UNLICENSED 유지.

- 기존 scan()을 공유하는 SecurityService와 CLI/VS Code 연결, 허용 workspace ID·bounded 결과 조회 추가.
- schemaVersion 1을 유지하는 modelVersion 1.1의 패키지/버전/권고 근거 메타데이터 추가. 알 수 없는 프로젝트 영향은 NOT_ANALYZED 유지.
- Semgrep 임시 경로가 rule ID에 들어가 실행마다 ID가 바뀌던 문제 수정. 기존 경로 접두사 기반 Semgrep ID와는 달라질 수 있음.
- snapshot과 raw 결과를 실제 byte 한도 안에서 읽도록 보강. MCP는 stdio 설계 문서와 서비스 경계 검증까지이며 SDK/서버는 미구현.
- Marketplace 준비 상태, 패키지 경계와 게시 승인 조건 문서 추가.
- 보안 문제 신고와 데이터 취급 경계를 설명하는 SECURITY.md 추가.

## 0.3.0

- 기존 확장 내부에 CISA KEV, GitHub Reviewed Advisories, OSV 변경 수집 추가.
- SQLite 로컬 캐시, 변경 이력, 조건부 HTTP 캐시와 누락 구간 이어받기 추가.
- VS Code 실행 중 일일 갱신, 수동 수집/취소, Threat Feed 및 근거 JSON 열기 추가.
- 프로젝트 영향은 NOT_ANALYZED로 유지. NVD/KISA/RSS, 코드 경로, 자동 수정, OS 예약 작업, GitHub Actions와 MCP 서버는 미구현/비활성.

## 0.2.0

- Semgrep CE, OSV-Scanner, Gitleaks, Trivy 로컬 CLI 연동.
- 설치 상태, 실행 실패/시간 제한/취소, 정규화된 JSON과 중복 병합 추가.
- VS Code Problems 진단, 파일 위치 이동과 로컬 JSON 보고서 추가.
- 임시 복사본 검사, 경로·인수 검증과 비밀정보 필드 제거 추가.
