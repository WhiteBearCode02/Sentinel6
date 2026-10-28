# Distribution Architecture & Marketplace Readiness

검토일: 2026-10-28. 검토 시작 기준은 main `1448275`, manifest `0.3.0`입니다. 사용자 설명의 v0.2.0 이후 TI-1이 이미 추가되어 있습니다. 이 문서는 배포 준비 상태와 다음 검증 절차를 기록하며 Marketplace 게시 승인이 아닙니다.

## 제품 경계

| 인터페이스 | 현재 상태 | 배포 방향 |
|---|---|---|
| VS Code Extension | 스캐너 4종·Problems·TI-1 Feed 구현 | Primary product. 로컬 VSIX 검증 후 Marketplace를 우선 |
| Local CLI | 기존 scan/Threat 수집 진입점 존재 | 공통 Security Core를 호출하는 로컬 인터페이스 |
| Local MCP stdio | 현재 단계에서 도입 설계 | 동일 코어를 호출. 원격 HTTP·별도 분석 엔진·백그라운드 scheduler를 만들지 않음 |
| Desktop application | 미구현 | 향후 같은 코어 재사용. 이번 배포 범위 제외 |

확장·CLI·MCP는 어댑터이고 분석 규칙과 결과 정규화는 공통 코어에 둡니다. 배포 채널이 늘어나도 스캐너 실행·경로 검증·비밀정보 제거를 복제하면 안 됩니다.

## 준비 상태

| 항목 | 확인 결과 | Marketplace 전 필요한 작업 |
|---|---|---|
| Publisher | `sentinel6-local` 문자열 존재. 계정·소유권·사용 가능 여부 미검증 | 사용자가 소유하는 Publisher ID 확정 및 계정에서 권한 확인. 이름을 임의로 등록/변경하지 않음 |
| License | `UNLICENSED`, 루트 LICENSE 없음 | 사용자 선택 후 라이선스 파일과 manifest를 함께 갱신. 현재 값 유지 |
| Marketplace icon | `package.json.icon` 없음 | 사용자가 승인한 PNG 등 지원 이미지 준비. Activity Bar의 `resources/sentinel6.svg`는 별도 용도 |
| README | 개발 호스트/F5, 도구 설치, 검사 범위, TI-1 안내 존재 | 일반 설치 사용법, 지원 OS/버전, 데이터 흐름·공개 HTTP 수집 기본값, 제한과 현재 화면을 최종 검토 |
| CHANGELOG | 이번 단계에 기존 0.2.0/0.3.0 이력 문서 추가 | 실제 패키지에 포함하고 게시할 버전/변경 내용 확정 |
| SECURITY.md | 이번 단계에 신고·취급 경계 문서 추가 | 비공개 신고 채널 활성화 여부와 운영 담당자 확인. 응답 시간·지원 기간은 미약속 |
| Extension metadata | name/displayName/version/main/engines/contributes 존재 | repository/bugs/homepage, 검색 category/keywords, 설명과 무료 표시를 검토. 게시 이름의 사용 가능 여부 미검증 |
| VSIX packaging | 고정 vsce 도구·package 명령·`.vscodeignore` 없음. 이 검토에서 VSIX 생성/설치 미수행 | 도구 버전 고정, 패키지 파일 목록 검토, 로컬 생성/격리 설치 검증 |
| GitHub Actions CI | `.github/workflows` 없음 | 읽기 전용 검증 workflow를 별도 검토. 계정/runner/요금 조건 확인과 사용자 승인 후 활성화 |
| 공개 게시 | 미수행 | 아래 release gates 완료 후 사용자의 별도 게시 승인 필요 |

Publisher를 소유하는 것과 Marketplace의 verified-domain badge는 별개입니다. 검증 배지가 있다고 표시하지 않습니다. 공식 게시 문서는 Publisher와 VSIX 절차를 설명하고, manifest icon에 SVG를 허용하지 않습니다. [VS Code 공식 게시 문서](https://code.visualstudio.com/api/working-with-extensions/publishing-extension), [공식 Extension Manifest](https://code.visualstudio.com/api/references/extension-manifest).

## 라이선스 선택은 보류

라이선스를 선택하거나 LICENSE 파일을 생성하지 않았습니다. 아래는 사용자 결정에 필요한 후보이며 프로젝트에 적용했다는 뜻이 아닙니다.

| 후보 | 선택 시 검토할 방향 |
|---|---|
| [MIT](https://opensource.org/license/mit) | 간결한 허용형 배포. 저작권·허가 고지 유지 조건 검토 |
| [Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0) | 허용형 배포와 명시적 특허 조항이 필요한 경우. 변경·고지 조건 검토 |
| [GPL-3.0](https://www.gnu.org/licenses/gpl-3.0.html) | 강한 copyleft 방향을 원하는 경우. 배포 방식과 소스 제공 조건 검토 |

선택 후 저작권자·기여 코드 권한·의존성/동봉 자산의 고지 요구를 확인해야 합니다. 무료 사용·Marketplace 공개·오픈 소스 라이선스는 서로 다른 결정입니다. `UNLICENSED`를 임의의 오픈 소스 허가로 해석하지 않습니다. 현 단계에서는 스캐너 실행 파일과 취약점 DB를 패키지에 동봉하지 않습니다.

## 패키지 경계와 누출 방지

`.gitignore`는 현재 `.tools/`, `.cache/`, `reports/`, `node_modules/`, `*.vsix`, `debug.log`를 제외합니다. Git에서 제외된다는 사실만으로 VSIX 제외를 확인했다고 볼 수 없습니다. 공식 문서는 `.vscodeignore`로 런타임에 불필요한 파일을 제외하도록 안내합니다. [공식 패키지 제외 규칙](https://code.visualstudio.com/api/working-with-extensions/publishing-extension#using-vscodeignore).

실제 패키징 전 파일 목록을 명시적으로 검토해야 합니다.

| 포함 필요 | 제외 필요 |
|---|---|
| `package.json`, `src/**`, `rules/semgrep.yml`, 사용되는 UI 자산 | `.git/**`, `.tools/**`, `.cache/**`, `reports/**`, `debug.log` |
| README/CHANGELOG/SECURITY 및 확정된 LICENSE/필수 제3자 고지 | 스캐너 원시 JSON, 실제 사용자 프로젝트, 환경변수 파일, 인증 파일 |
| `sql.js`의 실제 런타임 JS·`dist/sql-wasm.wasm` 및 해당 패키지 라이선스 | 테스트용 취약 fixture, 테스트 프로필, 테스트 도구 다운로드 파일 |

`src/threat/store.js`는 `require.resolve('sql.js/dist/'+file)`로 WASM을 로컬에서 찾습니다. `node_modules` 전체를 무조건 제외하면 TI-1이 설치 후 실패할 수 있습니다. 반대로 개발용 파일·DB를 함께 넣어서도 안 됩니다. vsce 파일 목록과 최종 VSIX ZIP 내용에서 JS/WASM 포함 여부 및 비공개 산출물 부재를 확인해야 합니다. 고정 npm 의존성은 `package-lock.json`으로 재현합니다.

원본 scanner 바이너리, 가상환경, 취약점 DB의 다운로드·검증은 사용자 환경 또는 명시적 테스트 준비 단계입니다. 새 사용자에게 `.tools`가 있다고 가정하지 않고 미설치 안내가 작동해야 합니다.

## 로컬 패키징과 설치 검증 순서

이 절차는 다음 배포 준비 단계에서 실행할 계획입니다. 이번 검토에서 실행하지 않았습니다.

1. Publisher/라이선스/icon/메타데이터를 확정하고 지원 대상 OS·VS Code 최소 버전을 정합니다.
2. 적절한 `@vscode/vsce` 버전을 검토·고정하고 `.vscodeignore` 또는 검증 가능한 패키지 포함 정책을 추가합니다. 패키징만으로 게시되지 않는 명령을 사용합니다.
3. `npm ci --ignore-scripts`, `npm test`, `npm run check`를 실행합니다. 실제 스캐너·확장 호스트 검사는 별도 준비 조건과 실행 결과를 남깁니다.
4. vsce의 파일 목록과 로컬 VSIX를 검사합니다. `.tools/.cache/reports`, 원시 결과·사용자 자료·토큰이 들어가면 중단합니다.
5. 격리된 VS Code 프로필에 로컬 VSIX를 설치합니다. 개발 호스트/F5 성공을 설치 검증으로 대체하지 않습니다.
6. sql.js WASM 로드, scanner 미설치/실패/취소, Problems 위치와 보고서, TI 공개 HTTP 수집/오프라인 캐시를 확인합니다.
7. 패키지 해시·검증한 OS/VS Code/도구 버전·제한을 기록하고 사용자가 검토할 결과를 만듭니다.

공식 도구의 `vsce package`는 로컬 VSIX를 만들고, 실제 게시 단계는 별도입니다. 게시·로그인·Publisher 생성 명령은 이번 단계에서 실행하지 않습니다. [공식 VSIX 패키징·설치 안내](https://code.visualstudio.com/api/working-with-extensions/publishing-extension#packaging-extensions).

## CI와 비용 경계

초기 CI 제안은 의존성 고정 설치, unit tests, 구문 검사와 패키지 내용 검증입니다. `contents: read`, 실행 시간 제한, 중복 job 취소, 짧은 artifact 보존을 기본으로 하고 게시 credential은 넣지 않습니다. 네트워크가 필요한 실제 공개 피드 검사는 결정적인 모의 응답 unit tests와 분리해야 합니다.

이 문서는 workflow를 추가하거나 Actions를 실행하지 않습니다. 저장소 공개 여부·계정 플랜·runner 종류·사용량·artifact 과금 조건을 확인하지 않았으므로 무료라고 단정하지 않습니다. 실행 또는 과금 가능 기능 활성화 전 조건을 보여주고 사용자 승인을 받아야 합니다. 로컬 `npm test`/구문 검증 경로는 유지합니다. 확장 호스트 CI는 별도 준비가 필요합니다. [VS Code 공식 CI 문서](https://code.visualstudio.com/api/working-with-extensions/continuous-integration).

게시 자동화는 검증 CI와 분리합니다. 공식 인증 방식은 게시 시점에 다시 확인하며, 토큰/클라우드 계정/인증 자원을 지금 생성하지 않습니다. 오래된 인증 예제를 그대로 활성화하지 않습니다.

## Release gates

- [ ] 사용자가 라이선스를 선택하고 LICENSE와 manifest가 일치한다.
- [ ] 실제 Publisher 소유권과 최종 extension ID/이름을 확인했다.
- [ ] Marketplace용 이미지와 검색/지원 메타데이터가 준비됐다.
- [ ] 비공개 보안 신고 채널과 유지관리 범위가 확인됐다.
- [ ] 패키지에서 비밀정보·사용자 자료·개발 DB/도구가 제외됐다.
- [ ] 설치된 VSIX에서 런타임 JS/WASM·스캐너·Problems·TI 흐름을 검증했다.
- [ ] 선언한 최소 VS Code/Node 및 지원 OS 범위를 실제 증거와 맞췄다.
- [ ] CI를 활성화한다면 권한과 비용 조건에 동의했다.
- [ ] 게시할 정확한 VSIX/버전/검증 결과를 사용자가 검토하고 게시를 별도 승인했다.

이 목록을 충족하기 전 Marketplace 준비 완료나 공개 배포 완료로 보고하지 않습니다. 게시 이후 지원 정책, 별도 MCP 배포, Desktop 배포는 후속 작업입니다.
