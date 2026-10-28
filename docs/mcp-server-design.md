# Local MCP adapter — design only

2026-10-28 기준. **이 문서는 서버 구현/설치/연결 완료를 뜻하지 않습니다.** 이번 단계에 SDK 의존성, stdio entrypoint, 원격 HTTP listener, Codex 설정 변경은 추가하지 않았습니다. 구현한 것은 MCP가 재사용할 `SecurityService` 경계와 그 입력/결과 테스트입니다.

## 공식 SDK 선택

공식 TypeScript SDK main은 현재 v2 stable이며 npm read-only 조회에서 `@modelcontextprotocol/server` latest **2.4.0**, Node **>=20**을 확인했습니다. 이 패키지는 core 2.4.0과 Zod ^4.2.0을 사용합니다. legacy 패키지 `@modelcontextprotocol/sdk` 1.32.2와 섞지 않습니다. 실제 도입 시 다시 안정 버전/보안 권고를 확인하고 server/core/Zod를 lockfile로 고정해야 합니다. [공식 SDK](https://github.com/modelcontextprotocol/typescript-sdk), [v2 문서](https://ts.sdk.modelcontextprotocol.io/v2/).

기존 CJS JavaScript 엔진을 유지하고 향후 작은 `src/mcp/server.mjs`에서 ESM SDK를 import하는 방식입니다. TypeScript SDK가 JavaScript 서버의 전체 TypeScript 재작성을 요구하는 것은 아닙니다.

stdio는 `McpServer`와 `@modelcontextprotocol/server/stdio`의 **serveStdio(factory)**를 사용합니다. 현대/legacy 프로토콜 협상은 공식 helper로 처리하고 JSON-RPC를 수동 재구현하지 않습니다. [공식 stdio](https://ts.sdk.modelcontextprotocol.io/v2/serving/stdio.html).

## 초기 도구 계약

모든 입력 스키마는 strict object로 unknown key를 거부합니다. annotations는 UI hint일 뿐 접근 권한 검사가 아닙니다. scan은 생성 보고서와 앱 캐시를 쓰므로 readOnlyHint를 맹목적으로 true로 표시하지 않습니다. 원본 코드 변경 도구는 없습니다.

| 도구 | 입력 | 연결/반환 |
|---|---|---|
| sentinel6_scanner_status | `{}` | service.scannerStatus(), executable path 제외 |
| sentinel6_scan_workspace | `{workspaceId, timeoutMs?}` | scanWorkspace() 후 getReport({scanId})의 header + execution 상태만 전송 |
| sentinel6_get_findings | `{scanId, offset?, limit?}` | getFindings(), total/nextOffset, 기본50/최대100 |
| sentinel6_get_report | `{scanId, includeFindings?}` | getReport(), 기본 header. 전체 내용이 byte 한도 초과하면 result_limit |

workspaceId/scanId는 `[A-Za-z0-9_-]` 1~80자, timeoutMs는 안전한 정수 50~600000이며 실제 한도는 호스트 설정 이하입니다. offset은 안전한 정수 0~해당 finding 수, limit은 1~100, includeFindings는 boolean입니다. ID는 경로가 아닙니다. 권한은 시작 시 사용자가 명시한 허용 작업 공간만으로 정하며 host가 제공하는 roots를 자동 승인 목록으로 쓰지 않습니다.

`getReport` header의 빈 findings는 검사 결과 0건이라는 의미가 아닙니다. findingsIncluded:false와 totalFindings를 함께 표시해야 합니다. scan 결과의 reportFile, 실행 파일 경로, 스캐너 원시 stdout/stderr, 파일 내용은 반환하지 않습니다. 보고서는 생성된 ID와 현재 프로세스의 제한된 저장소에서만 조회하며 파일 경로를 입력받지 않습니다.

## 구현 형태 예시 — 아직 실행되지 않은 설계 스케치

```javascript
import {McpServer} from '@modelcontextprotocol/server';
import {serveStdio} from '@modelcontextprotocol/server/stdio';
import {z} from 'zod/v4';
import shared from '../security-service.js';

// trustedConfig는 서버 시작 시 로컬 사용자가 제공/승인. tools/call에서 받지 않음.
const service = await shared.createSecurityService(trustedConfig);
serveStdio(() => {
  const server = new McpServer(
    {name: 'sentinel6', version: productVersion},
    {maxToolInputElements: 16}
  );
  server.registerTool('sentinel6_scan_workspace', {
    inputSchema: z.object({
      workspaceId: z.string().regex(/^[A-Za-z0-9_-]{1,80}$/),
      timeoutMs: z.number().int().min(50).max(600000).optional()
    }).strict()
  }, async (args, ctx) => {
    const local = await service.scanWorkspace(args, {signal: ctx.mcpReq.signal});
    const bounded = service.getReport({scanId: local.scanId});
    // 별도 outputSchema, 최종 serialized frame 한도, 안전한 오류 변환 추가 필요.
    return {
      content: [{type: 'text', text: `Scan ${local.scanId}: ${local.execution.status}`}],
      structuredContent: {...bounded, execution: local.execution}
    };
  });
  return server;
});
```

나머지 3개 도구도 같은 방식으로 등록하고 outputSchema를 명시해야 합니다. 실제 구현에서는 설명/오류 처리/권한 설정/종료 처리와 통합 테스트가 더 필요하므로 이 스케치만으로 제품을 실행하지 않습니다. 공식 `registerTool`은 스키마 검증과 structuredContent/outputSchema를 지원합니다. [Tools](https://ts.sdk.modelcontextprotocol.io/v2/servers/tools.html).

## 프로세스·프로토콜 보안 경계

- 로컬 stdio만 제공. HTTP/TCP/remote listener와 외부 인증 서버는 기본 미구현/비활성.
- stdout은 JSON-RPC 전용. readiness/고정 오류 코드는 stderr. CLI 스크립트는 stdout에 사용자용 JSON을 쓰므로 MCP entrypoint에서 import/실행하지 않음.
- 스캐너는 기존 shell:false 실행 계층으로만 호출. command/args/exec/report path/environment overrides는 tool input에 없음.
- SDK 요청의 `ctx.mcpReq.signal`을 공유 서비스로 전달. 연결 종료/notifications cancellation도 전파. 취소 사유 문자열 자체는 로그로 복사하지 않음. [공식 취소 문서](https://ts.sdk.modelcontextprotocol.io/v2/servers/logging-progress-cancellation.html).
- 호스트는 서버 실행·작업 공간 허용·필요 도구 호출을 승인. 서버도 독립적으로 workspace allowlist를 검증. MCP annotations나 LLM 응답을 승인으로 간주하지 않음.
- 원본 파일 읽기는 분석 목적만, 자동 패치/수정/Git/PR/비밀정보 수집·전송 도구 없음. 보고서는 앱 저장소에만 생성.
- 서비스 응답 256 KiB를 유지하고 최종 MCP envelope는 별도 한도(계획: 300 KiB) 검사. 인바운드 frame 한도와 maxToolInputElements를 별도 적용. text에 같은 전체 JSON을 중복 복사하지 않음.
- 한 번에 한 스캔, 최근3개/64MiB 메모리 결과 보관. 세션 종료/만료 후 report_not_found. 원시 예외·source snippets·취약한 API 문서의 지시문을 명령으로 실행하지 않음.
- core의 cooperative deadline를 실제 hard deadline로 오해하지 않음. worker 격리와 강제 종료 실패/자손 프로세스 테스트를 배포 전에 추가해야 함.

## 미구현 후속 도구

`sentinel6_check_threat_updates`, `sentinel6_analyze_cve_impact`, `sentinel6_explain_finding`, `sentinel6_suggest_remediation`은 광고하거나 등록하지 않습니다. 기존 TI-1 Monitor/SQLite를 재사용하되 프로젝트 버전 비교 및 근거 기반 영향 판정이 먼저 필요합니다. 로컬 LLM은 선택 기능이며 기본 판단에 필수 조건으로 만들지 않습니다.

MCP 프로세스는 host가 열어 둔 동안의 도구 endpoint입니다. **백그라운드 스케줄러가 아닙니다.** VS Code가 닫혀도 실행할 daily job은 별도 Windows scheduler/Actions 구현과 사용자 승인·비용/권한 확인이 필요합니다.

Sentinel6 자체는 유료 LLM API를 호출하지 않습니다. Codex 같은 host의 모델 사용량·구독·API 청구는 host 설정과 요금제에 속하며 Sentinel6의 API 비용과 별개입니다. 이 단계에서는 Codex 설정이나 과금 계정을 변경하지 않았습니다.

## 도입 전에 남은 검증

실제 SDK 설치와 stdio 서버 4도구 구현, modern/legacy initialize/tools-list/tools-call, 잘못된 JSON/frame/extra-field rejection, stdout 순수성, stderr 비밀값 검사, 요청 취소·연결 종료, timeout/동시 호출/메모리 eviction, worker 강제 종료, host 승인/allowlist 설정, Windows/macOS/Linux 검증이 필요합니다. 이번 서비스 테스트는 이 프로토콜 검증을 대체하지 않습니다. 구체적 순서는 [다음 개발 계획](next-development-plan.md)에 있습니다.
