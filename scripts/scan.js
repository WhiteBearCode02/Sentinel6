'use strict';
const path=require('node:path');
const {createSecurityService}=require('../src/security-service');
const controller=new AbortController();
process.on('SIGINT',()=>controller.abort());
const executables={};
for(const [id,name] of Object.entries({semgrep:'semgrep',osv:'osv-scanner',gitleaks:'gitleaks',trivy:'trivy'})) {
  if(process.env['SENTINEL6_'+id.toUpperCase()]) executables[id]=process.env['SENTINEL6_'+id.toUpperCase()];
}
createSecurityService({workspaces:[{id:'workspace',root:path.resolve(process.argv[2] || '.')}],scannerOptions:{executables,reportDir:process.argv[3] ? path.resolve(process.argv[3]) : undefined,cacheDir:process.env.SENTINEL6_TRIVY_CACHE,osvCacheDir:process.env.SENTINEL6_OSV_CACHE}})
  .then(service=>service.scanWorkspace({workspaceId:'workspace'},{signal:controller.signal}))
  .then(({report,reportFile,scanId,execution})=>{console.log(JSON.stringify({scanId,execution,scanners:report.scanners,coverage:report.coverage,findings:report.findings.length,reportFile},null,2)); if(report.scanners.some(s=>s.status !== 'completed')||execution.status!=='completed') process.exitCode=2;})
  .catch(()=>{console.error('Scan failed: verify paths, permissions and settings.');process.exitCode=1;});
