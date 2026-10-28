'use strict';
const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs/promises');
const path=require('node:path');
const os=require('node:os');
const {createSecurityService}=require('../src/security-service');
const {withReportMetadata}=require('../src/report-model');
const {readBounded}=require('../src/core');
const {parse}=require('../src/parsers');
async function temp(fn){const d=await fs.mkdtemp(path.join(os.tmpdir(),'sentinel6-service-'));try{const root=path.join(d,'project');await fs.mkdir(root);return await fn(root,d);}finally{await fs.rm(d,{recursive:true,force:true});}}
const report=()=>withReportMetadata({schemaVersion:1,scanners:[],findings:[{id:'fixture',file:'app.py',line:4,endLine:4,rule:'fixture.eval',kind:'sast',message:'Potential unsafe code pattern',aliases:[],scanners:['semgrep']}],coverage:{sast:{completed:['semgrep'],uncompleted:[]}},limitations:['Fixture only']});
function fake(overrides={}) {return {status:async()=>[{scanner:'semgrep',status:'available',executable:'/private/tool',rawSecret:'private-secret',version:'1.2.3'}],scan:async()=>({report:report(),reportFile:'/local/generated-report.json'}),...overrides};}
async function service(root,options={},engines=fake()){return createSecurityService({workspaces:[{id:'workspace',root}],...options},engines);}
test('shared service delegates to the existing scanner with trusted host options only',()=>temp(async root=>{
 let received;const s=await service(root,{scannerOptions:{timeout:10000,reportDir:path.dirname(root)}},fake({scan:async(r,o)=>{received={root:r,options:o};return {report:report(),reportFile:'/local/report.json'};}}));
 const result=await s.scanWorkspace({workspaceId:'workspace',timeoutMs:5000});assert.equal(received.root,await fs.realpath(root));assert.equal(received.options.timeout,5000);assert.equal(received.options.reportDir,path.dirname(root));assert.equal(result.execution.status,'completed');
 assert.deepEqual(s.getReport({scanId:result.scanId,includeFindings:true}).report,result.report);
}));
test('future MCP-shaped payloads reject commands, output paths, edits, extra parameters and malformed IDs',()=>temp(async root=>{
 let calls=0;await fs.writeFile(path.join(root,'app.py'),'unchanged');const s=await service(root,{},fake({scan:async()=>{calls++;return {report:report()};}}));
 for(const args of [null,[],{},{workspaceId:'workspace',command:'rm'},{workspaceId:'workspace',executables:{}},{workspaceId:'workspace',reportDir:root},{workspaceId:'workspace',applyFix:true},{workspaceId:'workspace',signal:{}},{workspaceId:'workspace',timeoutMs:NaN}])await assert.rejects(s.scanWorkspace(args));
 for(const id of ['../other',path.dirname(root),'unknown',{},'workspace\n'])await assert.rejects(s.scanWorkspace({workspaceId:id}));
 assert.equal(calls,0);assert.equal(await fs.readFile(path.join(root,'app.py'),'utf8'),'unchanged');
}));
test('allowlist realpath is rechecked after a registered symlink is retargeted',()=>temp(async(root,d)=>{
 const other=path.join(d,'other'),link=path.join(d,'linked');await fs.mkdir(other);await fs.symlink(root,link,'junction');const s=await createSecurityService({workspaces:[{id:'workspace',root:link}]},fake());
 await fs.unlink(link);await fs.symlink(other,link,'junction');await assert.rejects(s.scanWorkspace({workspaceId:'workspace'}),e=>e.code==='workspace_changed');
}));
test('scanner status strips executable paths and fields outside the public status model',()=>temp(async root=>{
 const s=await service(root);const result=await s.scannerStatus();assert.equal(result[0].version,'1.2.3');assert.ok(!JSON.stringify(result).includes('/private'));assert.ok(!JSON.stringify(result).includes('private-secret'));await assert.rejects(s.scannerStatus({command:'anything'}));
}));
test('report access is by generated ID only with strict bounded pagination',()=>temp(async root=>{
 const s=await service(root);const {scanId}=await s.scanWorkspace({workspaceId:'workspace'});
 assert.throws(()=>s.getReport({path:'/local/generated-report.json'}));assert.throws(()=>s.getReport({scanId:'../../report'}));assert.throws(()=>s.getReport({scanId:'unknown'}),e=>e.code==='report_not_found');
 for(const args of [{scanId,limit:101},{scanId,offset:-1},{scanId,offset:0.5},{scanId,offset:2},{scanId,limit:'1'},{scanId,file:'app.py'}])assert.throws(()=>s.getFindings(args));
 const page=s.getFindings({scanId,limit:1});assert.equal(page.total,1);assert.equal(page.findings[0].line,4);assert.equal(page.nextOffset,null);
 const header=s.getReport({scanId});assert.equal(header.findingsIncluded,false);assert.equal(header.totalFindings,1);assert.deepEqual(header.report.findings,[]);
}));
test('local response mutation cannot modify retained reports; retrieval has a byte bound',()=>temp(async root=>{
 const s=await service(root,{maxResponseBytes:1024},fake({scan:async()=>({report:{...report(),limitations:['x'.repeat(2000)]}})}));const {scanId,report:local}=await s.scanWorkspace({workspaceId:'workspace'});local.findings[0].message='private-secret';
 assert.ok(!JSON.stringify(s.getFindings({scanId,limit:1})).includes('private-secret'));
 assert.throws(()=>s.getReport({scanId,includeFindings:true}),e=>e.code==='result_limit');
}));
test('retained report count is bounded and old scan IDs expire',()=>temp(async root=>{
 const s=await service(root,{maxReports:1});const first=await s.scanWorkspace({workspaceId:'workspace'}),second=await s.scanWorkspace({workspaceId:'workspace'});
 assert.throws(()=>s.getReport({scanId:first.scanId}),e=>e.code==='report_not_found');assert.equal(s.getReport({scanId:second.scanId}).totalFindings,1);
}));
test('transport-ready service envelopes do not reintroduce scanner secrets or artifact paths',()=>temp(async root=>{
 const secret='ghp_'+'a'.repeat(36);
 const safe=withReportMetadata({schemaVersion:1,findings:parse('gitleaks',[{File:'app.py',StartLine:1,EndLine:1,RuleID:'github-pat',Secret:secret,Match:secret,Description:secret}],root),scanners:[],coverage:{},limitations:[]});
 const s=await service(root,{},fake({scan:async()=>({report:safe,reportFile:'/private/local-report.json'})}));const {scanId}=await s.scanWorkspace({workspaceId:'workspace'});
 const serialized=JSON.stringify([s.getReport({scanId,includeFindings:true}),s.getFindings({scanId})]);
 assert.ok(!serialized.includes(secret));assert.ok(!serialized.includes('/private/local-report.json'));assert.ok(!serialized.includes('"Secret"'));assert.ok(!serialized.includes('"Match"'));
}));
test('request cancellation is propagated without adding command execution or file edits',()=>temp(async root=>{
 const c=new AbortController();c.abort();let aborted;
 const s=await service(root,{},fake({scan:async(_r,o)=>{aborted=o.signal.aborted;return {report:report()};}}));const r=await s.scanWorkspace({workspaceId:'workspace'},{signal:c.signal});assert.equal(aborted,true);assert.equal(r.execution.status,'cancelled');
}));
test('request deadline aborts the underlying scan and records timeout separately',()=>temp(async root=>{
 const s=await service(root,{totalTimeoutMs:50},fake({scan:async(_r,o)=>new Promise(resolve=>o.signal.addEventListener('abort',()=>resolve({report:report()}),{once:true}))}));const r=await s.scanWorkspace({workspaceId:'workspace'});assert.equal(r.execution.status,'timeout');
}));
test('one scan runs per service instance and busy requests cannot start a second scan',()=>temp(async root=>{
 let finish;const waiting=new Promise(r=>finish=r);const s=await service(root,{},fake({scan:async()=>{await waiting;return {report:report()};}}));const first=s.scanWorkspace({workspaceId:'workspace'});await new Promise(r=>setTimeout(r,10));await assert.rejects(s.scanWorkspace({workspaceId:'workspace'}),e=>e.code==='scan_busy');finish();await first;
}));
test('real missing-scanner scan preserves original files and produces the common model',()=>temp(async(root,d)=>{
 await fs.writeFile(path.join(root,'app.py'),'eval(user_input)');const executables=Object.fromEntries(['semgrep','osv','gitleaks','trivy'].map(id=>[id,path.join(d,'not-installed',id+'.exe')]));
 const s=await createSecurityService({workspaces:[{id:'workspace',root}],scannerOptions:{executables,reportDir:path.join(d,'reports')}});const {report:r,reportFile}=await s.scanWorkspace({workspaceId:'workspace'});
 assert.equal(r.modelVersion,'1.1');assert.ok(r.scanners.every(s=>s.status==='not_installed'));assert.deepEqual(JSON.parse(await fs.readFile(reportFile,'utf8')),JSON.parse(JSON.stringify(r)));assert.equal(await fs.readFile(path.join(root,'app.py'),'utf8'),'eval(user_input)');
}));
test('legacy v1 reports receive additive defaults while original fields and IDs remain intact',async()=>{
 const old=JSON.parse(await fs.readFile(path.resolve('docs/phase2-sample-report.json'),'utf8')),original=JSON.stringify(old);const next=withReportMetadata(old);
 assert.equal(next.schemaVersion,1);assert.equal(next.modelVersion,'1.1');assert.equal(JSON.stringify(old),original);assert.deepEqual(next.findings.map(f=>f.id),old.findings.map(f=>f.id));assert.ok(next.findings.every(f=>f.impact.status==='NOT_ANALYZED'));assert.throws(()=>withReportMetadata({...old,schemaVersion:2}));
});
test('bounded reads reject growth beyond the actual byte limit instead of trusting stat size',async()=>{
 let position=0;const source=Buffer.from('secret-growth');const handle={async read(buffer,offset,length){const n=Math.min(length,source.length-position);source.copy(buffer,offset,position,position+n);position+=n;return {bytesRead:n};}};
 await assert.rejects(readBounded(handle,5),/file_size_limit/);assert.ok(position<=6,'Read must stop at cap + 1');
 const empty={read:async()=>({bytesRead:0})};assert.equal((await readBounded(empty,5)).length,0);
});
