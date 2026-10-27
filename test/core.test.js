const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs/promises');
const os=require('node:os');
const path=require('node:path');
const {scan,status,snapshot,argsFor}=require('../src/core');
async function temp(fn){const d=await fs.mkdtemp(path.join(os.tmpdir(),'s6-test-'));try{return await fn(d);}finally{await fs.rm(d,{recursive:true,force:true});}}
const missing=Object.fromEntries(['semgrep','osv','gitleaks','trivy'].map(s=>[s,path.resolve('.tools','does-not-exist',s+'.exe')]));
test('missing scanners do not crash and all uncovered areas are explicit',()=>temp(async d=>{
 const root=path.join(d,'source');await fs.mkdir(root);await fs.writeFile(path.join(root,'file.py'),'eval(x)');
 const {report,reportFile}=await scan(root,{executables:missing,reportDir:path.join(d,'reports')});
 assert.equal(report.scanners.length,4);assert.ok(report.scanners.every(s=>s.status==='not_installed' && s.install));
 assert.ok(Object.values(report.coverage).every(c=>!c.completed.length && c.uncompleted.length));
 assert.equal(JSON.parse(await fs.readFile(reportFile)).schemaVersion,1);assert.equal(await fs.readFile(path.join(root,'file.py'),'utf8'),'eval(x)');
}));
test('installation failures differ from missing tools',async()=>{const s=await status({...missing,semgrep:'not absolute'});assert.equal(s[0].status,'failed');assert.equal(s[1].status,'not_installed');});
test('scanner execution failure still reports every other scanner and area',()=>temp(async d=>{
 const root=path.join(d,'source');await fs.mkdir(root);
 const {report}=await scan(root,{executables:{...missing,gitleaks:process.execPath},reportDir:path.join(d,'reports')});
 assert.equal(report.scanners.find(s=>s.scanner==='gitleaks').status,'failed');
 assert.equal(report.scanners.find(s=>s.scanner==='trivy').status,'not_installed');
 assert.equal(report.scanners.length,4);assert.equal(report.coverage.secrets.completed.length,0);
}));
test('snapshot excludes scanner configuration, build trees and symlinks',()=>temp(async d=>{
 const root=path.join(d,'source'),dest=path.join(d,'copy');await fs.mkdir(root);await fs.mkdir(path.join(root,'node_modules'));
 await fs.writeFile(path.join(root,'app.py'),'eval(x)');await fs.writeFile(path.join(root,'trivy.yaml'),'untrusted');
 await fs.symlink(path.join(root,'node_modules'),path.join(root,'linked'),'junction');
 const result=await snapshot(root,dest);assert.equal(result.files,1);assert.equal(result.skipped.symlinks,1);assert.equal(result.skipped.scannerConfigs,1);
 assert.equal(await fs.readFile(path.join(dest,'app.py'),'utf8'),'eval(x)');
}));
test('reports cannot be saved in scanned source',()=>temp(async d=>{await assert.rejects(scan(d,{reportDir:path.join(d,'reports')}));}));
test('external report storage also works on a different Windows drive',()=>temp(async d=>{
 const {report,reportFile}=await scan(path.resolve('fixtures/vulnerable'),{executables:missing,reportDir:path.join(d,'reports')});
 assert.equal(report.scanners.length,4);assert.equal((await fs.stat(reportFile)).isFile(),true);
}));
test('storage symlinks cannot create files or directories in original project',()=>temp(async d=>{
 const root=path.join(d,'source');await fs.mkdir(root);await fs.symlink(root,path.join(d,'redirect'),'junction');
 await assert.rejects(scan(root,{reportDir:path.join(d,'redirect','new-directory')}));
 assert.deepEqual(await fs.readdir(root),[]);
 await assert.rejects(scan(root,{reportDir:path.join(d,'reports'),cacheDir:path.join(root,'cache')}));
 assert.deepEqual(await fs.readdir(root),[]);
}));
test('timeouts and scanner args cannot introduce shell commands',()=>temp(async d=>{
 await assert.rejects(scan(d,{timeout:Infinity}));
 for(const id of ['semgrep','osv','gitleaks','trivy']) {
 const args=argsFor(id,path.join(d,'project'),d,path.join(d,'cache'));assert.ok(args.every(x=>typeof x==='string'));assert.ok(!args.includes('--autofix'));assert.equal(args.at(-1),id==='semgrep' ? '.' : path.join(d,'project'));
 }
 assert.ok(argsFor('semgrep',d,d,d).includes('--metrics=off'));assert.ok(argsFor('osv',d,d,d).includes('--offline'));assert.ok(argsFor('gitleaks',d,d,d).includes('--redact=100'));assert.ok(argsFor('trivy',d,d,d).includes('--skip-db-update'));
}));
test('cancelled scan still saves coverage report',()=>temp(async d=>{
 const root=path.join(d,'src');await fs.mkdir(root);const c=new AbortController();c.abort();
 const {report}=await scan(root,{signal:c.signal,executables:missing,reportDir:path.join(d,'reports')});assert.ok(report.scanners.every(s=>s.status==='cancelled'));
}));
