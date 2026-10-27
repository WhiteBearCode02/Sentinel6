const {test}=require('node:test');
const assert=require('node:assert/strict');
const path=require('node:path');
const {parse,merge,safePath,checkedFile}=require('../src/parsers');
const fs=require('node:fs/promises');
const os=require('node:os');
const root=path.resolve('fixtures/vulnerable');
test('Semgrep normalizes location, severity and strips source/secret messages',()=>{
 const [f]=parse('semgrep',{results:[{path:'app.py',start:{line:4},end:{line:4},check_id:'eval',extra:{severity:'ERROR',message:'private-value',lines:'private-code'}}],errors:[]},root);
 assert.equal(f.line,4);assert.equal(f.severity,'high');assert.ok(!JSON.stringify(f).includes('private-'));
});
test('Gitleaks strips Secret, Match, Description and bad line numbers',()=>{
 const [f]=parse('gitleaks',[{File:'app.py',StartLine:-1,EndLine:NaN,RuleID:'generic-api-key',Secret:'private-value',Match:'private-value',Description:'private-value'}],root);
 assert.equal(f.line,1);assert.ok(!JSON.stringify(f).includes('private-value'));
});
test('OSV maps packages, aliases and unknown severity conservatively',()=>{
 const [f]=parse('osv',{results:[{source:{path:'requirements.txt'},packages:[{package:{name:'django'},vulnerabilities:[{id:'GHSA-abc',aliases:['CVE-2020-0001']}]}]}]},root);
 assert.equal(f.package,'django');assert.equal(f.severity,'unknown');assert.deepEqual(f.aliases,['CVE-2020-0001']);
});
test('Trivy supports vulnerabilities, secrets, misconfiguration and PASS suppression',()=>{
 const f=parse('trivy',{SchemaVersion:2,Results:[{Target:'Dockerfile',Vulnerabilities:[{VulnerabilityID:'CVE-2020-0001',PkgName:'alpine',Severity:'CRITICAL'}],Secrets:[{RuleID:'token',StartLine:2,EndLine:3,Match:'private-value'}],Misconfigurations:[{ID:'AVD-1',Status:'FAIL',Severity:'LOW',CauseMetadata:{StartLine:2}},{ID:'AVD-2',Status:'PASS'}]}]},root);
 assert.equal(f.length,3);assert.equal(f[0].severity,'critical');assert.ok(!JSON.stringify(f).includes('private-value'));
});
test('malformed schemas fail instead of reporting a clean scan',()=>{
 for(const s of ['semgrep','osv','gitleaks','trivy']) assert.throws(()=>parse(s,{},root));
});
test('paths reject traversal, absolute escapes, control characters and root',()=>{
 for(const p of ['../escape','..\\escape','bad\npath',root,path.resolve(root,'../outside')]) assert.throws(()=>safePath(root,p));
 assert.equal(safePath(root,path.join(root,'app.py')),'app.py');
});
test('merge coalesces aliases transitively while retaining distinct packages and files',()=>{
 const base={file:'requirements.txt',line:1,endLine:1,rule:'CVE-1',aliases:[],package:'django',kind:'dependency',severity:'medium',scanners:['trivy']};
 const result=merge([base,{...base,rule:'GHSA-1',aliases:['CVE-1'],severity:'high',scanners:['osv']},{...base,package:'requests'}]);
 assert.equal(result.length,2);assert.deepEqual(result[0].scanners,['osv','trivy']);assert.equal(result[0].severity,'high');
 assert.equal(merge([base,{...base,file:'other.txt'}]).length,2);
});
test('secrets at same file and line merge across scanners without value access',()=>{
 const f={file:'key.txt',line:2,endLine:2,kind:'secret',severity:'high',rule:'generic-api-key',aliases:[],scanners:['gitleaks']};
 assert.equal(merge([f,{...f,rule:'github-pat',scanners:['trivy']}]).length,1);
});
test('navigation resolves existing files and rejects missing files',async()=>{
 assert.equal(await checkedFile(root,'app.py'),await fs.realpath(path.join(root,'app.py')));
 await assert.rejects(checkedFile(root,'../outside')); await assert.rejects(checkedFile(root,'missing.py'));
});
test('navigation rejects symlink outside workspace',async t=>{
 const dir=await fs.mkdtemp(path.join(os.tmpdir(),'s6-path-'));
 try {await fs.symlink(root,path.join(dir,'outside'),'junction');await assert.rejects(checkedFile(dir,'outside/app.py'));}
 finally {await fs.rm(dir,{recursive:true,force:true});}
});
