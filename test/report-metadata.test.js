const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {parse,merge}=require('../src/parsers');
const root=path.resolve('fixtures/vulnerable');
function osv({version='1.0.0',affectedName='fixture-package',extra={}}={}) {
 return {results:[{source:{path:'requirements.txt'},packages:[{package:{name:'fixture-package',ecosystem:'PyPI',version,purl:'pkg:pypi/fixture-package@'+version},vulnerabilities:[{id:'GHSA-2345-6789-cfgh',aliases:['CVE-2099-99990001'],affected:[{package:{name:affectedName,ecosystem:'PyPI'},ranges:[{type:'ECOSYSTEM',events:[{introduced:'0'},{fixed:'2.0.0'}]}],versions:['1.0.0'],database_specific:{source:'https://github.com/example/advisories/example'}}],...extra}]}]}]};
}
function trivy({version='1.0.0',extra={}}={}) {
 return {SchemaVersion:2,Results:[{Target:'requirements.txt',Type:'pip',Vulnerabilities:[{VulnerabilityID:'CVE-2099-99990001',PkgName:'fixture-package',InstalledVersion:version,FixedVersion:'2.0.0, 3.0.1',PkgIdentifier:{PURL:'pkg:pypi/fixture-package@'+version},DataSource:{ID:'ghsa',Name:'Untrusted free text',URL:'https://github.com/advisories?query=public'},...extra}]}]};
}
test('OSV includes only provided package identity, exact version, ranges, fixes and advisory provenance',()=>{
 const [f]=parse('osv',osv(),root);
 assert.equal(f.package,'fixture-package');assert.equal(f.rule,'GHSA-2345-6789-cfgh');
 assert.deepEqual({...f.packageDetails,observations:undefined},{ecosystem:'PyPI',name:'fixture-package',detectedVersion:'1.0.0',purl:'pkg:pypi/fixture-package@1.0.0',observations:undefined});
 assert.deepEqual(f.vulnerability.fixedVersions,['2.0.0']);
 assert.deepEqual(f.vulnerability.affectedRanges[0],{type:'ECOSYSTEM',events:[{introduced:'0'},{fixed:'2.0.0'}]});
 assert.equal(f.vulnerability.advisorySources[0].url,'https://github.com/example/advisories/example');
 assert.deepEqual(f.impact,{status:'NOT_ANALYZED',confidence:'unknown'});
 assert.deepEqual(f.evidence,[{scanner:'osv',type:'scanner_finding',file:'requirements.txt',line:1,rule:'GHSA-2345-6789-cfgh'}]);
});
test('Trivy retains reported package type and fixes while ecosystem and affected range remain unknown',()=>{
 const [f]=parse('trivy',trivy(),root);
 assert.equal(f.packageDetails.ecosystem,null);assert.equal(f.packageDetails.observations[0].scannerPackageType,'pip');
 assert.deepEqual(f.vulnerability.fixedVersions,['2.0.0','3.0.1']);assert.deepEqual(f.vulnerability.affectedRanges,[]);
 assert.equal(f.vulnerability.advisorySources[0].id,'ghsa');assert.equal(f.vulnerability.advisorySources[0].url,'https://github.com/advisories');
 assert.ok(f.limitations.includes('affected_range_not_available'));
});
test('missing dependency metadata remains null or empty and is not inferred from source code or package name',()=>{
 const [f]=parse('osv',{results:[{source:{path:'requirements.txt'},packages:[{package:{name:'fixture-package'},vulnerabilities:[{id:'CVE-2099-99990001'}]}]}]},root);
 assert.equal(f.packageDetails.detectedVersion,null);assert.equal(f.packageDetails.purl,null);assert.equal(f.packageDetails.ecosystem,null);
 assert.deepEqual(f.vulnerability.fixedVersions,[]);assert.deepEqual(f.vulnerability.affectedRanges,[]);assert.equal(f.impact.status,'NOT_ANALYZED');
 assert.ok(f.limitations.includes('detected_version_not_available'));
});
test('ranges belonging to another package are not attributed to the detected dependency',()=>{
 const [f]=parse('osv',osv({affectedName:'different-package'}),root);assert.deepEqual(f.vulnerability.affectedRanges,[]);assert.deepEqual(f.vulnerability.fixedVersions,[]);
});
test('metadata sanitization rejects credentials, unsafe links and arbitrary source fields',()=>{
 const token='ghp_'+'a'.repeat(36);
 const d=trivy({version:token,extra:{Description:'private-description',Title:'private-title',Secret:token,Match:token,References:['https://example.com/private-token'],DataSource:{ID:token,URL:'https://user:private-password@example.com/advisory'}}});
 const [f]=parse('trivy',d,root);const saved=JSON.stringify(f);
 for(const secret of [token,'private-description','private-title','private-password','private-token'])assert.ok(!saved.includes(secret));
 assert.equal(f.packageDetails.detectedVersion,null);assert.equal(f.packageDetails.purl,null);assert.deepEqual(f.vulnerability.advisorySources,[]);
});
test('SAST, secrets and misconfiguration evidence never includes match or message text',()=>{
 const [f]=parse('semgrep',{results:[{path:'app.py',check_id:'fixture.eval',start:{line:4},extra:{message:'private-value',lines:'private-code',metadata:{confidence:'HIGH'}}}],errors:[]},root);
 assert.equal(f.packageDetails,null);assert.equal(f.vulnerability.id,null);assert.equal(f.impact.confidence,'unknown');assert.ok(!JSON.stringify(f).includes('private-'));
});
test('merging preserves additive metadata and all scanner evidence without changing the legacy finding identity',()=>{
 const old={file:'requirements.txt',line:1,endLine:1,rule:'GHSA-2345-6789-cfgh',aliases:['CVE-2099-99990001'],package:'fixture-package',kind:'dependency',severity:'high',scanners:['osv']};
 const legacy=merge([old,{...old,rule:'CVE-2099-99990001',aliases:[],scanners:['trivy']}]);
 const findings=merge([...parse('osv',osv(),root),...parse('trivy',trivy(),root)]);
 assert.equal(findings.length,1);assert.equal(findings[0].id,legacy[0].id);assert.deepEqual(findings[0].scanners,['osv','trivy']);
 assert.equal(findings[0].packageDetails.ecosystem,'PyPI');assert.equal(findings[0].packageDetails.detectedVersion,'1.0.0');assert.equal(findings[0].packageDetails.observations.length,2);
 assert.equal(findings[0].evidence.length,2);assert.equal(findings[0].vulnerability.advisorySources.length,2);assert.deepEqual(findings[0].vulnerability.fixedVersions,['2.0.0','3.0.1']);
 assert.ok(!findings[0].limitations.includes('affected_range_not_available'));
});
test('conflicting observed versions are preserved as evidence rather than arbitrarily choosing a version',()=>{
 const [f]=merge([...parse('osv',osv(),root),...parse('trivy',trivy({version:'1.1.0'}),root)]);
 assert.equal(f.packageDetails.detectedVersion,null);assert.equal(f.packageDetails.purl,null);
 assert.deepEqual(f.packageDetails.observations.map(o=>o.detectedVersion).sort(),['1.0.0','1.1.0']);
 assert.ok(f.limitations.includes('conflicting_detectedVersion'));assert.equal(f.impact.status,'NOT_ANALYZED');
});
test('bounded range extraction signals truncation rather than implying complete advisory coverage',()=>{
 const data=osv();const affected=data.results[0].packages[0].vulnerabilities[0].affected[0];affected.versions=Array.from({length:1001},(_,i)=>'1.0.'+i);
 const [f]=parse('osv',data,root);assert.ok(f.limitations.includes('scanner_metadata_truncated'));assert.equal(f.vulnerability.affectedRanges.find(r=>r.type==='EXPLICIT_VERSIONS').versions.length,1000);
});
test('safe metadata also parses the real previously recorded OSV and Trivy outputs when present',t=>{
 let available=0;
 for(const scanner of ['osv','trivy']) {
  const file=path.resolve('.tools',scanner+'-check.json');if(!fs.existsSync(file))continue;
  available++;
  const findings=parse(scanner,JSON.parse(fs.readFileSync(file)),root);assert.ok(findings.length>0);
  assert.ok(findings.every(f=>f.impact.status==='NOT_ANALYZED'));assert.ok(findings.some(f=>f.packageDetails.detectedVersion));
 }
 if(!available)t.skip('Local scanner output fixtures are not installed; live verification is separate.');
});
