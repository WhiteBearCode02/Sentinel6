const {test}=require('node:test');const assert=require('node:assert/strict');
const {correlate,shouldNotify}=require('../src/impact/correlation');const m=require('../src/threat/model');const f=require('./threat-fixtures');
function inventory(version='1.0.0',eco='npm',name='fixture-package'){return {project_id:'project',fingerprint:'inventory',inventory_timestamp:f.now,coverage:{status:'completed'},limitations:[],dependencies:[{id:'dependency',project_id:'project',ecosystem:eco,normalized_name:name,package_name:name,version,version_confidence:version?'LOCKFILE_EXACT':'UNKNOWN',source_file:'package-lock.json',line:5,dependency_type:'dependencies',direct_or_transitive:'direct',limitations:['installation_not_verified']}]};}
function run(records,inv=inventory(),extras={}){const a=m.combine(records,null,f.now);return correlate(inv,[a],records,{now:f.now,...extras});}
test('exact official npm package/version confirms a declared vulnerable component, not an attack path',()=>{
 const r=run(m.github([f.gh()]));const x=r.matches[0];assert.equal(x.impact_status,'CONFIRMED_AFFECTED');assert.equal(x.version_result,'AFFECTED_VERSION');assert.equal(x.attack_path_verified,false);assert.equal(x.installation_verified,false);assert.equal(x.source_file,'package-lock.json');assert.deepEqual(x.fixed_versions,['2.0.0']);
});
test('fixed version is not affected and never generates an urgent notification even with KEV',()=>{
 const records=[...m.github([f.gh()]),...m.cisa(f.kev())];const x=run(records,inventory('2.0.0')).matches[0];assert.equal(x.impact_status,'NOT_AFFECTED');assert.equal(x.priority.score,0);assert.equal(shouldNotify(null,x),false);
});
test('unknown versions remain insufficient instead of safe or affected',()=>{
 const x=run(m.github([f.gh()]),inventory(null)).matches[0];assert.equal(x.version_result,'VERSION_UNKNOWN');assert.equal(x.impact_status,'INSUFFICIENT_EVIDENCE');
});
test('same package in another ecosystem and unrelated package do not match',()=>{
 assert.equal(run(m.github([f.gh()]),inventory('1.0','PyPI')).matches.length,0);assert.equal(run(m.github([f.gh()]),inventory('1.0.0','npm','another')).matches.length,0);
});
test('CISA vendor product names alone remain review-only and are not guessed as dependencies',()=>{
 const r=run(m.cisa(f.kev()),inventory('1.0.0','npm','fixture-package'));assert.equal(r.matches.length,0);assert.equal(r.review_required_total,1);assert.equal(r.review_required[0].project_related,false);
});
test('PyPI name normalization and GitHub pip ecosystem are explicit aliases of PyPI',()=>{
 const record=m.github([f.gh({vulnerabilities:[{package:{ecosystem:'pip',name:'Fixture_Package'},vulnerable_version_range:'<2.0',first_patched_version:'2.0'}]})]);const r=run(record,inventory('1.0','PyPI'));assert.equal(r.matches[0].impact_status,'CONFIRMED_AFFECTED');
});
test('official CVE/GHSA/OSV aliases produce one correlated result with multiple source evidence',()=>{
 const r=run([...m.github([f.gh()]),m.osv(f.osv())]);assert.equal(r.matches.length,1);assert.equal(r.matches[0].canonical_id,f.cve);assert.ok(r.matches[0].evidence_count>=3);
});
test('conflicting official ranges are preserved and downgrade confidence',()=>{
 const gh=m.github([f.gh()]),osv=m.osv(f.osv({affected:[{package:{ecosystem:'npm',name:'fixture-package'},ranges:[{type:'SEMVER',events:[{introduced:'0'},{fixed:'0.9.0'}]}]}]}));
 const x=run([...gh,osv]).matches[0];assert.equal(x.impact_status,'POTENTIALLY_AFFECTED');assert.equal(x.confidence,'low');assert.ok(x.limitations.includes('source_range_conflict'));
});
test('withdrawn or ambiguous advisories cannot establish a new safe or confirmed affected state',()=>{
 const x=run(m.github([f.gh({withdrawn_at:f.now})])).matches[0];assert.equal(x.impact_status,'INSUFFICIENT_EVIDENCE');const record=m.osv(f.osv({aliases:[f.cve,'CVE-2099-99990002']}));assert.equal(run([record]).matches[0].impact_status,'INSUFFICIENT_EVIDENCE');
});
test('explicit unverified prerequisites are potential and never pretended to be checked',()=>{
 const [record]=m.github([f.gh()]);record.preconditions=['runtime feature enabled'];const x=run([record]).matches[0];assert.equal(x.impact_status,'POTENTIALLY_AFFECTED');assert.ok(x.required_checks.length);
});
test('only exact scanner package identity and official IDs are linked as supporting evidence',()=>{
 const scannerReport={findings:[{id:'safe',kind:'dependency',rule:f.cve,aliases:[],package:'fixture-package',packageDetails:{name:'fixture-package',ecosystem:'npm',detectedVersion:'1.0.0'},scanners:['osv']},{id:'wrong',kind:'dependency',rule:'CVE-2099-99990002',packageDetails:{name:'fixture-package',ecosystem:'npm'}}],coverage:{dependencies:{completed:['osv']}}};
 const x=run(m.github([f.gh()]),inventory(),{scannerReport}).matches[0];assert.equal(x.evidence.filter(e=>e.type==='scanner_cross_reference').length,1);assert.equal(x.attack_path_verified,false);
});
test('meaningful KEV escalation without a project version change is an alert; repeated state is not',()=>{
 const before=run(m.github([f.gh()])).matches[0],after=run([...m.github([f.gh()]),...m.cisa(f.kev())]).matches[0];assert.equal(shouldNotify(before,after),true);assert.equal(shouldNotify(after,after),false);assert.ok(after.priority.reasons.some(r=>r.reason==='cisa_kev_membership'));
});
test('correlation supports cancellation and never fabricates MITIGATED',()=>{
 const c=new AbortController();c.abort();assert.throws(()=>run(m.github([f.gh()]),inventory(),{signal:c.signal}),e=>e.code==='cancelled');assert.notEqual(run(m.github([f.gh()])).matches[0].impact_status,'MITIGATED');
});
