const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs/promises');
const path=require('node:path');
const os=require('node:os');
const {withStore,withReadStore,resetStore,atomicReplace}=require('../src/threat/store');
const m=require('../src/threat/model');
const f=require('./threat-fixtures');
async function temp(fn){const d=await fs.mkdtemp(path.join(os.tmpdir(),'s6-ti-store-'));try{return await fn(path.join(d,'intelligence.sqlite'));}finally{await fs.rm(d,{recursive:true,force:true});}}
test('CISA dateAdded is KEV date, not a fabricated publication or modified date',()=>{
 const [r]=m.cisa(f.kev());assert.equal(r.published_at,null);assert.equal(r.modified_at,null);assert.equal(r.kev_added_at,'2026-10-27T00:00:00.000Z');assert.equal(r.kev_status,true);assert.equal(r.analysis_status,'NOT_ANALYZED');
});
test('GitHub and OSV retain structured ranges and fixed versions without claiming project impact',()=>{
 const [g]=m.github([f.gh()]),o=m.osv(f.osv());assert.equal(g.canonical_id,f.cve);assert.equal(o.canonical_id,f.cve);assert.equal(g.patched_versions[0].version,'2.0.0');assert.equal(o.affected_versions[0].events[1].fixed,'2.0.0');
 assert.equal(o.analysis_status,'NOT_ANALYZED');
});
test('schema changes and invalid IDs fail closed',()=>{
 for(const fn of [()=>m.cisa({}),()=>m.github({}),()=>m.github([{...f.gh(),updated_at:'invalid'}]),()=>m.osv({...f.osv(),affected:[{}]})])assert.throws(fn,e=>e.code==='invalid_schema');
});
test('selected metadata omits full article text, tokens, code and arbitrary response fields',()=>{
 const token='ghp_'+'a'.repeat(36);const [r]=m.github([f.gh({summary:'fixture '+token,description:'private-body',secret:'private-secret',instructions:'run shell now'})]);
 const saved=JSON.stringify(r);for(const s of [token,'private-body','private-secret','run shell now'])assert.ok(!saved.includes(s));
});
test('ambiguous multi-CVE aliases are not assigned to an arbitrary CVE',()=>{
 const r=m.osv(f.osv({aliases:[f.cve,'CVE-2099-99990002']}));assert.equal(r.canonical_id,f.ghsa);assert.equal(r.identity_ambiguous,true);
});
test('later single-CVE evidence cannot promote an ambiguous multi-CVE record',()=>temp(async file=>{
 await withStore(file,async s=>{
 s.ingest(m.osv(f.osv({aliases:[f.cve,'CVE-2099-99990002']})),f.now);
 s.ingest(m.github([f.gh()])[0],f.now);assert.equal(s.counts().advisories,2);assert.equal(s.advisory(f.ghsa).identity_ambiguous,true);
 });
}));
test('SQLite file persists, reopens and deduplicates the same observed record',()=>temp(async file=>{
 await withStore(file,async s=>{s.ingest(m.github([f.gh()])[0],f.now);});
 assert.equal((await fs.readFile(file)).subarray(0,15).toString(),'SQLite format 3');
 await withStore(file,async s=>{const r=s.ingest(m.github([f.gh({updated_at:'2026-10-28T00:00:00Z'})])[0],'2026-10-29T00:00:00Z');assert.equal(r.changed,false);assert.equal(s.counts().revisions,1);assert.equal(s.advisory(f.cve).first_seen_at,f.now);});
}));
test('official shared CVE links CISA, GHSA and OSV while preserving source evidence',()=>temp(async file=>{
 await withStore(file,async s=>{s.ingest(m.github([f.gh()])[0],f.now);const change=s.ingest(m.cisa(f.kev())[0],f.now);s.ingest(m.osv(f.osv()),f.now);
 assert.ok(change.changes.includes('KEV_ADDED'));assert.equal(s.counts().advisories,1);const a=s.advisory(f.cve);assert.equal(a.evidence_sources.length,3);assert.equal(a.exploitation_status,'CONFIRMED_EXPLOITATION');assert.equal(a.mitigation,'Apply vendor update');});
}));
test('new CVE alias promotes a previously CVE-less GHSA without duplicate current rows',()=>temp(async file=>{
 await withStore(file,async s=>{
 s.ingest(m.github([f.gh({cve_id:null,identifiers:[{type:'GHSA',value:f.ghsa}]})])[0],f.now);
 s.ingest(m.osv(f.osv()),'2026-10-29T00:00:00Z');assert.equal(s.counts().advisories,1);assert.equal(s.advisory(f.ghsa),null);assert.ok(s.advisory(f.cve));
 });
}));
test('range, fix, CVSS, EPSS and withdrawal changes create meaningful revisions',()=>temp(async file=>{
 await withStore(file,async s=>{
 s.ingest(m.github([f.gh()])[0],f.now);
 const changed=f.gh({withdrawn_at:f.now,cvss:{score:9.5,vector_string:'CVSS:3.1/AV:N'},epss:{percentage:0.8,percentile:0.99},vulnerabilities:[{package:{name:'fixture-package',ecosystem:'npm'},vulnerable_version_range:'< 3.0.0',first_patched_version:'3.0.0'}]});
 const r=s.ingest(m.github([changed])[0],f.now);for(const c of ['WITHDRAWN','CVSS_CHANGED','EPSS_CHANGED','AFFECTED_RANGE_CHANGED','FIX_CHANGED'])assert.ok(r.changes.includes(c));
 s.ingest(m.github([f.gh()])[0],f.now);assert.equal(s.counts().revisions,3,'A real reversion is a new change, not a suppressed duplicate');
 });
}));
test('active writer lock excludes a second writer; readers retain last valid snapshot',()=>temp(async file=>{
 await withStore(file,async()=>{});
 await withStore(file,async s=>{await assert.rejects(withStore(file,async()=>{}),e=>e.code==='store_busy');assert.equal((await withReadStore(file,r=>r.counts())).advisories,0);});
}));
test('dead process lock is recovered on restart',()=>temp(async file=>{
 await fs.writeFile(file+'.lock','2147483646');await withStore(file,async s=>s.setState('cisa',{status:'completed'}));
 assert.equal((await withReadStore(file,s=>s.state('cisa'))).status,'completed');
}));
test('Windows atomic replace retries transient reader locks without deleting the old database',async()=>{
 let calls=0;const waits=[];
 await atomicReplace('temporary','existing',{rename:async()=>{if(++calls<3)throw Object.assign(new Error(),{code:'EPERM'});},wait:async n=>waits.push(n)});
 assert.equal(calls,3);assert.deepEqual(waits,[25,50]);
 await assert.rejects(atomicReplace('temporary','existing',{rename:async()=>{throw Object.assign(new Error(),{code:'EBUSY'});},wait:async()=>{}}),e=>e.code==='storage_busy');
});
test('retention prunes old observed records and reset removes local history including corrupt databases',()=>temp(async file=>{
 await withStore(file,async s=>{s.ingest(m.github([f.gh()])[0],'2025-01-01T00:00:00Z');s.prune(7,f.now);assert.equal(s.counts().advisories,0);assert.equal(s.counts().revisions,0);});
 await fs.writeFile(file,'corrupt');await assert.rejects(withReadStore(file,s=>s.counts()),e=>e.code==='invalid_database');await resetStore(file);assert.equal((await withReadStore(file,s=>s.counts())).advisories,0);
}));
