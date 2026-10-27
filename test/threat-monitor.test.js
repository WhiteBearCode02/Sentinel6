const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs/promises');
const path=require('node:path');
const os=require('node:os');
const {setTimeout:wait}=require('node:timers/promises');
const {ThreatMonitor,DAY}=require('../src/threat/monitor');
const {withStore,withReadStore}=require('../src/threat/store');
const {CollectionError,CISA,CISA_MIRROR}=require('../src/threat/http');
const {csv}=require('../src/threat/sources');
const f=require('./threat-fixtures');
async function temp(fn){const d=await fs.mkdtemp(path.join(os.tmpdir(),'s6-ti-monitor-'));try{return await fn(path.join(d,'threats.sqlite'));}finally{await fs.rm(d,{recursive:true,force:true});}}
function client(handler) {
 const c={calls:[],async get(url,options){this.calls.push(url);if(handler){const r=await handler(url,options);if(r)return r;}
 if(url===CISA||url===CISA_MIRROR)return f.response(f.kev());
 if(url.startsWith('https://api.github.com/advisories'))return f.response([f.gh()]);
 if(url.endsWith('modified_id.csv'))return f.response(`2026-10-27T00:00:00Z,${f.ghsa}\n2026-01-01T00:00:00Z,GHSA-2345-6789-cfgj\n`);
 if(url.startsWith('https://api.osv.dev/v1/vulns/'))return f.response(f.osv());throw new Error('Unexpected URL');
 }};return c;
}
function monitor(file,c,extra={}){return new ThreatMonitor({file,client:c,now:()=>f.now,ecosystems:['npm'],...extra});}
test('official response integration writes SQLite and source-backed feed without project impact claims',()=>temp(async file=>{
 const c=client(),m=monitor(file,c);await m.initialize();const result=await m.refresh();const snapshot=await m.snapshot();
 assert.equal(result.status,'completed');assert.equal(snapshot.counts.advisories,1);assert.equal(snapshot.advisories[0].evidence_sources.length,3);assert.equal(snapshot.analysis_status,'NOT_ANALYZED');
 for(const id of ['cisa','github','osv:npm'])assert.equal(snapshot.sources.find(s=>s.id===id).status,'completed');
 for(const id of ['nvd','kisa','news'])assert.equal(snapshot.sources.find(s=>s.id===id).status,'disabled');
 for(const url of c.calls){assert.ok(!url.includes('fixture-package'));assert.ok(!url.includes('affects='));}
}));
test('one collection per day, startup catch-up and restart preserve checkpoints',()=>temp(async file=>{
 let time=f.now;const c=client(),m=monitor(file,c,{now:()=>time});await m.initialize();await m.refresh();const count=c.calls.length;
 await m.refresh();assert.equal(c.calls.length,count);assert.equal((await m.snapshot()).counts.jobs,1);
 const restarted=monitor(file,c,{now:()=>time});await restarted.initialize();await restarted.refresh();assert.equal(c.calls.length,count);
 time=new Date(Date.parse(f.now)+3*DAY).toISOString();await restarted.refresh();assert.ok(c.calls.length>count);
 const github=c.calls.filter(u=>u.startsWith('https://api.github.com')).at(-1);assert.ok(new URL(github).searchParams.get('modified').startsWith('2026-10-27..'),'Missed interval must start from last checkpoint, not today');
}));
test('manual refresh is available without waiting for a file save or commit',()=>temp(async file=>{
 const c=client(),m=monitor(file,c);await m.initialize();await m.refresh();const count=c.calls.length;await m.refresh({force:true});assert.ok(c.calls.length>count);
 assert.equal((await m.snapshot()).counts.revisions,3,'Repeated identical observations do not add revisions');
}));
test('overlapping manual and scheduled refresh share one in-flight operation',()=>temp(async file=>{
 let release;const gate=new Promise(r=>release=r);const c=client(async url=>{if(url===CISA)await gate;});const m=monitor(file,c);await m.initialize();
 const a=m.refresh(),b=m.refresh({force:true});assert.equal(a,b);release();await a;assert.equal((await m.snapshot()).counts.jobs,1);
}));
test('a storage lock failure is visible without leaking error text or replacing valid advisories',()=>temp(async file=>{
 const m=monitor(file,client());await m.initialize();await m.refresh();
 await withStore(file,async()=>{await assert.rejects(m.refresh({force:true}),e=>e.code==='store_busy');assert.equal((await m.snapshot()).monitor_error,'store_busy');assert.equal((await m.snapshot()).counts.advisories,1);});
 await m.refresh({force:true});assert.equal((await m.snapshot()).monitor_error,null);
}));
test('network errors retain last valid data, mark stale and enforce retry cooldown',()=>temp(async file=>{
 let time=f.now,offline=false;const c=client(async()=>{if(offline)throw new CollectionError('network_failed');}),m=monitor(file,c,{now:()=>time});await m.initialize();await m.refresh();const before=await m.snapshot();
 time=new Date(Date.parse(f.now)+3*DAY).toISOString();offline=true;const failed=await m.refresh();assert.equal(failed.status,'partial');
 const after=await m.snapshot();assert.equal(after.counts.advisories,before.counts.advisories);assert.equal(after.counts.revisions,before.counts.revisions);assert.equal(after.sources.find(s=>s.id==='github').last_success,f.now);assert.equal(after.sources.find(s=>s.id==='github').stale,true);
 const count=c.calls.length;await m.refresh({force:true});assert.equal(c.calls.length,count,'Manual refresh cannot ignore cooldown');
 offline=false;time=new Date(Date.parse(time)+61000).toISOString();assert.equal((await m.refresh()).status,'completed');
}));
test('invalid schema does not overwrite a valid source snapshot',()=>temp(async file=>{
 let broken=false;const c=client(async url=>broken&&url===CISA?f.response({changed_schema:true}):null),m=monitor(file,c);await m.initialize();await m.refresh();broken=true;await m.refresh({force:true});
 const s=await m.snapshot();assert.equal(s.sources.find(s=>s.id==='cisa').error,'invalid_schema');assert.equal(s.advisories[0].kev_status,true);
}));
test('a failed manual refresh retries after cooldown even if last success was less than a day ago',()=>temp(async file=>{
 let time=f.now,broken=false;const c=client(async url=>{if(broken&&url.startsWith('https://api.github.com'))throw new CollectionError('network_failed');}),m=monitor(file,c,{now:()=>time});
 await m.initialize();await m.refresh();broken=true;await m.refresh({force:true});broken=false;time=new Date(Date.parse(f.now)+61000).toISOString();
 await m.refresh();assert.equal((await m.snapshot()).sources.find(s=>s.id==='github').status,'completed');
}));
test('CISA official mirror is used on blocked primary endpoint',()=>temp(async file=>{
 const c=client(async url=>{if(url===CISA)throw new CollectionError('http_403');}),m=monitor(file,c);await m.initialize();await m.refresh();assert.ok(c.calls.includes(CISA_MIRROR));assert.equal((await m.snapshot()).sources[0].endpoint,CISA_MIRROR);
}));
test('KEV catalog removal is tracked separately from CVE withdrawal or safety',()=>temp(async file=>{
 let removed=false;const other='CVE-2099-99990002';const c=client(async url=>url===CISA?f.response(f.kev(removed?[other]:[f.cve,other])):null),m=monitor(file,c);await m.initialize();await m.refresh();removed=true;await m.refresh({force:true});
 const a=(await m.advisory(f.cve)).advisory;assert.equal(a.kev_status,false);assert.equal(a.withdrawn_at,null);assert.equal(a.exploitation_status,'CONFIRMED_EXPLOITATION');assert.ok(a.change_type.includes('KEV_REMOVED'));
}));
test('GitHub page budget persists continuation and catches up after restart',()=>temp(async file=>{
 let time=f.now;const next='https://api.github.com/advisories?after=second';const c=client(async url=>{
 if(url.startsWith('https://api.github.com/advisories'))return url===next?f.response([]):{...f.response([f.gh()]),headers:{link:`<${next}>; rel="next"`}};
 });
 const m=monitor(file,c,{now:()=>time,githubPages:1});await m.initialize();assert.equal((await m.refresh()).status,'partial');
 const s=await withReadStore(file,s=>s.state('github'));assert.equal(s.last_success,null);assert.equal(s.cursor.next,next);
 time=new Date(Date.parse(f.now)+61000).toISOString();const restarted=monitor(file,c,{now:()=>time,githubPages:1});await restarted.initialize();await restarted.refresh();
 assert.equal((await restarted.snapshot()).sources.find(s=>s.id==='github').status,'completed');assert.equal((await restarted.snapshot()).sources.find(s=>s.id==='github').last_success,f.now);
}));
test('OSV record budget and retry preserve all pending records without advancing the window',()=>temp(async file=>{
 let time=f.now;const second='GHSA-2345-6789-cfgj';const c=client(async url=>{
 if(url.endsWith('modified_id.csv'))return f.response(`2026-10-27T00:00:00Z,${second}\n2026-10-26T00:00:00Z,${f.ghsa}\n`);
 if(url.endsWith(second))return f.response(f.osv({id:second}));
 });
 const m=monitor(file,c,{now:()=>time,osvRecords:1});await m.initialize();await m.refresh();
 let state=await withReadStore(file,s=>s.state('osv:npm'));assert.equal(state.cursor.queue.length,1);assert.equal(state.last_success,null);
 time=new Date(Date.parse(f.now)+61000).toISOString();await m.refresh();state=await withReadStore(file,s=>s.state('osv:npm'));assert.equal(state.cursor,null);assert.equal(state.last_success,f.now);
}));
test('source 304 responses reuse normalized cache and do not duplicate threat revisions',()=>temp(async file=>{
 let cached=false;const c=client(async(_url,o)=>cached&&o.cache?{status:304,headers:{}}:null),m=monitor(file,c);await m.initialize();await m.refresh();const n=(await m.snapshot()).counts.revisions;cached=true;await m.refresh({force:true});assert.equal((await m.snapshot()).counts.revisions,n);
}));
test('cancelled collection is recorded and restart marks interrupted jobs',()=>temp(async file=>{
 const c=client(async url=>{if(url===CISA)throw new CollectionError('cancelled');}),m=monitor(file,c);await m.initialize();assert.equal((await m.refresh()).status,'cancelled');
 await withStore(file,async s=>s.startJob(f.now));await m.initialize();const jobs=await withReadStore(file,s=>s.all('SELECT status FROM monitoring_jobs'));assert.ok(jobs.every(j=>j.status!=='running'));
}));
test('active timer deduplicates daily execution and stops cleanly',()=>temp(async file=>{
 const c=client(),m=monitor(file,c);await m.initialize();m.start({interval:5});await m.inFlight;const n=c.calls.length;await wait(30);m.stop();assert.equal(c.calls.length,n);assert.equal(m.timer,null);
}));
test('local deletion clears all threat data and source state',()=>temp(async file=>{
 const m=monitor(file,client());await m.initialize();await m.refresh();await m.clear();const s=await m.snapshot();assert.equal(s.counts.advisories,0);assert.equal(s.counts.revisions,0);assert.equal(s.sources[0].status,'never_checked');
}));
test('CSV validates chronology and schema; unsupported ecosystem settings are rejected',()=>{
 const window={start:'2026-01-01T00:00:00Z',end:f.now};
 assert.throws(()=>csv('new schema,not-an-id',window));assert.throws(()=>csv(`2026-10-26T00:00:00Z,${f.ghsa}\n2026-10-27T00:00:00Z,${f.ghsa}`,window));
 assert.throws(()=>monitor('/tmp/example',client(),{ecosystems:['private-project-name']}));
});
