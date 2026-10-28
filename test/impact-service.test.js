const {test}=require('node:test');const assert=require('node:assert/strict');
const fs=require('node:fs/promises'),os=require('node:os'),path=require('node:path');
const {createSecurityService}=require('../src/security-service');const {ProjectImpactService}=require('../src/impact/service');const storage=require('../src/impact/storage');
const {withStore,withReadStore}=require('../src/threat/store');const m=require('../src/threat/model');const f=require('./threat-fixtures');
async function fixture(fn,{version='1.0.0',advisory=true}={}){
 const d=await fs.mkdtemp(path.join(os.tmpdir(),'s6-impact-')),root=path.join(d,'project'),file=path.join(d,'data','threat.sqlite');await fs.mkdir(root);
 const write=async v=>{await fs.writeFile(path.join(root,'package.json'),JSON.stringify({dependencies:{'fixture-package':'*'}}));await fs.writeFile(path.join(root,'package-lock.json'),JSON.stringify({lockfileVersion:3,packages:{'':{dependencies:{'fixture-package':'*'}},'node_modules/fixture-package':{version:v}}}));};
 try{await write(version);await withStore(file,async s=>{if(advisory)s.ingest(m.github([f.gh()])[0],f.now);});const securityService=await createSecurityService({workspaces:[{id:'app',root}]});const service=new ProjectImpactService({securityService,file,workspaceIds:['app']});await service.initialize();try{return await fn({service,file,root,write,securityService});}finally{service.dispose();}}
 finally{await fs.rm(d,{recursive:true,force:true});}
}
test('SQLite version 1 migrates without losing prior advisory payloads',async()=>{
 const d=await fs.mkdtemp(path.join(os.tmpdir(),'s6-migrate-')),file=path.join(d,'old.sqlite');
 try{const SQL=await require('sql.js')({locateFile:f=>require.resolve('sql.js/dist/'+f)}),db=new SQL.Database();db.run('CREATE TABLE threat_advisories(canonical_id TEXT PRIMARY KEY,data TEXT NOT NULL,last_seen TEXT NOT NULL); PRAGMA user_version=1;');const data=JSON.stringify(m.combine(m.github([f.gh()]),null,f.now));db.run('INSERT INTO threat_advisories VALUES (?,?,?)',[f.cve,data,f.now]);await fs.writeFile(file,db.export());db.close();
 await withStore(file,async s=>{assert.equal(s.get('PRAGMA user_version').user_version,2);assert.equal(s.get('SELECT data FROM threat_advisories').data,data);assert.ok(s.get("SELECT name FROM sqlite_master WHERE name='project_inventory'"));});
 await withReadStore(file,s=>assert.equal(s.advisory(f.cve).canonical_id,f.cve));}finally{await fs.rm(d,{recursive:true,force:true});}
});
test('project analysis persists evidence and relative files without modifying or transmitting source',()=>fixture(async({service,root,file})=>{
 const before=await fs.readFile(path.join(root,'package-lock.json'));const r=await service.analyze({workspaceId:'app'});assert.equal(r.report.matches[0].impact_status,'CONFIRMED_AFFECTED');assert.deepEqual(await fs.readFile(path.join(root,'package-lock.json')),before);
 const saved=await service.snapshot('app');assert.ok(!JSON.stringify(saved).includes(root));assert.equal(saved.inventory.dependencies[0].source_file,'package-lock.json');assert.equal((await withReadStore(file,s=>s.get('SELECT count(*) AS n FROM impact_evidence').n)),1);
}));
test('fixed versions do not notify and unknown versions are insufficient',async()=>{
 await fixture(async({service})=>{const r=await service.analyze({workspaceId:'app'});assert.equal(r.report.matches[0].impact_status,'NOT_AFFECTED');assert.equal(r.notifications.length,0);},{version:'2.0.0'});
 await fixture(async({service})=>{const r=await service.analyze({workspaceId:'app'});assert.equal(r.report.matches[0].impact_status,'INSUFFICIENT_EVIDENCE');assert.equal(r.notifications.length,0);},{version:'^1.0.0'});
});
test('unchanged inventory and advisory reuse cache without duplicate scans or alerts',()=>fixture(async({service,file})=>{
 const first=await service.analyze({workspaceId:'app'}),second=await service.analyze({workspaceId:'app'});assert.equal(first.notifications.length,1);assert.equal(second.status,'not_changed');assert.equal(second.inventory_cache_reused,true);
 await service.analyze({workspaceId:'app',force:true});assert.equal((await service.history('app')).length,1);assert.equal((await withReadStore(file,s=>s.get('SELECT count(*) AS n FROM notification_history').n)),1);
}));
test('KEV revision triggers reassessment with unchanged project files and meaningful escalation only',()=>fixture(async({service,file,root})=>{
 const first=await service.analyze({workspaceId:'app'});await service.acknowledge(first.notifications.map(e=>e.event_key));const before=await fs.readFile(path.join(root,'package-lock.json'));let feedUpdates=0;const monitor={onUpdate:async()=>feedUpdates++};const binding=service.bindMonitor(monitor);
 const changed=await withStore(file,async s=>s.ingest(m.cisa(f.kev())[0],f.now));await monitor.onUpdate({changed:[changed]});const s=await service.snapshot('app');assert.equal(s.latest.matches[0].kev_status,true);assert.equal(s.notifications.length,1);assert.equal(s.notifications[0].reason,'KEV_ESCALATION');assert.deepEqual(await fs.readFile(path.join(root,'package-lock.json')),before);
 await monitor.onUpdate({changed:[]});assert.equal((await service.snapshot('app')).notifications.length,1);assert.equal(feedUpdates,2);binding.dispose();
}));
test('dependency update, regression, and restart preserve state and transition history',()=>fixture(async({service,write,file,securityService})=>{
 const initial=await service.analyze({workspaceId:'app'});await service.acknowledge(initial.notifications.map(e=>e.event_key));await write('2.0.0');await service.analyze({workspaceId:'app',reason:'dependency_change'});assert.equal((await service.snapshot('app')).latest.matches[0].impact_status,'NOT_AFFECTED');
 await write('1.0.0');const back=await service.analyze({workspaceId:'app',reason:'dependency_change'});assert.equal(back.notifications.length,1);assert.equal((await service.history('app')).length,3);
 const restarted=new ProjectImpactService({securityService,file,workspaceIds:['app']});await restarted.initialize();assert.equal((await restarted.snapshot('app')).latest.matches[0].impact_status,'CONFIRMED_AFFECTED');assert.equal((await restarted.analyze({workspaceId:'app'})).status,'not_changed');restarted.dispose();
}));
test('range updates and withdrawals are reassessed from cached inventory',()=>fixture(async({service,file})=>{
 await service.analyze({workspaceId:'app'});await withStore(file,async s=>s.ingest(m.github([f.gh({vulnerabilities:[{package:{ecosystem:'npm',name:'fixture-package'},vulnerable_version_range:'<0.9.0',first_patched_version:'0.9.0'}]})])[0],f.now));await service.reassess([{canonical_id:f.cve}]);assert.equal((await service.snapshot('app')).latest.matches[0].impact_status,'NOT_AFFECTED');
 await withStore(file,async s=>s.ingest(m.github([f.gh({withdrawn_at:f.now})])[0],f.now));await service.reassess([{canonical_id:f.cve}]);assert.equal((await service.snapshot('app')).latest.matches[0].impact_status,'INSUFFICIENT_EVIDENCE');
}));
test('unrelated threat revisions do not rescan or create project history',()=>fixture(async({service})=>{
 await service.analyze({workspaceId:'app'});assert.deepEqual(await service.reassess([{canonical_id:'CVE-2099-99990002'}]),[]);assert.equal((await service.history('app')).length,1);
}));
test('cancel/error retains latest valid assessment and unauthorized workspace is rejected',()=>fixture(async({service})=>{
 const first=await service.analyze({workspaceId:'app'});const c=new AbortController();c.abort();await assert.rejects(service.analyze({workspaceId:'app',force:true},{signal:c.signal}));assert.equal((await service.snapshot('app')).latest.analyzed_at,first.report.analyzed_at);assert.throws(()=>service.analyze({workspaceId:'../other'}));
}));
test('dependency navigation uses saved inventory and rejects fabricated match IDs',()=>fixture(async({service})=>{
 const r=await service.analyze({workspaceId:'app'});const loc=await service.dependencyLocation('app',r.report.matches[0].id);assert.equal(loc.source_file,'package-lock.json');await assert.rejects(service.dependencyLocation('app','../../outside'));assert.ok((await service.report('app','markdown')).includes('CONFIRMED_AFFECTED'));
}));
test('storage usage is explicit, old scans are bounded and oversized report writes retain last valid file',()=>fixture(async({service,file})=>{
 for(let i=0;i<5;i++)await service.analyze({workspaceId:'app',force:true});assert.equal(await withReadStore(file,s=>s.get('SELECT count(*) AS n FROM project_scans').n),3);assert.equal((await service.snapshot('app')).storage.limit_bytes,64*1024*1024);
 const before=await fs.readFile(file);await assert.rejects(withStore(file,async s=>{const inv=storage.inventory(s,service.id('app'));storage.save(s,inv,{analyzed_at:f.now,matches:[],padding:'x'.repeat(2*1024*1024)},'x','oversized');}),e=>e.code==='impact_report_limit');assert.deepEqual(await fs.readFile(file),before);
}));
test('empty source cache is explicitly incomplete and never a project-safe conclusion',()=>fixture(async({service})=>{
 const r=await service.analyze({workspaceId:'app'});assert.equal(r.report.matches.length,0);assert.ok(r.report.limitations.some(l=>l.includes('No cached')));
},{advisory:false}));
test('current source errors are visible even when unchanged advisory fingerprints reuse a saved result',()=>fixture(async({service,file})=>{
 await service.analyze({workspaceId:'app'});await withStore(file,async s=>s.setState('github',{status:'failed',last_success:null,error:'network_unavailable'}));assert.equal((await service.analyze({workspaceId:'app'})).status,'not_changed');const report=await service.report('app');assert.equal(report.current_coverage_incomplete,true);assert.equal(report.current_source_status[0].status,'failed');
}));
test('SQLite 64 MiB checkpoint limit fails visibly without replacing the last valid database',()=>fixture(async({service,file})=>{
 await service.analyze({workspaceId:'app'});const before=await fs.readFile(file);
 await assert.rejects(withStore(file,async s=>{s.run('CREATE TABLE capacity_probe(data BLOB)');s.run('INSERT INTO capacity_probe VALUES (zeroblob(?))',[64*1024*1024]);assert.equal(storage.usage(s).warning,true);}),e=>e.code==='database_limit');
 assert.deepEqual(await fs.readFile(file),before);assert.equal((await service.snapshot('app')).latest.matches[0].impact_status,'CONFIRMED_AFFECTED');
}));
test('a newly collected relevant advisory reassesses an unchanged project with cached inventory',()=>fixture(async({service,file,root})=>{
 await service.analyze({workspaceId:'app'});const before=await fs.readFile(path.join(root,'package-lock.json'));const change=await withStore(file,async s=>s.ingest(m.github([f.gh()])[0],f.now));const [result]=await service.reassess([change]);assert.equal(result.report.matches.length,1);assert.equal(result.report.inventory_cache_reused,true);assert.equal(result.notifications.length,1);assert.deepEqual(await fs.readFile(path.join(root,'package-lock.json')),before);
},{advisory:false}));
test('removed dependencies record unavailable evidence rather than automatic mitigation or safety',()=>fixture(async({service,root})=>{
 await service.analyze({workspaceId:'app'});await fs.writeFile(path.join(root,'package.json'),'{}');await fs.writeFile(path.join(root,'package-lock.json'),JSON.stringify({lockfileVersion:3,packages:{'':{}}}));const r=await service.analyze({workspaceId:'app'});assert.equal(r.report.matches.length,0);const h=(await service.history('app'))[0];assert.equal(h.data.impact_status,'NOT_ANALYZED');assert.equal(h.data.priority.score,0);
}));
test('official GHSA-to-CVE promotion preserves history without duplicate risk notification',()=>fixture(async({service,file})=>{
 await withStore(file,async s=>s.ingest(m.github([f.gh({cve_id:null,identifiers:[{type:'GHSA',value:f.ghsa}]})])[0],f.now));const first=await service.analyze({workspaceId:'app'});assert.equal(first.notifications.length,1);assert.equal(first.report.matches[0].canonical_id,f.ghsa);
 await withStore(file,async s=>s.ingest(m.github([f.gh()])[0],f.now));const r=await service.analyze({workspaceId:'app'});assert.equal(r.report.matches.length,1);assert.equal(r.report.matches[0].canonical_id,f.cve);assert.equal(r.notifications.length,0);assert.equal((await service.history('app',r.report.matches[0].id)).length,2);
},{advisory:false}));
