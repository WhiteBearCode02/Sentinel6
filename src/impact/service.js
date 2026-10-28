'use strict';
const crypto=require('node:crypto');
const {withStore,withReadStore}=require('../threat/store');
const storage=require('./storage');
const {correlate,ecosystem}=require('./correlation');
const {normalizeName,hash}=require('../inventory/identity');
const {stable}=require('../threat/model');
class ImpactError extends Error {constructor(code){super(code);this.code=code;}}
const fail=code=>{throw new ImpactError(code);};
const check=signal=>{if(signal?.aborted)fail('cancelled');};
function relevant(snapshot,inventory){
  const packages=new Set(inventory.dependencies.map(d=>d.ecosystem+':'+d.normalized_name));const ids=new Set();
  for(const r of snapshot.records)for(const p of r.affected_products||[]){const e=ecosystem(p.ecosystem),n=normalizeName(e,p.name);if(e&&n&&packages.has(e+':'+n))ids.add(r.canonical_id);}
  return ids;
}
function inputFingerprint(inventory,snapshot,configuration){const ids=relevant(snapshot,inventory);const intelligence=require('../intelligence/project').relevant(snapshot.intelligence||[],snapshot.advisories,ids);return hash(stable({inventory:inventory.fingerprint,advisories:snapshot.advisories.filter(a=>ids.has(a.canonical_id)).map(a=>[a.canonical_id,a.content_fingerprint]).sort(),intelligence:require('../intelligence/project').input(intelligence,configuration)}));}
function markdown(report){
  const escape=v=>String(v??'unknown').replace(/[\\`*_{}\[\]()<>#!|]/g,'\\$&').replace(/[\r\n]/g,' ');
  return ['# Sentinel6 Project Impact',`Analyzed: ${report.analyzed_at}`,`Project: ${report.project_id}`,report.scope,
    '| Advisory | Package | Version | Dependency file | Status | Priority |','|---|---|---|---|---|---|',
    ...report.matches.map(m=>`| ${escape(m.canonical_id)} | ${escape(m.package.ecosystem+':'+m.package.name)} | ${escape(m.package.detected_version)} | ${escape(m.source_file+':'+m.line)} | ${m.impact_status} | ${m.priority.level} |`),
    ...report.matches.flatMap(m=>['',`## ${escape(m.canonical_id)} / ${escape(m.package.name)}`,escape(m.title),`Version result: ${m.version_result}. Conditions / reachability: unverified.`,
      `Official sources: ${(m.official_sources||[]).map(escape).join(', ')}`,`Official fixed-version candidates: ${m.fixed_versions.map(escape).join(', ')||'not provided'}`,escape(m.recommended_action),`Limitations: ${m.limitations.map(escape).join(', ')}`]),
    '',`Inventory coverage: ${report.coverage.inventory.status}`,`Inventory last checked: ${report.inventory_checked_at||report.inventory_timestamp}`,
    `Current source status: ${(report.current_source_status||report.coverage.threat_sources).map(s=>escape(s.id+': '+s.status+(s.stale?' (STALE)':''))).join(', ')||'none'}`,
    `Current coverage incomplete: ${report.current_coverage_incomplete??true}`,`Review-only advisories: ${report.review_required_total}`,...report.limitations.map(l=>'- '+escape(l))].join('\n');
}
class ProjectImpactService {
  constructor({securityService,file,workspaceIds,onUpdate=()=>{},now=()=>new Date().toISOString(),timeout=60000}={}){
    if(!securityService||!file||!Array.isArray(workspaceIds)||workspaceIds.length>20||!Number.isFinite(timeout)||timeout<50||timeout>300000)fail('invalid_project_configuration');
    Object.assign(this,{securityService,file,workspaceIds,onUpdate,now,timeout});this.ids=new Map();this.controllers=new Set();this.tail=Promise.resolve();this.scannerReports=new Map();this.checked=new Map();this.lastError=null;
  }
  async initialize(){for(const id of this.workspaceIds)this.ids.set(id,(await this.securityService.workspaceIdentity({workspaceId:id})).project_id);}
  id(workspaceId){if(typeof workspaceId!=='string'||!this.ids.has(workspaceId))fail('workspace_not_allowed');return this.ids.get(workspaceId);}
  analyze({workspaceId,force=false,reason='manual'}={}, {signal}={}){
    if(this.disposed)return Promise.reject(new ImpactError('service_disposed'));
    this.id(workspaceId);if(typeof force!=='boolean'||!['manual','threat_revision','dependency_change','startup'].includes(reason))return Promise.reject(new ImpactError('invalid_parameters'));
    if(this.controllers.size>=20)return Promise.reject(new ImpactError('analysis_queue_limit'));
    const controller=new AbortController();this.controllers.add(controller);const cancel=()=>controller.abort();signal?.addEventListener('abort',cancel,{once:true});if(signal?.aborted)cancel();
    const job=this.tail.catch(()=>{}).then(async()=>{
      check(controller.signal);const timer=setTimeout(()=>controller.abort(),this.timeout);
      try{const r=await this.perform(workspaceId,force,reason,controller.signal);this.lastError=null;await this.onUpdate(r);return r;}
      catch(e){this.lastError=['cancelled','inventory_entry_limit','inventory_directory_limit','inventory_size_limit','dependency_limit','impact_report_limit','impact_match_limit','database_limit','store_busy','storage_busy','advisory_changed_during_analysis'].includes(e.code)?e.code:'analysis_failed';await this.onUpdate({status:'failed',error:this.lastError});throw new ImpactError(this.lastError);}
      finally{clearTimeout(timer);}
    }).finally(()=>{this.controllers.delete(controller);signal?.removeEventListener('abort',cancel);});
    this.tail=job;return job;
  }
  async perform(workspaceId,force,reason,signal){
    const id=this.id(workspaceId),now=this.now();
    const previous=await withReadStore(this.file,s=>({inventory:storage.inventory(s,id),latest:storage.latest(s,id),sources:storage.sourceSnapshot(s)}));check(signal);
    const inventory=await this.securityService.inventoryWorkspace({workspaceId},{signal,previous:previous.inventory});check(signal);
    this.checked.set(workspaceId,inventory.checked_at);
    const relevantIntelligence=require('../intelligence/project').relevant(previous.sources.intelligence||[],previous.sources.advisories,relevant(previous.sources,inventory));
    const needsConfiguration=relevantIntelligence.some(a=>a.data.attack_conditions.preconditions.some(p=>p.condition_id==='npm_lifecycle_scripts'));
    const configuration=needsConfiguration?await this.securityService.configurationFacts({workspaceId},{signal}):null;
    const fingerprint=inputFingerprint(inventory,previous.sources,configuration);
    if(!force&&previous.latest?.input_fingerprint===fingerprint)return {status:'not_changed',workspaceId,project_id:id,inventory_cache_reused:inventory.cache_reused,report:previous.latest.report};
    const report=correlate(inventory,previous.sources.advisories,previous.sources.records,{now,signal,sourceStates:previous.sources.states,scannerReport:this.scannerReports.get(workspaceId)});
    require('../intelligence/project').attach(report,relevantIntelligence,configuration);
    report.trigger=reason;report.inventory_checked_at=inventory.checked_at;report.source_count=previous.sources.advisories.length;
    if(!previous.sources.advisories.length)report.limitations.push('No cached official advisories; project safety cannot be assessed.');
    if(previous.sources.states.some(s=>s.stale||s.status!=='completed'))report.limitations.push('Some threat sources are stale, incomplete or failed; this is not a complete threat database.');
    check(signal);const scanId=crypto.randomUUID();
    const saved=await withStore(this.file,async store=>{
      check(signal);if(inputFingerprint(inventory,storage.sourceSnapshot(store),configuration)!==fingerprint)fail('advisory_changed_during_analysis');
      const notifications=storage.save(store,inventory,report,fingerprint,scanId);return {notifications,storage:storage.usage(store)};
    });
    return {status:'completed',workspaceId,project_id:id,scan_id:scanId,report,...saved};
  }
  async reassess(changed=[]){
    const results=[];for(const workspaceId of this.workspaceIds){
      const id=this.id(workspaceId),needed=await withReadStore(this.file,s=>{
        const inv=storage.inventory(s,id);if(!inv)return false;const snap=storage.sourceSnapshot(s),ids=relevant(snap,inv);return changed.length===0||changed.some(c=>ids.has(c.canonical_id)||storage.matches(s,id).some(m=>m.canonical_id===c.canonical_id));
      });if(needed)results.push(await this.analyze({workspaceId,reason:'threat_revision'}));
    }return results;
  }
  async snapshot(workspaceId){const id=this.id(workspaceId);return withReadStore(this.file,s=>{
    const latest=storage.latest(s,id)?.report||null,current_sources=storage.sourceStates(s),inv=storage.inventory(s,id);
    if(inv&&this.checked.has(workspaceId))inv.checked_at=this.checked.get(workspaceId);
    if(latest){latest.current_source_status=current_sources;latest.inventory_checked_at=inv?.checked_at||null;latest.inventory_age_seconds=inv?Math.max(0,Math.floor((Date.parse(this.now())-Date.parse(inv.checked_at))/1000)):null;latest.current_coverage_incomplete=!current_sources.length||current_sources.some(x=>x.stale||x.status!=='completed');}
    return {project_id:id,workspaceId,latest,inventory:inv,current_sources,notifications:storage.pending(s,id),storage:storage.usage(s),error:this.lastError};
  });}
  async history(workspaceId,matchId){const id=this.id(workspaceId);if(matchId!==undefined&&!/^[a-f0-9]{24}$/.test(matchId))fail('invalid_match_id');return withReadStore(this.file,s=>storage.history(s,id,matchId));}
  async report(workspaceId,format='json'){if(!['json','markdown'].includes(format))fail('invalid_format');const s=await this.snapshot(workspaceId);return s.latest?(format==='markdown'?markdown(s.latest):s.latest):null;}
  async dependencyLocation(workspaceId,matchId){
    await this.securityService.workspaceIdentity({workspaceId});const snapshot=await this.snapshot(workspaceId),match=snapshot.latest?.matches.find(m=>m.id===matchId);
    if(!match||!snapshot.inventory.dependencies.some(d=>d.id===match.evidence[0]?.dependency_id&&d.source_file===match.source_file))fail('dependency_not_in_inventory');return {source_file:match.source_file,line:match.line};
  }
  async acknowledge(events){if(!Array.isArray(events)||events.length>100||events.some(e=>typeof e!=='string'||!/^[a-f0-9]{64}$/.test(e)))fail('invalid_event_keys');await withStore(this.file,async s=>{for(const key of events)s.run('UPDATE notification_history SET delivered_at=? WHERE event_key=?',[this.now(),key]);});}
  recordScannerReport(workspaceId,report){this.id(workspaceId);if(report?.schemaVersion!==1||!Array.isArray(report.findings)||Buffer.byteLength(JSON.stringify(report))>2*1024*1024)fail('scanner_report_limit');this.scannerReports.set(workspaceId,JSON.parse(JSON.stringify(report)));}
  bindMonitor(monitor){
    const original=monitor.onUpdate,service=this;
    const handler=async result=>{await original(result);if(result.changed?.length)try{await service.reassess(result.changed);}catch{/* Project error is exposed independently; do not turn a successful collection into failure. */}};
    monitor.onUpdate=handler;return {dispose(){if(monitor.onUpdate===handler)monitor.onUpdate=original;}};
  }
  cancel(){for(const c of this.controllers)c.abort();}
  dispose(){this.disposed=true;this.cancel();}
}
module.exports={ProjectImpactService,ImpactError,inputFingerprint,markdown};
