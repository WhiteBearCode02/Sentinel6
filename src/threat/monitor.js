'use strict';
const {withStore,withReadStore,resetStore}=require('./store');
const {HttpClient,CollectionError,ECOSYSTEMS}=require('./http');
const {sources}=require('./sources');
const DAY=86400000;
const needsWork=(s,now)=>!!s.cursor||['failed','cancelled','interrupted','collecting'].includes(s.status)||!s.last_success||Date.parse(now)-Date.parse(s.last_success)>=DAY;
const deferredSources=[
  {id:'nvd',name:'NVD CVE API 2.0',status:'disabled',reason:'No implemented adapter; not collected in TI-3.'},
  {id:'kisa',name:'KISA',status:'disabled',reason:'No verified collection adapter/terms; not collected in TI-3.'}
];
class ThreatMonitor {
  constructor({file,client=new HttpClient(),now=()=>new Date().toISOString(),onUpdate=()=>{},ecosystems=['npm','PyPI'],retentionDays=90,githubPages=2,osvRecords=20,newsEnabled=false,vendorRecords=5}={}) {
    if(!file||!Array.isArray(ecosystems)||!ecosystems.length||ecosystems.length>4||ecosystems.some(e=>!ECOSYSTEMS.includes(e))||!Number.isInteger(retentionDays)||retentionDays<7||retentionDays>365)throw new CollectionError('invalid_settings');
    if(typeof newsEnabled!=='boolean'||!Number.isInteger(vendorRecords)||vendorRecords<1||vendorRecords>20)throw new CollectionError('invalid_settings');
    Object.assign(this,{file,client,now,onUpdate,retentionDays,githubPages,osvRecords,vendorRecords,newsEnabled});this.baseDefinitions=sources([...new Set(ecosystems)]);this.definitions=this.baseDefinitions;this.setNewsEnabled(newsEnabled);this.inFlight=null;this.controller=null;this.timer=null;this.lastError=null;
  }
  async snapshot() {
    const now=this.now();
    return withReadStore(this.file,store=>({schemaVersion:1,generated_at:now,phase:'TI-1',analysis_status:'NOT_ANALYZED',monitor_error:this.lastError,monitor_diagnostic:this.diagnostic || null,
      sources:[...this.definitions.map(d=>{const s=store.state(d.id);return {...s,pending_analysis:undefined,cursor:s.cursor?{pending_records:s.cursor.queue?.length,pending_page:!!s.cursor.next||!!s.cursor.more,window:s.cursor.window}:null,name:d.name,stale:!s.last_success||Date.parse(now)-Date.parse(s.last_success)>2*DAY};}),...deferredSources,...(!this.newsEnabled?[{id:'news',name:'Security News collection',status:'disabled',reason:'User opt-in required.'},...require('../intelligence/registry').descriptors.map(d=>({id:d.id,name:d.name,status:'disabled',reason:'Enable Security News to use reviewed metadata sources.'}))]:[])],
      security_news:require('../intelligence/storage').news(store).slice(0,100).map(d=>({source:d.source,source_id:d.source_id,title:d.title,official_url:d.official_url,related_cve_ids:d.related_cve_ids,related_ghsa_ids:d.related_ghsa_ids,verification_status:d.verification_status})),intelligence_count:store.get('SELECT count(*) AS n FROM intelligence_analysis').n,
      advisories:store.feed(),counts:store.counts(),scope:'CISA full catalog; GitHub reviewed advisories and configured OSV ecosystems, initial 7 days; pending backlogs are explicit.',
      limitations:['Public feed metadata does not evaluate project impact; opt-in local project assessments are separate.','No result here means the current feed has no matching stored record; it does not establish project safety.','Active monitoring stops when VS Code is closed.','NVD/KISA, OS scheduling, GitHub Actions and AI are disabled. Reviewed news collection requires separate user opt-in.']}));
  }
  async initialize() {await withStore(this.file,async store=>{
    store.run("UPDATE monitoring_jobs SET status='interrupted',finished_at=? WHERE status='running'",[this.now()]);
    for(const d of this.definitions){const s=store.state(d.id);if(s.status==='collecting')store.setState(d.id,{...s,status:'interrupted'});}
  });return this.snapshot();}
  setNewsEnabled(value){if(typeof value!=='boolean')throw new CollectionError('invalid_settings');if(!value&&this.newsEnabled)this.controller?.abort();this.newsEnabled=value;this.definitions=[...this.baseDefinitions,...(value?require('../intelligence/collector').sources():[])];}
  refreshNews(options={}){if(this.inFlight)throw new CollectionError('monitor_busy');if(!this.newsEnabled)throw new CollectionError('source_disabled');return this.refresh({...options,newsOnly:true});}
  refresh({force=false,signal,newsOnly=false}={}) {
    if(this.inFlight)return this.inFlight;
    this.controller=new AbortController();
    const cancel=()=>this.controller?.abort();signal?.addEventListener('abort',cancel,{once:true});if(signal?.aborted)cancel();
    this.inFlight=this.perform(force,this.controller.signal,newsOnly).then(r=>{this.lastError=null;this.diagnostic=null;return r;}).catch(async e=>{
      this.lastError=e instanceof CollectionError?e.code:'storage_failed';
      this.diagnostic={type:['Error','TypeError','RangeError','RuntimeError'].includes(e?.name)?e.name:'unknown',location:typeof e?.stack==='string'?e.stack.match(/(?:http|model|store|sources|monitor|view)\.js:\d+:\d+/)?.[0]||null:null};
      await this.onUpdate({status:'failed',error:this.lastError});throw e;
    }).finally(()=>{signal?.removeEventListener('abort',cancel);this.inFlight=null;this.controller=null;});
    return this.inFlight;
  }
  async perform(force,signal,newsOnly=false) {
    const now=this.now();
    const definitions=this.definitions.filter(d=>!newsOnly||['redhat','talos'].includes(d.id));
    const due=await withReadStore(this.file,store=>definitions.some(def=>{
      const s=store.state(def.id);
      return !(s.next_retry_at&&Date.parse(s.next_retry_at)>Date.parse(now))&&(force||needsWork(s,now));
    }));
    if(!due)return {status:'not_due',sources:[],changed:[]};
    const result=await withStore(this.file,async store=>{
      const job=store.startJob(now);await store.checkpoint();
      const summary={started_at:now,sources:[],changed:[],status:'completed'};
      for(const def of definitions) {
        if(signal.aborted){summary.status='cancelled';break;}
        const state=store.state(def.id);
        // Manual refresh cannot override a provider's persisted rate-limit cooldown.
        const cooling=state.next_retry_at&&Date.parse(state.next_retry_at)>Date.parse(now);
        const due=needsWork(state,now);
        if(cooling||!force&&!due){summary.sources.push({id:def.id,status:cooling?'cooldown':'not_due'});continue;}
        store.setState(def.id,{...state,status:'collecting',last_attempt:now});await store.checkpoint();await this.onUpdate({status:'collecting',source:def.id});
        try {
          const r=await def.collect(store,state,{client:this.client,signal,now,githubPages:this.githubPages,osvRecords:this.osvRecords,vendorRecords:this.vendorRecords});
          const next={...store.state(def.id),last_attempt:now,last_success:r.checkpoint||state.last_success,status:r.status,cursor:r.cursor,endpoint:r.endpoint,records:r.records,error:null,coverage:r.coverage,
            failures:0,next_retry_at:r.status==='partial'?new Date(Date.parse(now)+60000).toISOString():null};
          store.setState(def.id,next);summary.sources.push({id:def.id,status:r.status,records:r.records});summary.changed.push(...r.changes);
          if(r.status!=='completed')summary.status='partial';
        } catch(e) {
          const current=store.state(def.id),cancelled=e.code==='cancelled'||signal.aborted;
          const failures=(state.failures||0)+1;
          const error=e instanceof CollectionError?e.code:'collection_failed';
          store.setState(def.id,{...current,last_attempt:now,status:cancelled?'cancelled':'failed',error,failures,
            next_retry_at:cancelled?null:e.retryAt||new Date(Date.parse(now)+Math.min(DAY,60000*2**Math.min(failures-1,10))).toISOString()});
          summary.sources.push({id:def.id,status:cancelled?'cancelled':'failed',error});summary.status=cancelled?'cancelled':'partial';
        }
        await store.checkpoint();
      }
      if(!signal.aborted)summary.changed.push(...require('../intelligence/collector').finalize(store,summary.changed,now));
      summary.changed=[...new Map(summary.changed.map(c=>[c.canonical_id,c])).values()];
      store.prune(this.retentionDays,now);store.finishJob(job,summary.status,this.now(),summary);return summary;
    });
    await this.onUpdate(result);return result;
  }
  async advisory(id) {return withReadStore(this.file,s=>({advisory:s.advisory(id),revisions:s.revisions(id)}));}
  async clear() {
    if(this.inFlight)throw new CollectionError('monitor_busy');
    return resetStore(this.file);
  }
  start({interval=60000}={}) {
    if(this.timer)return;
    const tick=()=>this.refresh().catch(()=>this.onUpdate({status:'storage_failed'}));
    void tick();this.timer=setInterval(tick,interval);this.timer.unref?.();
  }
  stop(){if(this.timer)clearInterval(this.timer);this.timer=null;this.controller?.abort();}
  dispose(){this.stop();}
}
module.exports={ThreatMonitor,DAY,deferredSources};
