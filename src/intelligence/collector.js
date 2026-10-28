'use strict';
const {read,windowFor}=require('../threat/sources');
const {CollectionError}=require('../threat/http');
const {REDHAT,TALOS,descriptors}=require('./registry');
const adapters=require('./adapters');
const storage=require('./storage');
function context(ctx){return {...ctx,cacheVersion:'ti3-adapters-1',client:{get:(url,options)=>ctx.client.get(url,{...options,maxBytes:2*1024*1024})}};}
function remember(store,id,changed){
 const state=store.state(id),pending=[...new Set([...(state.pending_analysis||[]),...changed])];if(pending.length>1000)throw new CollectionError('intelligence_identity_limit');store.setState(id,{...state,pending_analysis:pending});
}
async function collectRedhat(store,state,ctx){
 const window=state.cursor?.window||windowFor(state,ctx.now);let queue=state.cursor?.queue,page=state.cursor?.page||1,more=state.cursor?.more;
 if(!queue){
  const url=`${REDHAT}/cve.json?after=${window.start.slice(0,10)}&per_page=20&page=${page}&isCompressed=false`;
  queue=await read(url,adapters.redhatIndex,store,context(ctx));more=queue.length===20;
  if(page===1){const observed=storage.news(store).filter(d=>d.source==='redhat').sort((a,b)=>a.observed_at.localeCompare(b.observed_at)).slice(0,10).map(d=>d.source_id);queue=[...new Set([...queue,...observed])];}
 }
 let records=0;const saveProgress=()=>store.setState(state.id,{...store.state(state.id),cursor:{queue,page,more,window},status:'partial'});
 saveProgress();await store.checkpoint();
 for(let i=0;i<(ctx.vendorRecords??5)&&queue.length;i++){
  if(ctx.signal?.aborted)throw new CollectionError('cancelled');const id=queue[0];
  const doc=await read(`${REDHAT}/cve/${id}.json`,t=>adapters.redhat(t,id,ctx.now),store,context(ctx));
  remember(store,state.id,storage.ingest(store,{...doc,observed_at:ctx.now},ctx.now));records++;queue=queue.slice(1);saveProgress();await store.checkpoint();
 }
 if(!queue.length&&more){if(page>=999)throw new CollectionError('backlog_limit');page++;queue=null;}
 const pending=!!queue?.length||more;
 return {status:pending?'partial':'completed',cursor:pending?{queue,page,more,window}:null,checkpoint:pending?state.last_success:window.end,changes:[],records,endpoint:REDHAT,coverage:'Publication window plus up to 10 previously observed CVEs per cycle; not a complete modification feed.'};
}
async function collectTalos(store,state,ctx){
 const docs=await read(TALOS,t=>adapters.rss(t,ctx.now),store,context(ctx));
 for(const d of docs)remember(store,state.id,storage.ingest(store,{...d,observed_at:ctx.now},ctx.now));
 return {status:'completed',cursor:null,checkpoint:ctx.now,changes:[],records:docs.length,endpoint:TALOS,coverage:'Current publisher RSS window only; no article crawling.'};
}
const adapterFunctions=Object.freeze({redhat:collectRedhat,talos:collectTalos});
function sources(){return descriptors.map(d=>{const collect=adapterFunctions[d.id];if(!collect)throw new CollectionError('invalid_source_adapter');return {...d,collect};});}
function finalize(store,legacyChanges,now){
 const documents=storage.news(store),related=new Set(documents.flatMap(d=>[...d.related_cve_ids,...d.related_ghsa_ids]));
 const analyses=storage.all(store);for(const a of analyses)for(const id of [a.vulnerability_id,...(a.data.aliases||[])])related.add(id);
 const ids=legacyChanges.filter(c=>related.has(c.canonical_id)).map(c=>c.canonical_id);
 for(const d of descriptors)ids.push(...(store.state(d.id).pending_analysis||[]));
 const changed=storage.analyze(store,ids,now);
 for(const d of descriptors){const state=store.state(d.id);if(state.pending_analysis?.length)store.setState(d.id,{...state,pending_analysis:[]});}
 return changed;
}
module.exports={sources,collectRedhat,collectTalos,finalize};
