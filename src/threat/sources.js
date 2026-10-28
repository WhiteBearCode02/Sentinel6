'use strict';
const {CollectionError,CISA,CISA_MIRROR,ECOSYSTEMS,validateUrl}=require('./http');
const model=require('./model');
function json(text) {try{return JSON.parse(text);}catch{throw new CollectionError('invalid_schema');}}
async function read(url,decode,store,{client,signal,now,indexSince,cacheVersion}) {
  let cached=store.cache(url);
  if(cacheVersion&&cached?.parsed?.normalization_version!==cacheVersion)cached=null;
  if(indexSince&&cached&&(!Array.isArray(cached.parsed?.entries)||typeof cached.parsed?.since!=='string'||cached.parsed.since>indexSince))cached=null;
  const response=await client.get(url,{cache:cached,signal,indexSince});
  if(response.status===304) {if(!cached)throw new CollectionError('cache_miss');return cacheVersion?cached.parsed.value:cached.parsed;}
  const decoded=decode(response.text,response.headers || {}),parsed=cacheVersion?{normalization_version:cacheVersion,value:decoded}:decoded;
  store.putCache(url,response,parsed,now);
  return decoded;
}
function ingest(store,records,now) {
  return records.map(r=>store.ingest(r,now)).filter(r=>r.changed);
}
async function collectCisa(store,state,ctx) {
  let records,url=CISA;
  try{records=await read(url,t=>model.cisa(json(t)),store,ctx);}
  catch(e){if(!['http_403','http_404','network_failed','timeout','dns_failed'].includes(e.code))throw e;url=CISA_MIRROR;records=await read(url,t=>model.cisa(json(t)),store,ctx);}
  const seen=new Set(records.map(r=>r.source_id));
  const removed=store.all("SELECT data FROM source_records WHERE source='cisa'").map(row=>JSON.parse(row.data)).filter(r=>!seen.has(r.source_id)&&r.kev_status===true)
    .map(r=>({...r,kev_status:false,evidence_sources:[...r.evidence_sources,{source:'cisa',id:r.source_id,url:'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',fact:'Absent from latest validated complete catalog; not a CVE withdrawal or proof of safety.'}]}));
  return {status:'completed',cursor:null,checkpoint:ctx.now,changes:ingest(store,[...records,...removed],ctx.now),records:records.length,endpoint:url};
}
function nextLink(headers) {
  const link=headers.link;
  if(!link)return null;
  if(typeof link!=='string'||link.length>10000)throw new CollectionError('invalid_schema');
  const value=link.split(',').map(x=>x.match(/<([^>]+)>;\s*rel="next"/)).find(Boolean)?.[1];
  if(value){const u=validateUrl(value);if(u.hostname!=='api.github.com'||u.pathname!=='/advisories')throw new CollectionError('blocked_url');}
  return value || null;
}
function windowFor(state,now) {
  return {start:new Date(state.last_success?Date.parse(state.last_success)-300000:Date.parse(now)-7*86400000).toISOString(),end:now};
}
async function collectGithub(store,state,ctx) {
  const window=state.cursor?.window || windowFor(state,ctx.now);
  let url=state.cursor?.next;
  if(!url){const u=new URL('https://api.github.com/advisories');u.searchParams.set('type','reviewed');u.searchParams.set('modified',`${window.start.slice(0,10)}..${window.end.slice(0,10)}`);u.searchParams.set('sort','updated');u.searchParams.set('direction','asc');u.searchParams.set('per_page','100');url=u.href;}
  const changes=[];let records=0;
  for(let i=0;i<(ctx.githubPages ?? 2);i++) {
    const page=await read(url,(t,h)=>({records:model.github(json(t)),next:nextLink(h)}),store,ctx);
    changes.push(...ingest(store,page.records,ctx.now));records+=page.records.length;
    url=page.next;
    // Persist page progress so a failure later cannot skip a successful page.
    const pending={...state,status:url?'partial':'completed',last_attempt:ctx.now,cursor:url?{next:url,window}:null};
    if(!url)pending.last_success=window.end;
    store.setState(state.id,pending);await store.checkpoint();
    if(!url)break;
  }
  return {status:url?'partial':'completed',cursor:url?{next:url,window}:null,checkpoint:url?state.last_success:window.end,changes,records,endpoint:'https://api.github.com/advisories',window};
}
function csv(text,window) {
  const rows=text.trim().split(/\r?\n/);if(rows.length>200000)throw new CollectionError('response_limit');
  const out=[];let previous=Infinity;
  if(!text.trim())throw new CollectionError('invalid_schema');
  for(const row of rows) {
    const comma=row.indexOf(',');if(comma<0)throw new CollectionError('invalid_schema');
    const modified=model.date(row.slice(0,comma),true),id=row.slice(comma+1).trim();model.identifier(id);
    const timestamp=Date.parse(modified);
    if(timestamp>previous)throw new CollectionError('invalid_schema');previous=timestamp;
    if(timestamp<Date.parse(window.start))break;
    if(timestamp<=Date.parse(window.end))out.push({id,modified});
  }
  return [...new Map(out.map(r=>[r.id,r])).values()].sort((a,b)=>a.modified.localeCompare(b.modified)||a.id.localeCompare(b.id));
}
async function collectOsv(store,state,ctx,ecosystem) {
  if(!ECOSYSTEMS.includes(ecosystem))throw new CollectionError('invalid_ecosystem');
  const window=state.cursor?.window || windowFor(state,ctx.now);
  let queue=state.cursor?.queue;
  if(!queue) {
    const url=`https://osv-vulnerabilities.storage.googleapis.com/${ecosystem}/modified_id.csv`;
    // Cache parsed index entries, not raw CSV/body. Re-filter a 304 cache for the current window.
    const index=await read(url,t=>({since:window.start,entries:csv(t,{start:window.start,end:'9999-01-01T00:00:00.000Z'})}),store,{...ctx,indexSince:window.start});
    queue=index.entries.filter(r=>r.modified>=window.start&&r.modified<=window.end);
    if(queue.length>50000)throw new CollectionError('backlog_limit');
  }
  const changes=[];let records=0;
  const budget=ctx.osvRecords ?? 20;
  for(let i=0;i<budget&&queue.length;i++) {
    if(ctx.signal?.aborted)throw new CollectionError('cancelled');
    const next=queue[0];
    try {
      const record=await read(`https://api.osv.dev/v1/vulns/${encodeURIComponent(next.id)}`,t=>model.osv(json(t)),store,ctx);
      if(record.source_id!==next.id)throw new CollectionError('invalid_schema');
      changes.push(...ingest(store,[record],ctx.now));records++;queue=queue.slice(1);
    } catch(e) {
      // Keep the failing record at the head for retry; do not silently skip it.
      store.setState(state.id,{...state,cursor:{queue,window},status:e.code==='cancelled'?'cancelled':'failed'});await store.checkpoint();throw e;
    }
  }
  return {status:queue.length?'partial':'completed',cursor:queue.length?{queue,window}:null,checkpoint:queue.length?state.last_success:window.end,changes,records,endpoint:'https://api.osv.dev/v1/vulns/{id}',window};
}
function sources(ecosystems=['npm','PyPI']) {
  return [{id:'cisa',name:'CISA KEV',collect:collectCisa},{id:'github',name:'GitHub Reviewed Advisories',collect:collectGithub},...ecosystems.map(e=>({id:'osv:'+e,name:'OSV '+e,collect:(s,state,ctx)=>collectOsv(s,state,ctx,e)}))];
}
module.exports={read,collectCisa,collectGithub,collectOsv,nextLink,csv,windowFor,sources};
