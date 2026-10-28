'use strict';
const {fingerprint,bounded}=require('./safety');
const {verify,legacyDocument}=require('./verification');
const {attackConditions}=require('./conditions');
const {CollectionError}=require('../threat/http');
const SCHEMA=`
 CREATE TABLE IF NOT EXISTS security_news(source TEXT NOT NULL,source_id TEXT NOT NULL,data TEXT NOT NULL,observed_at TEXT NOT NULL,PRIMARY KEY(source,source_id));
 CREATE TABLE IF NOT EXISTS intelligence_analysis(vulnerability_id TEXT PRIMARY KEY,fingerprint TEXT NOT NULL,data TEXT NOT NULL,analyzed_at TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS intelligence_revisions(id INTEGER PRIMARY KEY,vulnerability_id TEXT NOT NULL,fingerprint TEXT NOT NULL,data TEXT NOT NULL,observed_at TEXT NOT NULL);
 CREATE INDEX IF NOT EXISTS intelligence_revision_id ON intelligence_revisions(vulnerability_id,id);
 PRAGMA user_version=3;
`;
function migrate(store,version){if(version>3)throw new CollectionError('invalid_database');store.db.run(SCHEMA);}
function news(store){return store.all('SELECT data FROM security_news ORDER BY observed_at DESC,source_id LIMIT 2000').map(r=>JSON.parse(r.data));}
function ingest(store,doc,now){
 require('./validation').validateSource(doc);
 const old=store.get('SELECT data FROM security_news WHERE source=? AND source_id=?',[doc.source,doc.source_id]);const previous=old?JSON.parse(old.data):null;
 store.run('INSERT OR REPLACE INTO security_news VALUES (?,?,?,?)',[doc.source,doc.source_id,JSON.stringify(doc),now]);
 if(!previous||previous.content_fingerprint!==doc.content_fingerprint)return [...new Set([...(previous?.related_cve_ids||[]),...(previous?.related_ghsa_ids||[]),...doc.related_cve_ids,...doc.related_ghsa_ids,...(!doc.related_cve_ids.length&&!doc.related_ghsa_ids.length?['NEWS-'+doc.source_id.slice(0,24)]:[])])];return [];
}
function all(store){return store.all('SELECT vulnerability_id,fingerprint,data FROM intelligence_analysis').map(r=>({...r,data:JSON.parse(r.data)}));}
function get(store,id){const row=store.get('SELECT data FROM intelligence_analysis WHERE vulnerability_id=?',[id]);return row?JSON.parse(row.data):null;}
function build(store,id,now,cachedDocuments){
 const advisory=store.advisory(id),aliases=advisory&&!advisory.identity_ambiguous?advisory.source_ids:[id];
 const sources=store.all('SELECT data FROM source_records WHERE canonical_id=?',[id]).map(r=>legacyDocument(JSON.parse(r.data)));
 const documents=(cachedDocuments||news(store)).filter(d=>[...d.related_cve_ids,...d.related_ghsa_ids].some(i=>aliases.includes(i))||id==='NEWS-'+d.source_id.slice(0,24));
 if(sources.length+documents.length>50)throw new CollectionError('intelligence_source_limit');
 const verification=verify(id,[...sources,...documents],{identifierConfirmed:!!advisory}),conditions=attackConditions(id,verification);
 const result={schemaVersion:1,modelVersion:'ti-3.0',vulnerability_id:id,aliases,overview:{title:advisory?.title||documents[0]?.title||id,published_at:advisory?.published_at||documents[0]?.published_at||null,modified_at:advisory?.modified_at||documents[0]?.modified_at||null,severity:advisory?.severity||'unknown',withdrawn_at:advisory?.withdrawn_at||null},verification,attack_conditions:conditions,
  sources:documents.map(({claims,...d})=>d),official_links:[...new Set([...sources,...documents].map(d=>d.official_url).filter(Boolean))],last_verified_at:now,
  project_assessments:[],limitations:['Project dependency version, feature use, exposure and attack success are separate facts.','Cached or absent news is not a safety verdict.','Vendor fixed RPMs and prose upstream-fix statements are not npm/PyPI fixed-version recommendations.']};
 if(advisory?.withdrawn_at){conditions.analysis_status='INSUFFICIENT_EVIDENCE';result.limitations.push('An official advisory has been withdrawn; no active impact or mitigation is established by these cached claims.');}
 // Exclude observation times recursively, including nested component/range evidence.
 const material=JSON.parse(JSON.stringify(result,(key,value)=>['observed_at','last_verified_at'].includes(key)?undefined:value));
 result.fingerprint=fingerprint(material);return bounded(result);
}
function analyze(store,ids,now,{signal,deadline=Date.now()+15000}={}){
 const changed=[];
 if(!Array.isArray(ids)||ids.length>2000)throw new CollectionError('intelligence_identity_limit');
 const documents=news(store);
 const canonical=new Map();for(const a of store.all('SELECT canonical_id,data FROM threat_advisories')){const d=JSON.parse(a.data);if(!d.identity_ambiguous)for(const alias of d.source_ids||[])canonical.set(alias,a.canonical_id);}
 for(const id of new Set(ids.map(i=>canonical.get(i)||i))){
  if(signal?.aborted)throw new CollectionError('cancelled');if(Date.now()>deadline)throw new CollectionError('intelligence_analysis_timeout');
  const next=build(store,id,now,documents),previous=get(store,id);
  if(previous?.fingerprint===next.fingerprint)continue;
  store.run('INSERT OR REPLACE INTO intelligence_analysis VALUES (?,?,?,?)',[id,next.fingerprint,JSON.stringify(next),now]);
  store.run('INSERT INTO intelligence_revisions(vulnerability_id,fingerprint,data,observed_at) VALUES (?,?,?,?)',[id,next.fingerprint,JSON.stringify(next),now]);
  changed.push({canonical_id:id,changed:true,changes:['INTELLIGENCE_CHANGED']});
 }
 store.run('DELETE FROM security_news WHERE rowid NOT IN (SELECT rowid FROM security_news ORDER BY observed_at DESC,rowid DESC LIMIT 2000)');
 store.run('DELETE FROM intelligence_revisions WHERE id NOT IN (SELECT id FROM intelligence_revisions ORDER BY id DESC LIMIT 4000)');
 store.run('DELETE FROM intelligence_analysis WHERE vulnerability_id NOT IN (SELECT vulnerability_id FROM intelligence_analysis ORDER BY analyzed_at DESC,rowid DESC LIMIT 2000)');
 return changed;
}
function prune(store,cutoff){for(const table of ['security_news','intelligence_revisions'])store.run(`DELETE FROM ${table} WHERE observed_at<?`,[cutoff]);store.run('DELETE FROM intelligence_analysis WHERE analyzed_at<?',[cutoff]);}
function revisions(store,id){return store.all('SELECT fingerprint,data,observed_at FROM intelligence_revisions WHERE vulnerability_id=? ORDER BY id DESC LIMIT 20',[id]).map(r=>({...r,data:JSON.parse(r.data)}));}
module.exports={migrate,news,ingest,all,get,build,analyze,prune,revisions};
