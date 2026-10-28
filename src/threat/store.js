'use strict';
const fs=require('node:fs/promises');
const path=require('node:path');
const crypto=require('node:crypto');
const {setTimeout:sleep}=require('node:timers/promises');
const {combine}=require('./model');
const {CollectionError}=require('./http');
let sqlite;
async function sqliteModule() {
  if(!sqlite)sqlite=require('sql.js')({locateFile:file=>require.resolve('sql.js/dist/'+file)});
  return sqlite;
}
const SCHEMA=`
 PRAGMA foreign_keys=ON;
 CREATE TABLE IF NOT EXISTS threat_sources (id TEXT PRIMARY KEY, state TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS source_records (source TEXT NOT NULL, source_id TEXT NOT NULL, canonical_id TEXT NOT NULL, data TEXT NOT NULL, last_seen TEXT NOT NULL, PRIMARY KEY(source,source_id));
 CREATE INDEX IF NOT EXISTS source_canonical ON source_records(canonical_id);
 CREATE INDEX IF NOT EXISTS source_identifier ON source_records(source_id);
 CREATE TABLE IF NOT EXISTS threat_advisories (canonical_id TEXT PRIMARY KEY, data TEXT NOT NULL, last_seen TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS threat_revisions (id INTEGER PRIMARY KEY, canonical_id TEXT NOT NULL, fingerprint TEXT NOT NULL, observed_at TEXT NOT NULL, changes TEXT NOT NULL, data TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS http_cache (url TEXT PRIMARY KEY, etag TEXT, last_modified TEXT, parsed TEXT NOT NULL, observed_at TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS monitoring_jobs (id TEXT PRIMARY KEY, started_at TEXT NOT NULL, finished_at TEXT, status TEXT NOT NULL, summary TEXT);
`;
async function atomicReplace(temp,file,{rename=fs.rename,wait=sleep}={}) {
  for(let attempt=0;attempt<8;attempt++) {
    try {await rename(temp,file);return;}
    catch(e) {if(!['EPERM','EBUSY','EACCES'].includes(e.code))throw new CollectionError('storage_failed');
      if(attempt===7)throw new CollectionError('storage_busy');
      // Windows readers/antivirus can briefly deny replacing an open destination.
      // Keep the old database intact; never delete it to work around a lock.
      await wait(Math.min(1000,25*2**attempt));
    }
  }
}
class ThreatStore {
  constructor(SQL,file,db) {
    this.SQL=SQL;this.file=file;this.db=db;
    const version=db.exec('PRAGMA user_version')[0]?.values[0][0]||0;
    if(version>2)throw new Error('unsupported_database_version');
    db.run(SCHEMA);require('../impact/storage').migrate(this,version);
  }
  all(sql,params=[]) {const s=this.db.prepare(sql);try{s.bind(params);const out=[];while(s.step())out.push(s.getAsObject());return out;}finally{s.free();}}
  get(sql,params=[]) {return this.all(sql,params)[0];}
  run(sql,params=[]) {this.db.run(sql,params);}
  state(id) {const row=this.get('SELECT state FROM threat_sources WHERE id=?',[id]);return row?JSON.parse(row.state):{id,status:'never_checked',last_success:null,cursor:null};}
  setState(id,state) {this.run('INSERT OR REPLACE INTO threat_sources VALUES (?,?)',[id,JSON.stringify({...state,id})]);}
  cache(url) {const r=this.get('SELECT * FROM http_cache WHERE url=?',[url]);return r?{...r,parsed:JSON.parse(r.parsed)}:null;}
  putCache(url,response,parsed,now) {this.run('INSERT OR REPLACE INTO http_cache VALUES (?,?,?,?,?)',[url,response.etag||null,response.last_modified||null,JSON.stringify(parsed),now]);}
  advisory(id) {const row=this.get('SELECT data FROM threat_advisories WHERE canonical_id=?',[id]);return row?JSON.parse(row.data):null;}
  feed(limit=200) {return this.all("SELECT data FROM threat_advisories ORDER BY json_extract(data,'$.last_changed_at') DESC, COALESCE(json_extract(data,'$.modified_at'),json_extract(data,'$.published_at'),json_extract(data,'$.kev_added_at')) DESC,canonical_id LIMIT ?",[limit]).map(r=>JSON.parse(r.data));}
  revisions(id,limit=50) {return this.all('SELECT observed_at,changes,fingerprint FROM threat_revisions WHERE canonical_id=? ORDER BY id DESC LIMIT ?',[id,limit]).map(r=>({...r,changes:JSON.parse(r.changes)}));}
  ingest(record,now) {
    let canonical=record.canonical_id;
    const oldSource=this.get('SELECT canonical_id FROM source_records WHERE source=? AND source_id=?',[record.source,record.source_id]);
    const oldCanonical=oldSource?.canonical_id;
    const placeholders=record.source_ids.map(()=>'?').join(',');
    if(!record.identity_ambiguous&&!canonical.startsWith('CVE-')) {
      const related=this.all(`SELECT DISTINCT canonical_id FROM source_records WHERE source_id IN (${placeholders})`,record.source_ids).map(r=>r.canonical_id).filter(id=>id.startsWith('CVE-'));
      if(new Set(related).size===1)canonical=related[0];
    }
    const promoted=[];
    if(!record.identity_ambiguous&&canonical.startsWith('CVE-')) {
      for(const id of record.source_ids.filter(id=>!id.startsWith('CVE-'))) {
        const candidates=this.all('SELECT source,source_id,data FROM source_records WHERE canonical_id=?',[id]).filter(r=>!JSON.parse(r.data).identity_ambiguous);
        for(const row of candidates)this.run('UPDATE source_records SET canonical_id=? WHERE source=? AND source_id=?',[canonical,row.source,row.source_id]);
        if(candidates.length)promoted.push(id);
      }
    }
    record={...record,canonical_id:canonical,threat_id:canonical};
    const previous=this.advisory(canonical)||promoted.map(id=>this.advisory(id)).find(Boolean);
    this.run('INSERT OR REPLACE INTO source_records VALUES (?,?,?,?,?)',[record.source,record.source_id,canonical,JSON.stringify(record),now]);
    const records=this.all('SELECT data FROM source_records WHERE canonical_id=?',[canonical]).map(r=>({...JSON.parse(r.data),canonical_id:canonical,threat_id:canonical}));
    const combined=combine(records,previous,now);
    const changed=!previous||previous.content_fingerprint!==combined.content_fingerprint;
    if(!changed)combined.change_type=previous.change_type;
    combined.last_changed_at=changed?now:previous.last_changed_at||previous.first_seen_at;
    this.run('INSERT OR REPLACE INTO threat_advisories VALUES (?,?,?)',[canonical,JSON.stringify(combined),now]);
    if(changed) this.run('INSERT INTO threat_revisions(canonical_id,fingerprint,observed_at,changes,data) VALUES (?,?,?,?,?)',[canonical,combined.content_fingerprint,now,JSON.stringify(combined.change_type),JSON.stringify(combined)]);
    for(const id of new Set([...promoted,...(oldCanonical&&oldCanonical!==canonical?[oldCanonical]:[])])) {
      if(!this.get('SELECT canonical_id FROM source_records WHERE canonical_id=?',[id]))this.run('DELETE FROM threat_advisories WHERE canonical_id=?',[id]);
    }
    return {canonical_id:canonical,changed,changes:changed?combined.change_type:[]};
  }
  startJob(now) {
    this.run("UPDATE monitoring_jobs SET status='interrupted',finished_at=? WHERE status='running'",[now]);
    const id=crypto.randomUUID();this.run('INSERT INTO monitoring_jobs VALUES (?,?,NULL,?,NULL)',[id,now,'running']);return id;
  }
  finishJob(id,status,now,summary) {this.run('UPDATE monitoring_jobs SET status=?,finished_at=?,summary=? WHERE id=?',[status,now,JSON.stringify(summary),id]);}
  prune(days,now) {
    if(!Number.isInteger(days)||days<7||days>365)throw new CollectionError('invalid_retention');
    const cutoff=new Date(Date.parse(now)-days*86400000).toISOString();
    this.run('DELETE FROM threat_revisions WHERE observed_at<?',[cutoff]);
    this.run('DELETE FROM monitoring_jobs WHERE started_at<?',[cutoff]);
    this.run('DELETE FROM http_cache WHERE observed_at<?',[cutoff]);
    this.run('DELETE FROM source_records WHERE last_seen<?',[cutoff]);
    this.run('DELETE FROM threat_advisories WHERE last_seen<?',[cutoff]);
    require('../impact/storage').prune(this,cutoff);
  }
  counts() {return {advisories:this.get('SELECT count(*) AS n FROM threat_advisories').n,revisions:this.get('SELECT count(*) AS n FROM threat_revisions').n,jobs:this.get('SELECT count(*) AS n FROM monitoring_jobs').n};}
  async checkpoint() {
    const bytes=this.db.export();if(bytes.length>64*1024*1024)throw new CollectionError('database_limit');
    const temp=this.file+'.'+crypto.randomUUID()+'.tmp';
    try {const h=await fs.open(temp,'wx',0o600);try{await h.writeFile(bytes);await h.sync();}finally{await h.close();}await atomicReplace(temp,this.file);}
    finally {await fs.rm(temp,{force:true});}
  }
  close(){this.db.close();}
}
async function load(file) {
  const SQL=await sqliteModule();let bytes;
  try{const s=await fs.lstat(file);if(!s.isFile()||s.isSymbolicLink()||s.size>64*1024*1024)throw new CollectionError('invalid_database');bytes=await fs.readFile(file);}catch(e){if(e.code!=='ENOENT')throw new CollectionError('invalid_database');}
  try{return new ThreatStore(SQL,file,new SQL.Database(bytes));}catch{throw new CollectionError('invalid_database');}
}
async function withReadStore(file,fn) {const store=await load(file);try{return await fn(store);}finally{store.close();}}
async function withLock(file,fn) {
  if(!path.isAbsolute(file))throw new CollectionError('invalid_database_path');
  await fs.mkdir(path.dirname(file),{recursive:true,mode:0o700});
  const lock=file+'.lock';let handle;
  try{handle=await fs.open(lock,'wx',0o600);}catch(e){
    if(e.code!=='EEXIST')throw new CollectionError('storage_failed');
    let pid;try{const s=await fs.lstat(lock);if(!s.isFile()||s.isSymbolicLink()||s.size>32)throw new Error();pid=Number(await fs.readFile(lock,'utf8'));}catch{throw new CollectionError('store_busy');}
    if(!Number.isSafeInteger(pid)||pid<=0)throw new CollectionError('store_busy');
    let alive=true;try{process.kill(pid,0);}catch(error){if(error.code==='ESRCH')alive=false;}
    if(alive)throw new CollectionError('store_busy');
    await fs.rm(lock);try{handle=await fs.open(lock,'wx',0o600);}catch{throw new CollectionError('store_busy');}
  }
  try{await handle.writeFile(String(process.pid));return await fn();}
  finally{await handle.close();await fs.rm(lock,{force:true});}
}
async function withStore(file,fn) {
  return withLock(file,async()=>{const store=await load(file);try{const result=await fn(store);await store.checkpoint();return result;}finally{store.close();}});
}
async function resetStore(file) {
  return withLock(file,async()=>{const SQL=await sqliteModule(),store=new ThreatStore(SQL,file,new SQL.Database());try{await store.checkpoint();}finally{store.close();}});
}
module.exports={ThreatStore,withStore,withReadStore,resetStore,atomicReplace};
