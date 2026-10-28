'use strict';
const {hash}=require('../inventory/identity');
const {shouldNotify}=require('./correlation');
const SCHEMA=`
 CREATE TABLE IF NOT EXISTS project_inventory(project_id TEXT PRIMARY KEY,data TEXT NOT NULL,updated_at TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS project_dependencies(project_id TEXT NOT NULL,dependency_id TEXT NOT NULL,data TEXT NOT NULL,PRIMARY KEY(project_id,dependency_id));
 CREATE TABLE IF NOT EXISTS project_scans(scan_id TEXT PRIMARY KEY,project_id TEXT NOT NULL,analyzed_at TEXT NOT NULL,input_fingerprint TEXT NOT NULL,report TEXT NOT NULL);
 CREATE INDEX IF NOT EXISTS project_scan_time ON project_scans(project_id,analyzed_at);
 CREATE TABLE IF NOT EXISTS project_threat_matches(project_id TEXT NOT NULL,match_id TEXT NOT NULL,data TEXT NOT NULL,PRIMARY KEY(project_id,match_id));
 CREATE TABLE IF NOT EXISTS impact_evidence(project_id TEXT NOT NULL,match_id TEXT NOT NULL,data TEXT NOT NULL,PRIMARY KEY(project_id,match_id));
 CREATE TABLE IF NOT EXISTS impact_history(id INTEGER PRIMARY KEY,project_id TEXT NOT NULL,match_id TEXT NOT NULL,observed_at TEXT NOT NULL,previous_status TEXT,data TEXT NOT NULL,fingerprint TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS notification_history(event_key TEXT PRIMARY KEY,project_id TEXT NOT NULL,created_at TEXT NOT NULL,delivered_at TEXT,data TEXT NOT NULL);
 PRAGMA user_version=2;
`;
function migrate(store,previousVersion){if(previousVersion>2)throw new Error('unsupported_database_version');store.db.run(SCHEMA);}
function inventory(store,id){const r=store.get('SELECT data FROM project_inventory WHERE project_id=?',[id]);return r?JSON.parse(r.data):null;}
function latest(store,id){const r=store.get('SELECT * FROM project_scans WHERE project_id=? ORDER BY analyzed_at DESC,rowid DESC LIMIT 1',[id]);return r?{...r,report:JSON.parse(r.report)}:null;}
function matches(store,id){return store.all('SELECT data FROM project_threat_matches WHERE project_id=?',[id]).map(r=>JSON.parse(r.data));}
function sourceStates(store){return store.all('SELECT id,state FROM threat_sources').map(r=>{const s=JSON.parse(r.state);return {id:r.id,status:s.status,last_success:s.last_success,error:s.error,stale:!s.last_success||!Number.isFinite(Date.parse(s.last_success))||Date.now()-Date.parse(s.last_success)>172800000};});}
function sourceSnapshot(store){return {advisories:store.all('SELECT data FROM threat_advisories').map(r=>JSON.parse(r.data)),records:store.all('SELECT canonical_id,data FROM source_records').map(r=>({...JSON.parse(r.data),canonical_id:r.canonical_id})),states:sourceStates(store)};}
function usage(store){const page=store.get('PRAGMA page_count').page_count,size=store.get('PRAGMA page_size').page_size;return {bytes:page*size,limit_bytes:64*1024*1024,warning:page*size>51*1024*1024};}
function save(store,inv,report,inputFingerprint,scanId){
  const id=inv.project_id,now=report.analyzed_at,old=new Map(matches(store,id).map(m=>[m.id,m]));const notifications=[];
  if(Buffer.byteLength(JSON.stringify(report))>2*1024*1024)throw Object.assign(new Error('impact_report_limit'),{code:'impact_report_limit'});
  store.run('BEGIN IMMEDIATE');
  try{
    store.run('INSERT OR REPLACE INTO project_inventory VALUES (?,?,?)',[id,JSON.stringify(inv),inv.checked_at]);store.run('DELETE FROM project_dependencies WHERE project_id=?',[id]);
    for(const d of inv.dependencies)store.run('INSERT INTO project_dependencies VALUES (?,?,?)',[id,d.id,JSON.stringify(d)]);
    store.run('DELETE FROM project_threat_matches WHERE project_id=?',[id]);store.run('DELETE FROM impact_evidence WHERE project_id=?',[id]);
    for(const m of report.matches){
      // A later official CVE alias may promote a GHSA canonical ID without creating a new risk.
      const previous=old.get(m.id)||[...old.values()].find(p=>p.evidence[0]?.dependency_id===m.evidence[0]?.dependency_id&&(p.aliases||[]).some(a=>(m.aliases||[]).includes(a)));
      if(previous&&previous.id!==m.id)store.run('UPDATE impact_history SET match_id=? WHERE project_id=? AND match_id=?',[m.id,id,previous.id]);
      store.run('INSERT INTO project_threat_matches VALUES (?,?,?)',[id,m.id,JSON.stringify(m)]);store.run('INSERT INTO impact_evidence VALUES (?,?,?)',[id,m.id,JSON.stringify(m.evidence)]);
      if(!previous||previous.fingerprint!==m.fingerprint)store.run('INSERT INTO impact_history(project_id,match_id,observed_at,previous_status,data,fingerprint) VALUES (?,?,?,?,?,?)',[id,m.id,now,previous?.impact_status||null,JSON.stringify(m),m.fingerprint]);
      if(shouldNotify(previous,m)){
        const event={event_key:hash([id,m.id,previous?.fingerprint||'',m.fingerprint,scanId].join('|')),project_id:id,match_id:m.id,canonical_id:m.canonical_id,impact_status:m.impact_status,priority:m.priority.level,reason:previous?.kev_status!==true&&m.kev_status===true?'KEV_ESCALATION':previous?'RISK_INCREASED':'NEW_HIGH_RISK',action:m.recommended_action};
        notifications.push(event);store.run('INSERT OR IGNORE INTO notification_history VALUES (?,?,?,NULL,?)',[event.event_key,id,now,JSON.stringify(event)]);
      }
      old.delete(previous?.id||m.id);
    }
    for(const previous of old.values()){
      const missing={...previous,impact_status:'NOT_ANALYZED',confidence:'low',priority:{score:0,level:'informational',reasons:[{points:0,reason:'current_evidence_unavailable'}]},last_analyzed_at:now,limitations:[...previous.limitations,'dependency_or_advisory_not_in_current_snapshot'],recommended_action:'Dependency or advisory disappeared from the analyzed snapshot; review the updated inventory. This is not automatic proof of mitigation.'};
      missing.fingerprint=hash(previous.fingerprint+'|removed|'+inv.fingerprint);
      store.run('INSERT INTO impact_history(project_id,match_id,observed_at,previous_status,data,fingerprint) VALUES (?,?,?,?,?,?)',[id,previous.id,now,previous.impact_status,JSON.stringify(missing),missing.fingerprint]);
    }
    store.run('INSERT INTO project_scans VALUES (?,?,?,?,?)',[scanId,id,now,inputFingerprint,JSON.stringify(report)]);
    store.run('DELETE FROM project_scans WHERE project_id=? AND scan_id NOT IN (SELECT scan_id FROM project_scans WHERE project_id=? ORDER BY analyzed_at DESC,rowid DESC LIMIT 3)',[id,id]);
    store.run('DELETE FROM impact_history WHERE project_id=? AND id NOT IN (SELECT id FROM impact_history WHERE project_id=? ORDER BY id DESC LIMIT 1000)',[id,id]);
    store.run('DELETE FROM notification_history WHERE project_id=? AND event_key NOT IN (SELECT event_key FROM notification_history WHERE project_id=? ORDER BY created_at DESC,rowid DESC LIMIT 500)',[id,id]);
    store.run('COMMIT');
  }catch(e){store.run('ROLLBACK');throw e;}
  if(usage(store).warning)store.run('VACUUM');
  return notifications;
}
function history(store,id,matchId){return store.all('SELECT observed_at,previous_status,data FROM impact_history WHERE project_id=?'+(matchId?' AND match_id=?':'')+' ORDER BY id DESC LIMIT 100',matchId?[id,matchId]:[id]).map(r=>({...r,data:JSON.parse(r.data)}));}
function pending(store,id){return store.all('SELECT data FROM notification_history WHERE project_id=? AND delivered_at IS NULL ORDER BY created_at LIMIT 20',[id]).map(r=>JSON.parse(r.data));}
function prune(store,cutoff){
  store.run('DELETE FROM project_scans WHERE analyzed_at<?',[cutoff]);store.run('DELETE FROM impact_history WHERE observed_at<?',[cutoff]);store.run('DELETE FROM notification_history WHERE created_at<?',[cutoff]);
  for(const row of store.all('SELECT project_id FROM project_inventory WHERE updated_at<?',[cutoff]))for(const table of ['project_inventory','project_dependencies','project_threat_matches','impact_evidence'])store.run(`DELETE FROM ${table} WHERE project_id=?`,[row.project_id]);
}
module.exports={migrate,inventory,latest,matches,sourceSnapshot,sourceStates,usage,save,history,pending,prune};
