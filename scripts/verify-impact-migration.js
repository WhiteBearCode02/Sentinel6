'use strict';
const fs=require('node:fs/promises'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const {withStore}=require('../src/threat/store');
async function main(){
 const root=path.resolve(__dirname,'..'),source=path.join(root,'reports','threat-live-verified','threat-intelligence.sqlite'),target=path.join(root,'reports','ti2-migration','threat-intelligence.sqlite');
 const SQL=await require('sql.js')({locateFile:f=>require.resolve('sql.js/dist/'+f)}),original=await fs.readFile(source);
 function inspect(bytes){const db=new SQL.Database(bytes);try{return {version:db.exec('PRAGMA user_version')[0].values[0][0],tables:Object.fromEntries(['threat_advisories','source_records','threat_revisions'].map(t=>{const rows=db.exec(`SELECT * FROM ${t} ORDER BY rowid`)[0]?.values||[];return [t,{rows:rows.length,sha256:crypto.createHash('sha256').update(JSON.stringify(rows)).digest('hex')}];}))};}finally{db.close();}}
 const before=inspect(original);assert.equal(before.version,1,'Expected real pre-TI2 version-1 cache');await fs.mkdir(path.dirname(target),{recursive:true});await fs.writeFile(target,original);
 await withStore(target,async s=>assert.equal(s.get('PRAGMA user_version').user_version,2));const after=inspect(await fs.readFile(target));assert.equal(after.version,2);assert.deepEqual(after.tables,before.tables);assert.deepEqual(await fs.readFile(source),original,'Original cache changed');
 const result={realCachedData:true,before,after,allPayloadsPreserved:true,originalCacheUnchanged:true,copyOnly:true};await fs.writeFile(path.join(root,'reports','impact-migration-summary.json'),JSON.stringify(result,null,2));console.log(JSON.stringify(result,null,2));
}
main().catch(e=>{console.error('Migration verification failed: '+(e.code||e.name));process.exitCode=1;});
