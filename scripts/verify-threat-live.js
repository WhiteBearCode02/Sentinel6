'use strict';
// Explicit integration check: public metadata only, no project input or executable advice.
const fs=require('node:fs/promises');
const path=require('node:path');
const assert=require('node:assert/strict');
const {ThreatMonitor}=require('../src/threat/monitor');
const {HttpClient}=require('../src/threat/http');
async function main(){
 const dir=path.resolve(process.argv[2] || 'reports/threat-live-verified');
 const monitor=new ThreatMonitor({file:path.join(dir,'threat-intelligence.sqlite'),client:new HttpClient({minInterval:250}),githubPages:6,osvRecords:1000});
 const stop=()=>monitor.stop();process.once('SIGINT',stop);
 try {
  await monitor.initialize();const before=await monitor.snapshot();const run=await monitor.refresh();const snapshot=await monitor.snapshot();
  const active=snapshot.sources.filter(s=>s.status!=='disabled');
  const summary={observed_at:snapshot.generated_at,status:run.status,previous:before.counts,counts:snapshot.counts,changed:run.changed.length,sources:active.map(s=>({id:s.id,status:s.status,last_success:s.last_success,error:s.error,pending:s.cursor})),project_analysis:'NOT_ANALYZED'};
  await fs.writeFile(path.join(dir,'latest-feed.json'),JSON.stringify(snapshot,null,2));await fs.writeFile(path.join(dir,'live-validation.json'),JSON.stringify(summary,null,2));console.log(JSON.stringify(summary,null,2));
  assert.ok(active.every(s=>s.status==='completed'),'Real provider catch-up has not completed');assert.ok(snapshot.counts.advisories>0);
  const same=await monitor.refresh();assert.equal(same.status,'not_due','A second daily run should not refetch');
  const restart=new ThreatMonitor({file:monitor.file});await restart.initialize();assert.equal((await restart.snapshot()).counts.advisories,snapshot.counts.advisories);
  console.log('Live collection, complete catch-up, restart persistence and daily deduplication passed.');
 } finally {monitor.stop();process.removeListener('SIGINT',stop);}
}
main().catch(()=>{console.error('Live verification incomplete; inspect safe source states in live-validation.json.');process.exitCode=1;});
