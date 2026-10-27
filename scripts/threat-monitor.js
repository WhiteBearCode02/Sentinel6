'use strict';
const path=require('node:path');
const os=require('node:os');
const fs=require('node:fs/promises');
const {ThreatMonitor}=require('../src/threat/monitor');
async function main(){
 const dir=path.resolve(process.argv[2]||path.join(os.homedir(),'.sentinel6','threats'));
 const monitor=new ThreatMonitor({file:path.join(dir,'threat-intelligence.sqlite')});
 const cancel=()=>monitor.stop();process.once('SIGINT',cancel);
 try {
  await monitor.initialize();const result=await monitor.refresh({force:process.argv.includes('--force')});
  const snapshot=await monitor.snapshot();
  await fs.writeFile(path.join(dir,'latest-feed.json'),JSON.stringify(snapshot,null,2),{mode:0o600});
  console.log(JSON.stringify({status:result.status,changed:result.changed.length,counts:snapshot.counts,sources:snapshot.sources.map(s=>({id:s.id,status:s.status,error:s.error,last_success:s.last_success,pending:s.cursor,stale:s.stale})),report:path.join(dir,'latest-feed.json')},null,2));
  if(result.status==='partial'||result.status==='cancelled')process.exitCode=2;
 } finally {monitor.stop();process.removeListener('SIGINT',cancel);}
}
main().catch(e=>{console.error('Threat collection unavailable: '+(['store_busy','invalid_database'].includes(e.code)?e.code:'collection_failed'));process.exitCode=1;});
