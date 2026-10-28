'use strict';
// Official endpoints only. No project is registered, inspected, or uploaded.
const fs=require('node:fs/promises'),path=require('node:path');
const {ThreatMonitor}=require('../src/threat/monitor'),{withReadStore}=require('../src/threat/store'),storage=require('../src/intelligence/storage');
async function main(){
 const dir=path.resolve(__dirname,'../reports/ti3-live'),file=path.join(dir,'threat-intelligence.sqlite');await fs.mkdir(dir,{recursive:true});
 const monitor=new ThreatMonitor({file,newsEnabled:true,vendorRecords:2});
 try{await monitor.initialize();const result=await monitor.refreshNews({force:true});const snapshot=await monitor.snapshot();const analyses=await withReadStore(file,s=>storage.all(s));
  const summary={syntheticData:false,projectRegistered:false,projectUpload:false,requests:'Reviewed Red Hat API and Cisco Talos RSS only',status:result.status,sources:snapshot.sources.filter(s=>['redhat','talos'].includes(s.id)),newsItems:snapshot.security_news.length,analyses:analyses.length,
   structuredMetrics:analyses.filter(a=>a.data.attack_conditions.attack_surface!=='UNKNOWN').length,explicitProseConditions:analyses.filter(a=>a.data.attack_conditions.preconditions.length).length,limitations:'Limited source windows and request budget; UNKNOWN is preserved. No crawling, attack requests or LLM calls.'};
  await fs.writeFile(path.join(dir,'summary.json'),JSON.stringify(summary,null,2));console.log(JSON.stringify(summary,null,2));if(summary.sources.some(s=>s.status==='failed'))process.exitCode=2;
 }finally{monitor.dispose();}
}
main().catch(e=>{console.error('Live intelligence verification failed: '+(e.code||'collection_failed'));process.exitCode=1;});
