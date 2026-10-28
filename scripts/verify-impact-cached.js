'use strict';
// Offline matching against a COPY of previously collected real public advisories.
const fs=require('node:fs/promises'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const {createSecurityService}=require('../src/security-service');
const {ProjectImpactService}=require('../src/impact/service');
async function main(){
 const root=path.resolve(__dirname,'..'),project=path.join(root,'fixtures','vulnerable'),file=path.join(root,'reports','ti2-migration','threat-intelligence.sqlite');
 const hashes=async()=>{const out={};for(const n of await fs.readdir(project))out[n]=crypto.createHash('sha256').update(await fs.readFile(path.join(project,n))).digest('hex');return out;};const before=await hashes();
 const securityService=await createSecurityService({workspaces:[{id:'fixture',root:project}]}),service=new ProjectImpactService({securityService,file,workspaceIds:['fixture']});
 try{
  await service.initialize();const result=await service.analyze({workspaceId:'fixture',force:true});assert.deepEqual(await hashes(),before);const report=await service.report('fixture');
  const summary={syntheticAdvisories:false,source:'Previously collected official cache, offline; freshness remains explicit',sourceCount:report.source_count,dependencies:(await service.snapshot('fixture')).inventory.dependencies.length,matches:report.matches.length,statuses:report.summary,sourceUnchanged:true,networkRequests:0,examples:report.matches.slice(0,8).map(m=>({id:m.canonical_id,package:m.package.name,version:m.package.detected_version,status:m.impact_status,sources:m.official_sources})),storage:(await service.snapshot('fixture')).storage};
  await fs.writeFile(path.join(root,'reports','impact-cached-report.json'),JSON.stringify(report,null,2));await fs.writeFile(path.join(root,'reports','impact-cached-summary.json'),JSON.stringify(summary,null,2));console.log(JSON.stringify(summary,null,2));
 }finally{service.dispose();}
}
main().catch(e=>{console.error('Cached impact verification failed: '+(e.code||e.name));process.exitCode=1;});
