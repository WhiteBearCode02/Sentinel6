'use strict';
// Documented historical API example for schema/metric validation. No attack requests.
const fs=require('node:fs/promises'),path=require('node:path');
const {HttpClient}=require('../src/threat/http'),{REDHAT}=require('../src/intelligence/registry'),adapters=require('../src/intelligence/adapters'),{withStore}=require('../src/threat/store'),storage=require('../src/intelligence/storage');
async function main(){const id='CVE-2022-33980',now=new Date().toISOString(),response=await new HttpClient().get(`${REDHAT}/cve/${id}.json`,{maxBytes:2*1024*1024});const doc=adapters.redhat(response.text,id,now),dir=path.resolve(__dirname,'../reports/ti3-sample');await fs.mkdir(dir,{recursive:true});
 const report=await withStore(path.join(dir,'threat-intelligence.sqlite'),async s=>{storage.ingest(s,doc,now);storage.analyze(s,[id],now);return storage.get(s,id);});
 const summary={syntheticData:false,historicalSchemaSample:true,id,source:doc.official_url,verification:report.verification.status,type:report.attack_conditions.vulnerability_type,authentication:report.attack_conditions.authentication_required,requiredPrivileges:report.attack_conditions.required_privileges,attackSurface:report.attack_conditions.attack_surface,explicitConditions:report.attack_conditions.preconditions.length,projectRegistered:false,attackExecuted:false};await fs.writeFile(path.join(dir,'summary.json'),JSON.stringify(summary,null,2));console.log(JSON.stringify(summary,null,2));}
main().catch(e=>{console.error('Public API sample check failed: '+(e.code||'schema_failed'));process.exitCode=1;});
