'use strict';
const fs=require('node:fs/promises');
const path=require('node:path');
const crypto=require('node:crypto');
const assert=require('node:assert/strict');
const {spawn}=require('node:child_process');
const {comparableReport}=require('../test/scan-comparison');
async function main(){
 const root=path.resolve('.tools/vulnerable-live'),base=path.resolve('.tools'),dir=path.resolve('reports/shared-cli');
 const hash=async()=>{const out={};for(const file of await fs.readdir(root))out[file]=crypto.createHash('sha256').update(await fs.readFile(path.join(root,file))).digest('hex');return out;};
 const before=await hash();
 const env={...process.env,SENTINEL6_SEMGREP:path.join(base,'semgrep','Scripts','semgrep.exe'),SENTINEL6_OSV:path.join(base,'osv','osv-scanner.exe'),SENTINEL6_GITLEAKS:path.join(base,'gitleaks','gitleaks.exe'),SENTINEL6_TRIVY:path.join(base,'trivy','trivy.exe'),SENTINEL6_TRIVY_CACHE:path.resolve('.cache/trivy'),SENTINEL6_OSV_CACHE:path.resolve('.cache/osv')};
 const summary=await new Promise((resolve,reject)=>{
  const child=spawn(process.execPath,[path.resolve('scripts/scan.js'),root,dir],{env,windowsHide:true,shell:false,stdio:['ignore','pipe','pipe']});let output='',bytes=0;
  child.stdout.on('data',b=>{bytes+=b.length;if(bytes>1024*1024){child.kill();reject(new Error('CLI output limit'));}else output+=b.toString('utf8');});child.stderr.on('data',()=>{});child.on('error',reject);
  child.on('close',code=>{if(code!==0)return reject(new Error('CLI checks incomplete'));try{resolve(JSON.parse(output));}catch{reject(new Error('CLI returned invalid JSON'));}});
 });
 const report=JSON.parse(await fs.readFile(summary.reportFile,'utf8'));
 assert.equal(report.modelVersion,'1.1');assert.equal(report.schemaVersion,1);assert.ok(report.scanners.every(s=>s.status==='completed'));assert.deepEqual(await hash(),before);
 const prior=JSON.parse(await fs.readFile('reports/live-summary.json','utf8')),direct=JSON.parse(await fs.readFile(prior.reportFile,'utf8'));
 assert.deepEqual(comparableReport(report),comparableReport(direct),'CLI must preserve the direct engine result');
 await fs.writeFile('reports/shared-core-cli.json',JSON.stringify({schemaVersion:1,report,sourceUnchanged:true,directEngineConsistent:true},null,2));
 console.log(JSON.stringify({findings:report.findings.length,modelVersion:report.modelVersion,sourceUnchanged:true,directEngineConsistent:true,reportFile:summary.reportFile},null,2));
}
main().catch(()=>{console.error('Shared CLI verification failed; no scanner raw output was logged.');process.exitCode=1;});
