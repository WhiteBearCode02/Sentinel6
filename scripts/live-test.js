'use strict';
const fs=require('node:fs/promises');
const path=require('node:path');
const crypto=require('node:crypto');
const assert=require('node:assert/strict');
const {scan}=require('../src/core');
async function main(){
 const base=path.resolve('.tools'),project=path.join(base,'vulnerable-live');
 await fs.mkdir(project,{recursive:true});
 await fs.cp(path.resolve('fixtures/vulnerable'),project,{recursive:true});
 // Deliberately fake, random token with valid scanner syntax; never use a real key.
 const secret='ghp_'+crypto.randomBytes(30).toString('hex').slice(0,36);
 await fs.writeFile(path.join(project,'credentials.txt'),'github_token = "'+secret+'"\n');
 async function hashes(){const out={};for(const name of await fs.readdir(project)) out[name]=crypto.createHash('sha256').update(await fs.readFile(path.join(project,name))).digest('hex');return out;}
 const before=await hashes();
 const executables={semgrep:path.join(base,'semgrep','Scripts','semgrep.exe'),osv:path.join(base,'osv','osv-scanner.exe'),gitleaks:path.join(base,'gitleaks','gitleaks.exe'),trivy:path.join(base,'trivy','trivy.exe')};
 const {report,reportFile}=await scan(project,{executables,reportDir:path.resolve('reports/live'),cacheDir:path.resolve('.cache/trivy'),osvCacheDir:path.resolve('.cache/osv'),timeout:120000,onProgress:id=>console.log('Running '+id)});
 assert.deepEqual(await hashes(),before,'Source files changed');
 assert.ok(!JSON.stringify(report).includes(secret),'Secret escaped redaction');
 const summary={sourceUnchanged:true,secretOmitted:true,scanners:report.scanners,coverage:report.coverage,findings:report.findings.length,byKind:Object.fromEntries(['sast','dependency','secret','misconfiguration'].map(k=>[k,report.findings.filter(f=>f.kind===k).length])),reportFile};
 console.log(JSON.stringify(summary,null,2));
 await fs.writeFile(path.resolve('reports/live-summary.json'),JSON.stringify(summary,null,2));
 if(report.scanners.some(s=>s.status!=='completed')) process.exitCode=2;
 for(const id of Object.keys(executables)) {
  const s=report.scanners.find(s=>s.scanner===id);
  if(s.status==='completed') assert.ok(s.findings>0,`${id} detected nothing in vulnerable fixture`);
 }
}
main().catch(()=>{console.error('Live verification failed. No raw scanner output published.');process.exitCode=1;});
