'use strict';
// Test-only synthetic advisories and inert dependency files; never used by the extension.
const fs=require('node:fs/promises');
const path=require('node:path');
const {withStore,resetStore}=require('../src/threat/store');
const model=require('../src/threat/model');
const f=require('../test/threat-fixtures');
async function main(){
 const root=path.resolve(__dirname,'..'),project=path.join(root,'.tools','impact-fixture');
 const file=path.join(root,'.tools','vscode-impact-integration','User','globalStorage','sentinel6-local.sentinel6','threat-intelligence.sqlite');
 await fs.mkdir(project,{recursive:true});
 await fs.writeFile(path.join(project,'package.json'),JSON.stringify({private:true,dependencies:{'fixture-package':'*','fixture-fixed':'*','fixture-unknown':'^1.0.0'}},null,2));
 await fs.writeFile(path.join(project,'package-lock.json'),JSON.stringify({lockfileVersion:3,packages:{'':{dependencies:{'fixture-package':'*','fixture-fixed':'*','fixture-unknown':'^1.0.0'}},'node_modules/fixture-package':{version:'1.0.0'},'node_modules/fixture-fixed':{version:'2.0.0'},'node_modules/fixture-unknown':{version:'^1.0.0'}}},null,2));
 await fs.writeFile(path.join(project,'requirements.txt'),'fixture_python==1.0rc1\n');
 await resetStore(file);
 const definitions=[['fixture-package','npm',f.cve,f.ghsa],['fixture-fixed','npm','CVE-2099-99990002','GHSA-2345-6789-cfgj'],['fixture-unknown','npm','CVE-2099-99990003','GHSA-2345-6789-cfgm'],['fixture-python','pip','CVE-2099-99990004','GHSA-2345-6789-cfgq']];
 await withStore(file,async s=>{
  for(const [name,ecosystem,cve,ghsa]of definitions)s.ingest(model.github([f.gh({ghsa_id:ghsa,cve_id:cve,identifiers:[{type:'CVE',value:cve},{type:'GHSA',value:ghsa}],summary:'SYNTHETIC TEST FIXTURE - '+name,vulnerabilities:[{package:{ecosystem,name},vulnerable_version_range:ecosystem==='pip'?'>=1.0.dev1, <2.0':'<2.0.0',first_patched_version:ecosystem==='pip'?'2.0':'2.0.0'}]})])[0],f.now);
  s.setState('github',{status:'test_fixture',last_success:f.now,error:null});
 });
 console.log('Synthetic TI-2 fixture prepared; no dependency installed or vulnerability code executed.');
}
main().catch(()=>{console.error('Impact test preparation failed.');process.exitCode=1;});
