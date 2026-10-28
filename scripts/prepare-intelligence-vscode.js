'use strict';
// Synthetic test data only, in a dedicated extension profile. No project code is executed.
const fs=require('node:fs/promises'),path=require('node:path');
const {withStore,resetStore}=require('../src/threat/store'),model=require('../src/threat/model'),adapters=require('../src/intelligence/adapters'),storage=require('../src/intelligence/storage'),f=require('../test/intelligence-fixtures');
async function main(){
 const root=path.resolve(__dirname,'..'),project=path.join(root,'.tools/ti3-fixture'),file=path.join(root,'.tools/vscode-ti3-integration/User/globalStorage/sentinel6-local.sentinel6/threat-intelligence.sqlite');await fs.mkdir(project,{recursive:true});
 await fs.writeFile(path.join(project,'package.json'),JSON.stringify({private:true,dependencies:{'fixture-package':'*'}},null,2));await fs.writeFile(path.join(project,'package-lock.json'),JSON.stringify({lockfileVersion:3,packages:{'':{dependencies:{'fixture-package':'*'}},'node_modules/fixture-package':{version:'1.0.0'}}},null,2));await fs.writeFile(path.join(project,'.npmrc'),'ignore-scripts=false\n//registry.invalid/:_authToken=NEVER_COPY_TEST_TOKEN\n');
 await resetStore(file);await withStore(file,async s=>{s.ingest(model.github([f.gh()])[0],f.now);storage.ingest(s,adapters.redhat(JSON.stringify(f.vendor()),f.cve,f.now),f.now);for(const d of adapters.rss(f.rss(),f.now))storage.ingest(s,d,f.now);s.setState('redhat',{status:'test_fixture',last_success:f.now});s.setState('talos',{status:'test_fixture',last_success:f.now});});
 console.log('Synthetic TI-3 metadata fixture prepared in isolated profile.');
}
main().catch(()=>{console.error('TI-3 fixture preparation failed');process.exitCode=1;});
