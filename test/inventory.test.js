const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs/promises');
const path=require('node:path');
const os=require('node:os');
const {collectInventory}=require('../src/inventory');
async function fixture(files,fn){const d=await fs.mkdtemp(path.join(os.tmpdir(),'s6-inventory-'));try{for(const [file,text]of Object.entries(files)){await fs.mkdir(path.dirname(path.join(d,file)),{recursive:true});await fs.writeFile(path.join(d,file),typeof text==='string'?text:JSON.stringify(text,null,2));}return await fn(d);}finally{await fs.rm(d,{recursive:true,force:true});}}
for(const v of [2,3])test('npm lockfile '+v+' extracts exact direct and nested transitive versions',()=>fixture({'package.json':{dependencies:{alpha:'^1.0.0'}},'package-lock.json':{lockfileVersion:v,packages:{'':{dependencies:{alpha:'^1.0.0'}},'node_modules/alpha':{version:'1.2.3',resolved:'https://private:secret@example.invalid/a'},'node_modules/alpha/node_modules/beta':{version:'2.3.4'}}}},async root=>{
 const i=await collectInventory(root);const [a,b]=i.dependencies;assert.equal(a.package_name,'alpha');assert.equal(a.version,'1.2.3');assert.equal(a.direct_or_transitive,'direct');assert.equal(b.package_name,'beta');assert.equal(b.direct_or_transitive,'transitive');assert.ok(a.line>1);assert.ok(!JSON.stringify(i).includes('private:secret'));assert.equal(a.purl,'pkg:npm/alpha@1.2.3');
}));
test('manifest exact pins are declared evidence and ranges/URLs never become guessed versions',()=>fixture({'package.json':{dependencies:{alpha:'1.2.3',beta:'^2.0.0',gamma:'https://user:private@example.invalid/pkg'}}},async root=>{
 const i=await collectInventory(root);assert.equal(i.dependencies[0].version_confidence,'DECLARED_EXACT');assert.equal(i.dependencies[1].version,null);assert.equal(i.dependencies[2].version,null);assert.ok(!JSON.stringify(i).includes('private@example'));
}));
test('PyPI pins normalize names and PEP 440 while markers, ranges and VCS remain unknown',()=>fixture({'requirements.txt':'Django_App==1.0rc1\nrequests>=2\nconditional==1.2; python_version < "3"\nvcs_pkg @ git+https://user:private@example.invalid/x\n'},async root=>{
 const i=await collectInventory(root);assert.equal(i.dependencies[0].normalized_name,'django-app');assert.equal(i.dependencies[0].version,'1.0rc1');assert.ok(i.dependencies.slice(1).every(d=>d.version===null));assert.ok(!JSON.stringify(i).includes('private@example'));assert.equal(i.dependencies[0].direct_or_transitive,'unknown');
}));
test('safe requirements includes work but constraints do not invent resolved dependency versions',()=>fixture({'requirements.txt':'-r nested/pins.txt\n-c constraints.txt\nalpha==1.2\n','nested/pins.txt':'beta==2.0\n','constraints.txt':'alpha>=3.0\n'},async root=>{
 const i=await collectInventory(root);assert.ok(i.dependencies.some(d=>d.package_name==='beta'&&d.source_file==='nested/pins.txt'));assert.equal(i.dependencies.find(d=>d.package_name==='alpha').version,null);assert.ok(i.coverage.issues.some(x=>x.reason==='constraints_not_resolved'));
}));
test('malformed locks and unsupported managers have explicit partial coverage',()=>fixture({'package.json':{dependencies:{alpha:'^1.0'}},'package-lock.json':'{bad','yarn.lock':'private-code'},async root=>{
 const i=await collectInventory(root);assert.equal(i.coverage.status,'partial');assert.equal(i.dependencies[0].version,null);assert.ok(i.coverage.issues.some(x=>x.reason==='invalid_json'));assert.ok(i.coverage.issues.some(x=>x.reason==='unsupported_dependency_format'));
}));
test('requirements traversal and symlinks cannot read external files',()=>fixture({'requirements.txt':'-r ../outside.txt\n-r linked/requirements.txt\n'},async root=>{
 await fs.symlink(root,path.join(root,'linked'),'junction');const i=await collectInventory(root);assert.equal(i.dependencies.length,0);assert.ok(i.coverage.issues.some(x=>/include|symlink/.test(x.reason)));
}));
test('cache reuse checks current content and dependency changes invalidate it without modifying source',()=>fixture({'requirements.txt':'alpha==1.0\n'},async root=>{
 const first=await collectInventory(root),second=await collectInventory(root,{previous:first});assert.equal(second.cache_reused,true);await fs.writeFile(path.join(root,'requirements.txt'),'alpha==2.0\n');const third=await collectInventory(root,{previous:second});assert.equal(third.cache_reused,false);assert.equal(third.dependencies[0].version,'2.0');assert.equal(await fs.readFile(path.join(root,'requirements.txt'),'utf8'),'alpha==2.0\n');
}));
test('pre-cancelled inventory is rejected and no install or project script is executed',()=>fixture({'package.json':{scripts:{install:'never execute'},dependencies:{alpha:'1.0.0'}}},async root=>{
 const c=new AbortController();c.abort();await assert.rejects(collectInventory(root,{signal:c.signal}),e=>e.code==='cancelled');assert.equal((await collectInventory(root)).dependencies.length,1);
}));
test('stale locks, missing dependencies and unresolved aliases do not assert exact versions',()=>fixture({'package.json':{dependencies:{alpha:'^2.0.0',missing:'3.0.0'}},'package-lock.json':{lockfileVersion:3,packages:{'':{dependencies:{alpha:'^1.0.0'}},'node_modules/alpha':{version:'1.0.0'},'node_modules/alias':{name:'actual-package',version:'1.0.0'}}}},async root=>{
 const i=await collectInventory(root);assert.ok(i.dependencies.every(d=>d.version===null));assert.ok(i.dependencies.some(d=>d.limitations.includes('direct_dependency_missing_from_lock')));assert.ok(i.dependencies.some(d=>d.limitations.includes('manifest_lock_consistency_not_confirmed')));
}));
test('requirements include cycles are bounded and marker/hash lines do not leak original content',()=>fixture({'requirements.txt':'-r nested/pins.txt\nalpha==1.0 --hash=sha256:private-hash\n','nested/pins.txt':'-r ../requirements.txt\nbeta==2.0; sys_platform == "win32"\n'},async root=>{
 const i=await collectInventory(root);assert.ok(i.coverage.issues.some(x=>x.reason==='requirements_include_cycle'));assert.equal(i.dependencies.find(d=>d.package_name==='alpha').version,'1.0');assert.equal(i.dependencies.find(d=>d.package_name==='beta').version,null);assert.ok(!JSON.stringify(i).includes('private-hash'));
}));
test('no supported dependency file is explicitly partial coverage',()=>fixture({'app.py':'# inert source'},async root=>{
 const i=await collectInventory(root);assert.equal(i.coverage.status,'partial');assert.ok(i.coverage.issues.some(x=>x.reason==='no_supported_dependency_files'));
}));
test('compact constraint option and invalid lock dependency maps stay conservative',()=>fixture({'requirements.txt':'-cconstraints.txt\nalpha==1.0\n','package-lock.json':{lockfileVersion:3,packages:{'':{dependencies:'invalid-map'},'node_modules/beta':{version:'1.0.0'}}}},async root=>{
 const i=await collectInventory(root);assert.equal(i.dependencies.find(d=>d.package_name==='alpha').version,null);assert.ok(i.coverage.issues.some(x=>x.reason==='invalid_dependency_map'));assert.equal(i.dependencies.filter(d=>d.ecosystem==='npm').length,1);
}));
