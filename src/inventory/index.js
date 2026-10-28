'use strict';
const fs=require('node:fs/promises');
const constants=require('node:fs').constants;
const path=require('node:path');
const {readBounded}=require('../core');
const {safePath}=require('../parsers');
const {normalizeName,exactVersion,hash,projectId,purl,credential}=require('./identity');
const ignored=new Set(['.git','.tools','.cache','node_modules','.venv','venv','dist','build','reports','.sentinel6']);
const unsupported=new Set(['pnpm-lock.yaml','yarn.lock','poetry.lock','uv.lock','Pipfile.lock','pom.xml','build.gradle','build.gradle.kts']);
class InventoryError extends Error {constructor(code){super(code);this.code=code;}}
const cancelled=signal=>{if(signal?.aborted)throw new InventoryError('cancelled');};
async function collectInventory(root,{signal,previous,now=new Date().toISOString()}={}) {
  root=await fs.realpath(root);const id=projectId(root),files=new Map(),issues=[];let total=0,dirs=0,entries=0,issueCount=0;
  const issue=(file,reason)=>{issueCount++;if(issues.length<1000)issues.push({source_file:file,reason});else if(issues.length===1000)issues.push({source_file:'',reason:'additional_inventory_issues_omitted'});};
  async function load(relative) {
    cancelled(signal);safePath(root,relative);
    if(files.has(relative))return files.get(relative);
    if(files.size>=200)throw new InventoryError('inventory_file_limit');
    const full=path.join(root,relative),parts=relative.split('/');let at=root;
    for(const part of parts){at=path.join(at,part);const s=await fs.lstat(at);if(s.isSymbolicLink())throw new InventoryError('symlink_not_allowed');}
    safePath(root,await fs.realpath(full));const h=await fs.open(full,constants.O_RDONLY|(constants.O_NOFOLLOW||0));
    try{
      const s=await h.stat();if(!s.isFile()||s.size>2*1024*1024)throw new InventoryError('inventory_file_limit');
      const bytes=await readBounded(h,2*1024*1024);total+=bytes.length;if(total>20*1024*1024)throw new InventoryError('inventory_size_limit');
      const value={text:bytes.toString('utf8'),hash:hash(bytes),source_file:relative};files.set(relative,value);return value;
    }finally{await h.close();}
  }
  async function walk(dir,depth=0) {
    cancelled(signal);if(++dirs>2000)throw new InventoryError('inventory_directory_limit');
    for await(const e of await fs.opendir(path.join(root,dir))){
      cancelled(signal);if(++entries>20000)throw new InventoryError('inventory_entry_limit');const relative=[dir,e.name].filter(Boolean).join('/');
      if(credential(relative)||/[\0\r\n]/.test(relative)){issue('[redacted-path]','unsafe_path_omitted');continue;}
      if(e.isSymbolicLink()){issue(relative,'symlink_not_analyzed');continue;}
      if(e.isDirectory()&&!ignored.has(e.name)){if(depth<4)await walk(relative,depth+1);else issue(relative,'depth_limit');}
      else if(e.isFile()&&['package.json','package-lock.json','requirements.txt'].includes(e.name)){
        try{await load(relative);}catch(error){issue(relative,error.code||'file_unavailable');}
      }else if(e.isFile()&&unsupported.has(e.name))issue(relative,'unsupported_dependency_format');
    }
  }
  await walk('');
  if(!files.size)issue('', 'no_supported_dependency_files');
  // Discover safe requirements includes even when their name is not requirements.txt.
  const visiting=new Set(),requirements=new Map();let unresolvedConstraints=false;
  async function req(file) {
    if(visiting.has(file)){issue(file,'requirements_include_cycle');return;}if(requirements.has(file))return;
    visiting.add(file);const entry=await load(file);const rows=[];requirements.set(file,rows);let constraints=false;
    for(const [index,raw] of entry.text.split(/\r?\n/).entries()){
      cancelled(signal);let line=raw.trim();if(!line||line.startsWith('#')||line.startsWith('--hash='))continue;
      const include=line.match(/^(?:-r\s*|--requirement(?:=|\s+))([^\s]+)\s*(?:#.*)?$/);
      if(include){
        try{const target=include[1];if(path.isAbsolute(target)||/[:\0\r\n]/.test(target))throw new InventoryError('include_outside_workspace');
          if(!/\.(?:txt|in)$/i.test(target))throw new InventoryError('unsupported_include_format');
          const relative=safePath(root,path.resolve(root,path.dirname(file),target));await req(relative);
        }catch(error){issue(file,error.code||'unsafe_requirements_include');}continue;
      }
      if(/^(?:-c(?!-)|--constraint(?:=|\s|$))/.test(line)){constraints=true;unresolvedConstraints=true;issue(file,'constraints_not_resolved');continue;}
      if(line.startsWith('-')){issue(file,'requirements_option_not_analyzed');continue;}
      line=line.replace(/\s+#.*$/,'').replace(/\s+--hash=.*$/,'').replace(/\s*\\$/,'');
      const m=line.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[A-Za-z0-9_,.-]+\])?\s*(.*)$/);if(!m){issue(file,'unsupported_requirement');continue;}
      const limitations=[];const condition=m[3].includes(';');const pin=m[3].match(/^==\s*([^\s;,*]+)\s*$/);
      let version=pin?exactVersion('PyPI',pin[1]):null;
      if(condition){version=null;limitations.push('environment_marker_not_evaluated');}
      if(/@|git\+|https?:/i.test(m[3])){version=null;limitations.push('vcs_or_url_not_resolved');}
      if(m[2])limitations.push('extras_not_resolved');
      if(!version)limitations.push('exact_version_not_available');
      rows.push({ecosystem:'PyPI',name:m[1],version,source_file:file,line:index+1,dependency_type:'requirements',direct_or_transitive:'unknown',limitations});
    }
    if(constraints)for(const row of rows){row.version=null;row.limitations.push('constraints_not_resolved');}
    visiting.delete(file);
  }
  for(const file of [...files.keys()].filter(f=>path.basename(f)==='requirements.txt'))try{await req(file);}catch(error){issue(file,error.code||'requirements_unavailable');}
  if(unresolvedConstraints)for(const rows of requirements.values())for(const row of rows){row.version=null;row.limitations.push('constraints_not_resolved');}
  const fingerprint=hash(JSON.stringify({parser_version:1,files:[...files.values()].map(f=>[f.source_file,f.hash]).sort(),issues,issue_count:issueCount}));
  if(previous?.project_id===id&&previous.fingerprint===fingerprint)return {...previous,cache_reused:true,checked_at:now};
  const dependencies=[];
  function add(row){const name=normalizeName(row.ecosystem,row.name);if(!name){issue(row.source_file,'invalid_package_identifier');return;}
    dependencies.push({...row,id:hash([row.source_file,row.locator||row.line,row.ecosystem,name,row.dependency_type].join('|')).slice(0,24),project_id:id,package_name:name,normalized_name:name,purl:purl(row.ecosystem,name,row.version),version_confidence:row.version?(row.locked?'LOCKFILE_EXACT':'DECLARED_EXACT'):'UNKNOWN',inventory_timestamp:now,limitations:[...new Set(['installation_not_verified',...row.limitations])]});delete dependencies.at(-1).name;delete dependencies.at(-1).locked;
    if(dependencies.length>10000)throw new InventoryError('dependency_limit');
  }
  const json=(entry)=>{try{const d=JSON.parse(entry.text);if(!d||typeof d!=='object'||Array.isArray(d))throw new Error();return d;}catch{issue(entry.source_file,'invalid_json');return null;}};
  for(const entry of files.values()){
    if(path.basename(entry.source_file)!=='package.json')continue;
    const manifest=json(entry);if(!manifest)continue;const lockFile=path.posix.join(path.posix.dirname(entry.source_file),'package-lock.json').replace(/^\.\//,'');
    // A supported lock is authoritative for resolved direct/transitive versions.
    const lock=files.has(lockFile)?json(files.get(lockFile)):null;
    if(lock&&[2,3].includes(lock.lockfileVersion)&&lock.packages&&typeof lock.packages==='object'&&!Array.isArray(lock.packages))continue;
    for(const type of ['dependencies','devDependencies','optionalDependencies','peerDependencies']){
      const deps=manifest[type];if(deps===undefined)continue;if(!deps||typeof deps!=='object'||Array.isArray(deps)){issue(entry.source_file,'invalid_dependency_map');continue;}
      for(const [name,spec] of Object.entries(deps)){const version=exactVersion('npm',spec);add({ecosystem:'npm',name,version,source_file:entry.source_file,line:1,locator:type+':'+name,dependency_type:type,direct_or_transitive:'direct',limitations:version?['manifest_pin_not_resolved']:['exact_version_not_available']});}
    }
  }
  for(const entry of files.values()){
    if(path.basename(entry.source_file)!=='package-lock.json')continue;const lock=json(entry);if(!lock)continue;
    if(![2,3].includes(lock.lockfileVersion)||!lock.packages||typeof lock.packages!=='object'||Array.isArray(lock.packages)){issue(entry.source_file,'unsupported_or_invalid_lockfile');continue;}
    const rootPackage=lock.packages['']||{},direct=new Map(),specs=new Map();
    const manifestEntry=files.get(path.posix.join(path.posix.dirname(entry.source_file),'package.json').replace(/^\.\//,''));
    const manifest=manifestEntry?json(manifestEntry):null;
    for(const type of ['dependencies','devDependencies','optionalDependencies','peerDependencies']){
      const deps=rootPackage[type];if(deps===undefined)continue;if(!deps||typeof deps!=='object'||Array.isArray(deps)){issue(entry.source_file,'invalid_dependency_map');continue;}
      for(const name of Object.keys(deps))direct.set(name,type);
    }
    for(const type of ['dependencies','devDependencies','optionalDependencies','peerDependencies'])if(manifest?.[type]&&typeof manifest[type]==='object'&&!Array.isArray(manifest[type]))for(const [name,spec]of Object.entries(manifest[type])){direct.set(name,type);specs.set(name,spec);}
    const lines=new Map();entry.text.split(/\r?\n/).forEach((s,i)=>{const m=s.match(/^\s*("(?:[^"\\]|\\.)*")\s*:\s*\{/);if(m)try{lines.set(JSON.parse(m[1]),i+1);}catch{/* JSON already validated */}});
    const present=new Set();
    for(const [location,value] of Object.entries(lock.packages)){
      if(!location)continue;if(!value||typeof value!=='object'||!location.includes('node_modules/')){issue(entry.source_file,'workspace_or_invalid_lock_entry');continue;}
      const name=location.slice(location.lastIndexOf('node_modules/')+13),isDirect=location==='node_modules/'+name&&direct.has(name);if(isDirect)present.add(name);
      const limits=[];let version=value.link?null:exactVersion('npm',value.version);
      if(value.name&&value.name!==name){version=null;limits.push('package_alias_not_resolved');}
      if(isDirect&&specs.has(name)){
        const semver=require('semver'),spec=specs.get(name),range=typeof spec==='string'&&spec.length<=256?semver.validRange(spec):null;
        if(!range||version&&!semver.satisfies(version,range,{includePrerelease:true})){version=null;limits.push('manifest_lock_consistency_not_confirmed');}
      }
      if(value.link)limits.push('workspace_link_not_resolved');if(!version)limits.push('exact_version_not_available');
      add({ecosystem:'npm',name,version,source_file:entry.source_file,line:lines.get(location)||1,locator:location,locked:true,dependency_type:isDirect?direct.get(name):value.dev?'devDependencies':'dependencies',direct_or_transitive:isDirect?'direct':'transitive',limitations:limits});
    }
    for(const [name,type] of direct)if(!present.has(name))add({ecosystem:'npm',name,version:null,source_file:entry.source_file,line:1,locator:'unresolved:'+name,dependency_type:type,direct_or_transitive:'direct',limitations:['direct_dependency_missing_from_lock','exact_version_not_available']});
  }
  for(const rows of requirements.values())for(const row of rows)add(row);
  return {schemaVersion:1,project_id:id,inventory_timestamp:now,checked_at:now,fingerprint,cache_reused:false,dependencies,files:[...files.values()].map(({source_file,hash})=>({source_file,hash})),coverage:{ecosystems:['npm','PyPI'],status:issues.length?'partial':'completed',issues},limitations:['Declared/locked versions only; installed packages and runtime environment are not verified.','Other dependency managers and unresolved conditions are not assumed safe.']};
}
module.exports={collectInventory,InventoryError};
