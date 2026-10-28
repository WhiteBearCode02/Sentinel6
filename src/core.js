'use strict';
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const {run, executable} = require('./process');
const {parse, merge, safePath} = require('./parsers');
const {withReportMetadata}=require('./report-model');
const definitions = {
  semgrep: {command:'semgrep', areas:['sast'], install:'https://semgrep.dev/docs/getting-started/'},
  osv: {command:'osv-scanner', areas:['dependencies'], install:'https://google.github.io/osv-scanner/installation/'},
  gitleaks: {command:'gitleaks', areas:['secrets'], install:'https://github.com/gitleaks/gitleaks#installing'},
  trivy: {command:'trivy', areas:['dependencies','secrets','misconfiguration'], install:'https://trivy.dev/docs/latest/getting-started/installation/'}
};
async function status(executables = {}, signal) {
  const results = [];
  for (const [id, d] of Object.entries(definitions)) {
    if (signal?.aborted) {results.push({scanner:id, status:'cancelled', areas:d.areas}); continue;}
    let file;
    try {file = await executable(d.command, executables[id]);} catch {results.push({scanner:id,status:'failed',reason:'invalid_executable',areas:d.areas}); continue;}
    if (!file) {results.push({scanner:id,status:'not_installed',areas:d.areas,install:d.install}); continue;}
    const probe = await run(file, ['--version'], {cwd:path.dirname(file),timeout:30000, signal, limit:1024*1024});
    // Do not propagate arbitrary version stdout to reports or UI.
    const version = probe.stdout?.match(/\b\d+\.\d+\.\d+\b/)?.[0];
    results.push({scanner:id, status:probe.status === 'cancelled' ? 'cancelled' : probe.status === 'completed' && probe.code === 0 && version ? 'available' : 'failed',
      reason:probe.status === 'failed' ? probe.reason : probe.status === 'completed' && (probe.code !== 0 || !version) ? 'version_check_failed' : undefined, version, executable:file, areas:d.areas, install:d.install});
  }
  return results;
}
const excluded = new Set(['.git','.tools','.cache','node_modules','.venv','venv','reports','.sentinel6','dist','build']);
const configs = new Set(['trivy.yaml','trivy.yml','trivy-secret.yaml','.gitleaks.toml','.gitleaksignore','osv-scanner.toml']);
async function readBounded(handle,maxBytes) {
  const chunks=[];let bytes=0;
  while(bytes<=maxBytes) {const buffer=Buffer.alloc(Math.min(65536,maxBytes+1-bytes));const r=await handle.read(buffer,0,buffer.length,null);if(!r.bytesRead)break;bytes+=r.bytesRead;chunks.push(buffer.subarray(0,r.bytesRead));}
  if(bytes>maxBytes)throw new Error('file_size_limit');
  return Buffer.concat(chunks,bytes);
}
async function snapshot(root, destination, signal) {
  let bytes = 0, files = 0; const skipped = {symlinks:0,largeFiles:0,excludedDirectories:0,scannerConfigs:0};
  async function copy(dir, target) {
    await fs.mkdir(target, {recursive:true, mode:0o700});
    for (const entry of await fs.readdir(dir, {withFileTypes:true})) {
      if (signal?.aborted) throw new Error('cancelled');
      const src = path.join(dir, entry.name), dest = path.join(target, entry.name);
      if (entry.isSymbolicLink()) {skipped.symlinks++; continue;}
      if (entry.isDirectory()) {if (excluded.has(entry.name)) skipped.excludedDirectories++; else await copy(src, dest);}
      else if (entry.isFile()) {
        if (configs.has(entry.name)) {skipped.scannerConfigs++; continue;}
        const h = await fs.open(src, require('node:fs').constants.O_RDONLY | (require('node:fs').constants.O_NOFOLLOW || 0));
        try {
          // Recheck real path after opening, reject symlink escapes and changed entries.
          safePath(root, await fs.realpath(src));
          const s = await h.stat();
          if (s.size > 5*1024*1024) {skipped.largeFiles++; continue;}
          let contents;
          try{contents=await readBounded(h,5*1024*1024);}catch(e){if(e.message!=='file_size_limit')throw e;skipped.largeFiles++;continue;}
          bytes += contents.length; files++;
          if (bytes > 100*1024*1024 || files > 20000) throw new Error('snapshot_limit');
          await fs.writeFile(dest, contents, {mode:0o600});
        } finally {await h.close();}
      }
    }
  }
  await copy(root, destination);
  return {files, bytes, skipped, exclusions:[...excluded], maxFileBytes:5*1024*1024};
}
function argsFor(id, target, work, cache) {
  const output = path.join(work, id + '.json');
  switch (id) {
    case 'semgrep': return ['scan','--oss-only','--jobs=1','--timeout=10','--max-memory=512','--no-rewrite-rule-ids','--config',path.join(work,'rules.yml'),'--json','--metrics=off','--disable-version-check','--no-git-ignore','--output',output,'.'];
    case 'osv': return ['scan','source','--recursive','--no-ignore','--format=json','--offline','--no-call-analysis=all','--no-resolve','--output-file',output,target];
    case 'gitleaks': return ['dir','--redact=100','--no-banner','--no-color','--report-format=json','--report-path',output,target];
    case 'trivy': return ['fs','--scanners','vuln,secret,misconfig','--format=json','--quiet','--offline-scan','--skip-db-update','--skip-java-db-update','--skip-check-update','--cache-dir',cache,'--output',output,target];
    default: throw new Error('Unknown scanner');
  }
}
async function saveReport(report, destination) {
  await fs.mkdir(destination, {recursive:true, mode:0o700});
  const file = path.join(destination, `sentinel6-${Date.now()}-${require('node:crypto').randomUUID()}.json`);
  await fs.writeFile(file, JSON.stringify(report,null,2), {mode:0o600, flag:'wx'});
  return file;
}
async function outsideProject(root, candidate) {
  const resolved=path.resolve(candidate);
  let ancestor=resolved;
  for (;;) {
    try {const real=await fs.realpath(ancestor);const final=path.resolve(real,path.relative(ancestor,resolved));
      const rel=path.relative(root,final);
      if (!rel || (!path.isAbsolute(rel) && rel !== '..' && !rel.startsWith('..'+path.sep))) throw new Error('storage_inside_project');
      return final;
    } catch(e) {if(e.code !== 'ENOENT') throw e;const parent=path.dirname(ancestor);if(parent === ancestor) throw e;ancestor=parent;}
  }
}
async function scan(root, options = {}) {
  root = await fs.realpath(root);
  if (!(await fs.stat(root)).isDirectory() || /[\0\r\n]/.test(root)) throw new Error('Invalid project directory');
  const timeout = options.timeout ?? 120000;
  if (!Number.isFinite(timeout) || timeout < 50 || timeout > 600000) throw new Error('Invalid timeout');
  for (const value of [options.cacheDir,options.osvCacheDir]) if (value !== undefined && (typeof value !== 'string' || !path.isAbsolute(value) || /[\0\r\n]/.test(value))) throw new Error('Invalid cache path');
  const reportDir = await outsideProject(root,options.reportDir || path.join(os.homedir(),'.sentinel6','reports'));
  const trivyCache = await outsideProject(root,options.cacheDir || path.join(os.homedir(),'.cache','trivy'));
  if (options.osvCacheDir) await outsideProject(root,options.osvCacheDir);
  await fs.mkdir(reportDir,{recursive:true,mode:0o700});
  const realReportDir = await outsideProject(root,await fs.realpath(reportDir));
  const installed = await status(options.executables,options.signal);
  // Windows Semgrep's Python/native bridge can stall on cross-volume targets.
  // Prefer external report storage, then a writable scanner directory on its volume.
  let tempBase = realReportDir;
  const semgrep = installed.find(s=>s.scanner === 'semgrep' && s.status === 'available');
  if (process.platform === 'win32' && semgrep && path.parse(semgrep.executable).root.toLowerCase() !== path.parse(tempBase).root.toLowerCase()) {
    const candidate = path.dirname(semgrep.executable);
    const relative = path.relative(root,candidate);
    if (relative && (relative === '..' || relative.startsWith('..'+path.sep) || path.isAbsolute(relative))) {
      try {await fs.access(candidate,require('node:fs').constants.W_OK);tempBase=candidate;} catch { /* report storage fallback; timeout remains enforced */ }
    }
  }
  const work = await fs.mkdtemp(path.join(tempBase,'sentinel6-'));
  const target = path.join(work,'project');
  const report = {schemaVersion:1, startedAt:new Date().toISOString(), mode:'offline', scanners:[], findings:[],
    limitations:['Current files only; Git history is excluded.','Semgrep uses three bundled baseline rules, not a complete security ruleset.','Offline vulnerability databases must be provisioned separately; missing or stale databases limit coverage.','Dependency findings navigate to the manifest/lockfile at line 1.','Ignored, oversized files and symlinks are not scanned.']};
  try {
    await fs.copyFile(path.resolve(__dirname,'../rules/semgrep.yml'),path.join(work,'rules.yml'));
    try {report.snapshot = await snapshot(root,target,options.signal);} catch (e) {
      report.scanners = installed.map(s => ({...s,executable:undefined,status:s.status === 'not_installed' ? s.status : options.signal?.aborted ? 'cancelled' : 'failed',reason:options.signal?.aborted ? 'cancelled' : 'snapshot_failed'}));
      return await finish();
    }
    for (const s of installed) {
      const entry = {...s, executable:undefined}; report.scanners.push(entry);
      if (s.status !== 'available') continue;
      if (options.signal?.aborted) {entry.status='cancelled';continue;}
      const started = Date.now();
      options.onProgress?.(s.scanner);
      const result = await run(s.executable,argsFor(s.scanner,target,work,trivyCache), {cwd:target,timeout,signal:options.signal,cacheDir:options.osvCacheDir});
      entry.durationMs = Date.now()-started;
      if (result.status !== 'completed') {entry.status=result.status;entry.reason=result.reason;continue;}
      const accepted = s.scanner === 'gitleaks' || s.scanner === 'osv' ? [0,1] : [0];
      if (!accepted.includes(result.code)) {entry.status='failed';entry.reason='scanner_exit';entry.exitCode=result.code;continue;}
      try {
        const file = path.join(work,s.scanner+'.json');
        const handle=await fs.open(file,'r');let raw;
        try{if((await handle.stat()).size>32*1024*1024)throw new Error('oversize');raw=await readBounded(handle,32*1024*1024);}finally{await handle.close();}
        const data = JSON.parse(raw.toString('utf8'));
        const findings = parse(s.scanner,data,target);
        if (result.code === 1 && !findings.length) throw new Error('inconsistent_exit');
        // Ensure every returned location refers to a copied file, not a fabricated path.
        for (const f of findings) if (!(await fs.stat(path.join(target,f.file))).isFile()) throw new Error('bad_location');
        report.findings.push(...findings); entry.findings=findings.length;
        entry.status=s.scanner === 'semgrep' && data.errors.length ? 'partial' : 'completed';
        if (entry.status === 'partial') entry.reason='scanner_reported_errors';
      } catch {entry.status='failed';entry.reason='invalid_result';}
    }
    return await finish();
  } finally {await fs.rm(work,{recursive:true,force:true});}
  async function finish() {
    report.findings = merge(report.findings);
    report.finishedAt = new Date().toISOString();
    report.coverage = Object.fromEntries(['sast','dependencies','secrets','misconfiguration'].map(area => {
      const entries = report.scanners.filter(s=>s.areas.includes(area));
      return [area,{completed:entries.filter(s=>s.status === 'completed').map(s=>s.scanner), uncompleted:entries.filter(s=>s.status !== 'completed').map(s=>({scanner:s.scanner,status:s.status,reason:s.reason}))}];
    }));
    Object.assign(report,withReportMetadata(report));
    const reportFile = await saveReport(report,realReportDir);
    return {report,reportFile};
  }
}
module.exports = {scan,status,snapshot,argsFor,definitions,saveReport,outsideProject,readBounded};
