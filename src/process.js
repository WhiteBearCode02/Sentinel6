'use strict';
const {spawn} = require('node:child_process');
const path = require('node:path');
const fs = require('node:fs/promises');

async function executable(name, configured) {
  if (configured && (!path.isAbsolute(configured) || /[\r\n\0]/.test(configured))) throw new Error('Invalid executable path');
  const candidates = configured ? [configured] : (process.env.PATH || '').split(path.delimiter)
    .filter(Boolean).map(p => path.join(p.replace(/^"|"$/g, ''), name + (process.platform === 'win32' ? '.exe' : '')));
  for (const candidate of candidates) {
    if (/\.(cmd|bat|ps1)$/i.test(candidate)) continue;
    try { const s = await fs.stat(candidate); if (s.isFile()) { await fs.access(candidate, process.platform === 'win32' ? 0 : 1); return await fs.realpath(candidate); } } catch { /* not installed */ }
  }
  return null;
}
function run(file, args, {cwd, signal, timeout = 120000, limit = 32 * 1024 * 1024, cacheDir} = {}) {
  if (!path.isAbsolute(file) || args.some(a => typeof a !== 'string' || /[\0\r\n]/.test(a))) return Promise.resolve({status: 'failed', reason: 'invalid_arguments'});
  if (signal?.aborted) return Promise.resolve({status: 'cancelled'});
  return new Promise(resolve => {
    // Do not inherit scanner tokens, proxy credentials or project-controlled options.
    const env = {};
    for (const k of ['PATH','SystemRoot','WINDIR','HOME','USERPROFILE','TEMP','TMP','LOCALAPPDATA']) if (process.env[k]) env[k] = process.env[k];
    Object.assign(env, {SEMGREP_SEND_METRICS: 'off', SEMGREP_ENABLE_VERSION_CHECK: '0'});
    if (cacheDir) env.OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY = cacheDir;
    const child = spawn(file, args, {cwd, env, shell: false, windowsHide: true, detached: process.platform !== 'win32', stdio: ['ignore','pipe','pipe']});
    let output = [], size = 0, reason;
    const stop = why => {
      if (reason) return;
      reason = why;
      if (process.platform === 'win32' && child.pid) {
        const killer = spawn(path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'taskkill.exe'), ['/pid', String(child.pid), '/T', '/F'], {windowsHide: true, stdio: 'ignore', shell: false});
        killer.on('error', () => child.kill());
        killer.on('close', () => {if (child.exitCode === null) child.kill();});
      } else { try { process.kill(-child.pid, 'SIGKILL'); } catch { child.kill('SIGKILL'); } }
    };
    const timer = setTimeout(() => stop('timeout'), timeout);
    const abort = () => stop('cancelled');
    signal?.addEventListener('abort', abort, {once: true});
    if (signal?.aborted) abort();
    child.stdout.on('data', b => {size += b.length; if (size > limit) stop('output_limit'); else output.push(b);});
    // Drain but never retain or publish stderr: it can contain source and secrets.
    child.stderr.on('data', () => {});
    let settled = false;
    const finish = result => {if (settled) return; settled = true; clearTimeout(timer); signal?.removeEventListener('abort', abort); resolve(result);};
    child.on('error', () => finish({status: 'failed', reason: 'launch_failed'}));
    child.on('close', code => finish(reason ? {status: reason === 'cancelled' ? 'cancelled' : 'failed', reason} : {status: 'completed', code, stdout: Buffer.concat(output).toString('utf8')}));
  });
}
module.exports = {run, executable};
