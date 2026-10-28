'use strict';
const path=require('node:path');
const fs=require('node:fs/promises');
const crypto=require('node:crypto');
const core=require('./core');

class SecurityServiceError extends Error {constructor(code){super(code);this.code=code;}}
const reject=code=>{throw new SecurityServiceError(code);};
const ID=/^[a-zA-Z0-9_-]{1,80}$/;
function input(value,keys,required=[]) {
  if(!value||typeof value!=='object'||Array.isArray(value)||![Object.prototype,null].includes(Object.getPrototypeOf(value)))reject('invalid_parameters');
  if(Object.keys(value).some(k=>!keys.includes(k))||required.some(k=>!Object.hasOwn(value,k)))reject('invalid_parameters');
}
function integer(value,min,max) {if(!Number.isSafeInteger(value)||value<min||value>max)reject('invalid_parameters');return value;}
const clone=value=>JSON.parse(JSON.stringify(value));
function bounded(value,maxBytes) {if(Buffer.byteLength(JSON.stringify(value),'utf8')>maxBytes)reject('result_limit');return clone(value);}

/** Trusted host configuration only. Request payloads cannot change binaries,
 * output paths, caches or registered workspaces. This is not an MCP transport. */
async function createSecurityService({workspaces,scannerOptions={},maxResponseBytes=256*1024,maxReports=3,maxRetainedBytes=64*1024*1024,totalTimeoutMs}={}, engines={scan:core.scan,status:core.status}) {
  if(!Array.isArray(workspaces)||!workspaces.length)reject('invalid_workspace_configuration');
  integer(maxResponseBytes,256,1024*1024);integer(maxReports,1,10);integer(maxRetainedBytes,1024,128*1024*1024);
  const registered=new Map();
  for(const w of workspaces) {
    if(!w||!ID.test(w.id)||typeof w.root!=='string'||!path.isAbsolute(w.root)||/[\0\r\n]/.test(w.root)||registered.has(w.id))reject('invalid_workspace_configuration');
    try{const root=await fs.realpath(w.root);if(!(await fs.stat(root)).isDirectory())reject('invalid_workspace_configuration');registered.set(w.id,{requested:w.root,root});}
    catch{reject('invalid_workspace_configuration');}
  }
  const options={...scannerOptions,executables:{...scannerOptions.executables}};
  const scannerTimeout=options.timeout ?? 120000;
  integer(scannerTimeout,50,600000);
  const deadline=totalTimeoutMs ?? Math.min(600000,4*scannerTimeout+125000);
  integer(deadline,50,600000);
  const reports=new Map();let retainedBytes=0,busy=false;
  async function workspace(id) {
    if(typeof id!=='string'||!ID.test(id)||!registered.has(id))reject('workspace_not_allowed');
    const w=registered.get(id);
    try{if(await fs.realpath(w.requested)!==w.root||!(await fs.stat(w.root)).isDirectory())reject('workspace_changed');}
    catch{reject('workspace_changed');}
    return w.root;
  }
  function report(scanId) {
    if(typeof scanId!=='string'||!ID.test(scanId))reject('invalid_parameters');
    const r=reports.get(scanId);if(!r)reject('report_not_found');return r;
  }
  return Object.freeze({
    async scannerStatus(params={}, {signal}={}) {
      input(params,[]);
      const statuses=await engines.status(options.executables,signal);
      return bounded(statuses.map(s=>({scanner:s.scanner,status:s.status,reason:s.reason,version:s.version,areas:s.areas,install:s.install})),maxResponseBytes);
    },
    async inventoryWorkspace(params,{signal,previous}={}) {
      input(params,['workspaceId'],['workspaceId']);
      const root=await workspace(params.workspaceId);
      return require('./inventory').collectInventory(root,{signal,previous});
    },
    async workspaceIdentity(params) {
      input(params,['workspaceId'],['workspaceId']);
      return {project_id:require('./inventory/identity').projectId(await workspace(params.workspaceId))};
    },
    async scanWorkspace(params, {signal,onProgress}={}) {
      input(params,['workspaceId','timeoutMs'],['workspaceId']);
      const root=await workspace(params.workspaceId);
      const timeout=params.timeoutMs===undefined?scannerTimeout:Math.min(integer(params.timeoutMs,50,600000),scannerTimeout);
      if(busy)reject('scan_busy');busy=true;
      const controller=new AbortController();let expired=false;
      const cancel=()=>controller.abort();signal?.addEventListener('abort',cancel,{once:true});if(signal?.aborted)cancel();
      const timer=setTimeout(()=>{expired=true;controller.abort();},deadline);
      try {
        const result=await engines.scan(root,{...options,timeout,signal:controller.signal,onProgress});
        const bytes=Buffer.byteLength(JSON.stringify(result.report),'utf8');
        if(bytes>maxRetainedBytes)reject('report_limit');
        while(reports.size>=maxReports||retainedBytes+bytes>maxRetainedBytes){const key=reports.keys().next().value;retainedBytes-=reports.get(key).bytes;reports.delete(key);}
        const scanId=crypto.randomUUID();
        reports.set(scanId,{workspaceId:params.workspaceId,report:clone(result.report),bytes});retainedBytes+=bytes;
        // Full report is for local host APIs. A future MCP adapter must return the
        // bounded getReport()/getFindings() envelopes, never this local file path.
        return {...result,scanId,workspaceId:params.workspaceId,execution:{status:expired?'timeout':signal?.aborted?'cancelled':'completed',totalTimeoutMs:deadline}};
      } catch(e) {if(e instanceof SecurityServiceError)throw e;reject(expired?'scan_timeout':signal?.aborted?'scan_cancelled':'scan_failed');}
      finally{clearTimeout(timer);signal?.removeEventListener('abort',cancel);busy=false;}
    },
    getFindings(params) {
      input(params,['scanId','offset','limit'],['scanId']);
      const {workspaceId,report:r}=report(params.scanId),offset=integer(params.offset ?? 0,0,r.findings.length),limit=integer(params.limit ?? 50,1,100);
      const findings=r.findings.slice(offset,offset+limit);
      return bounded({scanId:params.scanId,workspaceId,schemaVersion:r.schemaVersion,modelVersion:r.modelVersion||'1.0',total:r.findings.length,offset,findings,nextOffset:offset+findings.length<r.findings.length?offset+findings.length:null},maxResponseBytes);
    },
    getReport(params) {
      input(params,['scanId','includeFindings'],['scanId']);
      if(params.includeFindings!==undefined&&typeof params.includeFindings!=='boolean')reject('invalid_parameters');
      const {workspaceId,report:r}=report(params.scanId),include=!!params.includeFindings;
      return bounded({scanId:params.scanId,workspaceId,totalFindings:r.findings.length,findingsIncluded:include,report:include?r:{...r,findings:[]}},maxResponseBytes);
    }
  });
}
module.exports={createSecurityService,SecurityServiceError};
