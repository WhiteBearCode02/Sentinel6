'use strict';
const https = require('node:https');
const dns = require('node:dns');
const net = require('node:net');
const {setTimeout: sleep} = require('node:timers/promises');

class CollectionError extends Error {
  constructor(code, retryAt) { super(code); this.code=code; this.retryAt=retryAt; }
}
const ECOSYSTEMS = ['npm','PyPI','Go','Maven'];
const CISA = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const CISA_MIRROR = 'https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json';
function validateUrl(value) {
  if (typeof value !== 'string' || value.length>2048 || /[\s\0-\x1f\\]/.test(value)) throw new CollectionError('blocked_url');
  let u; try {u=new URL(value);} catch {throw new CollectionError('blocked_url');}
  if (u.protocol!=='https:' || u.username || u.password || u.port || u.hash) throw new CollectionError('blocked_url');
  if (value===CISA || value===CISA_MIRROR) return u;
  if (u.hostname==='api.github.com' && u.pathname==='/advisories') {
    const keys=['type','modified','sort','direction','per_page','after','before'];
    if ([...u.searchParams.keys()].every(k=>keys.includes(k))) return u;
  }
  if (u.hostname==='osv-vulnerabilities.storage.googleapis.com' && !u.search && ECOSYSTEMS.some(e=>u.pathname===`/${e}/modified_id.csv`)) return u;
  if (u.hostname==='api.osv.dev' && !u.search && /^\/v1\/vulns\/[A-Za-z0-9_-]{1,150}$/.test(u.pathname)) return u;
  throw new CollectionError('blocked_url');
}
function publicAddress(address) {
  if (net.isIP(address)===4) {
    const [a,b,c]=address.split('.').map(Number);
    return !(a===0 || a===10 || a===127 || a===169&&b===254 || a===172&&b>=16&&b<=31 || a===192&&(b===168 || b===0 || b===2) || a===100&&b>=64&&b<=127 || a===198&&(b===18 || b===19 || b===51&&c===100) || a===203&&b===0&&c===113 || a>=224);
  }
  return net.isIP(address)===6 && /^[23][0-9a-f]{0,3}:/i.test(address) && !/^2001:db8:/i.test(address);
}
function lookupPublic(host, options, callback) {
  dns.lookup(host,{all:true,verbatim:true},(error,results)=>{
    if(error) return callback(new CollectionError('dns_failed'));
    if(!results.length || results.some(r=>!publicAddress(r.address))) return callback(new CollectionError('blocked_address'));
    const chosen=results[0];
    callback(null,options?.all ? [chosen] : chosen.address,chosen.family);
  });
}
function transport(value,{headers={},signal,timeout=15000,maxBytes=16*1024*1024,indexSince}={}) {
  const url=validateUrl(value);
  return new Promise((resolve,reject)=>{
    let finished=false;
    const done=(error,result)=>{if(finished)return;finished=true;clearTimeout(timer);signal?.removeEventListener('abort',abort);error ? reject(error) : resolve(result);};
    const req=https.request(url,{method:'GET',headers,lookup:lookupPublic,agent:false},res=>{
      const status=res.statusCode;
      if(status>=300 && status!==304) {res.resume();done(null,{status,headers:res.headers,text:''});return;}
      if (!indexSince && Number(res.headers['content-length'])>maxBytes || res.headers['content-encoding'] && res.headers['content-encoding']!=='identity') {req.destroy();done(new CollectionError('response_limit'));return;}
      let bytes=0,csvText='',checked=0;const chunks=[];
      res.on('data',b=>{
        bytes+=b.length;if(bytes>maxBytes){req.destroy();done(new CollectionError('response_limit'));return;}chunks.push(b);
        if(indexSince){
          csvText+=b.toString('utf8');let newline;
          while((newline=csvText.indexOf('\n',checked))>=0){
            const row=csvText.slice(checked,newline),comma=row.indexOf(','),date=comma>=0?Date.parse(row.slice(0,comma)):NaN;
            checked=newline+1;
            if(Number.isFinite(date)&&date<Date.parse(indexSince)){
              done(null,{status,headers:res.headers,text:csvText.slice(0,checked)});req.destroy();return;
            }
          }
        }
      });
      res.on('end',()=>done(null,{status,headers:res.headers,text:Buffer.concat(chunks).toString('utf8')}));
      res.on('error',()=>done(new CollectionError('network_failed')));
      res.on('aborted',()=>done(new CollectionError('network_failed')));
    });
    const abort=()=>{req.destroy();done(new CollectionError('cancelled'));};
    const timer=setTimeout(()=>{req.destroy();done(new CollectionError('timeout'));},timeout);
    req.on('error',e=>done(e instanceof CollectionError ? e : new CollectionError('network_failed')));
    signal?.addEventListener('abort',abort,{once:true});
    if(signal?.aborted) abort(); else req.end();
  });
}
function cleanHeader(value) {return typeof value==='string' && value.length<=512 && !/[\r\n\0]/.test(value) ? value : undefined;}
class HttpClient {
  constructor({send=transport,wait=sleep,now=Date.now,minInterval=1000}={}) {this.send=send;this.wait=wait;this.now=now;this.minInterval=minInterval;this.lastRequest=0;}
  async get(url,{cache,signal,indexSince}={}) {
    validateUrl(url);
    const headers={'User-Agent':'Sentinel6/0.3 (public threat metadata only)','Accept':'application/json','Accept-Encoding':'identity'};
    if(new URL(url).hostname==='api.github.com') {headers.Accept='application/vnd.github+json';headers['X-GitHub-Api-Version']='2026-03-10';}
    if(cleanHeader(cache?.etag)) headers['If-None-Match']=cache.etag;
    if(cleanHeader(cache?.last_modified)) headers['If-Modified-Since']=cache.last_modified;
    for(let attempt=0;attempt<3;attempt++) {
      if(signal?.aborted) throw new CollectionError('cancelled');
      const interval=new URL(url).hostname==='api.github.com'?Math.max(1000,this.minInterval):this.minInterval;
      const pause=Math.max(0,interval-(this.now()-this.lastRequest));
      if(pause) await this.wait(pause,undefined,{signal}).catch(()=>{throw new CollectionError('cancelled');});
      this.lastRequest=this.now();
      let response;
      try {response=await this.send(url,{headers,signal,indexSince});}
      catch(e) {
        if(e.code==='cancelled' || e.code==='blocked_address' || e.code==='response_limit' || attempt===2) throw e instanceof CollectionError ? e : new CollectionError('network_failed');
        await this.wait(500*2**attempt,undefined,{signal}).catch(()=>{throw new CollectionError('cancelled');});continue;
      }
      const {status}=response;
      if(status===200 || status===304) return {...response,etag:cleanHeader(response.headers?.etag) || null,last_modified:cleanHeader(response.headers?.['last-modified']) || null};
      if(status===429 || status===403 && (response.headers?.['x-ratelimit-remaining']==='0' || response.headers?.['retry-after'])) {
        const h=response.headers || {},raw=h['retry-after'];
        const delay=raw && /^\d+$/.test(raw) ? Number(raw)*1000 : raw ? Date.parse(raw)-this.now() : 60000;
        const reset=Number(h['x-ratelimit-reset'])*1000;
        const waitMs=Math.max(1000,Number.isFinite(delay)?delay:60000,Number.isFinite(reset)?reset-this.now():0);
        // Respect long server cooldowns via persisted retryAt, not an early capped retry.
        throw new CollectionError('rate_limited',new Date(this.now()+waitMs).toISOString());
      }
      if(status>=500 && attempt<2) {await this.wait(500*2**attempt,undefined,{signal}).catch(()=>{throw new CollectionError('cancelled');});continue;}
      throw new CollectionError(status>=300&&status<400 ? 'redirect_blocked' : `http_${status}`);
    }
  }
}
module.exports={HttpClient,CollectionError,transport,validateUrl,publicAddress,ECOSYSTEMS,CISA,CISA_MIRROR};
