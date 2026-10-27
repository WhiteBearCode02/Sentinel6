const {test}=require('node:test');
const assert=require('node:assert/strict');
const https=require('node:https');
const {EventEmitter}=require('node:events');
const {HttpClient,transport,validateUrl,publicAddress,CISA}=require('../src/threat/http');
test('HTTP allowlist blocks arbitrary hosts, credentials, ports, redirect targets and malformed URLs',()=>{
 for(const u of ['http://www.cisa.gov/','https://localhost/','https://127.0.0.1/','https://169.254.169.254/latest/meta-data','https://api.github.com.evil/advisories','https://user:pass@api.github.com/advisories','https://api.github.com:444/advisories','https://api.github.com/advisories#fragment','https://api.github.com/advisories?token=secret','https://api.osv.dev/v1/vulns/../../private','https://api.osv.dev/v1/vulns/test\n']) assert.throws(()=>validateUrl(u));
 assert.equal(validateUrl(CISA).hostname,'www.cisa.gov');
});
test('DNS policy rejects private, loopback, link-local, multicast and mapped addresses',()=>{
 for(const ip of ['127.0.0.1','10.0.0.1','169.254.169.254','172.16.1.1','192.168.0.1','100.64.0.1','0.0.0.0','224.0.0.1','::1','fe80::1','fc00::1','::ffff:127.0.0.1','2001:db8::1'])assert.equal(publicAddress(ip),false,ip);
 assert.equal(publicAddress('8.8.8.8'),true);assert.equal(publicAddress('2606:4700:4700::1111'),true);
});
test('conditional request headers are bounded and credentials are never added',async()=>{
 let headers;const c=new HttpClient({minInterval:0,send:async(_u,o)=>{headers=o.headers;return {status:304,headers:{}};}});
 await c.get(CISA,{cache:{etag:'"good"',last_modified:'bad\r\ninjection'}});
 assert.equal(headers['If-None-Match'],'"good"');assert.equal(headers['If-Modified-Since'],undefined);assert.equal(headers.Authorization,undefined);
});
test('429 and GitHub rate-limit responses defer until server cooldown without early retry',async()=>{
 for(const status of [429,403]) {
 let calls=0;const c=new HttpClient({now:()=>100000,minInterval:0,send:async()=>{calls++;return {status,headers:{'retry-after':'3600','x-ratelimit-remaining':'0'}};}});
 await assert.rejects(c.get(CISA),e=>e.code==='rate_limited'&&e.retryAt===new Date(3700000).toISOString());assert.equal(calls,1);
 }
});
test('transient errors retry with exponential backoff and permanent errors do not',async()=>{
 let calls=0;const sleeps=[];const c=new HttpClient({minInterval:0,wait:async n=>sleeps.push(n),send:async()=>({status:++calls<3?503:200,headers:{},text:'{}'})});
 assert.equal((await c.get(CISA)).status,200);assert.deepEqual(sleeps,[500,1000]);
 const bad=new HttpClient({minInterval:0,send:async()=>({status:302,headers:{location:'http://127.0.0.1'}})});
 await assert.rejects(bad.get(CISA),e=>e.code==='redirect_blocked');
});
function mockRequest(t,behavior) {
 const original=https.request;
 https.request=(_url,_options,callback)=>{
  const req=new EventEmitter();req.destroy=()=>{};
  req.end=()=>queueMicrotask(()=>behavior(req,callback));return req;
 };
 t.after(()=>{https.request=original;});
}
test('transport enforces total response size',async t=>{
 mockRequest(t,(_r,cb)=>{const res=new EventEmitter();res.statusCode=200;res.headers={};cb(res);res.emit('data',Buffer.alloc(101));res.emit('end');});
 await assert.rejects(transport(CISA,{maxBytes:100}),e=>e.code==='response_limit');
});
test('transport has a wall-clock timeout including stalled responses',async t=>{
 mockRequest(t,()=>{});await assert.rejects(transport(CISA,{timeout:5}),e=>e.code==='timeout');
});
test('transport supports cancellation',async t=>{
 mockRequest(t,()=>{});const c=new AbortController();const p=transport(CISA,{signal:c.signal});c.abort();await assert.rejects(p,e=>e.code==='cancelled');
});
test('OSV index streaming stops at old entries despite full-feed content length',async t=>{
 let destroyed=false;
 const original=https.request;https.request=(_u,_o,cb)=>{const req=new EventEmitter();req.destroy=()=>{destroyed=true;};req.end=()=>queueMicrotask(()=>{const res=new EventEmitter();res.statusCode=200;res.headers={'content-length':'999999999'};cb(res);res.emit('data',Buffer.from('2026-10-27T00:00:00Z,GHSA-2345-6789-cfgh\n2026-10-01T00:00:00Z,GHSA-2345-6789-cfgj\n'));});return req;};t.after(()=>https.request=original);
 const r=await transport('https://osv-vulnerabilities.storage.googleapis.com/npm/modified_id.csv',{indexSince:'2026-10-26T00:00:00Z'});assert.equal(r.status,200);assert.ok(destroyed);
});
