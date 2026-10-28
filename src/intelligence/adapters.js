'use strict';
const sax=require('sax');
const {CollectionError}=require('../threat/http');
const {date}=require('../threat/model');
const {clean,ids,array,fingerprint,bounded}=require('./safety');
const {REDHAT,documentUrl,descriptors}=require('./registry');
const {officialClaims}=require('./conditions');
const fail=()=>{throw new CollectionError('invalid_schema');};
function json(text){try{return JSON.parse(text);}catch{fail();}}
function record(source,id,url,title,published,modified,related,claims,now,products=[]){
 const descriptor=descriptors.find(s=>s.id===source);
 const r={schemaVersion:1,source_id:id,source:source,source_type:descriptor.source_type,title:clean(title,300),official_url:url,published_at:date(published),modified_at:date(modified),observed_at:now,
  related_cve_ids:related.filter(x=>x.startsWith('CVE-')),related_ghsa_ids:related.filter(x=>x.startsWith('GHSA-')),affected_products:products,advisory_summary:source==='talos'?'Research feed item; title and identifier references only. Read the original for context.':'Selected Red Hat structured metadata; product scope is not an upstream package identity.',
  source_confidence:source==='redhat'?'OFFICIAL_VENDOR':'RESEARCH_PUBLISHER',verification_status:'UNVERIFIED',claims,attribution:descriptor.attribution,limitations:source==='talos'?['Article body and links are not crawled.','Mentioned IDs are not asserted aliases.','Identifier extraction is bounded to 8,000 sanitized feed characters and 50 identifiers.']:['Details of ambiguous origin are not used to establish attack conditions.','Publication-date index is not a complete modification feed.']};
 const material={...r};delete material.observed_at;r.content_fingerprint=fingerprint(material);return bounded(r);
}
function redhat(text,expected,now){
 const data=json(text);if(!data||typeof data!=='object'||Array.isArray(data)||data.name!==expected||!/^CVE-\d{4}-\d{4,19}$/.test(expected)||typeof data.public_date!=='string')fail();date(data.public_date,true);
 const products=array(data.package_state||[],200).map(p=>({name:clean(p.product_name,150),component:clean(p.package_name,150),ecosystem:null,state:clean(p.fix_state,60)}));
 const claims=officialClaims(data);
 for(const p of products)if(p.name||p.component)claims.push({field:'affected_component',value:[p.name,p.component].filter(Boolean).join(' / '),path:'package_state',scope:'vendor_product'});
 for(const release of array(data.affected_release||[],200))if(release.package)claims.push({field:'vendor_fixed_package',value:clean(release.package,200),path:'affected_release.package',scope:clean(release.product_name,150)||'vendor_product'});
 if(data.upstream_fix)claims.push({field:'vendor_upstream_fix_statement',value:clean(data.upstream_fix,300),path:'upstream_fix',scope:'vendor_cve'});
 return record('redhat',expected,`${REDHAT.replace('/hydra/rest/securitydata','')}/security/cve/${expected}`,data.bugzilla?.description||expected,data.public_date,data.modified_date||null,[expected],claims.slice(0,64),now,products);
}
function redhatIndex(text){return array(json(text),20).map(d=>{if(!d||!/^CVE-\d{4}-\d{4,19}$/.test(d.CVE))fail();return d.CVE;});}
function rss(text,now){
 if(typeof text!=='string'||Buffer.byteLength(text)>2*1024*1024||/<!\s*(?:DOCTYPE|ENTITY)\b/i.test(text))throw new CollectionError('unsafe_xml');
 const parser=sax.parser(true,{strictEntities:true}),stack=[],items=[];let item=null,tags=0,root=false,channel=false;
 parser.onerror=fail;parser.ondoctype=fail;
 parser.onopentag=node=>{if(++tags>50000||stack.length>=32)throw new CollectionError('rss_limit');const tag=node.name.toLowerCase();stack.push(tag);if(stack.length===1){if(tag!=='rss')fail();root=true;}if(stack.join('/')==='rss/channel')channel=true;
  if(tag==='item'&&stack.join('/')==='rss/channel/item'){if(items.length>=200)throw new CollectionError('rss_limit');item={};}
 };
 const append=t=>{if(item&&stack.length===4&&['title','link','pubdate','dc:date','dcterms:modified','description'].includes(stack.at(-1))){const k=stack.at(-1);item[k]=(item[k]||'')+t;if(item[k].length>64000)throw new CollectionError('rss_limit');}};
 parser.ontext=append;parser.oncdata=append;
 parser.onclosetag=()=>{if(stack.join('/')==='rss/channel/item'){items.push(item);item=null;}stack.pop();};
 try{parser.write(text).close();}catch(e){if(e instanceof CollectionError)throw e;fail();}if(!root||!channel)fail();
 return items.map(i=>{
  const url=documentUrl(i.link?.trim(),'talos'),title=clean(i.title,300);if(!url||!title)fail();const related=ids((i.title||'')+' '+clean(i.description,8000)),claims=[];
  // Only one subject can support a reported claim. Never infer relationships among IDs in prose.
  if(related.length===1){const summary=clean(i.title,1000);if(!/\b(?:no|not|without|denies|unconfirmed|may|could|whether)\b|\?/i.test(summary)){
   if(/\b(?:proof.of.concept|PoC) (?:has been |was )?(?:published|released|available)\b/i.test(summary))claims.push({field:'exploitation_status',value:'PROOF_OF_CONCEPT_ONLY',path:'title',scope:'vendor_cve'});else if(/\b(?:actively exploited|exploited in the wild)\b/i.test(summary))claims.push({field:'exploitation_status',value:'REPORTED_EXPLOITATION',path:'title',scope:'vendor_cve'});
  }}
  return record('talos',fingerprint(url),url,title,i.pubdate||i['dc:date'],i['dcterms:modified'],related,claims,now);
 });
}
module.exports={rss,redhat,redhatIndex,json};
