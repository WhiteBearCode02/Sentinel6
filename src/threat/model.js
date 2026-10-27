'use strict';
const crypto=require('node:crypto');
const {CollectionError}=require('./http');
const ID=/^(?:CVE-\d{4}-\d{4,19}|GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}|[A-Za-z][A-Za-z0-9_]{1,30}-[A-Za-z0-9_-]{1,100})$/;
const fail=()=>{throw new CollectionError('invalid_schema');};
function text(v,max=500) {
  if(typeof v!=='string') return '';
  return v.replace(/[\x00-\x1f\x7f\u202a-\u202e\u2066-\u2069]/g,' ').replace(/(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[A-Z0-9]{16}|Bearer\s+\S+)/gi,'[REDACTED]').slice(0,max);
}
function date(v,required=false) {const n=typeof v==='string'?Date.parse(v):NaN;if(!Number.isFinite(n)){if(required)fail();return null;}return new Date(n).toISOString();}
function identifier(v) {if(typeof v!=='string'||!ID.test(v))fail();return v;}
function array(v,max=10000) {if(!Array.isArray(v)||v.length>max)fail();return v;}
function number(v,max=10) {return typeof v==='number'&&Number.isFinite(v)&&v>=0&&v<=max?v:null;}
function stable(v) {return JSON.stringify(v,(_k,x)=>x&&typeof x==='object'&&!Array.isArray(x)?Object.fromEntries(Object.keys(x).sort().map(k=>[k,x[k]])):x);}
const fingerprint=v=>crypto.createHash('sha256').update(stable(v)).digest('hex');
function base(source,id,aliases=[]) {
  identifier(id);aliases=array(aliases,100).map(identifier);
  const ids=[...new Set([id,...aliases])].sort();
  const cves=ids.filter(x=>x.startsWith('CVE-'));
  const ghsas=ids.filter(x=>x.startsWith('GHSA-'));
  const canonical=cves.length===1?cves[0]:!cves.length&&ghsas.length===1?ghsas[0]:id;
  return {threat_id:canonical,canonical_id:canonical,source_ids:ids,source,source_id:id,
    title:id,description:'Public advisory metadata; see source for full details.',published_at:null,modified_at:null,
    affected_products:[],affected_versions:[],patched_versions:[],cvss:null,epss:null,kev_status:null,exploitation_status:'UNKNOWN',
    preconditions:[],attack_primitives:[],cwes:[],official_references:[],evidence_sources:[],withdrawn_at:null,
    mitigation:null,identity_ambiguous:cves.length>1,analysis_status:'NOT_ANALYZED'};
}
function cisa(data) {
  if(!data || typeof data.catalogVersion!=='string' || !Number.isInteger(data.count))fail();
  date(data.dateReleased,true);
  const rows=array(data.vulnerabilities,20000);
  if(data.count!==rows.length)fail();
  return rows.map(v=>{
    if(!/^CVE-\d{4}-\d{4,19}$/.test(v.cveID)||typeof v.vulnerabilityName!=='string'||typeof v.product!=='string'||typeof v.vendorProject!=='string'||typeof v.requiredAction!=='string')fail();
    const r=base('cisa',v.cveID);
    Object.assign(r,{title:text(v.vulnerabilityName),modified_at:null,kev_status:true,exploitation_status:'CONFIRMED_EXPLOITATION',
      affected_products:[{vendor:text(v.vendorProject,100),name:text(v.product,150),ecosystem:null}],
      mitigation:text(v.requiredAction),kev_added_at:date(v.dateAdded,true),cwes:(v.cwes||[]).filter(c=>/^CWE-\d+$/.test(c)),
      official_references:['https://www.cisa.gov/known-exploited-vulnerabilities-catalog'],
      evidence_sources:[{source:'cisa',id:v.cveID,url:'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',fact:'CISA KEV membership; dateAdded is not the CVE publication date.'}]});
    return r;
  });
}
function github(data) {
  return array(data,100).map(v=>{
    identifier(v.ghsa_id);if(!v.ghsa_id.startsWith('GHSA-')||typeof v.summary!=='string')fail();
    const aliases=(v.identifiers||[]).filter(i=>['CVE','GHSA'].includes(i.type)).map(i=>i.value);
    if(v.cve_id)aliases.push(v.cve_id);
    const r=base('github',v.ghsa_id,aliases);
    Object.assign(r,{title:text(v.summary),published_at:date(v.published_at,true),modified_at:date(v.updated_at,true),withdrawn_at:date(v.withdrawn_at),
      cvss:v.cvss?{score:number(v.cvss.score),vector:text(v.cvss.vector_string,200)}:null,
      epss:v.epss?{probability:number(v.epss.percentage,1),percentile:number(v.epss.percentile,1)}:null,
      cwes:(v.cwes||[]).map(c=>c.cwe_id).filter(c=>/^CWE-\d+$/.test(c)),
      official_references:[`https://github.com/advisories/${v.ghsa_id}`],
      evidence_sources:[{source:'github',id:v.ghsa_id,url:`https://github.com/advisories/${v.ghsa_id}`,fact:'GitHub global reviewed security advisory.'}]});
    for(const a of array(v.vulnerabilities||[],1000)) {
      if(!a.package||typeof a.package.name!=='string'||typeof a.package.ecosystem!=='string')fail();
      const p={name:text(a.package.name,200),ecosystem:text(a.package.ecosystem,50)};
      r.affected_products.push(p);r.affected_versions.push({...p,range:text(a.vulnerable_version_range,1000),format:'github-advisory'});
      if(a.first_patched_version)r.patched_versions.push({...p,version:text(a.first_patched_version,100)});
    }
    r.severity=['low','medium','high','critical'].includes(v.severity)?v.severity:'unknown';return r;
  });
}
function osv(data) {
  if(!data || typeof data.id!=='string')fail();
  const r=base('osv',data.id,data.aliases||[]);
  Object.assign(r,{title:text(data.summary||data.id),published_at:date(data.published),modified_at:date(data.modified,true),withdrawn_at:date(data.withdrawn),
    cvss:data.severity?array(data.severity,100).filter(s=>/^CVSS_V[234]$/.test(s.type)).map(s=>({type:s.type,vector:text(s.score,200)})):null,
    official_references:[`https://osv.dev/vulnerability/${encodeURIComponent(data.id)}`],
    evidence_sources:[{source:'osv',id:data.id,url:`https://osv.dev/vulnerability/${encodeURIComponent(data.id)}`,fact:'OSV structured vulnerability record; ranges are not project impact proof.'}]});
  for(const a of array(data.affected||[],1000)) {
    if(!a.package||typeof a.package.name!=='string'||typeof a.package.ecosystem!=='string')fail();
    const p={name:text(a.package.name,200),ecosystem:text(a.package.ecosystem,50),purl:text(a.package.purl,300)||null};
    r.affected_products.push(p);
    for(const range of array(a.ranges||[],1000)) {
      if(!['SEMVER','ECOSYSTEM','GIT'].includes(range.type))fail();
      const events=array(range.events,1000).map(event=>{
        const keys=Object.keys(event);if(keys.length!==1||!['introduced','fixed','last_affected','limit'].includes(keys[0])||typeof event[keys[0]]!=='string')fail();
        if(event.fixed)r.patched_versions.push({...p,version:text(event.fixed,100)});
        return {[keys[0]]:text(event[keys[0]],200)};
      });
      r.affected_versions.push({...p,type:range.type,events,format:'osv'});
    }
    if(a.versions?.length)r.affected_versions.push({...p,versions:array(a.versions,20000).map(v=>text(v,100)),format:'explicit'});
  }
  return r;
}
function combine(records,previous,now) {
  const sorted=[...records].sort((a,b)=>({cisa:0,osv:1,github:2}[a.source]-{cisa:0,osv:1,github:2}[b.source]));
  const preferred=sorted.at(-1),out={...preferred};
  const union=key=>[...new Map(sorted.flatMap(r=>r[key]).map(v=>[stable(v),v])).values()].sort((a,b)=>stable(a).localeCompare(stable(b)));
  for(const k of ['source_ids','affected_products','affected_versions','patched_versions','official_references','evidence_sources','cwes'])out[k]=union(k);
  const earliest=key=>sorted.map(r=>r[key]).filter(Boolean).sort()[0]||null;
  out.published_at=earliest('published_at');out.modified_at=sorted.map(r=>r.modified_at).filter(Boolean).sort().at(-1)||null;
  out.kev_status=sorted.some(r=>r.kev_status===true)?true:sorted.some(r=>r.kev_status===false)?false:null;
  out.exploitation_status=sorted.some(r=>r.exploitation_status==='CONFIRMED_EXPLOITATION')?'CONFIRMED_EXPLOITATION':'UNKNOWN';
  out.mitigation=preferred.mitigation || sorted.find(r=>r.mitigation)?.mitigation || null;
  out.kev_added_at=sorted.find(r=>r.kev_added_at)?.kev_added_at || null;
  out.withdrawn_at=sorted.map(r=>r.withdrawn_at).find(Boolean)||null;
  out.cvss=preferred.cvss || sorted.find(r=>r.cvss)?.cvss || null;out.epss=preferred.epss || null;
  out.first_seen_at=previous?.first_seen_at||now;out.last_seen_at=now;
  out.severity=preferred.severity || 'unknown';
  delete out.source;delete out.source_id;
  const material={...out};for(const k of ['first_seen_at','last_seen_at','modified_at','content_fingerprint','change_type'])delete material[k];
  out.content_fingerprint=fingerprint(material);
  out.change_type=[];
  if(!previous)out.change_type.push('NEW_ADVISORY');
  else {
    if(previous.kev_status!==true&&out.kev_status===true)out.change_type.push('KEV_ADDED');
    if(previous.kev_status===true&&out.kev_status===false)out.change_type.push('KEV_REMOVED');
    if(!previous.withdrawn_at&&out.withdrawn_at)out.change_type.push('WITHDRAWN');
    for(const [key,type] of Object.entries({cvss:'CVSS_CHANGED',epss:'EPSS_CHANGED',affected_versions:'AFFECTED_RANGE_CHANGED',patched_versions:'FIX_CHANGED',mitigation:'MITIGATION_CHANGED'}))if(stable(previous[key])!==stable(out[key]))out.change_type.push(type);
    if(previous.content_fingerprint!==out.content_fingerprint&&!out.change_type.length)out.change_type.push('ADVISORY_UPDATED');
  }
  return out;
}
const validated=fn=>data=>{try{return fn(data);}catch(e){if(e instanceof CollectionError)throw e;throw new CollectionError('invalid_schema');}};
module.exports={cisa:validated(cisa),github:validated(github),osv:validated(osv),combine,fingerprint,stable,text,date,identifier,array};
