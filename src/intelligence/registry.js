'use strict';
// Code-reviewed endpoints only. Feed contents never add hosts or fetch targets.
const REDHAT='https://access.redhat.com/hydra/rest/securitydata';
const TALOS='https://blog.talosintelligence.com/rss/';
const descriptors=[
 {id:'redhat',name:'Red Hat Security Data API',source_type:'official_vendor',endpoint:REDHAT+'/cve.json',attribution:'Red Hat, CC BY 4.0; selected and normalized metadata',policy:'https://access.redhat.com/security/data'},
 {id:'talos',name:'Cisco Talos research RSS',source_type:'research_news',endpoint:TALOS,attribution:'Cisco Talos; title, original URL and identifier facts only',policy:'https://blog.talosintelligence.com/'}
];
function allowed(u){
 if(u.href===TALOS)return true;
 if(u.hostname!=='access.redhat.com')return false;
 if(/^\/hydra\/rest\/securitydata\/cve\/CVE-\d{4}-\d{4,19}\.json$/.test(u.pathname))return !u.search;
 if(u.pathname!=='/hydra/rest/securitydata/cve.json')return false;
 if([...u.searchParams.keys()].some(k=>!['after','per_page','page','isCompressed'].includes(k)))return false;
 if(new Set(u.searchParams.keys()).size!==[...u.searchParams.keys()].length)return false;
 return [...u.searchParams].every(([k,v])=>k==='after'?/^\d{4}-\d{2}-\d{2}$/.test(v):k==='isCompressed'?v==='false':k==='per_page'?v==='20':/^[1-9]\d{0,2}$/.test(v));
}
function documentUrl(value,source){
 if(typeof value!=='string'||value.length>1000||/[\s\\\x00-\x1f]/.test(value))return null;
 try{const u=new URL(value);if(u.protocol!=='https:'||u.port||u.hash||u.username||u.password||u.search)return null;
  if(source==='talos'&&u.hostname==='blog.talosintelligence.com'&&/^\/[a-z0-9][a-z0-9-]{0,250}\/$/.test(u.pathname))return u.href;
  if(source==='redhat'&&u.hostname==='access.redhat.com'&&/^\/security\/cve\/CVE-\d{4}-\d{4,19}$/.test(u.pathname))return u.href;
 }catch{}return null;
}
module.exports={REDHAT,TALOS,descriptors,allowed,documentUrl};
