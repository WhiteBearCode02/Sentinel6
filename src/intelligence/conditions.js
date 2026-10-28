'use strict';
const {clean}=require('./safety');
const CWE={89:'SQL_INJECTION',78:'COMMAND_INJECTION',287:'AUTHENTICATION_BYPASS',862:'AUTHORIZATION_BYPASS',918:'SSRF',22:'PATH_TRAVERSAL',502:'INSECURE_DESERIALIZATION',269:'PRIVILEGE_ESCALATION',200:'SENSITIVE_INFORMATION_DISCLOSURE',434:'INSECURE_FILE_UPLOAD'};
const TYPES=[...Object.values(CWE),'REMOTE_CODE_EXECUTION','SUPPLY_CHAIN_COMPROMISE','CONTAINER_MISCONFIGURATION','MCP_PERMISSION_MISCONFIGURATION','AI_AGENT_SANDBOX_EXPOSURE'];
function officialClaims(data){
 const claims=[];const add=(field,value,path,scope='vendor_cve')=>claims.push({field,value,path,scope});
 for(const cwe of [...new Set(String(data.cwe||'').match(/CWE-\d+/g)||[])]){add('cwe',cwe,'cwe');const type=CWE[cwe.slice(4)];if(type)add('vulnerability_type',type,'cwe');}
 const title=clean(data.bugzilla?.description,1000);
 if(!/\b(?:not|without|prevent|unaffected)\b/i.test(title))for(const [type,re]of [['REMOTE_CODE_EXECUTION',/\bremote code execution\b/i],['SUPPLY_CHAIN_COMPROMISE',/\bsupply.chain (?:compromise|attack)\b/i],['CONTAINER_MISCONFIGURATION',/\bcontainer misconfiguration\b/i],['MCP_PERMISSION_MISCONFIGURATION',/\bMCP permission misconfiguration\b/i],['AI_AGENT_SANDBOX_EXPOSURE',/\bAI agent sandbox exposure\b/i]])if(re.test(title))add('vulnerability_type',type,'bugzilla.description');
 // Details may originate from MITRE. Only Red Hat's explicit statement supplies prose conditions.
 const statement=clean(data.statement,16000);
 for(const [field,value,re]of [
  ['authentication_required','NO',/(?:^|[.!?]\s+)exploitation does not require authentication\.(?:\s|$)/i],
  ['authentication_required','YES',/(?:^|[.!?]\s+)exploitation requires authentication\.(?:\s|$)/i],
  ['exploitation_status','NOT_CONFIRMED',/(?:^|[.!?]\s+)Red Hat has not confirmed exploitation\.(?:\s|$)/i],
  ['exploitation_status','CONFIRMED_EXPLOITED',/(?:^|[.!?]\s+)Red Hat has confirmed exploitation in the wild\.(?:\s|$)/i],
  ['condition.custom_authentication_adapter',true,/(?:^|[.!?]\s+)exploitation requires (?:a )?custom authentication adapter to be enabled\.(?:\s|$)/i],
  ['condition.custom_authentication_adapter',false,/(?:^|[.!?]\s+)exploitation does not require (?:a )?custom authentication adapter\.(?:\s|$)/i],
  ['condition.npm_lifecycle_scripts',true,/(?:^|[.!?]\s+)exploitation requires npm lifecycle scripts to be enabled\.(?:\s|$)/i],
  ['condition.npm_lifecycle_scripts',false,/(?:^|[.!?]\s+)exploitation does not require npm lifecycle scripts\.(?:\s|$)/i]
 ])if(re.test(statement))add(field,value,'statement');
 const vector=data.cvss3?.cvss3_scoring_vector;
 if(data.cvss3?.status==='verified'&&typeof vector==='string'&&/^CVSS:3\.[01]\/AV:[NALP]\/AC:[LH]\/PR:[NLH]\/UI:[NR]\/S:[UC]\/C:[NLH]\/I:[NLH]\/A:[NLH]$/.test(vector)){
  const metrics=Object.fromEntries(vector.split('/').slice(1).map(v=>v.split(':')));
  add('required_privileges',{N:'NONE',L:'LOW',H:'HIGH'}[metrics.PR],'cvss3.cvss3_scoring_vector');
  add('attack_surface',{N:'NETWORK',A:'ADJACENT',L:'LOCAL',P:'PHYSICAL'}[metrics.AV],'cvss3.cvss3_scoring_vector');
  add('user_interaction',metrics.UI==='R'?'REQUIRED':'NONE','cvss3.cvss3_scoring_vector');
  for(const k of ['C','I','A'])if(metrics[k]!=='N')add('potential_impact',({C:'CONFIDENTIALITY',I:'INTEGRITY',A:'AVAILABILITY'})[k]+'_'+({H:'HIGH',L:'LOW'})[metrics[k]],'cvss3.cvss3_scoring_vector');
 }
 if(data.mitigation&&clean(data.mitigation))add('mitigation',clean(data.mitigation),'mitigation');
 return claims.slice(0,64);
}
function attackConditions(id,verification){
 const fields=verification.fields;
 const official=field=>(fields[field]?.claims||[]).filter(c=>c.authority==='official'&&c.assertion_status!=='WITHDRAWN');
 const values=field=>[...new Set(official(field).map(c=>c.value))];
 const scalar=field=>fields[field]?.status==='CONFLICTING_INFORMATION'?'UNKNOWN':values(field).length===1?values(field)[0]:'UNKNOWN';
 const preconditions=Object.keys(fields).filter(f=>f.startsWith('condition.')).map(field=>({condition_id:field.slice(10),required:scalar(field),verification_status:fields[field].status,evidence:fields[field].claims,project_status:'UNKNOWN'}));
 const types=values('vulnerability_type').filter(v=>TYPES.includes(v));
 return {vulnerability_id:id,vulnerability_type:types[0]||'UNKNOWN',vulnerability_types:types,affected_component:fields.affected_component?.claims||null,affected_versions:fields.affected_versions?.claims||[],
  preconditions,authentication_required:scalar('authentication_required'),required_privileges:scalar('required_privileges'),attack_surface:scalar('attack_surface'),trust_boundary:null,
  affected_functionality:[],potential_impact:values('potential_impact'),recommended_mitigations:values('mitigation'),
  cause:values('cwe').length?{kind:'CWE_CLASSIFICATION',values:values('cwe'),runtime_cause_verified:false}:null,
  evidence:Object.values(fields).flatMap(f=>f.claims).slice(0,200),unverified_assumptions:['Installed/deployed version, feature use, external exposure and attack success are separate and unverified.','CWE classification does not prove authentication, a function location or a reachable attack path.','Vendor product scope may differ from an upstream npm/PyPI package.'],
  analysis_status:preconditions.some(p=>p.required!=='UNKNOWN'&&['OFFICIAL_CONFIRMED','MULTI_SOURCE_CORROBORATED'].includes(p.verification_status))?'OFFICIAL_CONDITIONS_DOCUMENTED':'INSUFFICIENT_EVIDENCE'};
}
module.exports={officialClaims,attackConditions,TYPES};
