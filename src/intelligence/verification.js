'use strict';
const {stable}=require('../threat/model');
const {officialClaims}=require('./conditions');
function legacyDocument(record){
 const claims=[...(record.source_ids||[]).map(id=>({field:'identifier',value:id,path:'source_ids',scope:'identity'})),...officialClaims({cwe:(record.cwes||[]).join(' ')})];
 for(const [field,key]of [['affected_component','affected_products'],['affected_versions','affected_versions'],['fixed_versions','patched_versions']])if(record[key]?.length)claims.push({field,value:record[key].slice(0,20),path:key,scope:'upstream_metadata'});
 if(record.kev_status===true)claims.push({field:'exploitation_status',value:'CONFIRMED_EXPLOITED',path:'kev_status',scope:'vendor_cve'});
 return {source:record.source,source_id:record.source_id,source_type:'official_metadata',official_url:record.official_references?.[0]||null,observed_at:record.modified_at||record.published_at,modified_at:record.modified_at,published_at:record.published_at,claims,
  origin:['github','osv'].includes(record.source)?'vulnerability-metadata':record.source,withdrawn:!!record.withdrawn_at};
}
const exclusive=new Set(['authentication_required','required_privileges','attack_surface']);
function verify(id,documents,{identifierConfirmed=false}={}){
 const fields=Object.create(null);
 for(const doc of documents){
  for(const claim of doc.claims||[]){
   const authority=['official_vendor','official_metadata'].includes(doc.source_type)?'official':'reported';
   const evidence={...claim,authority,source:doc.source,source_id:doc.source_id,url:doc.official_url,origin:doc.origin||doc.source,published_at:doc.published_at||null,modified_at:doc.modified_at||null,observed_at:doc.observed_at||null,assertion_status:doc.withdrawn?'WITHDRAWN':'CURRENT'};
   (fields[claim.field]||= {claims:[]}).claims.push(evidence);
  }
 }
 for(const [name,field]of Object.entries(fields)){
  field.claims=[...new Map(field.claims.map(c=>[stable(c),c])).values()];
  const groups=new Map();for(const c of field.claims.filter(c=>c.assertion_status==='CURRENT')){const key=c.scope+'|'+stable(c.value);if(!groups.has(key))groups.set(key,new Set());groups.get(key).add(c.origin);}
  const scopes=new Map();for(const c of field.claims.filter(c=>c.assertion_status==='CURRENT')){if(!scopes.has(c.scope))scopes.set(c.scope,new Set());scopes.get(c.scope).add(stable(c.value));}
  const conflict=(exclusive.has(name)||name.startsWith('condition.'))&&[...scopes.values()].some(s=>s.size>1);
  field.authoritative_confirmed=field.claims.some(c=>c.authority==='official'&&c.assertion_status==='CURRENT');
  field.status=conflict?'CONFLICTING_INFORMATION':[...groups.values()].some(s=>s.size>=2)?'MULTI_SOURCE_CORROBORATED':field.authoritative_confirmed?'OFFICIAL_CONFIRMED':groups.size?'SINGLE_SOURCE_REPORTED':'UNVERIFIED';
  if(['affected_versions','fixed_versions'].includes(name))field.limitations=['Different product scopes, version syntaxes and maintenance branches are preserved; textual differences alone are not contradictions.'];
 }
 const statuses=Object.values(fields).map(f=>f.status),hasOfficial=documents.some(d=>['official_vendor','official_metadata'].includes(d.source_type)&&!d.withdrawn);
 const status=statuses.includes('CONFLICTING_INFORMATION')?'CONFLICTING_INFORMATION':!identifierConfirmed&&!hasOfficial?'UNVERIFIED':statuses.includes('MULTI_SOURCE_CORROBORATED')?'MULTI_SOURCE_CORROBORATED':hasOfficial?'OFFICIAL_CONFIRMED':statuses.length?'SINGLE_SOURCE_REPORTED':'UNVERIFIED';
 const levels=(fields.exploitation_status?.claims||[]).filter(c=>c.assertion_status==='CURRENT').map(c=>c.value);
 const exploitation_status=levels.includes('CONFIRMED_EXPLOITED')?'CONFIRMED_EXPLOITED':levels.includes('REPORTED_EXPLOITATION')?'REPORTED_EXPLOITATION':levels.includes('PROOF_OF_CONCEPT_ONLY')?'PROOF_OF_CONCEPT_ONLY':levels.includes('NOT_CONFIRMED')?'NOT_CONFIRMED':'UNKNOWN';
 return {vulnerability_id:id,status,identifier_status:identifierConfirmed||hasOfficial?'OFFICIAL_METADATA_REFERENCED':'NOT_CONFIRMED',fields,exploitation_status,
  limitations:['Corroboration is field- and product-scope-specific. Mirrored GitHub/OSV metadata is one origin.','No exploitation confirmation is not proof exploitation does not occur.','IDs co-mentioned in news are not asserted aliases.']};
}
module.exports={verify,legacyDocument};
