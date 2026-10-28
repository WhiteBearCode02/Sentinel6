'use strict';
const {CollectionError}=require('../threat/http');
const {documentUrl,descriptors}=require('./registry');
const {fingerprint,bounded}=require('./safety');
const {TYPES}=require('./conditions');
const keys=new Set(['schemaVersion','source_id','source','source_type','title','official_url','published_at','modified_at','observed_at','related_cve_ids','related_ghsa_ids','affected_products','advisory_summary','source_confidence','verification_status','claims','attribution','limitations','content_fingerprint']);
const values={authentication_required:['YES','NO'],required_privileges:['NONE','LOW','HIGH'],attack_surface:['NETWORK','ADJACENT','LOCAL','PHYSICAL'],user_interaction:['REQUIRED','NONE'],vulnerability_type:TYPES,exploitation_status:['CONFIRMED_EXPLOITED','REPORTED_EXPLOITATION','PROOF_OF_CONCEPT_ONLY','NOT_CONFIRMED','UNKNOWN']};
const textFields=new Set(['cwe','potential_impact','mitigation','vendor_fixed_package','vendor_upstream_fix_statement','affected_component']);
function validateSource(doc){
 const fail=()=>{throw new CollectionError('invalid_schema');};bounded(doc);
 const descriptor=descriptors.find(d=>d.id===doc?.source);
 if(!descriptor||doc.schemaVersion!==1||Object.keys(doc).some(k=>!keys.has(k))||doc.source_type!==descriptor.source_type||doc.attribution!==descriptor.attribution||!documentUrl(doc.official_url,doc.source)||typeof doc.title!=='string'||doc.title.length>300)fail();
 if(!Array.isArray(doc.related_cve_ids)||doc.related_cve_ids.length>50||doc.related_cve_ids.some(id=>!/^CVE-\d{4}-\d{4,19}$/.test(id))||!Array.isArray(doc.related_ghsa_ids)||doc.related_ghsa_ids.length>50||doc.related_ghsa_ids.some(id=>!/^GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}$/.test(id)))fail();
 if(doc.source==='redhat'?(doc.related_cve_ids.length!==1||doc.source_id!==doc.related_cve_ids[0]):doc.source_id!==fingerprint(doc.official_url))fail();
 if(!Array.isArray(doc.claims)||doc.claims.length>64||doc.claims.some(c=>{
  if(!c||typeof c.field!=='string')return true;if(Object.hasOwn(values,c.field))return !values[c.field].includes(c.value);
  if(['condition.custom_authentication_adapter','condition.npm_lifecycle_scripts'].includes(c.field))return typeof c.value!=='boolean';
  return !textFields.has(c.field)||typeof c.value!=='string'||c.value.length>400;
 }))fail();
 const material={...doc};delete material.observed_at;delete material.content_fingerprint;if(fingerprint(material)!==doc.content_fingerprint)fail();return doc;
}
module.exports={validateSource};
