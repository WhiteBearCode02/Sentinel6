'use strict';
const {withStore,withReadStore}=require('../threat/store');
const {identifier}=require('../threat/model');
const {CollectionError}=require('../threat/http');
const storage=require('./storage');
const {bounded,escape}=require('./safety');
function markdown(r){
 const a=r.attack_conditions,v=r.verification;
 return ['# Sentinel6 Security Intelligence',`Model: ${r.modelVersion}; last verified: ${r.last_verified_at}`,'','## A. Vulnerability overview',`${escape(r.vulnerability_id)}: ${escape(r.overview.title)}`,`Published: ${escape(r.overview.published_at)}; severity: ${escape(r.overview.severity)}`,
  '','## B. Attack conditions',`Type: ${escape(a.vulnerability_type)}; cause: ${escape(a.cause?.values?.join(', ')||'UNKNOWN')}`,`Authentication: ${a.authentication_required}; privileges: ${a.required_privileges}; attack surface: ${a.attack_surface}`,`Exploitation: ${v.exploitation_status}`,
  ...a.preconditions.map(p=>`- ${escape(p.condition_id)}: ${escape(p.required)} (${p.verification_status}); project runtime UNKNOWN`),'','## C. Project impact',
  ...(r.project_assessments.length?r.project_assessments.flatMap(p=>[`- ${escape(p.project_id||p.workspaceId)} / ${escape(p.package?.name)} ${escape(p.package?.detected_version)}: TI-2 ${escape(p.impact_status)}; feature use/exposure/attack success UNKNOWN.`,...(p.security_intelligence?.project_preconditions||[]).map(c=>`- ${escape(c.condition_id)}: ${c.project_status}; declared configuration match ${escape(c.declared_value_matches)}; vendor product applicability UNKNOWN.`)]):['No analyzed project match; this is not a safe verdict.']),
  '','## D. Response',...r.response.fixed_version_candidates.map(c=>'- Official fixed-version candidates for '+escape(c.package?.ecosystem+':'+c.package?.name)+': '+c.versions.map(escape).join(', ')),...a.recommended_mitigations.map(m=>'- Vendor statement (data only): '+escape(m)),
  'Use TI-2 official fixed-version candidates for the correct package/maintenance branch. Review vendor product scope and declared settings manually. Run project tests and existing Scan Project after an approved manual change. No patch or command is executed.',
  '','## E. Evidence and limitations',`Source verification: ${v.status}; withdrawal: ${escape(r.overview.withdrawn_at)}`,`Current source states: ${r.current_source_status.map(s=>escape(s.id+': '+s.status+(s.stale?' STALE':''))).join(', ')}`, ...Object.entries(v.fields).map(([name,f])=>`- ${escape(name)}: ${f.status}; ${f.claims.map(c=>escape(c.source+' / '+c.path+' / '+JSON.stringify(c.value)+' / '+c.url+' / published '+c.published_at+' / modified '+c.modified_at)).join('; ')}`),
  ...r.official_links.map(url=>'- Source: '+escape(url)),...r.sources.map(s=>'- Attribution: '+escape(s.attribution)),...r.limitations.map(l=>'- '+escape(l)),...a.unverified_assumptions.map(l=>'- '+escape(l))].join('\n');
}
class IntelligenceService{
 constructor({file,now=()=>new Date().toISOString()}={}){this.file=file;this.now=now;}
 async analyze(id,{signal}={}){identifier(id);if(signal?.aborted)throw new CollectionError('cancelled');return withStore(this.file,async s=>{
  if(signal?.aborted)throw new CollectionError('cancelled');storage.analyze(s,[id],this.now(),{signal});return storage.get(s,id)||storage.all(s).find(a=>a.data.aliases.includes(id))?.data;
 });}
 async report(id,{format='json',projectAssessments=[]}={}){
  identifier(id);if(!['json','markdown'].includes(format)||!Array.isArray(projectAssessments)||projectAssessments.length>200)throw new CollectionError('invalid_parameters');
  return withReadStore(this.file,s=>{const r=storage.get(s,id)||storage.all(s).find(a=>a.data.aliases.includes(id))?.data;if(!r)return null;
   r.project_assessments=projectAssessments;r.current_source_status=s.all('SELECT id,state FROM threat_sources').map(row=>{const x=JSON.parse(row.state);return {id:row.id,status:x.status,last_success:x.last_success,stale:!x.last_success||Date.parse(this.now())-Date.parse(x.last_success)>172800000};});
   r.response={fixed_version_candidates:projectAssessments.filter(p=>p.fixed_versions?.length).map(p=>({package:p.package,versions:p.fixed_versions,sources:p.official_sources})),vendor_mitigations:r.attack_conditions.recommended_mitigations,manual_checks:['Verify vendor product scope and actual installed/deployed version.','Review declared configuration and usage of the matched dependency; exact code locations and reachability are not analyzed.','After an approved manual change, run project tests and existing Scan Project.'],automatic_changes:false};
   r.revisions=storage.revisions(s,r.vulnerability_id).map(h=>({fingerprint:h.fingerprint,observed_at:h.observed_at}));bounded(r,512*1024);return format==='markdown'?markdown(r):r;
  });
 }
}
module.exports={IntelligenceService,markdown};
