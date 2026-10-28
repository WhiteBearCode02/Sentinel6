'use strict';
const {fingerprint}=require('./safety');
function attach(report,analyses,configuration){
 const items=[];
 for(const match of report.matches){
  const ids=new Set([match.canonical_id,...(match.aliases||[])]);
  const analysis=analyses.find(a=>ids.has(a.vulnerability_id)||(a.data.aliases||[]).some(id=>ids.has(id)))?.data;if(!analysis)continue;
  const preconditions=analysis.attack_conditions.preconditions.map(p=>{
   const fact=p.condition_id==='npm_lifecycle_scripts'?configuration?.facts.find(f=>f.name==='npm.ignore_scripts'):null;
   return {condition_id:p.condition_id,required:p.required,source_verification:p.verification_status,
    declared_configuration:fact||null,declared_value_matches:fact&&typeof p.required==='boolean'?(!fact.value)===p.required:null,
    project_status:fact?'DECLARED_CONFIGURATION_ONLY_SCOPE_UNVERIFIED':'UNKNOWN',runtime_verified:false};
  });
  items.push({match_id:match.id,vulnerability_id:analysis.vulnerability_id,analysis_fingerprint:analysis.fingerprint,verification_status:analysis.verification.status,exploitation_status:analysis.verification.exploitation_status,
   version_impact_status:match.impact_status,version_result:match.version_result,project_preconditions:preconditions,feature_use:'UNKNOWN',external_exposure:'UNKNOWN',attack_success:'NOT_VERIFIED',vendor_scope_verified:false,
   condition_assessment:match.impact_status==='NOT_AFFECTED'?'NOT_APPLICABLE_TO_DECLARED_VERSION':'INSUFFICIENT_EVIDENCE',configuration_limitations:configuration?.limitations||[],last_verified_at:analysis.last_verified_at});
 }
 report.security_intelligence={schemaVersion:1,modelVersion:'ti-3.0',items,limitations:['TI-2 impact_status retains its component-version contract.','Vendor product conditions and declared local config do not prove upstream applicability, runtime feature use, exposure or attack success.']};
 return report;
}
function relevant(analyses,advisories,ids){const aliases=new Set(advisories.filter(a=>ids.has(a.canonical_id)).flatMap(a=>[a.canonical_id,...(a.source_ids||[])]));return analyses.filter(a=>aliases.has(a.vulnerability_id)||(a.data.aliases||[]).some(id=>aliases.has(id)));}
function input(analyses,configuration){return fingerprint({analyses:analyses.map(a=>[a.vulnerability_id,a.fingerprint]).sort(),configuration:configuration||null});}
module.exports={attach,relevant,input};
