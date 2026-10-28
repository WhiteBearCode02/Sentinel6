'use strict';
const {normalizeName,hash,credential}=require('../inventory/identity');
const {matchVersion,version}=require('./version-matcher');
const {text,stable}=require('../threat/model');
const STATES=['CONFIRMED_AFFECTED','POTENTIALLY_AFFECTED','NOT_AFFECTED','INSUFFICIENT_EVIDENCE','MITIGATED','NOT_ANALYZED'];
const active=s=>['CONFIRMED_AFFECTED','POTENTIALLY_AFFECTED'].includes(s);
const ecosystem=e=>e==='npm'?'npm':['PyPI','pip'].includes(e)?'PyPI':null;
const unique=items=>[...new Map(items.map(x=>[stable(x),x])).values()];
function priority(match,advisory) {
  const reasons=[];let score=0;
  const add=(points,reason)=>{score+=points;reasons.push({points,reason});};
  if(active(match.impact_status)){
    add(match.impact_status==='CONFIRMED_AFFECTED'?35:20,'project_dependency_match');
    if(match.version_result==='AFFECTED_VERSION')add(15,'official_affected_version');
    if(match.confidence==='high')add(5,'lockfile_exact_version_evidence');else if(match.confidence==='medium')add(2,'declared_exact_version_evidence');
    if(advisory.kev_status===true)add(25,'cisa_kev_membership');
    if(advisory.exploitation_status==='CONFIRMED_EXPLOITATION')add(10,'official_exploitation_evidence');
    if(typeof advisory.cvss?.score==='number'&&advisory.cvss.score>=0&&advisory.cvss.score<=10)add(Math.round(advisory.cvss.score*2),'cvss_severity');
    if(typeof advisory.epss?.probability==='number'&&advisory.epss.probability>=0&&advisory.epss.probability<=1)add(Math.round(advisory.epss.probability*10),'observed_epss_probability');
    if(match.fix_available)add(5,'documented_fix_actionable');
  }
  score=Math.min(100,score);return {score,level:score>=80?'critical':score>=60?'high':score>=35?'medium':score?'low':'informational',reasons};
}
function correlate(inventory,advisories,sourceRecords,{scannerReport,now=new Date().toISOString(),signal,sourceStates=[]}={}) {
  const recordsById=new Map(),packages=new Map(),matches=[],review=[];const seen=new Set();let unrelated=0;
  for(const d of inventory.dependencies){const key=d.ecosystem+':'+d.normalized_name;if(!packages.has(key))packages.set(key,[]);packages.get(key).push(d);}
  for(const row of sourceRecords){if(!recordsById.has(row.canonical_id))recordsById.set(row.canonical_id,[]);recordsById.get(row.canonical_id).push(row);}
  for(const advisory of advisories){
    if(signal?.aborted)throw Object.assign(new Error('cancelled'),{code:'cancelled'});
    const records=recordsById.get(advisory.canonical_id)||[],byDependency=new Map();let explicit=false;
    for(const record of records){
      if(!['github','osv'].includes(record.source))continue;
      for(const p of record.affected_products||[]){
        const eco=ecosystem(p.ecosystem),name=normalizeName(eco,p.name);if(!eco||!name||p.name.length>=200)continue;explicit=true;
        for(const dep of packages.get(eco+':'+name)||[]){
          if(!byDependency.has(dep.id))byDependency.set(dep.id,{dep,observations:[]});
          const ranges=(record.affected_versions||[]).filter(r=>ecosystem(r.ecosystem)===eco&&normalizeName(eco,r.name)===name);
          const comparison=matchVersion(eco,dep.version,ranges);
          const fixed=(record.patched_versions||[]).filter(r=>ecosystem(r.ecosystem)===eco&&normalizeName(eco,r.name)===name).map(r=>version(eco,r.version)).filter(Boolean);
          byDependency.get(dep.id).observations.push({source:record.source,source_id:record.source_id,version_result:comparison.status,reason:comparison.reason,ranges:JSON.parse(JSON.stringify(ranges)),fixed_versions:fixed,identity_ambiguous:!!record.identity_ambiguous,preconditions:!!record.preconditions?.length});
        }
      }
    }
    if(!byDependency.size){if(!explicit)review.push({canonical_id:advisory.canonical_id,reason:'official_package_identifier_unavailable',project_related:false});else unrelated++;continue;}
    for(const {dep,observations:raw}of byDependency.values()){
      if(matches.length>=2000)throw Object.assign(new Error('impact_match_limit'),{code:'impact_match_limit'});
      const observations=unique(raw),statuses=observations.map(o=>o.version_result),positive=statuses.includes('AFFECTED_VERSION'),negative=statuses.includes('UNAFFECTED_VERSION'),conflict=positive&&negative;
      let state='INSUFFICIENT_EVIDENCE',confidence='low';const limitations=[...dep.limitations,'runtime_conditions_not_verified','attack_path_not_analyzed'];
      if(observations.some(o=>o.identity_ambiguous)){limitations.push('ambiguous_advisory_identity');}
      else if(advisory.withdrawn_at){limitations.push('advisory_withdrawn_no_safety_conclusion');}
      else if(conflict){state='POTENTIALLY_AFFECTED';limitations.push('source_range_conflict');}
      else if(positive){state=observations.some(o=>o.preconditions)?'POTENTIALLY_AFFECTED':'CONFIRMED_AFFECTED';confidence=dep.version_confidence==='LOCKFILE_EXACT'?'high':'medium';}
      else if(statuses.length&&statuses.every(s=>s==='UNAFFECTED_VERSION')){state='NOT_AFFECTED';confidence=dep.version_confidence==='LOCKFILE_EXACT'?'high':'medium';}
      const fixed=unique(observations.flatMap(o=>o.fixed_versions));
      const ids=new Set(advisory.source_ids||[advisory.canonical_id]);
      const scannerEvidence=(scannerReport?.findings||[]).filter(f=>f.kind==='dependency'&&[f.rule,...(f.aliases||[])].some(id=>ids.has(id))&&normalizeName(dep.ecosystem,f.packageDetails?.name||f.package)===dep.normalized_name&&(ecosystem(f.packageDetails?.ecosystem)===dep.ecosystem||dep.purl&&f.packageDetails?.purl===dep.purl))
        .slice(0,100).map(f=>({type:'scanner_cross_reference',finding_id:f.id,scanners:f.scanners,reported_version:f.packageDetails?.detectedVersion||null,current_version_matches:(f.packageDetails?.detectedVersion||null)===dep.version,current_installation_verified:false}));
      if(scannerEvidence.some(e=>!e.current_version_matches))limitations.push('scanner_version_differs_or_unknown_recheck_required');
      if(!scannerReport)limitations.push('security_scanners_not_run_for_this_assessment');
      const evidence=[{type:'dependency_file',source_file:dep.source_file,line:dep.line||1,dependency_id:dep.id,version:dep.version,version_confidence:dep.version_confidence},...observations.map(o=>({type:'official_version_comparison',...o})),...scannerEvidence];
      const result={id:hash(advisory.canonical_id+'|'+dep.id).slice(0,24),project_id:inventory.project_id,canonical_id:advisory.canonical_id,aliases:advisory.source_ids,title:text(advisory.title),official_sources:advisory.official_references,published_at:advisory.published_at,modified_at:advisory.modified_at,change_type:advisory.change_type||[],advisory_fingerprint:advisory.content_fingerprint,
        package:{ecosystem:dep.ecosystem,name:dep.normalized_name,detected_version:dep.version,purl:dep.purl},source_file:dep.source_file,line:dep.line||1,dependency_type:dep.dependency_type,direct_or_transitive:dep.direct_or_transitive,
        version_result:positive?'AFFECTED_VERSION':statuses.every(s=>s==='UNAFFECTED_VERSION')?'UNAFFECTED_VERSION':statuses.includes('VERSION_UNKNOWN')?'VERSION_UNKNOWN':statuses.includes('RANGE_UNSUPPORTED')?'RANGE_UNSUPPORTED':'INSUFFICIENT_DATA',
        impact_status:state,assessment_scope:'declared_dependency_version',attack_path_verified:false,installation_verified:false,confidence,evidence_count:evidence.length,evidence,
        fix_available:fixed.length>0,fixed_versions:fixed,kev_status:advisory.kev_status,exploitation_status:advisory.exploitation_status,severity:advisory.severity||'unknown',cvss:advisory.cvss||null,epss:advisory.epss||null,
        required_checks:['Verify installed/deployed version and environment conditions.','Review upstream advisory and relevant runtime use.'],recommended_action:state==='NOT_AFFECTED'?'Keep the verified version and re-evaluate when dependencies or advisories change.':fixed.length?'Review vendor fixed versions for the correct maintenance branch, update manually, run tests, and reassess.':'Resolve missing version/condition evidence and review the official mitigation before deciding.',
        rescan_required:state!=='NOT_AFFECTED',limitations:unique(limitations),last_analyzed_at:now};
      result.priority=priority(result,advisory);
      const material={...result};delete material.last_analyzed_at;delete material.change_type;result.fingerprint=hash(stable(material));
      if(!seen.has(result.id)){seen.add(result.id);matches.push(result);}
    }
  }
  return {schemaVersion:1,modelVersion:'ti-2.0',project_id:inventory.project_id,analyzed_at:now,inventory_fingerprint:inventory.fingerprint,inventory_timestamp:inventory.inventory_timestamp,inventory_cache_reused:!!inventory.cache_reused,
    scope:'Declared/locked dependency versions only; no runtime, reachability, exploitation or compromise verification.',matches,summary:Object.fromEntries(STATES.map(s=>[s,matches.filter(m=>m.impact_status===s).length])),unrelated_advisories:unrelated,review_required:review.slice(0,200),review_required_total:review.length,
    not_analyzed_advisories:review.length,coverage:{inventory:inventory.coverage,threat_sources:sourceStates,scanners:scannerReport?.coverage||{status:'NOT_RUN'}},limitations:[...inventory.limitations,'An absent package or feed record is not proof the entire project is safe.','Threat cache covers collected monitoring windows, not a complete historical vulnerability database. Run Scan Project with prepared scanner databases for broader coverage.','Inventory scopes and cached source freshness apply to every result.']};
}
function shouldNotify(previous,current){
  if(!active(current.impact_status)||!['high','critical'].includes(current.priority.level))return false;
  return !previous||!active(previous.impact_status)||!['high','critical'].includes(previous.priority.level)||previous.priority.level!=='critical'&&current.priority.level==='critical'||previous.kev_status!==true&&current.kev_status===true||previous.exploitation_status!=='CONFIRMED_EXPLOITATION'&&current.exploitation_status==='CONFIRMED_EXPLOITATION';
}
module.exports={correlate,priority,shouldNotify,STATES,ecosystem};
