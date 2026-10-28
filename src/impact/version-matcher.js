'use strict';
const semver=require('semver');
const pep440=require('@renovatebot/pep440');
const {exactVersion}=require('../inventory/identity');
const result=(status,reason,limitations=[])=>({status,reason,limitations});
function comparator(ecosystem){return ecosystem==='npm'?semver.compare:ecosystem==='PyPI'?pep440.compare:null;}
function version(ecosystem,v){if(typeof v!=='string'||/\d{16,}/.test(v))return null;return exactVersion(ecosystem,v);}
function one(ecosystem,installed,range) {
  if(!range||typeof range!=='object')return result('INSUFFICIENT_DATA','missing_range');
  if(range.type==='GIT')return result('RANGE_UNSUPPORTED','git_commit_range_not_compared');
  if(range.format==='github-advisory'){
    const spec=range.range;if(typeof spec!=='string'||!spec.trim()||spec.length>=1000)return result('RANGE_UNSUPPORTED','invalid_or_truncated_specifier');
    try {
      if(ecosystem==='npm'){
        const parts=spec.split(',');if(parts.length>1&&!parts.every(s=>/^\s*(?:[<>]=?|=)\s*[0-9][^,|]*$/.test(s)))return result('RANGE_UNSUPPORTED','npm_range_invalid');
        const normalized=semver.validRange(parts.join(' '));if(!normalized)return result('RANGE_UNSUPPORTED','npm_range_invalid');
        return result(semver.satisfies(installed,normalized)?'AFFECTED_VERSION':'UNAFFECTED_VERSION','npm_semver_range',semver.prerelease(installed)?['npm_standard_prerelease_range_rules']:[]);
      }
      if(ecosystem==='PyPI'&&pep440.validRange(spec))return result(pep440.satisfies(installed,spec,{prereleases:true})?'AFFECTED_VERSION':'UNAFFECTED_VERSION','pypi_pep440_specifier');
    }catch{/* unsupported public metadata is not proof of safety */}
    return result('RANGE_UNSUPPORTED','ecosystem_specifier_not_supported');
  }
  const compare=comparator(ecosystem);
  if(range.format==='explicit'||range.type==='EXPLICIT_VERSIONS'){
    if(!Array.isArray(range.versions)||!range.versions.length||range.versions.length>20000)return result('INSUFFICIENT_DATA','missing_explicit_versions');
    const values=range.versions.map(v=>version(ecosystem,v));if(values.some(v=>!v))return result('RANGE_UNSUPPORTED','invalid_explicit_version');
    return result(values.some(v=>compare(installed,v)===0)?'AFFECTED_VERSION':'UNAFFECTED_VERSION','explicit_version_list');
  }
  if(!['SEMVER','ECOSYSTEM'].includes(range.type)||range.type==='SEMVER'&&ecosystem!=='npm')return result('RANGE_UNSUPPORTED','range_type_not_supported');
  if(!Array.isArray(range.events)||!range.events.length||range.events.length>1000)return result('INSUFFICIENT_DATA','missing_events');
  const events=[];let hasFixed=false,hasLast=false;
  for(const e of range.events){
    if(!e||typeof e!=='object'||Object.keys(e).length!==1)return result('RANGE_UNSUPPORTED','invalid_event');
    const key=Object.keys(e)[0],raw=e[key];if(!['introduced','fixed','last_affected','limit'].includes(key))return result('RANGE_UNSUPPORTED','invalid_event');
    if(typeof raw!=='string'||raw.length>=100)return result('RANGE_UNSUPPORTED','invalid_or_truncated_event');
    const special=key==='introduced'&&raw==='0'||key==='limit'&&raw==='*';const parsed=special?raw:version(ecosystem,raw);
    if(!parsed)return result('RANGE_UNSUPPORTED','invalid_event_version');events.push({key,value:parsed,zero:key==='introduced'&&raw==='0'});hasFixed||=key==='fixed';hasLast||=key==='last_affected';
  }
  if(!events.some(e=>e.key==='introduced')||hasFixed&&hasLast)return result('RANGE_UNSUPPORTED','inconsistent_osv_events');
  const limits=events.filter(e=>e.key==='limit');
  if(limits.length&&!limits.some(e=>e.value==='*'||compare(installed,e.value)<0))return result('UNAFFECTED_VERSION','outside_osv_limit');
  const timeline=events.filter(e=>e.key!=='limit').sort((a,b)=>a.zero?(b.zero?0:-1):b.zero?1:compare(a.value,b.value)||(['introduced','fixed','last_affected'].indexOf(a.key)-['introduced','fixed','last_affected'].indexOf(b.key)));
  let open=false;for(const e of timeline){if(e.key==='introduced'){if(open)return result('RANGE_UNSUPPORTED','overlapping_osv_events');open=true;}else{if(!open)return result('RANGE_UNSUPPORTED','unpaired_osv_event');open=false;}}
  let affected=false;
  for(const e of timeline){if(e.key==='introduced'&&(e.zero||compare(installed,e.value)>=0))affected=true;else if(e.key==='fixed'&&compare(installed,e.value)>=0||e.key==='last_affected'&&compare(installed,e.value)>0)affected=false;}
  return result(affected?'AFFECTED_VERSION':'UNAFFECTED_VERSION','osv_version_timeline');
}
function matchVersion(ecosystem,detected,ranges) {
  if(!['npm','PyPI'].includes(ecosystem))return result('RANGE_UNSUPPORTED','ecosystem_not_supported');
  const installed=version(ecosystem,detected);if(!installed)return result('VERSION_UNKNOWN','exact_version_not_available_or_supported');
  if(!Array.isArray(ranges)||!ranges.length)return result('INSUFFICIENT_DATA','no_official_affected_range');
  if(ranges.length>1000)return result('RANGE_UNSUPPORTED','range_count_limit');
  const results=ranges.map(r=>one(ecosystem,installed,r));
  const matching=results.find(r=>r.status==='AFFECTED_VERSION');if(matching)return {...matching,ranges_evaluated:results.length};
  if(results.every(r=>r.status==='UNAFFECTED_VERSION'))return {...results[0],ranges_evaluated:results.length};
  const unknown=results.find(r=>r.status==='RANGE_UNSUPPORTED')||results.find(r=>r.status==='INSUFFICIENT_DATA');return {...unknown,ranges_evaluated:results.length};
}
module.exports={matchVersion,one,version};
