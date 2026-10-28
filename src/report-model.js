'use strict';

// schemaVersion describes the compatible base report. modelVersion identifies
// additive metadata; existing v1 readers can continue using the original fields.
const SCHEMA_VERSION=1;
const MODEL_VERSION='1.1';
function withReportMetadata(report) {
  if(report?.schemaVersion!==SCHEMA_VERSION||!Array.isArray(report.findings))throw new Error('unsupported_report_schema');
  return {...report,modelVersion:MODEL_VERSION,findings:report.findings.map(f=>({
    ...f,
    packageDetails:Object.hasOwn(f,'packageDetails')?f.packageDetails:f.kind==='dependency'?{ecosystem:null,name:f.package||null,detectedVersion:null,purl:null,observations:[]}:null,
    vulnerability:f.vulnerability || {id:f.kind==='dependency'&&f.rule!=='unclassified'?f.rule:null,affectedRanges:[],fixedVersions:[],advisorySources:[]},
    evidence:f.evidence || [],
    impact:f.impact || {status:'NOT_ANALYZED',confidence:'unknown'},
    limitations:f.limitations || ['Detailed evidence metadata was not captured in this legacy finding.']
  }))};
}
module.exports={SCHEMA_VERSION,MODEL_VERSION,withReportMetadata};
