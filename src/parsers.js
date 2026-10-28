'use strict';
const path = require('node:path');
const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const severity = value => ({ERROR:'high', WARNING:'medium', INFO:'info', CRITICAL:'critical', HIGH:'high', MEDIUM:'medium', LOW:'low', UNKNOWN:'unknown'}[String(value).toUpperCase()] || 'unknown');
function safePath(root, file) {
  if (typeof file !== 'string' || !file || /[\0\r\n]/.test(file)) throw new Error('Invalid result path');
  const normalized = file.replace(/\\/g, '/');
  const absolute = path.resolve(root, normalized);
  const rel = path.relative(root, absolute);
  if (!rel || rel === '..' || rel.startsWith('..' + path.sep) || path.isAbsolute(rel)) throw new Error('Result outside project');
  return rel.split(path.sep).join('/');
}
const line = n => Number.isSafeInteger(n) && n > 0 && n < 10000000 ? n : 1;
// Only explicitly selected identifiers survive. Never copy scanner messages, source or matches.
const identifier = s => typeof s === 'string' && /^[a-zA-Z0-9_.:/@+-]{1,200}$/.test(s) && !hasCredential(s) ? s : 'unclassified';
const hasCredential = s => /(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[A-Z0-9]{16}|bearer\s|(?:password|secret|token|api[_-]?key)\s*[=:])/i.test(s);
function value(s, pattern, max=200) {return typeof s === 'string' && s.length>0 && s.length<=max && pattern.test(s) && !hasCredential(s) ? s : null;}
const packageName = s => value(s,/^[A-Za-z0-9@][A-Za-z0-9_.:/@+-]*$/);
const version = s => value(s,/^[A-Za-z0-9][A-Za-z0-9._+!~:-]*$/);
const ecosystem = s => value(s,/^[A-Za-z][A-Za-z0-9 ._+-]*$/,50);
function purl(s) {
  const safe=value(s,/^pkg:[a-z][a-z0-9.+-]*\/[A-Za-z0-9._~!$&'()*+,;=:@%/?#-]+$/,600);
  if(!safe)return null;
  try {const decoded=decodeURIComponent(safe);if(/[\s\0-\x1f]/.test(decoded)||hasCredential(decoded)||/\b[a-z]+:\/\/[^/]*@/i.test(decoded))return null;} catch {return null;}
  return safe;
}
function advisoryUrl(s) {
  if(typeof s!=='string'||s.length>1000||/[\s\0-\x1f]/.test(s)||hasCredential(s))return null;
  try {
    const u=new URL(s);
    if(u.protocol!=='https:'||u.username||u.password||u.port||u.hostname.startsWith('[')||!u.hostname.includes('.')||/^(?:localhost|.*\.localhost|.*\.local)$/i.test(u.hostname)||require('node:net').isIP(u.hostname))return null;
    if(hasCredential(decodeURIComponent(u.pathname)))return null;
    // Query/fragment fields can carry access tokens and are unnecessary for source provenance.
    u.search='';u.hash='';return u.href;
  } catch {return null;}
}
const unique = values => [...new Map(values.map(v=>[JSON.stringify(v),v])).values()];
function dependencyMetadata(scanner,pkg,details={}) {
  const observation={scanner,ecosystem:ecosystem(details.ecosystem),name:packageName(pkg),detectedVersion:version(details.detectedVersion),purl:purl(details.purl),scannerPackageType:value(details.scannerPackageType,/^[A-Za-z0-9_-]+$/,50)};
  return {packageDetails:{ecosystem:observation.ecosystem,name:observation.name,detectedVersion:observation.detectedVersion,purl:observation.purl,observations:[observation]},
    affectedRanges:details.affectedRanges||[],fixedVersions:unique((details.fixedVersions||[]).map(version).filter(Boolean)),advisorySources:unique((details.advisorySources||[]).map(s=>({scanner,id:value(s.id,/^[A-Za-z0-9_.:/@+-]+$/),url:advisoryUrl(s.url)})).filter(s=>s.id||s.url))};
}
function osvMetadata(pkg,v) {
  const affectedRanges=[],fixedVersions=[],advisorySources=[];
  let truncated=false;
  const relevant=(Array.isArray(v.affected)?v.affected:[]).filter(a=>a.package?.name===pkg?.name&&(!pkg?.ecosystem||a.package?.ecosystem===pkg.ecosystem));
  for(const a of relevant.slice(0,64)) {
    const source=a.database_specific?.source;if(source)advisorySources.push({url:source});
    for(const range of (Array.isArray(a.ranges)?a.ranges:[]).slice(0,64)) {
      if(!['SEMVER','ECOSYSTEM','GIT'].includes(range.type)||!Array.isArray(range.events))continue;
      const events=[];
      for(const event of range.events.slice(0,256)) {
        const key=Object.keys(event||{}).find(k=>['introduced','fixed','last_affected','limit'].includes(k));
        const safe=key?version(event[key]):null;if(!safe)continue;
        events.push({[key]:safe});if(key==='fixed'&&range.type!=='GIT')fixedVersions.push(safe);
      }
      if(events.length)affectedRanges.push({type:range.type,events});
      if(range.events.length>256)truncated=true;
    }
    const versions=(Array.isArray(a.versions)?a.versions:[]).slice(0,1000).map(version).filter(Boolean);
    if(versions.length)affectedRanges.push({type:'EXPLICIT_VERSIONS',versions});
    if(a.ranges?.length>64||a.versions?.length>1000)truncated=true;
  }
  if(relevant.length>64)truncated=true;
  for(const ref of (Array.isArray(v.references)?v.references:[]).slice(0,64))if(ref.type==='ADVISORY')advisorySources.push({url:ref.url});
  return {...dependencyMetadata('osv',pkg?.name,{ecosystem:pkg?.ecosystem,detectedVersion:pkg?.version,purl:pkg?.purl,affectedRanges:unique(affectedRanges),fixedVersions,advisorySources}),truncated};
}
function parse(scanner, data, root) {
  const findings = [];
  const add = (file, start, end, rule, sev, kind, pkg, aliases = [], metadata) => {
    const location=safePath(root,file),safeRule=identifier(rule),startLine=line(start);
    const limitations=['project_impact_not_analyzed'];
    if(kind==='dependency') {
      if(!metadata?.packageDetails?.detectedVersion)limitations.push('detected_version_not_available');
      if(!metadata?.affectedRanges?.length)limitations.push('affected_range_not_available');
      if(!metadata?.fixedVersions?.length)limitations.push('fixed_version_not_available');
      if(metadata?.truncated)limitations.push('scanner_metadata_truncated');
    }
    findings.push({
      file: location, line: startLine, endLine: Math.max(startLine, line(end)),
      rule: safeRule, severity: severity(sev), kind, package: pkg ? identifier(pkg) : undefined,
      aliases: aliases.map(identifier).filter(x => x !== 'unclassified'), scanners: [scanner],
      message: {sast:'Potential unsafe code pattern', dependency:'Known vulnerable dependency', secret:'Potential exposed secret (value omitted)', misconfiguration:'Potential insecure configuration'}[kind],
      packageDetails:metadata?.packageDetails||null,
      vulnerability:{id:kind==='dependency'&&safeRule!=='unclassified'?safeRule:null,affectedRanges:metadata?.affectedRanges||[],fixedVersions:metadata?.fixedVersions||[],advisorySources:metadata?.advisorySources||[]},
      evidence:[{scanner,type:'scanner_finding',file:location,line:startLine,rule:safeRule}],
      impact:{status:'NOT_ANALYZED',confidence:'unknown'},limitations
    });
  };
  if (scanner === 'semgrep') {
    if (!Array.isArray(data.results) || !Array.isArray(data.errors)) throw new Error('Invalid Semgrep schema');
    for (const f of data.results) add(f.path, f.start?.line, f.end?.line, f.check_id, f.extra?.severity, 'sast');
  } else if (scanner === 'gitleaks') {
    if (!Array.isArray(data)) throw new Error('Invalid Gitleaks schema');
    for (const f of data) add(f.File, f.StartLine, f.EndLine, f.RuleID, 'HIGH', 'secret');
  } else if (scanner === 'osv') {
    if (!Array.isArray(data.results)) throw new Error('Invalid OSV schema');
    for (const r of data.results) {
      if (!Array.isArray(r.packages)) throw new Error('Invalid OSV packages');
      for (const p of r.packages) for (const v of p.vulnerabilities || []) add(r.source?.path, 1, 1, v.id, v.database_specific?.severity, 'dependency', p.package?.name, v.aliases || [],osvMetadata(p.package,v));
    }
  } else if (scanner === 'trivy') {
    if (!Number.isInteger(data.SchemaVersion) || (data.Results !== undefined && !Array.isArray(data.Results))) throw new Error('Invalid Trivy schema');
    for (const r of data.Results || []) {
      for (const f of r.Vulnerabilities || []) add(r.Target, 1, 1, f.VulnerabilityID, f.Severity, 'dependency', f.PkgName,[],dependencyMetadata('trivy',f.PkgName,{detectedVersion:f.InstalledVersion,purl:f.PkgIdentifier?.PURL,scannerPackageType:r.Type,fixedVersions:typeof f.FixedVersion==='string'?f.FixedVersion.split(',').map(s=>s.trim()):[],advisorySources:f.DataSource?[{id:f.DataSource.ID,url:f.DataSource.URL}]:[]}));
      for (const f of r.Secrets || []) add(r.Target, f.StartLine, f.EndLine, f.RuleID, f.Severity, 'secret');
      for (const f of r.Misconfigurations || []) if (f.Status !== 'PASS') add(r.Target, f.CauseMetadata?.StartLine, f.CauseMetadata?.EndLine, f.ID, f.Severity, 'misconfiguration');
    }
  } else throw new Error('Unknown scanner');
  return findings;
}
function merge(findings) {
  const out = [];
  const rank = {unknown:0, info:1, low:2, medium:3, high:4, critical:5};
  for (const f of findings) {
    const ids = new Set([f.rule, ...f.aliases]);
    const matches = out.filter(x => x.file === f.file && x.kind === f.kind && x.package === f.package &&
      (f.kind === 'secret' ? x.line === f.line : f.kind === 'dependency' ? [x.rule,...x.aliases].some(id => ids.has(id)) : x.line === f.line && x.rule === f.rule));
    const combined = {...f, aliases: [...f.aliases], scanners: [...f.scanners]};
    for (const x of matches) {
      combined.aliases.push(x.rule, ...x.aliases); combined.scanners.push(...x.scanners);
      combined.endLine = Math.max(combined.endLine, x.endLine);
      if (rank[x.severity] > rank[combined.severity]) combined.severity = x.severity;
      if(combined.packageDetails||x.packageDetails) {
        const observations=unique([...(combined.packageDetails?.observations||[]),...(x.packageDetails?.observations||[])]);
        const packageDetails={observations};
        for(const field of ['ecosystem','name','detectedVersion','purl']) {
          const values=[...new Set(observations.map(o=>o[field]).filter(Boolean))];packageDetails[field]=values.length===1?values[0]:null;
          if(values.length>1)combined.limitations=unique([...(combined.limitations||[]),'conflicting_'+field]);
        }
        combined.packageDetails=packageDetails;
      }
      if(combined.vulnerability||x.vulnerability) {
        const a=combined.vulnerability||{},b=x.vulnerability||{};
        combined.vulnerability={id:a.id||b.id||null,affectedRanges:unique([...(a.affectedRanges||[]),...(b.affectedRanges||[])]),fixedVersions:unique([...(a.fixedVersions||[]),...(b.fixedVersions||[])]),advisorySources:unique([...(a.advisorySources||[]),...(b.advisorySources||[])])};
      }
      if(combined.evidence||x.evidence)combined.evidence=unique([...(combined.evidence||[]),...(x.evidence||[])]);
      if(combined.limitations||x.limitations)combined.limitations=unique([...(combined.limitations||[]),...(x.limitations||[])]);
      out.splice(out.indexOf(x), 1);
    }
    combined.aliases = [...new Set(combined.aliases)].sort(); combined.scanners = [...new Set(combined.scanners)].sort();
    if(combined.packageDetails?.detectedVersion)combined.limitations=combined.limitations?.filter(l=>l!=='detected_version_not_available');
    if(combined.vulnerability?.affectedRanges?.length)combined.limitations=combined.limitations?.filter(l=>l!=='affected_range_not_available');
    if(combined.vulnerability?.fixedVersions?.length)combined.limitations=combined.limitations?.filter(l=>l!=='fixed_version_not_available');
    out.push(combined);
  }
  return out.map(f => ({...f, id: crypto.createHash('sha256').update([f.file,f.kind,f.line,f.package || '',[f.rule,...f.aliases].sort().join(',')].join('|')).digest('hex').slice(0,24)}));
}
async function checkedFile(root, file) {
  const relative = safePath(root, file);
  const realRoot = await fs.realpath(root), real = await fs.realpath(path.join(root, relative));
  safePath(realRoot, real);
  if (!(await fs.stat(real)).isFile()) throw new Error('Not a file');
  return real;
}
module.exports = {parse, merge, safePath, checkedFile};
