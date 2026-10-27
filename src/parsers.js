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
const identifier = s => typeof s === 'string' && /^[a-zA-Z0-9_.:/@+-]{1,200}$/.test(s) ? s : 'unclassified';
function parse(scanner, data, root) {
  const findings = [];
  const add = (file, start, end, rule, sev, kind, pkg, aliases = []) => findings.push({
    file: safePath(root, file), line: line(start), endLine: Math.max(line(start), line(end)),
    rule: identifier(rule), severity: severity(sev), kind, package: pkg ? identifier(pkg) : undefined,
    aliases: aliases.map(identifier).filter(x => x !== 'unclassified'), scanners: [scanner],
    message: {sast:'Potential unsafe code pattern', dependency:'Known vulnerable dependency', secret:'Potential exposed secret (value omitted)', misconfiguration:'Potential insecure configuration'}[kind]
  });
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
      for (const p of r.packages) for (const v of p.vulnerabilities || []) add(r.source?.path, 1, 1, v.id, v.database_specific?.severity, 'dependency', p.package?.name, v.aliases || []);
    }
  } else if (scanner === 'trivy') {
    if (!Number.isInteger(data.SchemaVersion) || (data.Results !== undefined && !Array.isArray(data.Results))) throw new Error('Invalid Trivy schema');
    for (const r of data.Results || []) {
      for (const f of r.Vulnerabilities || []) add(r.Target, 1, 1, f.VulnerabilityID, f.Severity, 'dependency', f.PkgName);
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
      out.splice(out.indexOf(x), 1);
    }
    combined.aliases = [...new Set(combined.aliases)].sort(); combined.scanners = [...new Set(combined.scanners)].sort();
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
