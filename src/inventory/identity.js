'use strict';
const crypto=require('node:crypto');
const semver=require('semver');
const pep440=require('@renovatebot/pep440');
const credential=s=>/(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_|AKIA[A-Z0-9]{16}|(?:password|token|secret|api[_-]?key)\s*[=:])/i.test(s);
function normalizeName(ecosystem,name) {
  if(typeof name!=='string'||name.length>200||credential(name))return null;
  if(ecosystem==='npm')return /^(?:@[a-z0-9_.-]+\/)?[a-z0-9][a-z0-9_.-]*$/.test(name)?name:null;
  if(ecosystem==='PyPI')return /^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$/.test(name)?name.toLowerCase().replace(/[-_.]+/g,'-'):null;
  return null;
}
function exactVersion(ecosystem,value) {
  if(typeof value!=='string'||value.length>128||credential(value)||/[\s\0-\x1f]/.test(value))return null;
  try {return ecosystem==='npm'?semver.valid(value):ecosystem==='PyPI'&&pep440.valid(value)?pep440.clean(value):null;}catch{return null;}
}
const hash=s=>crypto.createHash('sha256').update(s).digest('hex');
const projectId=root=>hash(process.platform==='win32'?root[0].toUpperCase()+root.slice(1):root);
function purl(ecosystem,name,version){return version?`pkg:${ecosystem==='npm'?'npm':'pypi'}/${name.split('/').map(encodeURIComponent).join('/')}@${encodeURIComponent(version)}`:null;}
module.exports={normalizeName,exactVersion,hash,projectId,purl,credential};
