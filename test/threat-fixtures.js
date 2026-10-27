'use strict';
const now='2026-10-28T00:00:00.000Z';
const cve='CVE-2099-99990001',ghsa='GHSA-2345-6789-cfgh';
function kev(ids=[cve]) {return {catalogVersion:'2026.10.28',dateReleased:now,count:ids.length,vulnerabilities:ids.map(cveID=>({cveID,vulnerabilityName:'Synthetic vulnerability',vendorProject:'fixture',product:'fixture-package',dateAdded:'2026-10-27',shortDescription:'fixture',requiredAction:'Apply vendor update',dueDate:'2026-11-20',cwes:['CWE-78']}))};}
function gh(extra={}) {return {ghsa_id:ghsa,cve_id:cve,summary:'Synthetic advisory',published_at:'2026-10-26T00:00:00Z',updated_at:'2026-10-27T00:00:00Z',withdrawn_at:null,severity:'high',identifiers:[{type:'CVE',value:cve},{type:'GHSA',value:ghsa}],cvss:{score:8.5,vector_string:'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'},vulnerabilities:[{package:{name:'fixture-package',ecosystem:'npm'},vulnerable_version_range:'< 2.0.0',first_patched_version:'2.0.0'}],...extra};}
function osv(extra={}) {return {id:ghsa,aliases:[cve],summary:'Synthetic OSV fixture',published:'2026-10-26T00:00:00Z',modified:'2026-10-27T00:00:00Z',affected:[{package:{name:'fixture-package',ecosystem:'npm',purl:'pkg:npm/fixture-package'},ranges:[{type:'SEMVER',events:[{introduced:'0'},{fixed:'2.0.0'}]}]}],...extra};}
const response=data=>({status:200,headers:{},etag:'"fixture"',last_modified:null,text:typeof data==='string'?data:JSON.stringify(data)});
module.exports={now,cve,ghsa,kev,gh,osv,response};
