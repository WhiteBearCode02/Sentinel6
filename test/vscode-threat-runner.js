const vscode=require('vscode');
const assert=require('node:assert/strict');
const path=require('node:path');
const fs=require('node:fs/promises');
const crypto=require('node:crypto');
async function run(){
 const root=path.resolve(__dirname,'..');
 const source=path.join(root,'fixtures','vulnerable','app.py');
 const hash=async()=>crypto.createHash('sha256').update(await fs.readFile(source)).digest('hex');
 const before=await hash();
 const ext=vscode.extensions.getExtension('sentinel6-local.sentinel6');assert.ok(ext);const api=await ext.activate();assert.ok(api.threat,'Threat subsystem not initialized in Electron');
 const initial=await api.threat.snapshot();assert.ok(initial.counts.advisories>0,'Real cached feed missing');
 await vscode.commands.executeCommand('sentinel6.threatFeed');
 const {ThreatFeed}=require('../src/threat/view');
 const provider=new ThreatFeed({snapshot:api.threat.snapshot},()=>false);
 try {
  const roots=await provider.getChildren();assert.ok(roots[0].label.includes('stops when VS Code closes'));
  const rows=await provider.getChildren(roots.find(r=>r.group==='advisories'));assert.ok(rows.length>0&&rows.length<=200);
  await vscode.commands.executeCommand('sentinel6.threatOpen',rows[0].id);
  const details=JSON.parse(vscode.window.activeTextEditor.document.getText());assert.equal(details.advisory.analysis_status,'NOT_ANALYZED');assert.ok(details.advisory.evidence_sources.length);
  const result=await vscode.commands.executeCommand('sentinel6.threatRefresh');assert.ok(result,'Manual refresh did not return a result');
  if(result.status==='failed'){const diagnostic=(await api.threat.snapshot()).monitor_diagnostic;console.log('Safe monitor diagnostic: '+JSON.stringify(diagnostic));}
  assert.notEqual(result.status,'failed','Manual refresh error: '+result.error);
  const updated=await api.threat.snapshot();const supported=updated.sources.filter(s=>s.status!=='disabled');
  assert.ok(supported.every(s=>['completed','partial'].includes(s.status)),'A live source failed in extension host');
  assert.equal(await hash(),before,'Target fixture was modified');
  const summary={vscode:vscode.version,treeRows:rows.length,realAdvisories:updated.counts.advisories,sqliteInExtensionHost:true,evidenceOpened:true,manualRefresh:result.status,sources:supported.map(s=>({id:s.id,status:s.status,last_success:s.last_success,pending:s.cursor})),sourceUnchanged:true,projectImpact:'NOT_ANALYZED'};
  await fs.writeFile(path.join(root,'reports','threat-vscode-summary.json'),JSON.stringify(summary,null,2));console.log(JSON.stringify(summary,null,2));
 } finally {provider.dispose();}
}
module.exports={run};
