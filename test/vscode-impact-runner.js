'use strict';
const vscode=require('vscode'),assert=require('node:assert/strict'),path=require('node:path'),fs=require('node:fs/promises'),crypto=require('node:crypto');
const {withStore}=require('../src/threat/store'),model=require('../src/threat/model'),f=require('./threat-fixtures');
async function run(){
 const root=path.resolve(__dirname,'..'),project=vscode.workspace.workspaceFolders[0].uri.fsPath;
 const hash=async()=>{const out={};for(const n of ['package.json','package-lock.json','requirements.txt'])out[n]=crypto.createHash('sha256').update(await fs.readFile(path.join(project,n))).digest('hex');return out;};const before=await hash();
 const ext=vscode.extensions.getExtension('sentinel6-local.sentinel6'),api=await ext.activate();assert.ok(api.threat?.impact);
 await vscode.commands.executeCommand('sentinel6.projectAnalyze','project-0');
 const service=await api.threat.impact.ensure();let snap=await service.snapshot('project-0');
 const byName=()=>Object.fromEntries(snap.latest.matches.map(m=>[m.package.name,m]));let found=byName();
 assert.equal(found['fixture-package'].impact_status,'CONFIRMED_AFFECTED');assert.equal(found['fixture-fixed'].impact_status,'NOT_AFFECTED');assert.equal(found['fixture-unknown'].impact_status,'INSUFFICIENT_EVIDENCE');assert.equal(found['fixture-python'].impact_status,'CONFIRMED_AFFECTED');
 assert.ok(!snap.notifications.some(n=>n.canonical_id==='CVE-2099-99990002'));assert.equal(snap.notifications.length,0,'Local notification attempts should have persisted deduplication');
 await vscode.commands.executeCommand('sentinel6.projectImpact','project-0');assert.equal(JSON.parse(vscode.window.activeTextEditor.document.getText()).matches.length,4);
 await vscode.commands.executeCommand('sentinel6.projectEvidence','project-0',found['fixture-package'].id);const evidence=JSON.parse(vscode.window.activeTextEditor.document.getText());assert.ok(evidence.official_sources.length&&evidence.evidence_count>=2&&evidence.fixed_versions.includes('2.0.0'));assert.equal(evidence.attack_path_verified,false);
 await vscode.commands.executeCommand('sentinel6.projectOpenDependency','project-0',found['fixture-package'].id);assert.equal(vscode.window.activeTextEditor.document.uri.fsPath,path.join(project,'package-lock.json'));assert.ok(vscode.window.activeTextEditor.selection.active.line>0);
 const {ThreatFeed}=require('../src/threat/view'),provider=new ThreatFeed({snapshot:api.threat.snapshot},()=>false);provider.projectView=api.threat.impact;
 try{const roots=await provider.getChildren(),projects=await provider.getChildren(roots.find(r=>r.impactNode)),groups=await provider.getChildren(projects[0]);assert.ok(groups.some(g=>g.label==='Related dependency versions: 2'));assert.ok(groups.some(g=>g.label==='Version not affected: 1'));assert.ok(groups.some(g=>g.label==='More evidence required: 1'));assert.ok(roots.some(r=>r.group==='advisories'));}finally{provider.dispose();}
 // Simulate an official provider revision in this isolated fixture DB, not a real discovery.
 const change=await withStore(api.threat.storage,async s=>s.ingest(model.cisa(f.kev())[0],f.now));await service.reassess([change]);snap=await service.snapshot('project-0');assert.equal(byName()['fixture-package'].kev_status,true);assert.deepEqual(await hash(),before);
 const history=await service.history('project-0');const length=history.length;await vscode.commands.executeCommand('sentinel6.projectReassess','project-0');assert.equal((await service.history('project-0')).length,length,'Repeated evidence duplicated history');assert.equal((await service.snapshot('project-0')).notifications.length,0);
 await vscode.commands.executeCommand('sentinel6.projectMarkdown','project-0');assert.ok(vscode.window.activeTextEditor.document.getText().includes('Official fixed-version candidates'));
 await vscode.commands.executeCommand('sentinel6.projectHistory','project-0');assert.ok(JSON.parse(vscode.window.activeTextEditor.document.getText()).some(h=>h.data.kev_status===true));
 // Only the harness edits and restores its own generated fixture to exercise the actual watcher.
 const lockFile=path.join(project,'package-lock.json'),original=await fs.readFile(lockFile),lock=JSON.parse(original);
 async function waitState(expected){const end=Date.now()+15000;while(Date.now()<end){snap=await service.snapshot('project-0');if(byName()['fixture-package'].impact_status===expected)return;await new Promise(resolve=>setTimeout(resolve,100));}assert.fail('Dependency watcher did not reach '+expected);}
 try{lock.packages['node_modules/fixture-package'].version='2.0.0';await fs.writeFile(lockFile,JSON.stringify(lock,null,2));await waitState('NOT_AFFECTED');}
 finally{await fs.writeFile(lockFile,original);}
 await waitState('CONFIRMED_AFFECTED');assert.deepEqual(await hash(),before);
 const summary={fixture:true,advisories:'synthetic official-format test data; not real discoveries',vscode:vscode.version,scenarios:{affected:true,fixed:true,unknown:true,kevWithoutSourceChange:true,evidenceAndNavigation:true,existingFeed:true},matches:4,history:(await service.history('project-0')).length,sourceUnchanged:true,notificationsDeduplicated:true,dependencyInstalled:false,networkCollection:false,dependencyWatcherTransitions:2,testHarnessEditsRestored:true};
 await fs.mkdir(path.join(root,'reports'),{recursive:true});await fs.writeFile(path.join(root,'reports','impact-vscode-summary.json'),JSON.stringify(summary,null,2));console.log(JSON.stringify(summary,null,2));
}
module.exports={run};
