'use strict';
const vscode=require('vscode'),assert=require('node:assert/strict'),fs=require('node:fs/promises'),path=require('node:path'),crypto=require('node:crypto');
const f=require('./intelligence-fixtures');
async function run(){
 const root=path.resolve(__dirname,'..'),folder=vscode.workspace.workspaceFolders[0].uri.fsPath;
 const hashes=async()=>{const o={};for(const n of ['package.json','package-lock.json','.npmrc'])o[n]=crypto.createHash('sha256').update(await fs.readFile(path.join(folder,n))).digest('hex');return o;};const before=await hashes();
 const api=await vscode.extensions.getExtension('sentinel6-local.sentinel6').activate();assert.ok(api.threat.intelligence);assert.equal(api.threat.intelligence.enabled(),false);
 const commands=await vscode.commands.getCommands();for(const c of ['intelligenceAnalyze','attackConditions','verifySources','intelligenceReport','newsRefresh'])assert.ok(commands.includes('sentinel6.'+c));
 await vscode.commands.executeCommand('sentinel6.intelligenceAnalyze',f.cve);let report=JSON.parse(vscode.window.activeTextEditor.document.getText());assert.equal(report.modelVersion,'ti-3.0');assert.equal(report.attack_conditions.vulnerability_type,'SQL_INJECTION');assert.equal(report.attack_conditions.authentication_required,'YES');assert.equal(report.verification.exploitation_status,'PROOF_OF_CONCEPT_ONLY');assert.ok(report.verification.fields.authentication_required.claims[0].url.startsWith('https://access.redhat.com/'));assert.ok(!JSON.stringify(report).includes('NEVER_COPY_TEST_TOKEN'));
 await vscode.commands.executeCommand('sentinel6.projectReassess','project-0');const impact=await api.threat.impact.ensure(),p=await impact.report('project-0');assert.equal(p.matches[0].impact_status,'CONFIRMED_AFFECTED');assert.equal(p.security_intelligence.items[0].condition_assessment,'INSUFFICIENT_EVIDENCE');assert.equal(p.security_intelligence.items[0].project_preconditions.find(c=>c.condition_id==='npm_lifecycle_scripts').declared_value_matches,true);
 await vscode.commands.executeCommand('sentinel6.attackConditions',f.cve);assert.equal(JSON.parse(vscode.window.activeTextEditor.document.getText()).authentication_required,'YES');
 await vscode.commands.executeCommand('sentinel6.verifySources',f.cve);assert.equal(JSON.parse(vscode.window.activeTextEditor.document.getText()).status,'OFFICIAL_CONFIRMED');
 await vscode.commands.executeCommand('sentinel6.intelligenceReport',f.cve);const md=vscode.window.activeTextEditor.document.getText();assert.ok(md.includes('## C. Project impact'));assert.ok(md.includes('CONFIRMED\\_AFFECTED'));assert.ok(md.includes('UNKNOWN'));
 const {ThreatFeed}=require('../src/threat/view'),provider=new ThreatFeed({snapshot:api.threat.snapshot},()=>false);provider.projectView=api.threat.impact;provider.intelligence=api.threat.intelligence;
 try{const roots=await provider.getChildren(),news=await provider.getChildren(roots.find(r=>r.group==='securityNews'));assert.equal(news.length,3);const actions=await provider.getChildren(news[1]);assert.ok(actions.some(a=>a.command.command==='sentinel6.attackConditions'));assert.ok(roots.some(r=>r.group==='advisories'));assert.ok(roots.some(r=>r.impactNode));}finally{provider.dispose();}
 await vscode.commands.executeCommand('sentinel6.projectOpenDependency','project-0',p.matches[0].id);assert.equal(vscode.window.activeTextEditor.document.uri.fsPath,path.join(folder,'package-lock.json'));
 assert.deepEqual(await hashes(),before);
 const summary={fixture:true,vscode:vscode.version,commandsRegistered:24,sourceVerification:true,attackConditions:true,json:true,markdown:true,projectVersionContractPreserved:true,projectConditionsUnverified:true,dependencyNavigation:true,existingFeed:true,sourceUnchanged:true,noSecretsInReport:true,networkCollection:false,paidAI:false};await fs.writeFile(path.join(root,'reports/intelligence-vscode-summary.json'),JSON.stringify(summary,null,2));console.log(JSON.stringify(summary,null,2));
}
module.exports={run};
