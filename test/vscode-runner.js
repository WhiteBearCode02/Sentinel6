// Executed by the installed VS Code extension host, not by node --test.
const vscode=require('vscode');
const assert=require('node:assert/strict');
const path=require('node:path');
const fs=require('node:fs/promises');
const {comparableReport}=require('./scan-comparison');
async function run(){
 const root=path.resolve(__dirname,'..');
 const extension=vscode.extensions.getExtension('sentinel6-local.sentinel6');
 assert.ok(extension,'Extension not discovered');const api=await extension.activate();assert.ok(api.threat,'Threat Intelligence failed to initialize');
 assert.equal(api.threat.impact.enabled(),false,'Scanner regression must not opt into project analysis');
 const commands=await vscode.commands.getCommands();
 for(const name of ['scan','cancel','status','results']) assert.ok(commands.includes('sentinel6.'+name));
 for(const name of ['threatFeed','threatRefresh','threatCancel','threatOpen','threatSource','threatClear'])assert.ok(commands.includes('sentinel6.'+name));
 for(const name of ['projectAnalyze','projectReassess','projectCancel','projectImpact','projectMarkdown','projectRelated','projectHistory','projectEvidence','projectOpenDependency'])assert.ok(commands.includes('sentinel6.'+name));
 for(const name of ['intelligenceAnalyze','attackConditions','verifySources','intelligenceReport','newsRefresh'])assert.ok(commands.includes('sentinel6.'+name));assert.equal(api.threat.intelligence.enabled(),false);
 await vscode.workspace.getConfiguration('sentinel6').update('executables',{
 semgrep:path.join(root,'.tools','semgrep','Scripts','semgrep.exe'),osv:path.join(root,'.tools','osv','osv-scanner.exe'),gitleaks:path.join(root,'.tools','gitleaks','gitleaks.exe'),trivy:path.join(root,'.tools','trivy','trivy.exe')
 },vscode.ConfigurationTarget.Global);
 await vscode.workspace.getConfiguration('sentinel6').update('caches',{trivy:path.join(root,'.cache','trivy'),osv:path.join(root,'.cache','osv')},vscode.ConfigurationTarget.Global);
 const result=await vscode.commands.executeCommand('sentinel6.scan');assert.ok(result?.scanId,'Shared service did not return a scan ID');
 const diagnostics=vscode.languages.getDiagnostics().flatMap(([uri,items])=>items.filter(d=>d.source?.startsWith('Sentinel6')).map(d=>({uri,d})));
 assert.ok(diagnostics.length>0,'No Problems diagnostics from real scan');
 const sast=diagnostics.find(x=>x.uri.fsPath.endsWith('app.py'));
 assert.ok(sast,'Semgrep Problems entry missing');
 assert.ok([3,5].includes(sast.d.range.start.line),'Wrong zero-based source line');
 const editor=await vscode.window.showTextDocument(sast.uri);
 editor.selection=new vscode.Selection(0,0,0,0);
 await vscode.commands.executeCommand('editor.action.marker.next');
 assert.ok(editor.selection.active.line>0,'Problem navigation did not select code');
 await vscode.commands.executeCommand('sentinel6.results');
 assert.ok(vscode.window.activeTextEditor.document.fileName.endsWith('.json'));
 const report=JSON.parse(vscode.window.activeTextEditor.document.getText());
 assert.ok(report.coverage && report.scanners.length===4);
 const cli=JSON.parse(await fs.readFile(path.join(root,'reports','shared-core-cli.json'),'utf8'));
 assert.deepEqual(comparableReport(report),comparableReport(cli.report),'CLI and VS Code report semantics differ');
 const summary={commandsRegistered:24,diagnostics:diagnostics.length,sourceLine:sast.d.range.start.line+1,problemNavigation:true,localReportOpened:true,threatInitialized:true,modelVersion:report.modelVersion,sharedCore:true,cliConsistent:true,projectAnalysisOff:true,securityNewsOff:true};
 await fs.mkdir(path.join(root,'reports'),{recursive:true});await fs.writeFile(path.join(root,'reports','vscode-summary.json'),JSON.stringify(summary,null,2));
 console.log('Sentinel6 VS Code extension host checks passed');
}
module.exports={run};
