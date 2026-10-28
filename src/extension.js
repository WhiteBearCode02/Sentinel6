'use strict';
const vscode = require('vscode');
const path = require('node:path');
const {createSecurityService} = require('./security-service');
const {checkedFile} = require('./parsers');
let active;
async function activate(context) {
  const diagnostics = vscode.languages.createDiagnosticCollection('Sentinel6');
  const output = vscode.window.createOutputChannel('Sentinel6');
  let latest;
  const settings = () => {
    const cfg=vscode.workspace.getConfiguration('sentinel6');
    // Executable overrides are accepted only from user settings, never workspace settings.
    const caches=cfg.inspect('caches')?.globalValue || {};
    return {executables:cfg.inspect('executables')?.globalValue || {}, timeout:cfg.get('timeoutSeconds',120)*1000,cacheDir:caches.trivy,osvCacheDir:caches.osv};
  };
  const register=(name,fn)=>context.subscriptions.push(vscode.commands.registerCommand('sentinel6.'+name,fn));
  register('cancel',()=>active?.abort());
  register('status',async()=>{
    if (!vscode.workspace.isTrusted) return;
    output.clear();
    const folders=(vscode.workspace.workspaceFolders || []).filter(f=>f.uri.scheme==='file');
    if(!folders.length)return;
    const service=await createSecurityService({workspaces:folders.map((f,i)=>({id:'workspace-'+i,root:f.uri.fsPath})),scannerOptions:settings()});
    for (const s of await service.scannerStatus()) output.appendLine(`${s.scanner}: ${s.status} ${s.version || ''}\nInstallation: ${s.install || ''}`);
    output.show();
  });
  register('results',async()=>{if(latest) await vscode.window.showTextDocument(await vscode.workspace.openTextDocument(latest));});
  register('scan',async()=>{
    if (!vscode.workspace.isTrusted) {vscode.window.showWarningMessage('Sentinel6 requires a trusted workspace.');return;}
    if (active) {vscode.window.showInformationMessage('Sentinel6 scan is already running.');return;}
    const folders=(vscode.workspace.workspaceFolders || []).filter(f=>f.uri.scheme === 'file');
    const folder=folders.length === 1 ? folders[0] : (await vscode.window.showQuickPick(folders.map(f=>({label:f.name,folder:f}))))?.folder;
    if (!folder) return;
    active=new AbortController(); diagnostics.clear();output.clear();
    try {
      return await vscode.window.withProgress({location:vscode.ProgressLocation.Notification,title:'Sentinel6: scanning saved files',cancellable:true},async(progress,token)=>{
        const sub=token.onCancellationRequested(()=>active?.abort());
        try {
          const service=await createSecurityService({workspaces:[{id:'workspace',root:folder.uri.fsPath}],scannerOptions:{...settings(),reportDir:path.join(context.globalStorageUri.fsPath,'reports')}});
          const result=await service.scanWorkspace({workspaceId:'workspace'},{signal:active.signal,onProgress:s=>progress.report({message:s})});
          const {report,reportFile}=result;
          latest=vscode.Uri.file(reportFile);
          const byFile=new Map();
          for(const f of report.findings) {
            try {
              const file=await checkedFile(folder.uri.fsPath,f.file);
              const doc=await vscode.workspace.openTextDocument(vscode.Uri.file(file));
              const start=Math.min(f.line-1,doc.lineCount-1),end=Math.min(f.endLine-1,doc.lineCount-1);
              const d=new vscode.Diagnostic(new vscode.Range(start,0,end,doc.lineAt(end).text.length),`${f.message} [${f.rule}]`,['critical','high'].includes(f.severity) ? vscode.DiagnosticSeverity.Error : vscode.DiagnosticSeverity.Warning);
              d.source=`Sentinel6 (${f.scanners.join(', ')})`; d.code=f.rule;
              if(!byFile.has(file)) byFile.set(file,[]); byFile.get(file).push(d);
            } catch {output.appendLine('A result location is no longer available.');}
          }
          for(const [file,items] of byFile) diagnostics.set(vscode.Uri.file(file),items);
          for(const s of report.scanners) output.appendLine(`${s.scanner}: ${s.status}${s.reason ? ' ('+s.reason+')' : ''}${s.status === 'not_installed' ? '\nInstall: '+s.install : ''}`);
          for(const [area,c] of Object.entries(report.coverage)) output.appendLine(`${area}: completed=${c.completed.join(', ') || 'none'}; uncompleted=${c.uncompleted.map(x=>x.scanner+':'+x.status).join(', ') || 'none'}`);
          output.appendLine(`Snapshot: ${JSON.stringify(report.snapshot || {})}`);
          output.appendLine(`Findings: ${report.findings.length}\nReport: ${reportFile}`);output.show(true);
          const incomplete=report.scanners.some(s=>s.status !== 'completed');
          vscode.window.showInformationMessage(`Sentinel6: ${report.findings.length} findings. ${incomplete ? 'Some checks were not completed; see Sentinel6 output.' : 'Checks completed within documented coverage.'}`);
          return result;
        } finally {sub.dispose();}
      });
    } catch {vscode.window.showErrorMessage('Sentinel6 scan could not complete. Check project access and settings.');}
    finally {active=undefined;}
  });
  context.subscriptions.push(diagnostics,output,{dispose:()=>active?.abort()});
  let threat;
  try {threat=await require('./threat/view').activateThreats(context);}
  catch {
    output.appendLine('Threat Intelligence initialization failed. Scanner commands remain available.');
    context.subscriptions.push(vscode.window.registerTreeDataProvider('sentinel6ThreatFeed',{
      getTreeItem:item=>item,getChildren:()=>[new vscode.TreeItem('Threat Intelligence unavailable: check local storage, run npm ci --ignore-scripts, then reload.')]
    }));
  }
  return {threat};
}
function deactivate(){active?.abort();}
module.exports={activate,deactivate};
