'use strict';
const vscode=require('vscode');
const path=require('node:path');
const fs=require('node:fs/promises');
const {ThreatMonitor}=require('./monitor');
const {outsideProject}=require('../core');

class ThreatFeed {
  constructor(monitor,enabled) {this.monitor=monitor;this.enabled=enabled;this.change=new vscode.EventEmitter();this.onDidChangeTreeData=this.change.event;}
  refresh(){this.change.fire();}
  getTreeItem(item){return item;}
  async getChildren(item) {
    if(item?.impactNode)return this.projectView?.children(item)||[];
    let data;try{data=await this.monitor.snapshot();}catch{return [new vscode.TreeItem('Threat cache unavailable; retry refresh.')];}
    if(item?.group==='sources')return data.sources.map(s=>{
      const row=new vscode.TreeItem(`${s.name}: ${s.status}${s.stale?' · STALE / incomplete':''}`);
      row.tooltip=`Last successful window: ${s.last_success || 'never'}\nLast attempt: ${s.last_attempt || 'never'}\n${s.error || s.reason || ''}${s.cursor?'\nBacklog pending; catch-up is not complete.':''}`;
      row.command={command:'sentinel6.threatSource',title:'Source status',arguments:[s]};return row;
    });
    if(item?.group==='advisories')return data.advisories.map(a=>{
      const row=new vscode.TreeItem(`${a.canonical_id}: ${a.title}`);row.id=a.canonical_id;
      row.description=[a.kev_status===true?'KEV':'',a.withdrawn_at?'WITHDRAWN':'',...(a.change_type||[])].filter(Boolean).join(' · ');
      row.tooltip=`Public feed: ${a.analysis_status}. See Project Impact for workspace-specific assessments.\nFirst observed: ${a.first_seen_at}\nLast changed: ${a.last_changed_at}\nSources: ${a.evidence_sources.map(s=>s.source).join(', ')}`;
      row.command={command:'sentinel6.threatOpen',title:'View public evidence',arguments:[a.canonical_id]};return row;
    });
    const mode=new vscode.TreeItem(`Active monitoring: ${this.enabled()?'ON · daily':'OFF'} · stops when VS Code closes`);
    const scope=new vscode.TreeItem('Public threat metadata; project impact requires local analysis');
    const source=new vscode.TreeItem('Sources / freshness',vscode.TreeItemCollapsibleState.Expanded);source.group='sources';
    const feed=new vscode.TreeItem(`Threat Feed: ${data.counts.advisories} cached (latest 200)`,vscode.TreeItemCollapsibleState.Expanded);feed.group='advisories';
    const project=new vscode.TreeItem('Project Impact'+(this.projectView?.enabled()?'':' (OFF)'),vscode.TreeItemCollapsibleState.Expanded);project.impactNode=true;
    return [...(data.monitor_error?[new vscode.TreeItem('Monitoring error: '+data.monitor_error)]:[]),mode,scope,...(this.projectView?[project]:[]),source,feed];
  }
  dispose(){this.change.dispose();}
}
function userSetting(name,fallback) {return vscode.workspace.getConfiguration('sentinel6').inspect('threatMonitoring.'+name)?.globalValue ?? fallback;}
async function activateThreats(context) {
  // All intelligence data is extension-owned and must remain outside analyzed projects.
  const storage=path.join(context.globalStorageUri.fsPath,'threat-intelligence.sqlite');
  for(const folder of vscode.workspace.workspaceFolders || [])if(folder.uri.scheme==='file')await outsideProject(await fs.realpath(folder.uri.fsPath),storage);
  const monitor=new ThreatMonitor({file:storage,ecosystems:userSetting('ecosystems',['npm','PyPI']),retentionDays:userSetting('retentionDays',90)});
  await monitor.initialize();
  const feed=new ThreatFeed(monitor,()=>userSetting('enabled',true));
  monitor.onUpdate=()=>feed.refresh();
  const impact=await require('../impact/view').createProjectView(context,monitor,()=>feed.refresh());
  feed.projectView=impact;
  const tree=vscode.window.createTreeView('sentinel6ThreatFeed',{treeDataProvider:feed,showCollapseAll:true});
  const reg=(name,fn)=>context.subscriptions.push(vscode.commands.registerCommand('sentinel6.'+name,fn));
  const show=async(data)=>{const doc=await vscode.workspace.openTextDocument({content:JSON.stringify(data,null,2),language:'json'});return vscode.window.showTextDocument(doc,{preview:true});};
  reg('threatFeed',()=>vscode.commands.executeCommand('sentinel6ThreatFeed.focus'));
  reg('threatSource',state=>show(state));
  reg('threatOpen',async id=>{
    if(typeof id!=='string'||!/^[A-Za-z0-9_-]{1,150}$/.test(id))return;
    const data=await monitor.advisory(id);if(data.advisory)await show({...data,analysis_time:new Date().toISOString(),project_assessments:await impact.assessments(id),project_impact_scope:'Only explicit package identifiers in analyzed inventories are linked. No linked result does not prove project safety.'});
  });
  reg('threatRefresh',async()=>{
    if(!vscode.workspace.isTrusted){vscode.window.showWarningMessage('Threat monitoring requires a trusted workspace.');return;}
    try {
      return await vscode.window.withProgress({location:vscode.ProgressLocation.Notification,title:'Sentinel6: collecting public threat metadata (no project upload)',cancellable:true},async(_p,token)=>{
        const c=new AbortController(),sub=token.onCancellationRequested(()=>c.abort());
        try {const r=await monitor.refresh({force:true,signal:c.signal});feed.refresh();vscode.window.showInformationMessage(`Threat collection: ${r.status}. ${r.changed.length} changed advisories. ${impact.enabled()?'Related project inventories were reassessed; see Project Impact.':'Project impact analysis is OFF.'}`);return r;}finally{sub.dispose();}
      });
    } catch {
      feed.refresh();vscode.window.showWarningMessage('Threat collection unavailable. Last valid cache is retained; see Threat Feed source status.');
      return {status:'failed',changed:[],error:monitor.lastError || 'collection_unavailable'};
    }
  });
  reg('threatCancel',()=>monitor.controller?.abort());
  reg('threatClear',async()=>{
    const answer=await vscode.window.showWarningMessage('Delete local threat advisories, collection history, HTTP cache, dependency inventories, impact evidence and notification history? Project source and scanner reports are not affected.',{modal:true},'Delete local threat data');
    if(answer!=='Delete local threat data')return;
    try{impact.reset();await monitor.clear();feed.refresh();}catch{vscode.window.showWarningMessage('Threat data is busy; cancel collection and retry.');}
  });
  const schedule=()=>{monitor.stop();if(vscode.workspace.isTrusted&&userSetting('enabled',true))monitor.start();feed.refresh();};
  context.subscriptions.push(monitor,feed,tree,vscode.workspace.onDidGrantWorkspaceTrust(schedule),vscode.workspace.onDidChangeConfiguration(e=>{
    if(e.affectsConfiguration('sentinel6.threatMonitoring.enabled'))schedule();
    if(e.affectsConfiguration('sentinel6.threatMonitoring.ecosystems')||e.affectsConfiguration('sentinel6.threatMonitoring.retentionDays'))vscode.window.showInformationMessage('Reload the VS Code window to apply threat source/retention settings.');
  }));
  schedule();
  return {snapshot:()=>monitor.snapshot(),refresh:options=>monitor.refresh(options),advisory:id=>monitor.advisory(id),storage,treeId:tree.id,impact};
}
module.exports={activateThreats,ThreatFeed};
