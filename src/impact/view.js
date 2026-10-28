'use strict';
const vscode=require('vscode');
const path=require('node:path');
const {createSecurityService}=require('../security-service');
const {checkedFile}=require('../parsers');
const {ProjectImpactService}=require('./service');
function enabled(){return vscode.workspace.getConfiguration('sentinel6').inspect('projectAnalysis.enabled')?.globalValue===true;}
async function createProjectView(context,monitor,refresh){
  let service=null,initializing=null,binding=null,watcher=null,folders=[],disposed=false,generation=0;const timers=new Map();
  const register=(name,fn)=>context.subscriptions.push(vscode.commands.registerCommand('sentinel6.'+name,fn));
  const show=async data=>vscode.window.showTextDocument(await vscode.workspace.openTextDocument({language:typeof data==='string'?'markdown':'json',content:typeof data==='string'?data:JSON.stringify(data,null,2)}),{preview:true});
  const valid=()=>enabled()&&vscode.workspace.isTrusted&&!disposed;
  function stop(){generation++;initializing=null;binding?.dispose();binding=null;watcher?.dispose();watcher=null;service?.dispose();service=null;for(const t of timers.values())clearTimeout(t);timers.clear();}
  async function notify(s,workspaceId){
    if(!valid())return;const snapshot=await s.snapshot(workspaceId),events=snapshot.notifications;
    if(!events.length)return;
    const folder=folders[Number(workspaceId.split('-').at(-1))];
    void vscode.window.showWarningMessage(`Sentinel6 ${folder?.name||'project'}: ${[...new Set(events.map(e=>e.canonical_id))].slice(0,3).join(', ')} — high-risk declared dependency evidence changed. Review official fixes and runtime conditions.`, 'View Impact').then(choice=>{if(choice==='View Impact'&&valid())void s.report(workspaceId).then(show);});
    await s.acknowledge(events.map(e=>e.event_key));
  }
  async function ensure(){
    if(!valid())return null;if(service)return service;if(initializing)return initializing;
    const current=generation;
    const pending=(async()=>{
      folders=(vscode.workspace.workspaceFolders||[]).filter(f=>f.uri.scheme==='file');if(!folders.length)return null;
      const ids=folders.map((_f,i)=>'project-'+i),securityService=await createSecurityService({workspaces:folders.map((f,i)=>({id:ids[i],root:f.uri.fsPath}))});
      const s=new ProjectImpactService({securityService,file:monitor.file,workspaceIds:ids,onUpdate:async result=>{refresh();if(result.status==='completed'&&valid())await notify(s,result.workspaceId);}});
      await s.initialize();if(!valid()||current!==generation){s.dispose();return null;}service=s;binding=s.bindMonitor(monitor);
      watcher=vscode.workspace.createFileSystemWatcher('**/{package.json,package-lock.json,.npmrc,*.txt,*.in,pnpm-lock.yaml,yarn.lock,poetry.lock,uv.lock}');
      const changed=uri=>{
        if(!valid())return;
        folders.forEach((folder,i)=>{const relative=path.relative(folder.uri.fsPath,uri.fsPath);if(relative&&!path.isAbsolute(relative)&&relative!=='..'&&!relative.startsWith('..'+path.sep)){
          const id=ids[i];clearTimeout(timers.get(id));timers.set(id,setTimeout(()=>{timers.delete(id);if(valid())void s.analyze({workspaceId:id,reason:'dependency_change'}).catch(()=>refresh());},600));
        }});
      };
      watcher.onDidChange(changed);watcher.onDidCreate(changed);watcher.onDidDelete(changed);
      return s;
    })();
    initializing=pending;
    try{return await pending;}finally{if(initializing===pending)initializing=null;refresh();}
  }
  async function select(input){
    const s=await ensure();if(!s)return null;
    if(input!==undefined){if(typeof input!=='string'||!s.workspaceIds.includes(input))throw new Error('workspace_not_allowed');return {s,id:input};}
    if(folders.length===1)return {s,id:'project-0'};
    const choice=await vscode.window.showQuickPick(folders.map((f,i)=>({label:f.name,id:'project-'+i})));return choice?{s,id:choice.id}:null;
  }
  async function analyze(input,force=true){
    if(!vscode.workspace.isTrusted){vscode.window.showWarningMessage('Project impact requires a trusted workspace.');return {status:'untrusted'};}
    if(!enabled()){
      const answer=await vscode.window.showInformationMessage('Analyze local npm/PyPI dependency files against cached official advisories? This reads saved dependency files, stores local evidence, and never installs packages, edits project files or uploads project data.','Enable Project Analysis','Later');
      if(answer!=='Enable Project Analysis')return {status:'disabled'};
      await vscode.workspace.getConfiguration('sentinel6').update('projectAnalysis.enabled',true,vscode.ConfigurationTarget.Global);
    }
    const selected=await select(input);if(!selected)return {status:'disabled'};
    return vscode.window.withProgress({location:vscode.ProgressLocation.Notification,title:'Sentinel6: project dependency impact (local)',cancellable:true},async(_progress,token)=>{
      const c=new AbortController(),sub=token.onCancellationRequested(()=>c.abort());
      try{const r=await selected.s.analyze({workspaceId:selected.id,force,reason:'manual'},{signal:c.signal});refresh();return r;}
      catch(e){vscode.window.showWarningMessage(`Project analysis: ${e.code||'failed'}. Previous valid assessment is retained.`);return {status:'failed',error:e.code||'analysis_failed'};}
      finally{sub.dispose();}
    });
  }
  register('projectAnalyze',id=>analyze(id));register('projectReassess',id=>analyze(id));register('projectCancel',()=>service?.cancel());
  register('projectImpact',async id=>{const x=await select(id);if(!x){vscode.window.showInformationMessage('Enable Analyze Current Project to create a local impact assessment.');return;}const report=await x.s.report(x.id);if(report)return show(report);vscode.window.showInformationMessage('No project analysis yet. Run Analyze Current Project.');});
  register('projectMarkdown',async id=>{const x=await select(id);if(x){const report=await x.s.report(x.id,'markdown');if(report)return show(report);}});
  register('projectRelated',()=>vscode.commands.executeCommand('sentinel6ThreatFeed.focus'));
  register('projectHistory',async id=>{const x=await select(id);if(x)return show(await x.s.history(x.id));});
  register('projectEvidence',async(id,matchId)=>{const x=await select(id);if(x){const r=await x.s.report(x.id),match=r?.matches.find(m=>m.id===matchId);if(match)return show(match);}});
  register('projectOpenDependency',async(id,matchId)=>{
    try{const x=await select(id);if(!x)return;const loc=await x.s.dependencyLocation(id,matchId),folder=folders[Number(id.split('-').at(-1))];
      const file=await checkedFile(folder.uri.fsPath,loc.source_file),doc=await vscode.workspace.openTextDocument(vscode.Uri.file(file)),line=Math.min(Math.max(0,loc.line-1),doc.lineCount-1);
      return vscode.window.showTextDocument(doc,{selection:new vscode.Range(line,0,line,0)});
    }catch{vscode.window.showWarningMessage('Dependency location is unavailable or outside the registered workspace.');}
  });
  async function snapshots(){const s=await ensure();return s?Promise.all(s.workspaceIds.map(id=>s.snapshot(id))):[];}
  const api={enabled,analyze,ensure,snapshots,
    async children(node){
      if(!valid()){const row=new vscode.TreeItem('Project Impact: OFF — Analyze Current Project');row.command={command:'sentinel6.projectAnalyze',title:'Enable local analysis'};return [row];}
      const states=await snapshots();
      if(!node.workspaceId)return states.map((s,i)=>{const row=new vscode.TreeItem(`${folders[i]?.name||s.project_id.slice(0,8)}: ${s.latest?'analyzed dependency versions':'NOT_ANALYZED'}`,vscode.TreeItemCollapsibleState.Expanded);row.impactNode=true;row.workspaceId=s.workspaceId;return row;});
      const state=states.find(s=>s.workspaceId===node.workspaceId);if(!state)return [];
      if(node.category)return (state.latest?.matches||[]).filter(m=>node.category.includes(m.impact_status)).slice(0,200).map(m=>{
        const row=new vscode.TreeItem(`${m.canonical_id}: ${m.package.name} ${m.package.detected_version||'version unknown'}`,vscode.TreeItemCollapsibleState.Collapsed);row.description=m.impact_status;row.tooltip=`${m.version_result}; ${m.priority.level}. Runtime and attack path unverified.`;row.command={command:'sentinel6.projectEvidence',title:'View Evidence',arguments:[state.workspaceId,m.id]};row.impactNode=true;row.workspaceId=state.workspaceId;row.matchId=m.id;return row;
      });
      if(node.matchId){const row=new vscode.TreeItem('Open Dependency File');row.command={command:'sentinel6.projectOpenDependency',title:'Open Dependency File',arguments:[state.workspaceId,node.matchId]};const match=state.latest.matches.find(m=>m.id===node.matchId),intel=new vscode.TreeItem('Analyze Threat Details / Attack Conditions');intel.command={command:'sentinel6.intelligenceAnalyze',title:'Analyze Threat Details',arguments:[match.canonical_id]};return [row,intel];}
      const rows=[];if(state.error)rows.push(new vscode.TreeItem('Analysis error: '+state.error+'; last valid result retained'));
      const analyzeRow=new vscode.TreeItem('Analyze / Reassess Project');analyzeRow.command={command:'sentinel6.projectReassess',title:'Reassess Project',arguments:[state.workspaceId]};rows.push(analyzeRow);
      if(!state.latest)return [...rows,new vscode.TreeItem('NOT_ANALYZED: no saved assessment')];
      for(const [label,category]of [['Related dependency versions',['CONFIRMED_AFFECTED','POTENTIALLY_AFFECTED']],['More evidence required',['INSUFFICIENT_EVIDENCE']],['Version not affected',['NOT_AFFECTED']],['Mitigated / not analyzed',['MITIGATED','NOT_ANALYZED']]]){
        const count=state.latest.matches.filter(m=>category.includes(m.impact_status)).length,row=new vscode.TreeItem(`${label}: ${count}`,vscode.TreeItemCollapsibleState.Collapsed);row.impactNode=true;row.workspaceId=state.workspaceId;row.category=category;rows.push(row);
      }
      rows.push(new vscode.TreeItem(`Not project-linked: ${state.latest.unrelated_advisories}; identifier review-only: ${state.latest.review_required_total}`));
      rows.push(new vscode.TreeItem('Monitoring cache is not a full historical database; also run Scan Project.'));
      rows.push(new vscode.TreeItem(`Inventory ${state.latest.coverage.inventory.status}; ${state.inventory.dependencies.length} records; checked ${state.inventory.checked_at}`));
      rows.push(new vscode.TreeItem(`Current sources: ${state.current_sources.map(s=>s.id+':'+s.status+(s.stale?' (STALE)':'')).join(', ')||'none; NOT_ANALYZED'}`));
      rows.push(new vscode.TreeItem(`Local SQLite: ${Math.round(state.storage.bytes/1024)} KiB / 65536 KiB${state.storage.warning?' — STORAGE WARNING':''}`));
      const history=new vscode.TreeItem('View Impact History');history.command={command:'sentinel6.projectHistory',title:'View Impact History',arguments:[state.workspaceId]};rows.push(history);return rows;
    },
    async assessments(advisoryId){return (await snapshots()).flatMap(s=>(s.latest?.matches||[]).filter(m=>m.canonical_id===advisoryId).map(m=>({workspaceId:s.workspaceId,...m,security_intelligence:s.latest.security_intelligence?.items.find(i=>i.match_id===m.id)||null})));},
    async recordScannerReport(root,report){const s=await ensure();if(s){const index=folders.findIndex(f=>path.resolve(f.uri.fsPath)===path.resolve(root));if(index>=0){s.recordScannerReport('project-'+index,report);await s.analyze({workspaceId:'project-'+index,force:true});}}},
    reset:stop,
    dispose(){disposed=true;stop();}
  };
  async function startup(){if(valid())try{const s=await ensure();if(s)for(const id of s.workspaceIds)await s.analyze({workspaceId:id,reason:'startup'});}catch{refresh();}}
  context.subscriptions.push(api,vscode.workspace.onDidGrantWorkspaceTrust(()=>void startup()),vscode.workspace.onDidChangeConfiguration(e=>{if(e.affectsConfiguration('sentinel6.projectAnalysis.enabled')){if(!enabled())stop();else void startup();refresh();}}),vscode.workspace.onDidChangeWorkspaceFolders(()=>{stop();if(valid())void startup();refresh();}));
  if(valid())void startup();
  return api;
}
module.exports={createProjectView,enabled};
