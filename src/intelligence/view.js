'use strict';
const vscode=require('vscode');
const {IntelligenceService}=require('./service');
function enabled(){return vscode.workspace.getConfiguration('sentinel6').inspect('securityNews.enabled')?.globalValue===true;}
function createIntelligenceView(context,monitor,impact,refresh){
 const service=new IntelligenceService({file:monitor.file});
 const show=async value=>vscode.window.showTextDocument(await vscode.workspace.openTextDocument({content:typeof value==='string'?value:JSON.stringify(value,null,2),language:typeof value==='string'?'markdown':'json'}),{preview:true});
 const register=(name,fn)=>context.subscriptions.push(vscode.commands.registerCommand('sentinel6.'+name,fn));
 async function select(id){
  if(typeof id==='string')return id;if(id!==undefined)throw new Error('invalid_parameters');
  const snapshot=await monitor.snapshot();const items=[...snapshot.advisories.map(a=>({label:a.canonical_id,description:a.title,id:a.canonical_id})),...snapshot.security_news.map(n=>({label:n.title,description:n.source,id:n.related_cve_ids[0]||n.related_ghsa_ids[0]||'NEWS-'+n.source_id.slice(0,24)}))];return (await vscode.window.showQuickPick(items))?.id;
 }
 async function analyze(id,part){
  if(!vscode.workspace.isTrusted)return {status:'untrusted'};
  try{id=await select(id);if(!id)return;
   return await vscode.window.withProgress({location:vscode.ProgressLocation.Notification,title:'Sentinel6: analyzing cached source evidence (local)',cancellable:true},async(_p,token)=>{
    const c=new AbortController(),sub=token.onCancellationRequested(()=>c.abort());
    try{const project=await impact.ensure();if(project)await project.tail.catch(()=>{});const analyzed=await service.analyze(id,{signal:c.signal});id=analyzed?.vulnerability_id||id;if(project)await project.reassess([{canonical_id:id}]);const report=await service.report(id,{format:part==='markdown'?'markdown':'json',projectAssessments:await impact.assessments(id)});if(!report)return;
     refresh();return show(typeof report==='string'?report:part==='conditions'?report.attack_conditions:part==='verification'?report.verification:report);
    }finally{sub.dispose();}
   });
  }catch(e){vscode.window.showWarningMessage('Security Intelligence unavailable: '+(['cancelled','store_busy','intelligence_result_limit','invalid_schema'].includes(e.code)?e.code:'analysis_failed')+'. Last valid data is retained.');return {status:'failed'};}
 }
 register('intelligenceAnalyze',id=>analyze(id));register('attackConditions',id=>analyze(id,'conditions'));register('verifySources',id=>analyze(id,'verification'));register('intelligenceReport',id=>analyze(id,'markdown'));
 register('newsRefresh',async()=>{
  if(!vscode.workspace.isTrusted)return {status:'untrusted'};
  if(!enabled()){
   const choice=await vscode.window.showInformationMessage('Enable reviewed Red Hat public API and Cisco Talos RSS metadata collection? No project upload or paid AI. Stores selected facts with original links and attribution; no article crawling. Daily collection runs only while VS Code is open and threat monitoring is enabled.','Enable Security News','Later');
   if(choice!=='Enable Security News')return {status:'disabled'};
   await vscode.workspace.getConfiguration('sentinel6').update('securityNews.enabled',true,vscode.ConfigurationTarget.Global);
  }
  monitor.setNewsEnabled(true);
  try{return await vscode.window.withProgress({location:vscode.ProgressLocation.Notification,title:'Sentinel6: refreshing reviewed security metadata',cancellable:true},async(_p,token)=>{
   const c=new AbortController(),sub=token.onCancellationRequested(()=>c.abort());try{const r=await monitor.refreshNews({force:true,signal:c.signal});refresh();return r;}finally{sub.dispose();}
  });}catch{refresh();vscode.window.showWarningMessage('Security News unavailable or busy. Previous cache retained; inspect source status and retry after cooldown.');return {status:'failed'};}
 });
 context.subscriptions.push(vscode.workspace.onDidChangeConfiguration(e=>{if(e.affectsConfiguration('sentinel6.securityNews.enabled')){monitor.setNewsEnabled(enabled());refresh();}}));
 return {service,analyze,enabled};
}
module.exports={createIntelligenceView,enabled};
