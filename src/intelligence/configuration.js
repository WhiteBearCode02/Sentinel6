'use strict';
const fs=require('node:fs/promises');
const constants=require('node:fs').constants;
const {checkedFile}=require('../parsers');
const {readBounded}=require('../core');
async function configurationFacts(root,{signal}={}){
 const facts={schemaVersion:1,facts:[],limitations:['Declared project .npmrc only; environment, user/global npm config, runtime and installation are not verified.']};
 if(signal?.aborted)throw Object.assign(new Error('cancelled'),{code:'cancelled'});
 let file;try{file=await checkedFile(root,'.npmrc');}catch{facts.limitations.push('npmrc_missing_or_unsafe');return facts;}
 const h=await fs.open(file,constants.O_RDONLY|(constants.O_NOFOLLOW||0));
 try{if((await h.stat()).size>65536){facts.limitations.push('npmrc_size_limit');return facts;}
  const value=(await readBounded(h,65536)).toString('utf8'),matches=[];
  for(const [i,line]of value.split(/\r?\n/).entries()){
   const match=line.match(/^\s*ignore-scripts\s*=\s*(true|false)\s*(?:[;#].*)?$/i);if(match)matches.push({value:match[1].toLowerCase()==='true',line:i+1});
   else if(/^\s*ignore-scripts\s*=/i.test(line))facts.limitations.push('npm_ignore_scripts_value_unresolved');
  }
  if(matches.length===1&&!facts.limitations.includes('npm_ignore_scripts_value_unresolved'))facts.facts.push({name:'npm.ignore_scripts',value:matches[0].value,source_file:'.npmrc',line:matches[0].line,scope:'DECLARED_PROJECT_CONFIGURATION'});
  else facts.limitations.push('npm_ignore_scripts_missing_or_ambiguous');
 }finally{await h.close();}
 if(signal?.aborted)throw Object.assign(new Error('cancelled'),{code:'cancelled'});return facts;
}
module.exports={configurationFacts};
