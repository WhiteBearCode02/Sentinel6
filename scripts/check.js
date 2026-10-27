'use strict';
const fs=require('node:fs');
const path=require('node:path');
const {spawnSync}=require('node:child_process');
function check(dir){for(const e of fs.readdirSync(dir,{withFileTypes:true})){const file=path.join(dir,e.name);if(e.isDirectory())check(file);else if(file.endsWith('.js')){const r=spawnSync(process.execPath,['--check',file],{encoding:'utf8',shell:false});if(r.status!==0){process.stderr.write(r.stderr);process.exitCode=1;}}}}
for(const dir of ['src','scripts','test'])check(dir);
if(!process.exitCode)console.log('All JavaScript syntax checks passed.');
