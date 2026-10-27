const {test}=require('node:test');
const assert=require('node:assert/strict');
const {run,executable}=require('../src/process');
test('commands use literal arguments without shell interpretation',async()=>{
 const value='hello & echo unsafe; $(whoami)';const r=await run(process.execPath,['-e','process.stdout.write(process.argv[1])',value]);
 assert.equal(r.status,'completed');assert.equal(r.stdout,value);
});
test('stderr and inherited credential variables never become output',async()=>{
 process.env.SENTINEL6_TEST_SECRET='private-value';
 const r=await run(process.execPath,['-e',"console.error('private-value'); console.log(process.env.SENTINEL6_TEST_SECRET || 'absent')"]);
 delete process.env.SENTINEL6_TEST_SECRET;
 assert.equal(r.stdout.trim(),'absent');assert.ok(!JSON.stringify(r).includes('private-value'));
});
test('process timeout terminates execution',async()=>{const r=await run(process.execPath,['-e','setInterval(()=>{},1000)'],{timeout:100});assert.equal(r.reason,'timeout');});
test('cancellation kills running process',async()=>{const a=new AbortController();const p=run(process.execPath,['-e','setInterval(()=>{},1000)'],{signal:a.signal});setTimeout(()=>a.abort(),100);assert.equal((await p).status,'cancelled');});
test('pre-cancelled scans never launch',async()=>{const a=new AbortController();a.abort();assert.equal((await run(process.execPath,[],{signal:a.signal})).status,'cancelled');});
test('output is bounded',async()=>{const r=await run(process.execPath,['-e',"console.log('x'.repeat(100000))"],{limit:100});assert.equal(r.reason,'output_limit');assert.equal(r.stdout,undefined);});
test('invalid arguments and missing launch are failures',async()=>{assert.equal((await run('relative',['a'])).reason,'invalid_arguments');assert.equal((await run(process.execPath,['bad\narg'])).reason,'invalid_arguments');assert.equal((await run(process.execPath+'missing',[])).reason,'launch_failed');});
test('executable resolver distinguishes invalid paths and missing tools',async()=>{await assert.rejects(executable('tool','relative'));assert.equal(await executable('tool',process.execPath+'missing'),null);assert.equal(await executable('tool',process.execPath),await require('node:fs/promises').realpath(process.execPath));});
