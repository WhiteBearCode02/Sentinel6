const {test}=require('node:test');const assert=require('node:assert/strict');
const {matchVersion}=require('../src/impact/version-matcher');
const timeline=(events,type='SEMVER')=>({format:'osv',type,events});
const status=(eco,v,r)=>matchVersion(eco,v,r).status;
test('npm affected interval, fixed boundary and before introduction use semantic ordering',()=>{
 const ranges=[timeline([{introduced:'1.2.0'},{fixed:'1.10.0'}])];assert.equal(status('npm','1.9.0',ranges),'AFFECTED_VERSION');assert.equal(status('npm','1.10.0',ranges),'UNAFFECTED_VERSION');assert.equal(status('npm','1.1.9',ranges),'UNAFFECTED_VERSION');
});
test('OSV reintroduction and multiple ranges remain vulnerable after later introduction',()=>{
 const ranges=[timeline([{introduced:'1.0.0'},{fixed:'1.2.0'},{introduced:'2.0.0'},{fixed:'2.1.0'}])];assert.equal(status('npm','1.5.0',ranges),'UNAFFECTED_VERSION');assert.equal(status('npm','2.0.3',ranges),'AFFECTED_VERSION');assert.equal(status('npm','3.0.0',[...ranges,timeline([{introduced:'3.0.0'}])]),'AFFECTED_VERSION');
});
test('last_affected is inclusive while fixed and limit are exclusive',()=>{
 assert.equal(status('npm','2.0.0',[timeline([{introduced:'0'},{last_affected:'2.0.0'}])]),'AFFECTED_VERSION');assert.equal(status('npm','2.0.1',[timeline([{introduced:'0'},{last_affected:'2.0.0'}])]),'UNAFFECTED_VERSION');assert.equal(status('npm','2.0.0',[timeline([{introduced:'0'},{limit:'2.0.0'}])]),'UNAFFECTED_VERSION');
});
test('OSV compares prereleases while npm expression matching follows SemVer prerelease rules',()=>{
 assert.equal(status('npm','1.0.0-rc.1',[timeline([{introduced:'0'},{fixed:'1.0.0'}])]),'AFFECTED_VERSION');assert.equal(status('npm','1.0.0-rc.1',[{format:'github-advisory',range:'>=1.0.0-rc.1 <1.0.0'}]),'AFFECTED_VERSION');
});
test('PEP440 epochs, development, release candidates, post releases and release padding are not npm strings',()=>{
 const r=[timeline([{introduced:'1.0.dev1'},{fixed:'1.0.post1'}],'ECOSYSTEM')];assert.equal(status('PyPI','1.0rc1',r),'AFFECTED_VERSION');assert.equal(status('PyPI','1.0.post1',r),'UNAFFECTED_VERSION');assert.equal(status('PyPI','1!1.0',r),'UNAFFECTED_VERSION');assert.equal(status('PyPI','1.0',[{format:'explicit',versions:['1.0.0']}]),'AFFECTED_VERSION');assert.equal(status('npm','1.0rc1',r),'VERSION_UNKNOWN');
});
test('PyPI specifiers use PEP440 rather than accepting npm caret notation',()=>{
 assert.equal(status('PyPI','1.4.2',[{format:'github-advisory',range:'>=1.0, <2.0'}]),'AFFECTED_VERSION');assert.equal(status('PyPI','1.4.2',[{format:'github-advisory',range:'^1.0.0'}]),'RANGE_UNSUPPORTED');
});
test('PEP440 exclusive final bounds exclude that release prereleases even when prereleases are requested',()=>{
 assert.equal(status('PyPI','1.0rc1',[{format:'github-advisory',range:'>=1.0.dev1, <1.0'}]),'UNAFFECTED_VERSION');assert.equal(status('PyPI','1.0rc1',[{format:'github-advisory',range:'>=1.0.dev1, <2.0'}]),'AFFECTED_VERSION');
});
test('explicit lists and Git/unknown versions are distinguished without safe guesses',()=>{
 assert.equal(status('npm','1.0.0',[{format:'explicit',versions:['2.0.0']}]),'UNAFFECTED_VERSION');assert.equal(status('npm','1.0.0',[{type:'GIT',events:[{introduced:'abc'}]}]),'RANGE_UNSUPPORTED');assert.equal(status('npm',null,[timeline([{introduced:'0'}])]),'VERSION_UNKNOWN');assert.equal(status('npm','1.0.0',[]),'INSUFFICIENT_DATA');
});
test('unsupported interval combined with negative intervals never becomes unaffected',()=>{
 assert.equal(status('npm','2.0.0',[timeline([{introduced:'0'},{fixed:'1.0.0'}]),{type:'GIT'}]),'RANGE_UNSUPPORTED');assert.equal(status('npm','2.0.0',[timeline([{introduced:'0'}]),{type:'GIT'}]),'AFFECTED_VERSION');
});
test('unsorted events are sorted semantically and malformed event payloads fail conservatively',()=>{
 assert.equal(status('npm','1.1.0',[timeline([{fixed:'2.0.0'},{introduced:'1.0.0'}])]),'AFFECTED_VERSION');assert.equal(status('npm','1.0.0',[timeline([{introduced:'0',fixed:'2.0.0'}])]),'RANGE_UNSUPPORTED');
});
test('unpaired, overlapping or potentially truncated public events cannot imply safety',()=>{
 for(const events of [[{fixed:'1.0.0'},{introduced:'2.0.0'}],[{introduced:'0'},{introduced:'1.0.0'}],[{introduced:'0'},{fixed:'1.'+'0'.repeat(100)}]])assert.equal(status('npm','1.2.0',[timeline(events)]),'RANGE_UNSUPPORTED');
});
