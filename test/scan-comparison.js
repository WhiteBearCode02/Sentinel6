'use strict';
// Timestamps and tool duration describe separate executions. Everything else,
// including findings/metadata/IDs, coverage and snapshot scope, must agree.
function comparableReport(report) {
  const copy=JSON.parse(JSON.stringify(report));
  delete copy.startedAt;delete copy.finishedAt;
  copy.scanners=copy.scanners.map(s=>{delete s.durationMs;return s;});
  copy.findings.sort((a,b)=>a.id.localeCompare(b.id));return copy;
}
module.exports={comparableReport};
