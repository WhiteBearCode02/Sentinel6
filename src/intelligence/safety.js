'use strict';
const {text,stable}=require('../threat/model');
const {hash}=require('../inventory/identity');
const {CollectionError}=require('../threat/http');
function clean(value,max=400){
 if(typeof value!=='string')return '';
 return text(value.replace(/<(script|style|pre|code)\b[^>]*>[\s\S]*?<\/\1\s*>/gi,' ').replace(/<[^>]*>/g,' ').replace(/(?:https?:\/\/)?[^\s<>]*:[^\s<>]*@[^\s<>]+/gi,'[REDACTED_URL]').replace(/\b(?:password|secret|token|api[_-]?key)\s*[=:]\s*["']?[^\s"'<>]+/gi,'[REDACTED]').replace(/\s+/g,' ').trim(),max);
}
function ids(value){const s=clean(value,8000);return [...new Set(s.match(/\bCVE-\d{4}-\d{4,19}\b|\bGHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}\b/g)||[])].sort().slice(0,50);}
function array(value,max=200){if(!Array.isArray(value)||value.length>max)throw new CollectionError('invalid_schema');return value;}
function bounded(value,max=128*1024){if(Buffer.byteLength(JSON.stringify(value))>max)throw new CollectionError('intelligence_result_limit');return value;}
function fingerprint(value){return hash(stable(value));}
function escape(value){return text(String(value??'UNKNOWN'),2000).replace(/\b(?:password|secret|token|api[_-]?key)\s*[=:]\s*["']?[^\s"'<>]+/gi,'[REDACTED]').replace(/[\\`*_{}\[\]()<>#!|]/g,'\\$&');}
module.exports={clean,ids,array,bounded,fingerprint,escape};
