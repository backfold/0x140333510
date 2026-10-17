// check-batch3.js — 래퍼 {tool,args,ok,result} 구조 확정: result 문자열 원시 검사 후 항목 상태 출력
import fs from 'fs';
const file = 'H:/SA_Analysis/evidence/session33.jsonl';
const lines = fs.readFileSync(file, 'utf8').replace(/^\uFEFF/, '').split('\n').filter(x => x.trim());
const out = [];
for (const line of lines) {
  const j = JSON.parse(line);
  out.push(`tool=${j.tool} ok=${j.ok} resultLen=${typeof j.result === 'string' ? j.result.length : '(obj)'}`);
  if (typeof j.result !== 'string' || j.tool !== 'batch_decompile') continue;
  const s = j.result;
  out.push(`  head=${JSON.stringify(s.slice(0, 60))}`);
  out.push(`  tail=${JSON.stringify(s.slice(-80))}`);
  let r;
  try { r = JSON.parse(s); out.push('  PARSE OK'); }
  catch (e) { out.push(`  PARSE FAIL: ${e.message}`); continue; }
  const items = (r.normalized_result && r.normalized_result.items) || [];
  for (const it of items) {
    const p = it.procedure || {};
    const code = p.decompiled_code || it.decompiled_code || p.pseudocode || '';
    out.push(`  ${it.address} status=${p.status || it.status || '?'} err=${(p.error && p.error.code) || ''} codeLen=${typeof code === 'string' ? code.length : JSON.stringify(code).length}`);
  }
}
fs.writeFileSync('H:/SA_Analysis/logs/check-batch3.out.txt', out.join('\n'), 'utf8');
console.log(out.join('\n'));
