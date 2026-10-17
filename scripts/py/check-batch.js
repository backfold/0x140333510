// check-batch.js — batch_decompile 결과 항목별 상태 (파일로 안전 출력)
import fs from 'fs';
const file = process.argv[2] || 'H:/SA_Analysis/evidence/session33.jsonl';
const lines = fs.readFileSync(file, 'utf8').replace(/^\uFEFF/, '').split('\n').filter(x => x.trim());
const out = [];
for (const line of lines) {
  let j;
  try { j = JSON.parse(line); } catch (e) { out.push(`PARSE-ERR line(${line.length}B): ${e.message.slice(0, 120)}`); continue; }
  if (j.operation !== 'batch_decompile') { out.push(`skip op=${j.operation || j.tool || '?'}`); continue; }
  const r = typeof j.result === 'string' ? JSON.parse(j.result) : j.result;
  if (!r) { out.push('result 없음 raw_result=' + (j.raw_result ? '있음' : 'null')); continue; }
  const items = (r.normalized_result && r.normalized_result.items) || r.items || [];
  out.push(`items=${items.length}`);
  for (const it of items) {
    const p = it.procedure || {};
    const st = p.status || it.status || '?';
    const err = (p.error && p.error.code) || (it.error && it.error.code) || '';
    const code = p.decompiled_code || it.decompiled_code || p.pseudocode || '';
    out.push(`${it.address} status=${st} err=${err} codeLen=${typeof code === 'string' ? code.length : JSON.stringify(code).length}`);
  }
}
fs.writeFileSync('H:/SA_Analysis/logs/check-batch.out.txt', out.join('\n'), 'utf8');
console.log(out.join('\n'));
