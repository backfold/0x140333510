// check-batch2.js — operation 필드 원시 확인
import fs from 'fs';
const file = 'H:/SA_Analysis/evidence/session33.jsonl';
const lines = fs.readFileSync(file, 'utf8').replace(/^\uFEFF/, '').split('\n').filter(x => x.trim());
for (const line of lines) {
  const j = JSON.parse(line);
  const op = j.operation;
  console.log(`len=${line.length} op=${JSON.stringify(op)} codes=${[...String(op)].map(c => c.charCodeAt(0).toString(16)).join(' ')}`);
  console.log(`  keys=${Object.keys(j).join(',')}`);
  const r = typeof j.result === 'string' ? JSON.parse(j.result) : j.result;
  console.log(`  result type=${typeof j.result} keys=${r ? Object.keys(r).join(',') : 'null'}`);
  if (r && r.normalized_result) {
    const items = r.normalized_result.items || [];
    console.log(`  items=${items.length}`);
    for (const it of items) {
      const p = it.procedure || {};
      const st = p.status || it.status || '?';
      const err = (p.error && p.error.code) || (it.error && it.error.code) || '';
      const code = p.decompiled_code || it.decompiled_code || p.pseudocode || '';
      console.log(`  ${it.address} status=${st} err=${err} codeLen=${typeof code === 'string' ? code.length : JSON.stringify(code).length}`);
    }
  }
}
