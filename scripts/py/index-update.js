// index-update.js — session31~33 JSONL → evidence_index.tsv 행追加 (형식: sN\ttool\targs\tok)
import fs from 'fs';
const dir = 'H:/SA_Analysis/evidence/';
const idxPath = dir + 'evidence_index.tsv';
const existing = fs.readFileSync(idxPath, 'utf8');
const out = [];
for (const s of [31, 32, 33]) {
  const p = dir + `session${s}.jsonl`;
  if (!fs.existsSync(p)) { console.log(`session${s}: 파일 없음, 건너뜀`); continue; }
  const raw = fs.readFileSync(p, 'latin1').replace(/^\uFEFF/, '');
  let n = 0;
  for (const line of raw.split('\n')) {
    const t = line.trim();
    if (!t) continue;
    let rec;
    try { rec = JSON.parse(t); } catch { continue; }
    // wrapper: {tool,args,ok,result} — 실제 레코드만 (tool 문자열 있을 때)
    if (typeof rec.tool !== 'string') continue;
    out.push(`s${s}\t${rec.tool}\t${JSON.stringify(rec.args)}\t${rec.ok}`);
    n++;
  }
  console.log(`session${s}: ${n}레코드`);
}
fs.appendFileSync(idxPath, '\n' + out.join('\n') + '\n');
console.log(`추가 ${out.length}행 → evidence_index.tsv`);
