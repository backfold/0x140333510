// split-session29.js v2 — {"tool","args","ok","result":"<json-string>"} 형식 처리
import fs from 'fs';
const raw = fs.readFileSync('H:/SA_Analysis/evidence/session29.jsonl', 'utf8').replace(/^\uFEFF/, '');
const lines = raw.split(/\r?\n/).filter(Boolean);
const outDir = 'H:/SA_Analysis/decompiled';
fs.mkdirSync(outDir, { recursive: true });
let saved = 0;
for (const ln of lines) {
  let o; try { o = JSON.parse(ln); } catch (e) { console.log('파싱 실패:', e.message); continue; }
  let res = o.result;
  if (typeof res === 'string') { try { res = JSON.parse(res); } catch { } }
  const items = res?.normalized_result?.items;
  if (Array.isArray(items)) {
    for (const it of items) {
      const name = (it.address || 'unk').replace(/^0x/, 'FUN_');
      const pc = it.pseudocode || '';
      fs.writeFileSync(`${outDir}/${name}_s29.c`, pc);
      console.log(`저장: ${name}_s29.c (${pc.length}자, status=${it.status})`);
      saved++;
    }
  } else if (o.tool === 'xrefs') {
    const s = JSON.stringify(res?.normalized_result ?? res);
    console.log(`\n=== xrefs ${o.args.address} ===`);
    console.log(s?.length > 2500 ? s.slice(0, 2500) + '...[trunc]' : s);
  } else {
    console.log(`(${o.tool} — 항목 없음)`);
  }
}
console.log(`\n총 ${saved}개 저장`);
