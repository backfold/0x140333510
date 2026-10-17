// split-jsonl.js — REA MCP 출력 JSONL → decompiled/*.c 분리 (범용)
// 사용: node split-jsonl.js <session.jsonl> <축약어> [기록주소...]
import fs from 'fs';
const [file, tag] = process.argv.slice(2);
const lines = fs.readFileSync(file, 'utf8').replace(/^\uFEFF/, '').split('\n').filter(Boolean);
let n = 0;
for (const line of lines) {
  let o; try { o = JSON.parse(line); } catch { continue; }
  if (!o.ok || !o.result) continue;
  let res; try { res = JSON.parse(o.result); } catch { continue; }
  const items = res.items || (res.result && res.result.items) || [];
  for (const it of items) {
    if (!it.pseudocode || !it.address) continue;
    const name = `FUN_${it.address.replace(/^0x/, '').toLowerCase()}_${tag}.c`;
    fs.writeFileSync(`H:/SA_Analysis/decompiled/${name}`, it.pseudocode);
    console.log(`${name}: ${it.pseudocode.length}자 status=${it.status}`);
    n++;
  }
  if (!items.length && res.result && typeof res.result === 'object') {
    console.log(`[${o.tool}] keys=${Object.keys(res.result)} ${JSON.stringify(res.result).slice(0, 400)}`);
  }
}
console.log(`${n}개 디컴파일 저장`);
