// inner-parse7.js — 런/인터리브 구조 판별: P[i]==P[i+1], P[i]==P[i+2], 런길이 분포, 짝수오프셋 서브스트림
import fs from 'fs';
const lines = fs.readFileSync('H:/SA_Analysis/logs/run1/decoded.log', 'latin1').split('\n');
const frames = [];
let cur = null;
for (const line of lines) {
  const m = line.match(/^#(\d+) (C2S|S2C) type=(0x[0-9a-f]+) key=0x[0-9a-f]+ plen=(\d+)/);
  if (m) { if (cur) frames.push(cur); cur = { n: +m[1], dir: m[2], type: m[3], len: +m[4], bytes: [] }; continue; }
  if (cur && /^[0-9a-f]{4}\s/.test(line)) {
    for (const h of line.slice(6, 6 + 96).trim().split(/\s+/)) { const b = parseInt(h, 16); if (!Number.isNaN(b)) cur.bytes.push(b); }
  }
}
if (cur) frames.push(cur);

function stats(name, list) {
  let eq1 = 0, eq2 = 0, eq1nz = 0, eq2nz = 0, tot = 0;
  const runLen = {};
  for (const f of list) {
    for (let i = 0; i + 2 < f.len; i++) {
      tot++;
      if (f.bytes[i] !== 0) {
        if (f.bytes[i] === f.bytes[i + 1]) eq1nz++;
        if (f.bytes[i] === f.bytes[i + 2]) eq2nz++;
      }
      if (f.bytes[i] === f.bytes[i + 1]) eq1++;
      if (f.bytes[i] === f.bytes[i + 2]) eq2++;
    }
    // 런 길이 (0 포함)
    let rl = 1;
    for (let i = 1; i <= f.len; i++) {
      if (i < f.len && f.bytes[i] === f.bytes[i - 1]) rl++;
      else { if (rl >= 3) runLen[rl] = (runLen[rl] || 0) + 1; rl = 1; }
    }
  }
  console.log(`${name}: n=${list.length} 위치수=${tot}`);
  console.log(`  P[i]==P[i+1]: ${(eq1 / tot * 100).toFixed(1)}% (비제로만 ${(eq1nz / tot * 100).toFixed(1)}%)  P[i]==P[i+2]: ${(eq2 / tot * 100).toFixed(1)}% (비제로 ${(eq2nz / tot * 100).toFixed(1)}%)`);
  console.log(`  런(>=3) 길이분포:`, Object.entries(runLen).sort((a, b) => b[1] - a[1]).slice(0, 6).map(([k, v]) => `${k}B:${v}`).join(' '));
}

stats('S2C 0x8e/198', frames.filter(f => f.type === '0x8e' && f.len === 198).slice(0, 5000));
stats('S2C 0xbe/198', frames.filter(f => f.type === '0xbe' && f.len === 198).slice(0, 5000));
stats('C2S 0x08/198 (대조: 하트비트)', frames.filter(f => f.type === '0x08' && f.dir === 'C2S' && f.len === 198).slice(0, 100));

// 0xbe #24: 런 축소(연속동일 1개로) 후 텍스트
const f24 = frames.find(f => f.n === 24);
const dedup = [];
for (const b of f24.bytes) if (dedup.length === 0 || dedup[dedup.length - 1] !== b) dedup.push(b);
console.log(`#24 런축소(${f24.len}→${dedup.length}B):`, dedup.slice(0, 80).map(b => (b >= 0x20 && b < 0x7f) ? String.fromCharCode(b) : '.').join(''));

// 0xbe #531 (printable 99%) 전문 텍스트 — '깨끗한' 사례가 어떤 모양인지
for (const n of [531, 513, 303]) {
  const f = frames.find(x => x.n === n);
  if (f) console.log(`#${n} 0xbe:`, f.bytes.map(b => (b >= 0x20 && b < 0x7f) ? String.fromCharCode(b) : '.').join('').slice(0, 120));
}
