// layer3-classify.js — 전 타입 분류: 평문 ASCII 최장런 / 0-반복률 / 이중쌍률 → 텍스트·인코딩·바이너리·암호 4분류 + 예시 수집
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

const clean = b => b >= 0x20 && b < 0x7f;
// 평문 후보 charset: 숫자/문장부호/대소문자
const txtch = b => (b >= 0x30 && b <= 0x39) || (b >= 0x41 && b <= 0x5a) || (b >= 0x61 && b <= 0x7a) || b === 0x20 || b === 0x2c || b === 0x2d || b === 0x28 || b === 0x29 || b === 0x3b || b === 0x7c;

const cls = {};
for (const f of frames) {
  if (f.len < 8) continue;
  const k = `${f.dir} ${f.type}`;
  // 최장 텍스트런
  let best = 0, run = 0, bestOff = 0;
  let zeros = 0, eq = 0, eqnz = 0;
  for (let i = 0; i < f.len; i++) {
    if (txtch(f.bytes[i])) { run++; if (run > best) { best = run; bestOff = i - run + 1; } } else run = 0;
    if (f.bytes[i] === 0) zeros++;
    if (i + 1 < f.len) { if (f.bytes[i] === f.bytes[i + 1]) { eq++; if (f.bytes[i] !== 0) eqnz++; } }
  }
  const c = cls[k] || (cls[k] = { n: 0, sumBest: 0, maxBest: 0, sumZero: 0, sumEqnz: 0, sumLen: 0, ex: null, exN: 0 });
  c.n++; c.sumBest += best; if (best > c.maxBest && f.len >= 30) { c.maxBest = best; c.exN = f.n; c.ex = f.bytes.map(b => clean(b) ? String.fromCharCode(b) : '.').join('').slice(0, 100); }
  c.sumZero += zeros; c.sumEqnz += eqnz; c.sumLen += f.len;
}

const rows = Object.entries(cls).map(([k, c]) => ({
  k, n: c.n,
  bestAvg: (c.sumBest / c.n).toFixed(1),
  zeroPct: (c.sumZero / c.sumLen * 100).toFixed(0),
  eqnzPct: (c.sumEqnz / (c.sumLen) * 100).toFixed(1),
  exN: c.exN, ex: c.ex,
})).sort((a, b) => b.n - a.n);

const out = ['dir/type | n | 최장텍스트런(평균) | 0비율% | 비제로 인접동일% | 예시프레임', '---|---|---|---|---|---'];
for (const r of rows.slice(0, 60)) out.push(`${r.k} | ${r.n} | ${r.bestAvg} | ${r.zeroPct} | ${r.eqnzPct} | #${r.exN} ${r.ex ? r.ex.replace(/\|/g, '!').slice(0, 60) : ''}`);
fs.writeFileSync('H:/SA_Analysis/logs/layer3-classify.txt', rows.map(r => `${r.k} n=${r.n} bestAvg=${r.bestAvg} zero%=${r.zeroPct} eqnz%=${r.eqnzPct} ex#${r.exN} "${r.ex || ''}"`).join('\n') + '\n');
console.log(out.join('\n'));
console.log('\n(전체 → logs/layer3-classify.txt)');
