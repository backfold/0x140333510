// inner-parse2.js — 0x8e(198B) 프레임 내부 구조 통계: 첫 u16 히스토그램, 마지막 비제로 오프셋, 0x0b/0x3a 필러 분포
import fs from 'fs';
const lines = fs.readFileSync('H:/SA_Analysis/logs/run1/decoded.log', 'latin1').split('\n');
const payloads = [];
let cur = null;
for (const line of lines) {
  const m = line.match(/^#(\d+) (C2S|S2C) type=(0x[0-9a-f]+) key=0x[0-9a-f]+ plen=(\d+)/);
  if (m) {
    if (cur && cur.type === '0x8e' && cur.dir === 'S2C' && cur.len === 198) payloads.push(cur.bytes);
    cur = { type: m[3], dir: m[2], len: +m[4], bytes: [] };
    continue;
  }
  if (cur && /^[0-9a-f]{4}\s/.test(line)) {
    for (const h of line.slice(6, 6 + 96).trim().split(/\s+/)) { const b = parseInt(h, 16); if (!Number.isNaN(b)) cur.bytes.push(b); }
  }
}
if (cur && cur.type === '0x8e' && cur.len === 198) payloads.push(cur.bytes);
console.log(`0x8e 198B 프레임 ${payloads.length}개`);

const firstU16 = {}, lastNonzero = {}, nonzeroCnt = {};
for (const p of payloads) {
  const u = p[0] | (p[1] << 8);
  firstU16[u] = (firstU16[u] || 0) + 1;
  let lnz = -1, nz = 0;
  for (let i = 0; i < 198; i++) if (p[i] !== 0) { lnz = i; nz++; }
  lastNonzero[lnz] = (lastNonzero[lnz] || 0) + 1;
  nonzeroCnt[nz] = (nonzeroCnt[nz] || 0) + 1;
}
console.log('first-u16 상위:', Object.entries(firstU16).sort((a, b) => b[1] - a[1]).slice(0, 8).map(([k, v]) => `0x${(+k).toString(16)}:${v}`).join(' '));
console.log('lastNonzeroOff 상위:', Object.entries(lastNonzero).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([k, v]) => `${k}:${v}`).join(' '));
console.log('nonzero바이트수 상위:', Object.entries(nonzeroCnt).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([k, v]) => `${k}:${v}`).join(' '));

// 전체 처음 4개 + 중간 2개 풀덤프
const idx = [0, 1, 2, 3, Math.floor(payloads.length / 2), payloads.length - 3];
for (const i of idx) {
  const p = payloads[i];
  console.log(`--- 프레임#${i} full ---`);
  for (let o = 0; o < 198; o += 32) {
    console.log(`  ${o.toString(16).padStart(3, '0')} ${p.slice(o, o + 32).map(x => x.toString(16).padStart(2, '0')).join(' ')}`);
  }
}
