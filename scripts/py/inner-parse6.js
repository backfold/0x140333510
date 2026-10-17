// inner-parse6.js — 0xbe 가독성 시계열 + 단일바이트 XOR/시프트 가설 + 0x8e 198B 토큰 어휘 추출
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

// (1) 0xbe 가독성(인쇄가능 비율) 시계열: 처음 20 + 이후 10 간격 샘플
const be = frames.filter(f => f.type === '0xbe');
const pr = b => (b >= 0x20 && b < 0x7f) ? 1 : 0;
const samp = [];
for (let i = 0; i < be.length; i++) if (i < 20 || i % Math.floor(be.length / 20) === 0) samp.push(i);
console.log(`0xbe ${be.length}개. 인쇄가능 비율 시계열:`);
for (const i of samp) {
  const f = be[i];
  const r = f.bytes.reduce((a, b) => a + pr(b), 0) / f.len;
  console.log(`  #${f.n} plen=${f.len} printable=${(r * 100).toFixed(0)}%`);
}

// (2) #24에 단일바이트 XOR / ±시프트 → 인쇄가능 최대화?
const f24 = be.find(f => f.n === 24);
let best = [];
for (let k = 1; k < 256; k++) {
  let c = 0; for (const b of f24.bytes) { const x = (b ^ k) >>> 0; if (x >= 0x20 && x < 0x7f) c++; }
  best.push([c, `xor 0x${k.toString(16)}`]);
}
for (let k = 1; k < 128; k++) {
  let c1 = 0, c2 = 0;
  for (const b of f24.bytes) { const x = (b + k) & 0xff; if (x >= 0x20 && x < 0x7f) c1++; const y = (b - k + 256) & 0xff; if (y >= 0x20 && y < 0x7f) c2++; }
  best.push([c1, `+${k}`]); best.push([c2, `-${k}`]);
}
best.sort((a, b) => b[0] - a[0]);
console.log(`#24 원본 인쇄가능=${f24.bytes.reduce((a, b) => a + pr(b), 0)}/${f24.len}, 변환 상위:`, best.slice(0, 3).map(([c, t]) => `${t}:${c}`).join(' '));

// (3) 0x8e 198B '트레일러 있음' 그룹의 반복 토큰 어휘: 3바이트 트리그램 빈도 상위
const tri = {};
for (const f of frames.filter(f => f.type === '0x8e' && f.len === 198).slice(0, 20000)) {
  for (let i = 2; i < 190; i++) {
    if (f.bytes[i] === 0 && f.bytes[i + 1] === 0 && f.bytes[i + 2] === 0) continue;
    const k = `${f.bytes[i].toString(16).padStart(2, '0')} ${f.bytes[i + 1].toString(16).padStart(2, '0')} ${f.bytes[i + 2].toString(16).padStart(2, '0')}`;
    tri[k] = (tri[k] || 0) + 1;
  }
}
console.log('0x8e 트리그램 상위 15:', Object.entries(tri).sort((a, b) => b[1] - a[1]).slice(0, 15).map(([k, v]) => `${k}:${v}`).join(' | '));

// (4) 0xbe 트리그램도 (텍스트류 확인)
const triBe = {};
for (const f of be.slice(0, 300)) for (let i = 0; i < f.len - 2; i++) {
  const k = `${f.bytes[i].toString(16).padStart(2, '0')} ${f.bytes[i + 1].toString(16).padStart(2, '0')} ${f.bytes[i + 2].toString(16).padStart(2, '0')}`;
  triBe[k] = (triBe[k] || 0) + 1;
}
console.log('0xbe 트리그램 상위 10:', Object.entries(triBe).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([k, v]) => `${k}:${v}`).join(' | '));
