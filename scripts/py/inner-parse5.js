// inner-parse5.js — 0xbe 텍스트 확인, 0x8e 비-198 변형 구조, 0x8e 198B의 u16 정렬 가설 검증
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

// (1) 0xbe 앞 3개 풀덤프 + latin1 텍스트로
const be = frames.filter(f => f.type === '0xbe').slice(0, 3);
for (const f of be) {
  console.log(`--- #${f.n} S2C 0xbe plen=${f.len} ---`);
  const t = f.bytes.map(b => (b >= 0x20 && b < 0x7f) ? String.fromCharCode(b) : '.').join('');
  console.log(`  text: ${t}`);
  console.log(`  hex : ${f.bytes.slice(0, 64).map(x => x.toString(16).padStart(2, '0')).join(' ')}`);
}

// (2) 0x8e 비-198 변형: 길이별 첫 프레임 풀덤프
const seen = new Set();
for (const f of frames.filter(f => f.type === '0x8e')) {
  if (f.len === 198 || seen.has(f.len)) continue;
  seen.add(f.len);
  console.log(`--- #${f.n} S2C 0x8e plen=${f.len} ---`);
  for (let o = 0; o < f.len; o += 32) console.log(`  ${o.toString(16).padStart(3, '0')} ${f.bytes.slice(o, o + 32).map(x => x.toString(16).padStart(2, '0')).join(' ')}`);
  if (seen.size >= 4) break;
}

// (3) 0x8e 198B에서 마지막 2바이트가 아닌 "트레일러 있/없" 두 그룹의 byte0 분포 차이
const withTr = {}, noTr = {};
let wt = 0, nt = 0;
for (const f of frames.filter(f => f.type === '0x8e' && f.len === 198)) {
  const has = f.bytes[193] === 0xc8 && f.bytes[194] === 0xc8 && f.bytes[195] === 0x01 && f.bytes[196] === 0x49 && f.bytes[197] === 0x7f;
  const h = has ? withTr : noTr;
  if (has) wt++; else nt++;
  h[f.bytes[0]] = (h[f.bytes[0]] || 0) + 1;
}
console.log(`트레일러 있음=${wt} 없음=${nt}`);
console.log('있음 그룹 byte0 상위:', Object.entries(withTr).sort((a, b) => b[1] - a[1]).slice(0, 6).map(([k, v]) => `0x${(+k).toString(16)}:${v}`).join(' '));
console.log('없음 그룹 byte0 상위:', Object.entries(noTr).sort((a, b) => b[1] - a[1]).slice(0, 6).map(([k, v]) => `0x${(+k).toString(16)}:${v}`).join(' '));

// (4) u16 정렬 검증: 비제로 바이트의 홀/짝 오프셋(2..191) 비율
let odd = 0, even = 0;
for (const f of frames.filter(f => f.type === '0x8e' && f.len === 198).slice(0, 5000))
  for (let i = 2; i < 192; i++) if (f.bytes[i] !== 0) { if (i % 2) odd++; else even++; }
console.log(`비제로 바이트 홀오프셋=${odd} 짝오프셋=${even} (홀 비율 ${(odd / (odd + even) * 100).toFixed(1)}%)`);
