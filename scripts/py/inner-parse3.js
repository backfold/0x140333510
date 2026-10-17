// inner-parse3.js — 0x8e(198B) 구조 가설 검증: 트레일러 고정성, byte192 체크섬 가설, 이중바이트쌍 통계, 레코드 반복
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
const N = payloads.length;
console.log(`N=${N}`);

// (1) 트레일러 고정성: 193..197 전체 일치?
let trailerOK = 0, t192 = {};
for (const p of payloads) {
  if (p[193] === 0xc8 && p[194] === 0xc8 && p[195] === 0x01 && p[196] === 0x49 && p[197] === 0x7f) trailerOK++;
  t192[p[192]] = (t192[p[192]] || 0) + 1;
}
console.log(`트레일러 c8 c8 01 49 7f @193..197 일치: ${trailerOK}/${N}`);
console.log(`byte192 분포 상위:`, Object.entries(t192).sort((a, b) => b[1] - a[1]).slice(0, 12).map(([k, v]) => `0x${(+k).toString(16)}:${v}`).join(' '));

// (2) byte192 체크섬 가설: sum(0..191) mod 256, xor, sum(0..192) 포함, -0x25 등 변형
let sumHit = 0, xorHit = 0, sum192 = 0, addHit = 0, addInv = 0;
for (const p of payloads) {
  let s = 0, x = 0;
  for (let i = 0; i < 192; i++) { s = (s + p[i]) & 0xff; x ^= p[i]; }
  if (s === p[192]) sumHit++;
  if (x === p[192]) xorHit++;
  let s2 = (s + p[192]) & 0xff;
  if (s2 === 0) sum192++;
  if (((s + 0x25) & 0xff) === p[192]) addHit++;
  if (((0x100 - s) & 0xff) === p[192]) addInv++;
}
console.log(`chk 가설: sum(0..191)=b192 → ${sumHit}/${N}, xor → ${xorHit}/${N}, sum(0..192)=0 → ${sum192}/${N}, sum+0x25 → ${addHit}/${N}, -sum → ${addInv}/${N}`);

// (3) 첫 바이트 분포 + bytes[2..191] 콘텐츠: 첫 비제로 오프셋/마지막 비제로(트레일러 제외 192까지)
let b0 = {}, firstNz = {}, lastNzBody = {};
for (const p of payloads) {
  b0[p[0]] = (b0[p[0]] || 0) + 1;
  let fn = -1, ln = -1;
  for (let i = 2; i < 192; i++) if (p[i] !== 0) { if (fn < 0) fn = i; ln = i; }
  firstNz[fn] = (firstNz[fn] || 0) + 1;
  lastNzBody[ln] = (lastNzBody[ln] || 0) + 1;
}
console.log('byte0 상위:', Object.entries(b0).sort((a, b) => b[1] - a[1]).slice(0, 12).map(([k, v]) => `0x${(+k).toString(16)}:${v}`).join(' '));
console.log('byte1 상위는 위 first-u16 참조. body(2..191) 첫 비제로 오프셋 상위:', Object.entries(firstNz).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([k, v]) => `${k}:${v}`).join(' '));
console.log('body 마지막 비제로 오프셋 상위:', Object.entries(lastNzBody).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([k, v]) => `${k}:${v}`).join(' '));

// (4) 이중바이트쌍 (p[i]==p[i+1], i=2..190) 개수 분포 — 무작위 기대 = 189/256 ≈ 0.74
let dbl = 0;
for (const p of payloads) for (let i = 2; i < 191; i++) if (p[i] === p[i + 1] && p[i] !== 0) dbl++;
console.log(`비제로 이중쌍 총 ${dbl}개, 프레임당 평균 ${(dbl / N).toFixed(2)} (무작위 기대 ≈0.66)`);

// (5) 레코드 반복: 각 프레임에서 6바이트 윈도우가 2회 이상 등장하는 것 상위
const recHist = {};
for (const p of payloads) {
  const seen = new Set(), dup = new Set();
  for (let i = 2; i < 186; i++) {
    const w = ((p[i] << 16) | (p[i + 1] << 8) | p[i + 2]).toString(16) + '_' + ((p[i + 3] << 16) | (p[i + 4] << 8) | p[i + 5]).toString(16);
    if (seen.has(w)) dup.add(w); else seen.add(w);
  }
  for (const w of dup) if (!w.includes('_0_0') && !w.startsWith('0_')) recHist[w] = (recHist[w] || 0) + 1;
}
console.log('프레임내 2회+ 반복 6B윈도우 상위 12:', Object.entries(recHist).sort((a, b) => b[1] - a[1]).slice(0, 12).map(([k, v]) => `${k}:${v}`).join(' '));
