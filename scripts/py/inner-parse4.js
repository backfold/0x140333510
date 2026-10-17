// inner-parse4.js — 0x8e 타임라인/인접 프로토콜/이중쌍 값 분포
import fs from 'fs';
const lines = fs.readFileSync('H:/SA_Analysis/logs/run1/decoded.log', 'latin1').split('\n');
const frames = [];
let cur = null;
for (const line of lines) {
  const m = line.match(/^#(\d+) (C2S|S2C) type=(0x[0-9a-f]+) key=0x[0-9a-f]+ plen=(\d+)/);
  if (m) {
    if (cur) frames.push(cur);
    cur = { n: +m[1], dir: m[2], type: m[3], len: +m[4], bytes: [] };
    continue;
  }
  if (cur && /^[0-9a-f]{4}\s/.test(line)) {
    for (const h of line.slice(6, 6 + 96).trim().split(/\s+/)) { const b = parseInt(h, 16); if (!Number.isNaN(b)) cur.bytes.push(b); }
  }
}
if (cur) frames.push(cur);
console.log(`총 프레임 ${frames.length} (마지막 #${frames[frames.length - 1].n})`);

// (1) 0x8e 크기 분포 + 프레임 번호 범위
const e8 = frames.filter(f => f.type === '0x8e');
const sizeH = {};
for (const f of e8) sizeH[f.len] = (sizeH[f.len] || 0) + 1;
console.log(`0x8e ${e8.length}개, 크기분포:`, Object.entries(sizeH).sort((a, b) => b[1] - a[1]).slice(0, 8).map(([k, v]) => `${k}:${v}`).join(' '));
console.log(`0x8e 프레임번호 범위: #${e8[0].n} ~ #${e8[e8.length - 1].n}, 전체 #1~#${frames[frames.length - 1].n}`);

// (2) 0x8e 구간 내 다른 타입 census
const inRange = frames.filter(f => f.n >= e8[0].n && f.n <= e8[e8.length - 1].n);
const cnt = {};
for (const f of inRange) { const k = `${f.dir} ${f.type}`; cnt[k] = (cnt[k] || 0) + 1; }
console.log(`구간内 상위:`, Object.entries(cnt).sort((a, b) => b[1] - a[1]).slice(0, 14).map(([k, v]) => `${k}:${v}`).join(' '));

// (3) 구간 진입 직전 25프레임 (게임 입장 핸드셰이크 찾기)
const pre = frames.filter(f => f.n < e8[0].n).slice(-25);
console.log('--- 0x8e 시작 직전 25프레임 ---');
for (const f of pre) console.log(`  #${f.n} ${f.dir} ${f.type} plen=${f.len} head=${f.bytes.slice(0, 8).map(x => x.toString(16).padStart(2, '0')).join(' ')}`);

// (4) 중간 30프레임 인터리빙 샘플
const midN = e8[Math.floor(e8.length / 2)].n;
console.log(`--- #${midN} 전후 30프레임 ---`);
for (const f of frames.filter(f => Math.abs(f.n - midN) < 15)) console.log(`  #${f.n} ${f.dir} ${f.type} plen=${f.len}`);

// (5) 이중쌍 값 히스토그램 (어떤 값이 겹치나)
const dblv = {};
for (const f of e8) if (f.len === 198)
  for (let i = 2; i < 191; i++) if (f.bytes[i] === f.bytes[i + 1] && f.bytes[i] !== 0) { dblv[f.bytes[i]] = (dblv[f.bytes[i]] || 0) + 1; }
console.log('이중쌍 값 상위:', Object.entries(dblv).sort((a, b) => b[1] - a[1]).slice(0, 16).map(([k, v]) => `0x${(+k).toString(16)}:${v}`).join(' '));

// (6) 0x8e 등장 이후 C2S 요청-응답 짝 후보: 구간 내 C2S 상위 타입 plen 분포
const c2sInRange = inRange.filter(f => f.dir === 'C2S');
const c2 = {};
for (const f of c2sInRange) { const k = `${f.type}/${f.len}`; c2[k] = (c2[k] || 0) + 1; }
console.log('구간内 C2S type/plen 상위:', Object.entries(c2).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([k, v]) => `${k}:${v}`).join(' '));
