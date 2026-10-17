// check-frames.js — RAW 블록 크기 vs 프레임 LEN 정합성: 멀티프레임 블록 탐지
import fs from 'fs';
const raw = fs.readFileSync('H:/SA_Analysis/logs/run1/packets.log', 'utf8');
const blocks = []; let dir = null, inRaw = false, bytes = [];
for (const line of raw.split('\n')) {
  if (line.startsWith('#') && line.includes('conn=')) { const m = line.match(/^#(\d+)\s+(C2S|S2C)/); if (m) { dir = m[2]; inRaw = false; bytes = []; } continue; }
  if (line.includes('-- RAW --')) { inRaw = true; continue; }
  if (line.startsWith('--')) { if (inRaw && dir && bytes.length) blocks.push({ idx: blocks.length, dir, raw: Uint8Array.from(bytes) }); inRaw = false; bytes = []; continue; }
  if (inRaw) { const m = line.match(/^\s*[0-9a-f]{4}\s+((?:[0-9a-f]{2,8}[ ])+)/); if (m) for (const h of m[1].trim().split(/\s+/)) if (/^[0-9a-f]{2}$/.test(h)) bytes.push(parseInt(h, 16)); }
}
let multi = 0, exact = 0, truncated = 0, noFrame = 0;
const multiExamples = [];
let off5 = 0;
for (const b of blocks.slice(0, 2000)) {
  const f = b.raw;
  if (f.length < 2) { noFrame++; continue; }
  const len = f[0] | (f[1] << 8);
  if (len + 2 === f.length) exact++;
  else if (len + 2 > f.length) truncated++;
  else {
    multi++;
    if (multiExamples.length < 8) multiExamples.push({ idx: b.idx, dir: b.dir, blkLen: f.length, len1: len });
    // 블록 내 프레임 개수 세기
    let p = 0, cnt = 0;
    while (p + 2 <= f.length) { const L = f[p] | (f[p + 1] << 8); if (L + 2 > f.length - p) break; p += L + 2; cnt++; }
    if (b.idx < 60) off5 += 0;
    if (multiExamples.length && multiExamples[multiExamples.length - 1].idx === b.idx) multiExamples[multiExamples.length - 1].frames = cnt;
  }
}
console.log(`블록 2000개 중: 정확(1프레임)=${exact} 멀티=${multi} 잘림=${truncated} 기타=${noFrame}`);
console.log('멀티 예시:', JSON.stringify(multiExamples));
// 첫 60블록 상세
console.log('\n== 첫 60블록: blkLen / frame1_len / 내부 프레임 수 ==');
for (const b of blocks.slice(0, 60)) {
  const f = b.raw; const len = f[0] | (f[1] << 8);
  let p = 0, cnt = 0, lens = [];
  while (p + 2 <= f.length) { const L = f[p] | (f[p + 1] << 8); if (L + 2 > f.length - p) { lens.push(`X${f.length - p}`); break; } p += L + 2; cnt++; lens.push(L); }
  console.log(`#${b.idx} ${b.dir} blk=${f.length} frames=${cnt} lens=${lens.slice(0, 12).join(',').slice(0, 90)}`);
}
