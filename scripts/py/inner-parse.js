// inner-parse.js — 0x8e 벌크 프레임 페이로드에서 내부 [u16le sublen] 메시지 스트림 파싱 실험
import fs from 'fs';
const TAG = process.argv[2] || '0x8e';
const lines = fs.readFileSync('H:/SA_Analysis/logs/run1/decoded.log', 'latin1').split('\n');
const payloads = [];
let cur = null;
for (const line of lines) {
  const m = line.match(/^#(\d+) (C2S|S2C) type=(0x[0-9a-f]+) key=0x[0-9a-f]+ plen=(\d+)/);
  if (m) {
    if (cur && cur.type === TAG && cur.dir === 'S2C' && cur.len === 198) payloads.push(cur.bytes);
    cur = { type: m[3], dir: m[2], len: +m[4], bytes: [] };
    continue;
  }
  if (cur && /^[0-9a-f]{4}\s/.test(line)) {
    for (const h of line.slice(6, 6 + 96).trim().split(/\s+/)) { const b = parseInt(h, 16); if (!Number.isNaN(b)) cur.bytes.push(b); }
  }
}
if (cur && cur.type === TAG && cur.len === 198) payloads.push(cur.bytes);
console.log(`${TAG} plen=198 프레임 ${payloads.length}개`);

// 실험 A: 프레임 단위 파싱 (첫 u16=sublen 가정)
let a = { ok: 0, bad: 0, hist: {} };
for (const p of payloads.slice(0, 500)) {
  let off = 0;
  while (off + 2 <= 198) {
    const sl = p[off] | (p[off + 1] << 8);
    if (sl === 0 || off + 2 + sl > 198) { a.bad++; break; }
    a.ok++;
    const first = p[off + 2];
    a.hist[first] = (a.hist[first] || 0) + 1;
    off += 2 + sl;
  }
}
console.log(`A(프레임내 완결): ok=${a.ok} bad=${a.bad} first-byte 상위:`, Object.entries(a.hist).sort((x, y) => y[1] - x[1]).slice(0, 10).map(([k, v]) => `0x${(+k).toString(16)}:${v}`).join(' '));

// 실험 B: 전체 연결(스트림) 파싱 — 프레임 경계 무시
let b = { ok: 0, bad: 0, hist: {} };
let off = 0;
const total = payloads.length;
for (let fi = 0; fi < Math.min(total, 500); fi++) {
  const p = payloads[fi];
  // 스트림 버퍼에 append 방식 대신, 간단히: 프레임 시작이 항상 메시지 경계라는 가정은 A와 동일하므로
  // B는 "sublen이 프레임 끝을 넘어가면 다음 프레임으로 이어짐" 검증
  let o = 0;
  while (o + 2 <= 198) {
    const sl = p[o] | (p[o + 1] << 8);
    if (sl === 0) { b.bad++; break; }
    if (o + 2 + sl > 198) { b.bad++; break; } // 경계 넘침 — A와 동일 결과, 카운트만 분리
    b.ok++;
    const first = p[o + 2];
    b.hist[first] = (b.hist[first] || 0) + 1;
    o += 2 + sl;
  }
}
console.log(`B(동일기준 대조): ok=${b.ok} bad=${b.bad}`);

// 샘플: 앞 3개 프레임의 원시 페이로드 헤드 → 내부 구조 육안 확인
for (const p of payloads.slice(0, 3)) {
  console.log(`  head: ${p.slice(0, 24).map(x => x.toString(16).padStart(2, '0')).join(' ')}`);
}
// 대조: 마지막 3개
for (const p of payloads.slice(-2)) {
  console.log(`  tail: ${p.slice(0, 24).map(x => x.toString(16).padStart(2, '0')).join(' ')}`);
}
