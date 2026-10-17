// check-framing.js — s2c.bin 원시 스트림에서 u16 LEN 프레이밍 전수 검증 + 탈락 지점 기록
import fs from 'fs';
const buf = fs.readFileSync('H:/SA_Analysis/logs/run1/s2c.bin');
console.log(`s2c.bin ${buf.length}B`);
let off = 0, n = 0, breaks = [];
while (off + 2 <= buf.length) {
  const len = buf.readUInt16LE(off);
  if (len < 10 || len > 0x20000) { breaks.push({ off, len, head: [...buf.subarray(off, off + 16)] }); if (breaks.length > 8) break; off += 1; continue; }
  if (off + 2 + len > buf.length) { breaks.push({ off, len, tail: true }); break; }
  off += 2 + len; n++;
}
console.log(`정상 프레임 ${n}개, 최종 오프셋 ${off}/${buf.length}`);
console.log(`이탈 ${breaks.length}건:`);
for (const b of breaks) console.log(`  @0x${b.off.toString(16)} len=${b.len} ${b.tail ? 'TAIL' : ''} ${b.head ? b.head.map(x => x.toString(16).padStart(2, '0')).join(' ') : ''}`);
// 특정 지점 주변 덤프
const around = parseInt(process.argv[2] || '0', 16);
if (around) {
  console.log(`\n--- 0x${around.toString(16)} 주변 ---`);
  for (let i = Math.max(0, around - 32); i < Math.min(buf.length, around + 32); i += 16) {
    console.log(`${i.toString(16)}  ${[...buf.subarray(i, i + 16)].map(x => x.toString(16).padStart(2, '0')).join(' ')}`);
  }
}
