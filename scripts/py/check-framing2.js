// check-framing2.js — sa-proxy Framer 로직 그대로 s2c.bin 재생: 첫 역직렬화 지점 프레임 단위 덤프
import fs from 'fs';
const buf = fs.readFileSync('H:/SA_Analysis/logs/run1/s2c.bin');
let off = 0, n = 0, desync = false;
const frames = [];
while (!desync && off + 2 <= buf.length) {
  const len = buf.readUInt16LE(off);
  const total = len + 2;
  if (len === 0 || total > 0x20000) { desync = true; break; }
  if (off + total > buf.length) { desync = 'tail'; break; }
  frames.push({ n: ++n, off, len, bytes: buf.subarray(off + 2, off + total) });
  off += total;
}
console.log(`프레임 ${n}개 소비, 끝=${off}/${buf.length} desync=${desync}`);
// 역직렬화 지점前后 프레임 5개 덤프 (프록시 로그의 #번호와 대조할 수 있게 LEN/선두바이트만)
for (let i = Math.max(0, frames.length - 5); i < frames.length; i++) {
  const f = frames[i];
  console.log(`  #${f.n} @0x${f.off.toString(16)} LEN=${f.len} head=${[...f.bytes.subarray(0, 12)].map(x => x.toString(16).padStart(2, '0')).join(' ')} tail=${[...f.bytes.subarray(-4)].map(x => x.toString(16).padStart(2, '0')).join(' ')}`);
}
if (desync === true) {
  console.log(`desync @0x${off.toString(16)}: len=${buf.readUInt16LE(off)} 바이트:`);
  for (let i = Math.max(0, off - 48); i < Math.min(buf.length, off + 64); i += 16) {
    console.log(`${i.toString(16).padEnd(7)} ${[...buf.subarray(i, i + 16)].map(x => x.toString(16).padStart(2, '0')).join(' ')}`);
  }
}
