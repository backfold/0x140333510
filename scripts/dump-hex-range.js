// dump-hex-range.js — VA 범위 원시 hex 덤프 (디스어셈블 불가 영역 수동 분석용)
'use strict';
const fs = require('fs');
const buf = fs.readFileSync('H:\\SA_Analysis\\target\\suddenattack.exe');
const peOff = buf.readUInt32LE(0x3c);
const numSec = buf.readUInt16LE(peOff + 6);
const optSize = buf.readUInt16LE(peOff + 0x14);
const secBase = peOff + 0x18 + optSize;
const secs = [];
for (let i = 0; i < numSec; i++) {
  const o = secBase + i * 40;
  secs.push({ n: buf.toString('ascii', o, o + 8).replace(/\0+$/, ''), va: buf.readUInt32LE(o + 12), rs: buf.readUInt32LE(o + 16), rp: buf.readUInt32LE(o + 20) });
}
function va2o(va) {
  const r = va - 0x140000000;
  for (const s of secs) if (r >= s.va && r < s.va + s.rs) return s.rp + (r - s.va);
  return null;
}
const args = process.argv.slice(2).map(x => parseInt(x, 16));
for (let a = 0; a + 1 < args.length; a += 2) {
  let va = args[a], end = args[a + 1];
  console.log(`== ${va.toString(16)} .. ${end.toString(16)} ==`);
  let o = va2o(va);
  while (va < end) {
    let line = `${va.toString(16)}: `;
    for (let i = 0; i < 32 && va + i < end; i++) line += buf[o + i].toString(16).padStart(2, '0') + ' ';
    console.log(line);
    va += 32; o += 32;
  }
}
