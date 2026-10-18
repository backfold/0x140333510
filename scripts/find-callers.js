// find-callers.js — .text 전체에서 E8/E9 rel32 호출이 특정 VA로 향하는 위치 스캔
'use strict';
const fs = require('fs');
const exe = fs.readFileSync('H:\\SA_Analysis\\target\\suddenattack.exe');
const peOff = exe.readUInt32LE(0x3c);
const numSec = exe.readUInt16LE(peOff + 6);
const optSize = exe.readUInt16LE(peOff + 20);
const secBase = peOff + 24 + optSize;
const sections = [];
for (let i = 0; i < numSec; i++) {
  const s = secBase + i * 40;
  sections.push({
    name: exe.toString('ascii', s, s + 8).replace(/\0.*$/, ''),
    va: exe.readUInt32LE(s + 12), vsize: exe.readUInt32LE(s + 8),
    raw: exe.readUInt32LE(s + 20), rsize: exe.readUInt32LE(s + 16),
  });
}
const IMG = 0x140000000;
function off2va(off) {
  for (const s of sections)
    if (off >= s.raw && off < s.raw + s.rsize) return IMG + s.va + (off - s.raw);
  return null;
}
const targets = process.argv.slice(2).map(a => parseInt(a, 16));
const text = sections.find(s => s.name === '.text');
console.log(`.text: raw=0x${text.raw.toString(16)} size=0x${text.rsize.toString(16)}`);
for (const t of targets) {
  console.log(`\n=== callers of 0x${t.toString(16)} ===`);
  let n = 0;
  for (let off = text.raw; off < text.raw + text.rsize - 5; off++) {
    const op = exe[off];
    if (op !== 0xe8 && op !== 0xe9) continue;
    const rel = exe.readInt32LE(off + 1);
    const va = off2va(off);
    const dst = va + 5 + rel;
    if (dst === t) {
      console.log(`  0x${va.toString(16)}  ${op === 0xe8 ? 'CALL' : 'JMP'}`);
      n++;
    }
  }
  console.log(`  (${n} refs)`);
}
