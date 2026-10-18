// dump-vtable.js — PE 섹션 매핑으로 VA→파일오프셋 변환 후 vtable qword 덤프
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
    va: exe.readUInt32LE(s + 12),
    vsize: exe.readUInt32LE(s + 8),
    raw: exe.readUInt32LE(s + 20),
    rsize: exe.readUInt32LE(s + 16),
  });
}
const IMG = 0x140000000n;
function va2off(va) {
  const rva = va - IMG;
  for (const s of sections) if (rva >= s.va && rva < s.va + Math.max(s.vsize, s.rsize)) return s.raw + Number(rva - BigInt(s.va));
  return null;
}
const va = BigInt('0x' + process.argv[2].replace(/^0x/, ''));
const off = va2off(va);
console.log(`VA 0x${va.toString(16)} → file offset 0x${off.toString(16)}`);
for (let i = 0; i < 24; i++) {
  const p = exe.readBigUInt64LE(off + i * 8);
  console.log(`  [+0x${(i * 8).toString(16).padStart(3, '0')}] 0x${p.toString(16)}`);
}
