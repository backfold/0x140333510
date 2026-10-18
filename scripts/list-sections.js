// list-sections.js — PE 섹션 테이블 + 특정 VA 커버 여부
'use strict';
const fs = require('fs');
const exe = fs.readFileSync('H:\\SA_Analysis\\target\\suddenattack.exe');
console.log(`file size: 0x${exe.length.toString(16)}`);
const pe = exe.readUInt32LE(0x3c);
console.log(`PE off: 0x${pe.toString(16)}`);
const nsec = exe.readUInt16LE(pe + 6);
const optsz = exe.readUInt16LE(pe + 20);
const imgbase = exe.readUInt32LE(pe + 24 + 28); // OptionalHeader.ImageBase (PE32+ 24바이트 고정 헤더 뒤)
console.log(`sections: ${nsec}, optHdrSize: 0x${optsz.toString(16)}, imageBase: 0x${imgbase.toString(16)}`);
for (let i = 0; i < nsec; i++) {
  const s = pe + 24 + optsz + i * 40;
  const name = exe.toString('ascii', s, s + 8).replace(/\0.*$/, '');
  const vsz = exe.readUInt32LE(s + 8), va = exe.readUInt32LE(s + 12), rsz = exe.readUInt32LE(s + 16), raw = exe.readUInt32LE(s + 20);
  console.log(`  [${i}] ${name.padEnd(8)} va=0x${(imgbase + va).toString(16)} vsz=0x${vsz.toString(16)} raw=0x${raw.toString(16)} rsz=0x${rsz.toString(16)}`);
}
const target = parseInt(process.argv[2] || '140354950', 16);
for (let i = 0; i < nsec; i++) {
  const s = pe + 24 + optsz + i * 40;
  const vsz = exe.readUInt32LE(s + 8), va = exe.readUInt32LE(s + 12), rsz = exe.readUInt32LE(s + 16), raw = exe.readUInt32LE(s + 20);
  if (target >= imgbase + va && target < imgbase + va + Math.max(vsz, rsz)) {
    console.log(`0x${target.toString(16)} covered by ${exe.toString('ascii', s, s + 8)} (raw avail: ${target < imgbase + va + rsz ? 'YES' : 'no'})`);
  }
}
