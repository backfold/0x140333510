// dump-rdata.js — PE 섹션 매핑으로 특정 VA들의 UTF-16/ASCII 문자열 덤프
'use strict';
const fs = require('fs');
const buf = fs.readFileSync('H:\\SA_Analysis\\target\\suddenattack.exe');
const peOff = buf.readUInt32LE(0x3c);
const numSec = buf.readUInt16LE(peOff + 6);
const optSize = buf.readUInt16LE(peOff + 0x14);
const secBase = peOff + 0x18 + optSize;
const sections = [];
for (let i = 0; i < numSec; i++) {
  const o = secBase + i * 40;
  sections.push({
    name: buf.toString('ascii', o, o + 8).replace(/\0+$/, ''),
    va: buf.readUInt32LE(o + 12), rawSize: buf.readUInt32LE(o + 16), rawPtr: buf.readUInt32LE(o + 20),
    virtSize: buf.readUInt32LE(o + 8),
  });
}
const IMG = 0x140000000;
function vaToOff(va) {
  const r = va - IMG;
  for (const s of sections) if (r >= s.va && r < s.va + Math.max(s.rawSize, s.virtSize)) return s.rawPtr + (r - s.va);
  return null;
}
function offToVa(o) {
  for (const s of sections) if (o >= s.rawPtr && o < s.rawPtr + s.rawSize) return IMG + s.va + (o - s.rawPtr);
  return 0;
}
function dumpWStr(va, max = 64) {
  const off = vaToOff(va); if (off == null) return '(unmapped)';
  let s = '';
  for (let i = 0; i < max; i++) {
    const w = buf.readUInt16LE(off + i * 2);
    if (w === 0) break;
    s += String.fromCharCode(w);
  }
  return JSON.stringify(s);
}
for (const va of [0x140354950, 0x140354940, 0x140354960, 0x140354970]) {
  console.log(`0x${va.toString(16)}: ${dumpWStr(va)}`);
}
console.log('sections:', sections.map(s => `${s.name} va=0x${s.va.toString(16)} raw=0x${s.rawPtr.toString(16)} sz=0x${s.rawSize.toString(16)}`).join(' | '));
// 0x140354750..+0x400 UTF-16 문자열 스캔
const base = vaToOff(0x140354750);
const end = base + 0x400;
let i = base;
while (i < end) {
  let j = i, s = '';
  while (j + 2 <= end) {
    const w = buf.readUInt16LE(j);
    if (w >= 0x20 && w < 0x7f) { s += String.fromCharCode(w); j += 2; } else break;
  }
  if (s.length >= 3) {
    console.log(`0x${offToVa(i).toString(16)}: ${JSON.stringify(s)}`);
    i = j;
  } else i += 2;
}
