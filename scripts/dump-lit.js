// dump-lit.js — 지정 VA 주변 hex + UTF-16 덤프
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
for (const va of process.argv.slice(2).map(x => parseInt(x, 16))) {
  const o = va2o(va);
  if (o == null) { console.log(`0x${va.toString(16)}: unmapped`); continue; }
  let hex = '';
  for (let i = 0; i < 32; i++) hex += buf[o + i].toString(16).padStart(2, '0') + ' ';
  let s = '';
  for (let i = 0; i < 16; i++) { const w = buf.readUInt16LE(o + i * 2); if (!w) break; s += String.fromCharCode(w); }
  console.log(`0x${va.toString(16)} hex: ${hex}`);
  console.log(`   utf16: ${JSON.stringify(s)}`);
}
