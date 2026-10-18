// find-refs.js — 대상 VA로의 E8 CALL 사이트와 포인터 참조를 원시 바이트에서 검색
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
  sections.push({ name: buf.toString('ascii', o, o + 8).replace(/\0+$/, ''), va: buf.readUInt32LE(o + 12), rawSize: buf.readUInt32LE(o + 16), rawPtr: buf.readUInt32LE(o + 20) });
}
const IMG = 0x140000000;
function offToVa(o) { for (const s of sections) if (o >= s.rawPtr && o < s.rawPtr + s.rawSize) return IMG + s.va + (o - s.rawPtr); return 0; }
function vaToOff(va) { const r = va - IMG; for (const s of sections) if (r >= s.va && r < s.va + s.rawSize) return s.rawPtr + (r - s.va); return null; }
const target = parseInt(process.argv[2], 16);
// 1) E8 rel32: call site 다음 명령 주소 + rel = target
const text = sections.find(s => s.name === '.text');
for (let o = text.rawPtr; o < text.rawPtr + text.rawSize - 5; o++) {
  if (buf[o] !== 0xe8) continue;
  const rel = buf.readInt32LE(o + 1);
  const siteVa = offToVa(o);
  if (siteVa + 5 + rel === target) console.log(`CALL 0x${siteVa.toString(16)} -> 0x${target.toString(16)}`);
}
// 2) 절대 주소 리틀엔디언 등장 (vtable/데이터 참조)
const pat = Buffer.alloc(8); pat.writeBigUInt64LE(BigInt(target));
let pos = 0;
while ((pos = buf.indexOf(pat, pos)) !== -1) {
  console.log(`PTR  @file 0x${pos.toString(16)} va 0x${offToVa(pos).toString(16)} -> 0x${target.toString(16)}`);
  pos++;
}
