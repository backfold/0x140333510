// pdata-func.js — .pdata에서 주어진 VA를 덮는 RUNTIME_FUNCTION 범위 출력
'use strict';
const fs = require('fs');
const buf = fs.readFileSync('H:\\SA_Analysis\\target\\suddenattack.exe');
const peOff = buf.readUInt32LE(0x3c);
const numSec = buf.readUInt16LE(peOff + 6);
const optSize = buf.readUInt16LE(peOff + 0x14);
const secBase = peOff + 0x18 + optSize;
let pdata = null;
for (let i = 0; i < numSec; i++) {
  const o = secBase + i * 40;
  const name = buf.toString('ascii', o, o + 8).replace(/\0+$/, '');
  if (name === '.pdata') pdata = { va: buf.readUInt32LE(o + 12), rawSize: buf.readUInt32LE(o + 16), rawPtr: buf.readUInt32LE(o + 20) };
}
const IMG = 0x140000000;
const targets = process.argv.slice(2).map(x => parseInt(x, 16));
const n = Math.floor(pdata.rawSize / 12);
for (const t of targets) {
  const r = t - IMG;
  let found = null;
  for (let i = 0; i < n; i++) {
    const o = pdata.rawPtr + i * 12;
    const b = buf.readUInt32LE(o), e = buf.readUInt32LE(o + 4);
    if (b <= r && r < e) { found = { b: IMG + b, e: IMG + e, uw: buf.readUInt32LE(o + 8) }; break; }
  }
  console.log(`0x${t.toString(16)}: ${found ? `func 0x${found.b.toString(16)}..0x${found.e.toString(16)} (size 0x${(found.e - found.b).toString(16)}) unwind=0x${(IMG + found.uw).toString(16)}` : '(pdata에 없음)'}`);
}
