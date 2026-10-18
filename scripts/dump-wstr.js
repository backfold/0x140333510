// dump-wstr.js — exe에서 VA의 UTF-16 리터럴 덤프 (dump-vtable.js 방식 매핑)
'use strict';
const fs = require('fs');
const exe = fs.readFileSync('H:\\SA_Analysis\\target\\suddenattack.exe');
const pe = exe.readUInt32LE(0x3c);
const nsec = exe.readUInt16LE(pe + 6);
const optsz = exe.readUInt16LE(pe + 20);
const secs = [];
for (let i = 0; i < nsec; i++) {
  const s = pe + 24 + optsz + i * 40;
  secs.push({
    name: exe.toString('ascii', s, s + 8).replace(/\0.*$/, ''),
    va: exe.readUInt32LE(s + 12), raw: exe.readUInt32LE(s + 20),
    vsz: exe.readUInt32LE(s + 8), rsz: exe.readUInt32LE(s + 16),
  });
}
function va2o(vaFull) {
  const va = vaFull - BASE;
  for (const s of secs) {
    if (va >= s.va && va < s.va + s.vsz) {
      // raw 매핑이 가능한 섹션만
      if (s.raw === 0 || s.rsz === 0) return { sec: s.name, o: null };
      const off = s.raw + (va - s.va);
      if (off >= exe.length) return { sec: s.name, o: null };
      return { sec: s.name, o: off };
    }
  }
  return { sec: '?', o: null };
}
const args = process.argv.slice(2).map((a) => parseInt(a, 16));
const BASE = 0x140000000;
for (const va of args) {
  const r = va2o(va);
  console.log(`0x${va.toString(16)}: sec=${r.sec}` + (r.o === null ? ' (no raw mapping — file-unavailable section)' : ''));
  if (r.o === null) continue;
  // UTF-16 최대 128글자까지
  let out = '', n = 0;
  while (n < 128) {
    const w = exe.readUInt16LE(r.o + n * 2);
    if (w === 0) break;
    out += String.fromCharCode(w);
    n++;
  }
  console.log(`  wstr(${n}): ${JSON.stringify(out)}`);
  console.log(`  hex: ${exe.subarray(r.o, r.o + Math.min(n * 2 + 8, 96)).toString('hex')}`);
}
