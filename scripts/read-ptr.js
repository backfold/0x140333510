// read-ptr.js — PE 파일에서 VA 배열(포인터) 덤프
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
function va2o(va) {
  for (const s of secs) if (va >= s.va && va < s.va + s.vsz) return s.raw + (va - s.va);
  return null;
}
const va = parseInt(process.argv[2], 16);
const n = parseInt(process.argv[3] || '16', 10);
const o = va2o(va);
console.log(`vtable @0x${va.toString(16)} (file off 0x${o.toString(16)}):`);
for (let i = 0; i < n; i++) {
  const p = exe.readUInt32LE(o + i * 4);
  console.log(`  [+0x${(i*4).toString(16).padStart(2,'0')}] 0x${(0x140000000 + p).toString(16)}`);
}
