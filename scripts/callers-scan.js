// callers-scan.js — find relative call/jmp sites (E8/E9 rel32) targeting the
// given VAs in a PE image. Local static scan.
'use strict';
const fs = require('fs');
const file = process.argv[2];
const targets = process.argv.slice(3).map((a) => BigInt(a));
const buf = fs.readFileSync(file);
const peOff = buf.readUInt32LE(0x3c);
const n = buf.readUInt16LE(peOff + 6);
const opt = buf.readUInt16LE(peOff + 20);
const base = buf.readBigUInt64LE(peOff + 24 + 24);
const secs = [];
for (let i = 0; i < n; i++) {
  const s = peOff + 24 + opt + i * 40;
  secs.push({ name: buf.toString('latin1', s, s + 8).replace(/\0+$/, ''), vaddr: buf.readUInt32LE(s + 12), rawptr: buf.readUInt32LE(s + 20), rawsize: buf.readUInt32LE(s + 16) });
}
const secByName = (nm) => secs.find((s) => s.name === nm);
const text = secByName('.text');
// VA <-> file offset
const vaToOff = (va) => { const rva = Number(va - base); for (const s of secs) if (rva >= s.vaddr && rva < s.vaddr + s.rawsize) return s.rawptr + (rva - s.vaddr); return null; };
for (const t of targets) {
  const tOff = vaToOff(t);
  console.log(`\ntarget 0x${t.toString(16)} (file 0x${tOff ? tOff.toString(16) : '?'})`);
  const hits = [];
  for (let o = text.rawptr; o + 5 <= text.rawptr + text.rawsize; o++) {
    const op = buf[o];
    if (op !== 0xe8 && op !== 0xe9) continue;
    const rel = buf.readInt32LE(o + 1);
    const dstOff = o + 5 + rel;
    if (dstOff === tOff) hits.push({ off: o, kind: op === 0xe8 ? 'call' : 'jmp' });
  }
  console.log(`  direct ${hits.length} site(s):`);
  for (const h of hits.slice(0, 30)) {
    const va = base + BigInt(text.vaddr + h.off - text.rawptr);
    console.log(`    ${h.kind} @file 0x${h.off.toString(16)} VA 0x${va.toString(16)}`);
  }
}
