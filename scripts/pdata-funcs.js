// pdata-funcs.js — resolve function bounds from .pdata RUNTIME_FUNCTION
// entries, then decompile targets can be picked precisely.
'use strict';
const fs = require('fs');
const file = process.argv[2];
const addrs = process.argv.slice(3).map((a) => parseInt(a, 16));
const buf = fs.readFileSync(file);
const peOff = buf.readUInt32LE(0x3c);
const n = buf.readUInt16LE(peOff + 6);
const opt = buf.readUInt16LE(peOff + 20);
const base = buf.readBigUInt64LE(peOff + 24 + 24);
const secs = {};
for (let i = 0; i < n; i++) {
  const s = peOff + 24 + opt + i * 40;
  const name = buf.toString('latin1', s, s + 8).replace(/\0+$/, '');
  secs[name] = { vaddr: buf.readUInt32LE(s + 12), rawptr: buf.readUInt32LE(s + 20), rawsize: buf.readUInt32LE(s + 16), vsize: buf.readUInt32LE(s + 8) };
}
const pd = secs['.pdata'];
const fns = [];
for (let o = pd.rawptr; o + 12 <= pd.rawptr + pd.rawsize; o += 12) {
  const start = buf.readUInt32LE(o), end = buf.readUInt32LE(o + 4);
  if (start && end > start) fns.push([start, end]);
}
fns.sort((a, b) => a[0] - b[0]);
console.log(`.pdata functions: ${fns.length}, imageBase=0x${base.toString(16)}`);
const rvaOf = (va) => va - Number(base);
for (const a of addrs) {
  const rva = rvaOf(a);
  // binary search
  let lo = 0, hi = fns.length - 1, hit = null;
  while (lo <= hi) { const m = (lo + hi) >> 1; if (fns[m][0] <= rva) { hit = m; lo = m + 1; } else hi = m - 1; }
  if (hit !== null && fns[hit][1] > rva) {
    console.log(`VA 0x${a.toString(16)} → function 0x${(Number(base) + fns[hit][0]).toString(16)} .. 0x${(Number(base) + fns[hit][1]).toString(16)} (size ${fns[hit][1] - fns[hit][0]})`);
  } else {
    console.log(`VA 0x${a.toString(16)} → no .pdata entry`);
  }
}
