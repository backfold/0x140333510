// entropy.js — chunked entropy profile
'use strict';
const fs = require('fs');
const file = process.argv[2];
const chunk = parseInt(process.argv[3] || '65536', 10);
const buf = fs.readFileSync(file);
for (let off = 0; off < Math.min(buf.length, 64 * 1024 * 1024); off += chunk) {
  const b = buf.slice(off, Math.min(off + chunk, buf.length));
  const f = new Array(256).fill(0);
  for (const x of b) f[x]++;
  let h = 0;
  for (const c of f) { if (!c) continue; const p = c / b.length; h -= p * Math.log2(p); }
  console.log(`${off.toString(16).padStart(8, '0')} ${b.length.toString().padStart(8)} H=${h.toFixed(3)}`);
}
