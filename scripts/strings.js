// strings.js — extract ASCII + UTF-16LE strings from a file, filterable.
// Usage: node strings.js <file> [minLen]
'use strict';
const fs = require('fs');
const file = process.argv[2];
const minLen = parseInt(process.argv[3] || '6', 10);
const buf = fs.readFileSync(file);
const out = [];
// ASCII
let cur = '';
for (let i = 0; i < buf.length; i++) {
  const c = buf[i];
  if (c >= 0x20 && c <= 0x7e) cur += String.fromCharCode(c);
  else { if (cur.length >= minLen) out.push({ off: i - cur.length, enc: 'a', s: cur }); cur = ''; }
}
if (cur.length >= minLen) out.push({ off: buf.length - cur.length, enc: 'a', s: cur });
// UTF-16LE
cur = '';
let start = 0;
for (let i = 0; i + 1 < buf.length; i += 2) {
  const c = buf[i], z = buf[i + 1];
  if (c >= 0x20 && c <= 0x7e && z === 0) cur += String.fromCharCode(c);
  else { if (cur.length >= minLen) out.push({ off: start, enc: 'u', s: cur }); cur = ''; start = i + 2; }
}
for (const o of out) console.log(`${o.off.toString(16).padStart(8, '0')}\t${o.enc}\t${o.s}`);
