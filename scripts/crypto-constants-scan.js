// crypto-constants-scan.js — fingerprint known crypto constants in a PE file.
// Read-only local scan; no execution.
'use strict';
const fs = require('fs');

const SIGS = [
  ['TEA/XTEA delta 0x9E3779B9', [0xb9, 0x79, 0x37, 0x9e]],
  ['TEA sum variant 0x61C88647', [0x47, 0x86, 0xc8, 0x61]],
  ['Blowfish P[0] 0x243F6A88 (pi)', [0x88, 0x6a, 0x3f, 0x24]],
  ['Blowfish P[1] 0x85A308D3', [0xd3, 0x08, 0xa3, 0x85]],
  ['MD5 init A 0x67452301', [0x01, 0x23, 0x45, 0x67]],
  ['MD5 init B 0xEFCDAB89', [0x89, 0xab, 0xcd, 0xef]],
  ['SHA1 init 0x67452301', [0x01, 0x23, 0x45, 0x67]],
  ['SHA256 init 0x6A09E667', [0x67, 0xe6, 0x09, 0x6a]],
  ['CRC32 poly 0x04C11DB7', [0xb7, 0x1d, 0xc1, 0x04]],
  ['CRC32 reflected 0xEDB88320', [0x20, 0x83, 0xb8, 0xed]],
  ['AES S-box head (63 7c 77 7b f2 6b 6f c5)', [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5]],
  ['AES Te0 head (c6 63 63 a5)', [0xc6, 0x63, 0x63, 0xa5]],
  ['AES Te1 head (a5 c6 63 63)', [0xa5, 0xc6, 0x63, 0x63]],
  ['Snow2 alpha_mul[1] (13 cf 9f e1)', [0x13, 0xcf, 0x9f, 0xe1]],
  ['Snow2 alphainv[1] (cd 40 0f 18)', [0xcd, 0x40, 0x0f, 0x18]],
  ['DES? 0x0A4F0419 / SP-box', [0x19, 0x04, 0x4f, 0x0a]],
  ['SEED? 0x9E3779B9-adj', [0xb9, 0x79, 0x37, 0x9e]],
  ['zlib 0x08320420 / adler', [0x20, 0x04, 0x32, 0x08]],
  ['zlib head 1.2.11 str', [0x31, 0x2e, 0x32, 0x2e, 0x31, 0x31, 0x00]],
];

for (const file of process.argv.slice(2)) {
  const buf = fs.readFileSync(file);
  console.log(`\n=== ${file} (${buf.length} bytes) ===`);
  // section map for VA reporting
  const peOff = buf.readUInt32LE(0x3c);
  const n = buf.readUInt16LE(peOff + 6);
  const opt = buf.readUInt16LE(peOff + 20);
  const base = buf.readBigUInt64LE(peOff + 24 + 24);
  const secs = [];
  for (let i = 0; i < n; i++) {
    const s = peOff + 24 + opt + i * 40;
    secs.push({ name: buf.toString('latin1', s, s + 8).replace(/\0+$/, ''), vaddr: buf.readUInt32LE(s + 12), rawptr: buf.readUInt32LE(s + 20), rawsize: buf.readUInt32LE(s + 16) });
  }
  const offToVa = (o) => { for (const s of secs) if (o >= s.rawptr && o < s.rawptr + s.rawsize) return (base + BigInt(s.vaddr + o - s.rawptr)).toString(16) + ' (' + secs.map((x) => x).filter((x) => o >= x.rawptr && o < x.rawptr + x.rawsize)[0].name + ')'; return '?'; };
  for (const [name, pat] of SIGS) {
    const needle = Buffer.from(pat);
    const hits = [];
    let i = 0;
    while ((i = buf.indexOf(needle, i)) !== -1 && hits.length < 6) { hits.push(i); i++; }
    if (hits.length) {
      console.log(`  ${name}: ${hits.length} hit(s)`);
      for (const h of hits) console.log(`    file 0x${h.toString(16)} → VA 0x${offToVa(h)}`);
    }
  }
}
