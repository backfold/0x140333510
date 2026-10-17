// pkg-scan-index.js — v2: byte-granular scan for the index region start.
// Data region is CONFIRMED (Snow2, signed key load, subtract op, dataStart =
// N1+1+4+2*len). The index cipher uses key2 (FUN_14029f6b0) with the same
// mechanics; its region starts at dataStart + N2 + dataSize per FUN_1402aa700.
// Keystream is position-0-based and offset-independent, so precompute once.
// Entry format (FUN_140290e00/FUN_1402b18c0): u32 strlen, strlen*2 UTF-16LE
// bytes, 6*u32, u32 count, count*16B, 16B, [flag&0x10 -> +32B].
'use strict';
const fs = require('fs');
const TABLES = JSON.parse(fs.readFileSync('H:\\SA_Analysis\\evidence\\snow_tables_from_exe.json', 'utf8')).tables;
const T = {
  a: TABLES.snow_alpha_mul.words, ai: TABLES.snow_alphainv_mul.words,
  t0: TABLES.snow_T0.words, t1: TABLES.snow_T1.words, t2: TABLES.snow_T2.words, t3: TABLES.snow_T3.words,
};
const a_mul = (w) => (((w << 8) >>> 0) ^ T.a[(w >>> 24) & 0xff]) >>> 0;
const ainv_mul = (w) => ((w >>> 8) ^ T.ai[w & 0xff]) >>> 0;
const fsmT = (w) => (T.t0[w & 0xff] ^ T.t1[(w >>> 8) & 0xff] ^ T.t2[(w >>> 16) & 0xff] ^ T.t3[(w >>> 24) & 0xff]) >>> 0;
class Snow2 {
  constructor(key16, variant) {
    this.s = new Uint32Array(16); this.r1 = 0; this.r2 = 0;
    const b = key16;
    const sx = (x) => (x & 0x80 ? x - 256 : x) | 0;
    const w32 = (k) => variant === 'unsigned'
      ? ((b[4*k] << 24) | (b[4*k+1] << 16) | (b[4*k+2] << 8) | b[4*k+3]) >>> 0
      : ((sx(b[4*k]) << 24) | (sx(b[4*k+1]) << 16) | (sx(b[4*k+2]) << 8) | sx(b[4*k+3])) >>> 0;
    for (let k = 0; k < 4; k++) { const w = w32(k); this.s[15-k] = w; this.s[11-k] = ~w >>> 0; this.s[7-k] = w; this.s[3-k] = ~w >>> 0; }
    for (let k = 0; k < 32; k++) this.initStep(k % 16);
    this.refresh();
  }
  initStep(k) {
    const s = this.s;
    const out = (((this.r1 + s[(k+15)%16]) >>> 0) ^ this.r2) >>> 0;
    const ns = (a_mul(s[k]) ^ s[(k+2)%16] ^ ainv_mul(s[(k+11)%16]) ^ out) >>> 0;
    const tmp = (this.r2 + s[(k+5)%16]) >>> 0;
    s[k] = ns; this.r2 = fsmT(this.r1); this.r1 = tmp;
  }
  ksStep(k) {
    const s = this.s;
    const ns = (a_mul(s[k]) ^ s[(k+2)%16] ^ ainv_mul(s[(k+11)%16])) >>> 0;
    const tmp = (this.r2 + s[(k+5)%16]) >>> 0;
    const oldNext = s[(k+1)%16];
    s[k] = ns; this.r2 = fsmT(this.r1); this.r1 = tmp;
    return (((this.r1 + ns) >>> 0) ^ this.r2 ^ oldNext) >>> 0;
  }
  refresh() { this.ks = new Uint32Array(16); for (let k = 0; k < 16; k++) this.ks[k] = this.ksStep(k); this.ksPos = 0; }
  nextWord() { if (this.ksPos >= 16) this.refresh(); return this.ks[this.ksPos++]; }
}
function charSum(s) { let x = 0; for (const c of s) x = (x + c.charCodeAt(0)) >>> 0; return x; }

const file = process.argv[2], path = process.argv[3] || file.replace(/.*[\\/]/, '');
const buf = fs.readFileSync(file);
const n1 = (charSum(path) % 312) + 30;
const n2 = ((charSum(path) * 3) % 212) + 33;
const masked = buf.subarray(0, n1);
const key0 = Buffer.from(masked); for (let i = 0; i < n1; i++) key0[i] = (masked[i] >> 1) | (masked[i] & 0x80);
const len = (buf.readUInt32LE(n1 + 1) ^ (key0[0] & 0x80 ? key0[0] - 256 : key0[0])) >>> 0;
let headerStr = '';
for (let i = 0; i < len; i++) {
  const k = key0[i % n1] & 0x80 ? key0[i % n1] - 256 : key0[i % n1];
  headerStr += String.fromCharCode(buf.readUInt16LE(n1 + 5 + i * 2) ^ (k & 0xffff));
}
const dataStart = n1 + 5 + len * 2;
const str = path + headerStr, L = str.length;
const k1 = Buffer.alloc(16), k2 = Buffer.alloc(16);
for (let i = 0; i < 16; i++) {
  k1[i] = (i + (str.charCodeAt(i % L) & 0xff)) & 0xff;
  k2[i] = ((str.charCodeAt(L - (i % L) - 1) & 0xff) * ((i % 3) + 2) + i) & 0xff;
}
console.log(`file=${file} path="${path}" N1=${n1} N2=${n2} headerStr="${headerStr}" dataStart=${dataStart}`);
console.log(`key2 = ${[...k2].map((b) => b.toString(16).padStart(2, '0')).join(' ')}`);

const WIN = 64; // words = 256 bytes
const printable = (c) => (c >= 0x20 && c < 0x7f) || c === 0x5c || (c >= 0xac00 && c <= 0xd7a3);

for (const which of ['key2', 'key1']) {
  const key = which === 'key2' ? k2 : k1;
  for (const variant of ['nested', 'unsigned']) {
    const c = new Snow2(key, variant);
    const ks = [];
    for (let i = 0; i < WIN; i++) ks.push(c.nextWord());
    for (const op of ['sub', 'xor', 'add']) {
      // pre-decrypt map: at each byte offset o, word index is o/4 when aligned to
      // the region start; since region start is arbitrary, compute per offset.
      let hits = 0;
      for (let is = dataStart; is + 256 <= buf.length; is++) {
        // strlen = first u32 decrypted with ks[0]
        const w0 = buf.readUInt32LE(is);
        const p0 = op === 'xor' ? (w0 ^ ks[0]) >>> 0 : op === 'add' ? (w0 + ks[0]) >>> 0 : (w0 - ks[0]) >>> 0;
        if (p0 === 0 || p0 > 200) continue;
        // check up to 24 name chars: char j is in word 1 + (j>>1), half (j&1)
        let name = '', good = true, okc = 0;
        const nCheck = Math.min(p0, 24);
        for (let j = 0; j < nCheck; j++) {
          const wIdx = 1 + (j >> 1);
          const w = buf.readUInt32LE(is + wIdx * 4);
          const p = op === 'xor' ? (w ^ ks[wIdx]) >>> 0 : op === 'add' ? (w + ks[wIdx]) >>> 0 : (w - ks[wIdx]) >>> 0;
          const ch = (j & 1) === 0 ? p & 0xffff : (p >>> 16) & 0xffff;
          if (!printable(ch)) { good = false; break; }
          name += String.fromCharCode(ch);
          okc++;
        }
        if (!good || okc < Math.min(p0, 4)) continue;
        console.log(`[HIT ${which}/${variant}/${op}] off=${is} (0x${is.toString(16)}, dataStart+${is - dataStart}) strlen=${p0} "${name}"`);
        hits++;
        if (hits >= 12) break;
      }
    }
  }
}
console.log('scan done');
