// pkg-dump-data.js — decrypt the whole tail from dataStart with key1 (confirmed
// working via [checksum][count] head) and dump readable structure for inspection.
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
  constructor(key16) {
    this.s = new Uint32Array(16); this.r1 = 0; this.r2 = 0;
    for (let k = 0; k < 4; k++) {
      const w = ((key16[4*k] << 24) | (key16[4*k+1] << 16) | (key16[4*k+2] << 8) | key16[4*k+3]) >>> 0;
      this.s[15 - k] = w; this.s[11 - k] = (~w) >>> 0; this.s[7 - k] = w; this.s[3 - k] = (~w) >>> 0;
    }
    for (let k = 0; k < 32; k++) this.initStep(k % 16);
    this.refresh();
  }
  initStep(k) {
    const s = this.s;
    const out = (((this.r1 + s[(k + 15) % 16]) >>> 0) ^ this.r2) >>> 0;
    const ns = (a_mul(s[k]) ^ s[(k + 2) % 16] ^ ainv_mul(s[(k + 11) % 16]) ^ out) >>> 0;
    const tmp = (this.r2 + s[(k + 5) % 16]) >>> 0;
    s[k] = ns; this.r2 = fsmT(this.r1); this.r1 = tmp;
  }
  ksStep(k) {
    const s = this.s;
    const ns = (a_mul(s[k]) ^ s[(k + 2) % 16] ^ ainv_mul(s[(k + 11) % 16])) >>> 0;
    const tmp = (this.r2 + s[(k + 5) % 16]) >>> 0;
    const oldNext = s[(k + 1) % 16];
    s[k] = ns; this.r2 = fsmT(this.r1); this.r1 = tmp;
    return (((this.r1 + ns) >>> 0) ^ this.r2 ^ oldNext) >>> 0;
  }
  refresh() { this.ks = new Uint32Array(16); for (let k = 0; k < 16; k++) this.ks[k] = this.ksStep(k); this.ksPos = 0; }
  nextWord() { if (this.ksPos >= 16) this.refresh(); return this.ks[this.ksPos++]; }
  decrypt(buf, off, len) {
    for (let i = 0; i < len; i += 4) {
      buf.writeUInt32LE((buf.readUInt32LE(off + i) - this.nextWord()) >>> 0, off + i);
    }
  }
}
function charSum(s) { let x = 0; for (const c of s) x = (x + c.charCodeAt(0)) >>> 0; return x; }

const file = process.argv[2], path = process.argv[3] || file.replace(/.*[\\/]/, '');
const buf = fs.readFileSync(file);
const n1 = (charSum(path) % 312) + 30;
const masked = buf.subarray(0, n1);
const key0 = Buffer.from(masked); for (let i = 0; i < n1; i++) key0[i] = (masked[i] >> 1) | (masked[i] & 0x80);
const len = (buf.readUInt32LE(n1 + 1) ^ (key0[0] & 0x80 ? key0[0] - 256 : key0[0])) >>> 0;
let headerStr = '';
for (let i = 0; i < len; i++) {
  const k = key0[i % n1] & 0x80 ? key0[i % n1] - 256 : key0[i % n1];
  headerStr += String.fromCharCode(buf.readUInt16LE(n1 + 5 + i * 2) ^ (k & 0xffff));
}
const dataStart = n1 + 5 + len * 2;
console.log(`path="${path}" N1=${n1} headerStr="${headerStr}" dataStart=${dataStart}`);
const str = path + headerStr, L = str.length;
const key1 = Buffer.alloc(16);
for (let i = 0; i < 16; i++) key1[i] = (i + (str.charCodeAt(i % L) & 0xff)) & 0xff;
console.log('key1[0..16] =', [...key1].map((b) => b.toString(16).padStart(2, '0')).join(' '));
const tail = Buffer.from(buf.subarray(dataStart));
new Snow2(key1).decrypt(tail, 0, tail.length - (tail.length % 4));
fs.writeFileSync('H:\\SA_Analysis\\evidence\\pkg_data_region_global.bin', tail);
// dump: look for ASCII / UTF-16 / zlib markers
let ascii = 0;
const out = [];
for (let i = 0; i < Math.min(tail.length, 4096); i += 16) {
  const row = tail.subarray(i, i + 16);
  const hex = [...row].map((b) => b.toString(16).padStart(2, '0')).join(' ');
  const txt = [...row].map((b) => (b >= 0x20 && b < 0x7f) ? String.fromCharCode(b) : '.').join('');
  out.push(`${(dataStart + i).toString(16).padStart(6, ' ')}  ${hex}  ${txt}`);
}
console.log(out.join('\n'));
// scan whole decrypted region for ASCII runs >= 6
const runs = [];
let cur = '';
for (let i = 0; i < tail.length; i++) {
  const b = tail[i];
  if (b >= 0x20 && b < 0x7f) cur += String.fromCharCode(b);
  else { if (cur.length >= 6) runs.push([i - cur.length, cur]); cur = ''; }
}
if (cur.length >= 6) runs.push([tail.length - cur.length, cur]);
console.log('\nASCII runs >= 6 chars (offset relative to dataStart):');
for (const [off, s] of runs.slice(0, 60)) console.log(`  +0x${off.toString(16)}  "${s.slice(0, 80)}"`);
// UTF-16LE runs
const runs16 = [];
cur = '';
for (let i = 0; i + 1 < tail.length; i += 2) {
  const w = tail.readUInt16LE(i);
  if (w >= 0x20 && w < 0x7f) cur += String.fromCharCode(w);
  else { if (cur.length >= 5) runs16.push([i - cur.length * 2, cur]); cur = ''; }
}
console.log('\nUTF-16LE runs >= 5 chars:');
for (const [off, s] of runs16.slice(0, 60)) console.log(`  +0x${off.toString(16)}  "${s.slice(0, 80)}"`);
