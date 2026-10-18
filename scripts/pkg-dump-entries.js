// pkg-dump-entries.js — 엔트리별 f0..f5, n(세그먼트 수), 세그먼트 원문 덤프
// 목적: 블록모드(n>0) 여부 확인 + f 필드 산술 관계 (blockSize, f3, f4, f5)
'use strict';
const fs = require('fs');
function charSum(s) { let x = 0; for (const c of s) x = (x + c.charCodeAt(0)) >>> 0; return x; }
for (const f of ['texturescripts_00000.pkg', 'global_00000.pkg']) {
  const buf = fs.readFileSync(`H:\\SA_Analysis\\target\\pkg_samples\\${f}`);
  const n1 = (charSum(f) % 312) + 30, n2 = ((charSum(f) * 3) % 212) + 33;
  const masked = buf.subarray(0, n1);
  const key0 = Buffer.from(masked); for (let i = 0; i < n1; i++) key0[i] = (masked[i] >> 1) | (masked[i] & 0x80);
  const len = (buf.readUInt32LE(n1 + 1) ^ (key0[0] & 0x80 ? key0[0] - 256 : key0[0])) >>> 0;
  let s0 = '';
  for (let i = 0; i < len; i++) {
    const k = key0[i % n1] & 0x80 ? key0[i % n1] - 256 : key0[i % n1];
    s0 += String.fromCharCode(buf.readUInt16LE(n1 + 5 + i * 2) ^ (k & 0xffff));
  }
  const dataStart = n1 + 5 + len * 2, indexStart = dataStart + n2 + 8;
  const str = f + s0, L = str.length;
  const k2 = Buffer.alloc(16);
  for (let i = 0; i < 16; i++) k2[i] = ((str.charCodeAt(L - (i % L) - 1) & 0xff) * ((i % 3) + 2) + i) & 0xff;
  // Snow2 (인덱스 복호화용)
  const TABLES = JSON.parse(fs.readFileSync('H:\\SA_Analysis\\evidence\\snow_tables_from_exe.json', 'utf8')).tables;
  const T = { a: TABLES.snow_alpha_mul.words, ai: TABLES.snow_alphainv_mul.words, t0: TABLES.snow_T0.words, t1: TABLES.snow_T1.words, t2: TABLES.snow_T2.words, t3: TABLES.snow_T3.words };
  const a_mul = (w) => (((w << 8) >>> 0) ^ T.a[(w >>> 24) & 0xff]) >>> 0;
  const ainv_mul = (w) => ((w >>> 8) ^ T.ai[w & 0xff]) >>> 0;
  const fsmT = (w) => (T.t0[w & 0xff] ^ T.t1[(w >>> 8) & 0xff] ^ T.t2[(w >>> 16) & 0xff] ^ T.t3[(w >>> 24) & 0xff]) >>> 0;
  class Snow2 {
    constructor(key16) {
      this.s = new Uint32Array(16); this.r1 = 0; this.r2 = 0;
      const b = key16; const sx = (x) => (x & 0x80 ? x - 256 : x) | 0;
      for (let k = 0; k < 4; k++) {
        const w = ((sx(b[4*k]) << 24) | (sx(b[4*k+1]) << 16) | (sx(b[4*k+2]) << 8) | sx(b[4*k+3])) >>> 0;
        this.s[15-k] = w; this.s[11-k] = (~w) >>> 0; this.s[7-k] = w; this.s[3-k] = (~w) >>> 0;
      }
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
      const old = s[(k+1)%16];
      s[k] = ns; this.r2 = fsmT(this.r1); this.r1 = tmp;
      return (((this.r1 + ns) >>> 0) ^ this.r2 ^ old) >>> 0;
    }
    refresh() { this.ks = new Uint32Array(16); for (let k = 0; k < 16; k++) this.ks[k] = this.ksStep(k); this.ksPos = 0; }
    nextWord() { if (this.ksPos >= 16) this.refresh(); return this.ks[this.ksPos++]; }
  }
  const c2 = new Snow2(k2);
  const region = Buffer.from(buf.subarray(indexStart));
  for (let i = 0; i + 4 <= region.length - (region.length % 4); i += 4)
    region.writeUInt32LE((region.readUInt32LE(i) - c2.nextWord()) >>> 0, i);
  let off = 0;
  console.log(`\n=== ${f} (s0=${JSON.stringify(s0)}) ===`);
  console.log('name                                           f0        f1        f2        f3        f4        f5        n   tail16');
  while (off + 4 <= region.length) {
    const sl = region.readUInt32LE(off); off += 4;
    if (sl === 0 || sl > 0x400 || off + sl * 2 + 28 > region.length) break;
    let name = '';
    for (let i = 0; i < sl; i++) name += String.fromCharCode(region.readUInt16LE(off + i * 2));
    off += sl * 2;
    const f2 = []; for (let i = 0; i < 6; i++) { f2.push(region.readUInt32LE(off)); off += 4; }
    const n = region.readUInt32LE(off); off += 4;
    const segs = [];
    for (let i = 0; i < Math.min(n, 4); i++) { segs.push(region.subarray(off, off + 16).toString('hex')); off += 16; }
    if (n > 4) off += (n - 4) * 16;
    const tail = region.subarray(off, off + 16).toString('hex'); off += 16;
    if (f2[1] & 0x10) off += 32;
    console.log(`${name.padEnd(46)} ${f2.map(x => x.toString(16).padStart(9, ' ')).join(' ')} ${String(n).padStart(3)} ${tail}`);
    for (let i = 0; i < segs.length; i++) console.log(`    seg[${i}]=${segs[i]}`);
    if (f2[1] & 0x10) console.log(`    (+0x10 플래그)`);
  }
}
