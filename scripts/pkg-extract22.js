// pkg-extract22.js — d7f0 판독 슬롯 확인 후 수정 모델
//   리더 +0x48(d7f0): 블록모드 아니면 limit 무시·항상 d8d0 복호화 → L1/L2 모두 전체 적용
//   dec = ct ⊖ L1ks[전체,word0부터] ⊖ L2ks[전체,word0부터]
//   L1/L2 키를 독립적으로 조합 (C × A-variants, 순서 포함)
'use strict';
const fs = require('fs');
const zlib = require('zlib');
function charSum(s) { let x = 0; for (const c of s) x = (x + c.charCodeAt(0)) >>> 0; return x; }
function fnv32(s) { let h = 0x811c9dc5; for (let i = 0; i < s.length; i++) { h = (h ^ (s.charCodeAt(i) & 0xffff)) >>> 0; h = Math.imul(h, 0x01000193) >>> 0; } return h >>> 0; }
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
function deriveC(ctx, src16) {
  const out = Buffer.alloc(128);
  const ctxLen = ctx.length;
  for (let j = 0; j < 128; j++) {
    const t8 = ((src16[j & 15]) - 5 * Math.floor(j / 10) + 2 + j) & 0xff;
    const ts = t8 & 0x80 ? t8 - 256 : t8;
    const cc = ctx.charCodeAt(j % ctxLen) & 0xff;
    const ccs = cc & 0x80 ? cc - 256 : cc;
    out[j] = ((ts * ccs + j) & 0xff) >>> 0;
  }
  return out;
}
function deriveA(ctx, src16, variant) {
  const v = variant >>> 0;
  const dg = [];
  let x = v;
  do { dg.push(x % 10); x = Math.floor(x / 10); } while (x > 0);
  dg.reverse();
  const nd = dg.length;
  const out = Buffer.alloc(128);
  const ctxLen = ctx.length;
  for (let j = 0; j < 128; j++) {
    const A = dg[j % nd] & 1, B = dg[(j + 1) % nd], C = dg[(j + 2) % nd];
    let t = (((B + j) % 5) + src16[(C + j) % 16] + A) & 0xff;
    const ts = t & 0x80 ? t - 256 : t;
    const cc = ctx.charCodeAt(j % ctxLen) & 0xff;
    const ccs = cc & 0x80 ? cc - 256 : cc;
    out[j] = ((ts * ccs + j) & 0xff) >>> 0;
  }
  return out;
}
function parsePkg(f) {
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
  const c2 = new Snow2(k2);
  const region = Buffer.from(buf.subarray(indexStart));
  for (let i = 0; i + 4 <= region.length - (region.length % 4); i += 4)
    region.writeUInt32LE((region.readUInt32LE(i) - c2.nextWord()) >>> 0, i);
  let off = 0;
  const ents = [];
  while (off + 4 <= region.length) {
    const sl = region.readUInt32LE(off); off += 4;
    if (sl === 0 || sl > 0x400 || off + sl * 2 + 28 > region.length) break;
    let name = '';
    for (let i = 0; i < sl; i++) name += String.fromCharCode(region.readUInt16LE(off + i * 2));
    off += sl * 2;
    const f2 = []; for (let i = 0; i < 6; i++) { f2.push(region.readUInt32LE(off)); off += 4; }
    const n = region.readUInt32LE(off); off += 4;
    off += n * 16;
    const tail = Buffer.from(region.subarray(off, off + 16)); off += 16;
    if (f2[1] & 0x10) off += 32;
    ents.push({ name, f: f2, tail });
  }
  const indexEnd = indexStart + off;
  const align = (x) => { const r = x & 0x3ff; return r ? x - r + 0x400 : x; };
  // k1 헤더 {A,B,cnt}
  const k1 = Buffer.alloc(16);
  for (let i = 0; i < 16; i++) k1[i] = (i + (str.charCodeAt(i % L) & 0xff)) & 0xff;
  const c1 = new Snow2(k1);
  const hdr = Buffer.from(buf.subarray(dataStart, dataStart + 8));
  for (let i = 0; i < 8; i += 4) hdr.writeUInt32LE((hdr.readUInt32LE(i) - c1.nextWord()) >>> 0, i);
  return { buf, file: f, s0, ents, base: align(indexEnd), fileSize: buf.length, hdrA: hdr.readUInt16LE(0), hdrB: hdr.readUInt16LE(2), hdrCnt: hdr.readUInt32LE(4) };
}
function score(dec, f1) {
  if ((f1 & 1) && dec.length >= 2 && dec[0] === 0x78 && ((dec[0] * 256 + dec[1]) % 31) === 0) return 'ZLIB';
  let g = 0; const n = Math.min(dec.length, 64);
  for (let i = 0; i < n; i++) { const c = dec[i]; if ((c >= 0x20 && c < 0x7f) || c === 0x0a || c === 0x0d || c === 0x09 || c === 0) g++; }
  return g / n;
}
let hits = 0;
for (const pkgFile of ['texturescripts_00000.pkg', 'global_00000.pkg']) {
  const pkg = parsePkg(pkgFile);
  console.log(`\n=== ${pkgFile} base=0x${pkg.base.toString(16)} hdr={A=${pkg.hdrA},B=${pkg.hdrB},cnt=${pkg.hdrCnt}} ents=${pkg.ents.length}`);
  const variants = { A: pkg.hdrA, B: pkg.hdrB, AB: pkg.hdrA | (pkg.hdrB << 16), BA: pkg.hdrB | (pkg.hdrA << 16), AxB: pkg.hdrA * pkg.hdrB, AplusB: pkg.hdrA + pkg.hdrB };
  for (const e of pkg.ents.slice(0, 8)) {
    const F = pkg.base + e.f[2] * 0x400;
    const stored = Math.min(e.f[4], pkg.fileSize - F);
    const ct = Buffer.from(pkg.buf.subarray(F, F + stored));
    // 키 후보 (L1/L2 독립)
    const keys = { C: deriveC(e.name, e.tail) };
    for (const [vn, vv] of Object.entries(variants)) keys['A_' + vn] = deriveA(e.name, e.tail, vv);
    keys['A_fnvs0'] = deriveA(e.name, e.tail, fnv32(pkg.s0));
    keys['A_fnvname'] = deriveA(e.name, e.tail, fnv32(e.name));
    const knames = Object.keys(keys);
    const nw = ct.length >> 2;
    for (const kn1 of knames) {
      for (const kn2 of knames) {
        const c1 = new Snow2(keys[kn1].subarray(0, 16));
        const c2c = new Snow2(keys[kn2].subarray(0, 16));
        const dec = Buffer.from(ct);
        for (let w = 0; w < nw; w++)
          dec.writeUInt32LE((dec.readUInt32LE(w * 4) - c1.nextWord() - c2c.nextWord()) >>> 0, w * 4);
        const s = score(dec, e.f[1]);
        if (s === 'ZLIB' || (typeof s === 'number' && s > 0.9)) {
          hits++;
          console.log(`  HIT ${e.name} L1=${kn1} L2=${kn2} score=${typeof s === 'number' ? s.toFixed(3) : s}`);
          console.log(`    head=${dec.subarray(0, 32).toString('hex')}`);
          if (s === 'ZLIB') { try { const d = zlib.inflateSync(dec); console.log(`    inflate OK len=${d.length}: ${JSON.stringify(d.subarray(0, 64).toString('latin1'))}`); } catch (err) { console.log(`    inflate fail: ${err.message}`); } }
          else console.log(`    text=${JSON.stringify(dec.subarray(0, 80).toString('latin1'))}`);
        }
      }
    }
  }
  console.log('  (done)');
}
console.log(`\ntotal hits: ${hits}`);
