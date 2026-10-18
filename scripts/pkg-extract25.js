// pkg-extract25.js — ctx 브루트포스: f1=7 엔트리 zlib 2바이트 오라클
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
  const out = Buffer.alloc(16);
  const ctxLen = ctx.length;
  for (let j = 0; j < 16; j++) {
    const t8 = ((src16[j & 15]) - 5 * Math.floor(j / 5) + 2 + j) & 0xff;
    const ts = t8 & 0x80 ? t8 - 256 : t8;
    const cc = ctx.charCodeAt(j % ctxLen) & 0xff;
    const ccs = cc & 0x80 ? cc - 256 : cc;
    out[j] = ((ts * ccs + j) & 0xff) >>> 0;
  }
  return out;
}
function deriveA(ctx, src16, variant) {
  const v = variant >>> 0;
  const dg = []; let x = v;
  do { dg.push(x % 10); x = Math.floor(x / 10); } while (x > 0);
  dg.reverse();
  const nd = dg.length;
  const out = Buffer.alloc(16);
  const ctxLen = ctx.length;
  for (let j = 0; j < 16; j++) {
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
  return { buf, file: f, s0, ents, base: align(indexEnd), fileSize: buf.length };
}
// ctx 후보 생성
function ctxCandidates(e, pkg) {
  const name = e.name;
  const pkgFile = pkg.file;
  const stem = pkgFile.replace(/\.pkg$/, '');
  const stemNoNum = stem.replace(/_\d+$/, '');
  const dot = name.lastIndexOf('.');
  const noext = dot >= 0 ? name.slice(0, dot) : name;
  const slash = name.lastIndexOf('/');
  const base = slash >= 0 ? name.slice(slash + 1) : name;
  const dir = slash >= 0 ? name.slice(0, slash) : '';
  const ext = dot >= 0 ? name.slice(dot + 1) : '';
  const up = name.toUpperCase(), lo = name.toLowerCase();
  const bs = name.replace(/\//g, '\\');
  const cands = [];
  const add = (s) => { if (s && s.length) cands.push(s); };
  add(name); add(up); add(lo); add(bs); add(bs.toUpperCase()); add(bs.toLowerCase());
  add(noext); add(noext.toUpperCase()); add(noext.toLowerCase());
  add(base); add(base.toUpperCase()); add(base.toLowerCase());
  add(dir); add(ext); add(ext.toUpperCase());
  for (const sep of ['/', '\\', '.', '']) {
    add(stem + sep + name); add(stemNoNum + sep + name); add(pkgFile + sep + name);
    add(dir + sep + base);
    add(stem + sep + base); add(stemNoNum + sep + base);
  }
  add(pkg.s0 + name); add(pkg.s0 + base); add(name + pkg.s0);
  add(stem); add(stemNoNum); add(pkgFile);
  add(pkg.s0); add(pkg.s0 + stem); add(stem + pkg.s0);
  // 대소문자 섞은 pkg 스템
  add(stemNoNum.toUpperCase()); add(stemNoNum.toLowerCase());
  return cands;
}
let hits = 0;
for (const pkgFile of ['texturescripts_00000.pkg', 'global_00000.pkg']) {
  const pkg = parsePkg(pkgFile);
  const zlibEnts = pkg.ents.filter(e => (e.f[1] & 1) && e.f[4] >= 8);
  for (const e of zlibEnts) {
    const F = pkg.base + e.f[2] * 0x400;
    const stored = Math.min(e.f[4], pkg.fileSize - F);
    const ct = pkg.buf.subarray(F, F + stored);
    const c0 = ct.readUInt32LE(0), c1w = ct.readUInt32LE(4);
    let tried = 0;
    const cands = ctxCandidates(e, pkg);
    outer:
    for (const ctx of cands) {
      tried++;
      // deriveC + 파생 변형
      const variants = [
        ['C', deriveC(ctx, e.tail)],
        ['A0', deriveA(ctx, e.tail, 0)],
        ['A1', deriveA(ctx, e.tail, 1)],
        ['Afnv', deriveA(ctx, e.tail, fnv32(ctx))],
        ['AfnvN', deriveA(ctx, e.tail, fnv32(e.name))],
      ];
      for (const [vn, key] of variants) {
        const c = new Snow2(key);
        const d0 = (c0 - c.nextWord()) >>> 0;
        const d1 = (c1w - c.nextWord()) >>> 0;
        const b0 = d0 & 0xff, b1 = (d0 >>> 8) & 0xff;
        if (b0 === 0x78 && ((b0 * 256 + b1) % 31) === 0) {
          hits++;
          console.log(`HIT! ${pkgFile} ${e.name} ctx=${JSON.stringify(ctx)} derive=${vn} dec0=${d0.toString(16)} dec1=${d1.toString(16)}`);
          // 전체 복호화 + inflate
          const c2 = new Snow2(key);
          const dec = Buffer.from(ct);
          for (let w = 0; w < (dec.length >> 2); w++) dec.writeUInt32LE((dec.readUInt32LE(w * 4) - c2.nextWord()) >>> 0, w * 4);
          try { const d = zlib.inflateSync(dec); console.log(`  inflate OK len=${d.length} (f3=${e.f[3]}): ${JSON.stringify(d.subarray(0, 100).toString('latin1'))}`); }
          catch (err) { console.log(`  inflate fail: ${err.message} head=${dec.subarray(0, 16).toString('hex')}`); }
          break outer;
        }
      }
    }
    console.log(`  ${e.name}: tried ${tried} ctx × 5 derives — no hit`);
  }
}
console.log(`\ntotal hits: ${hits}`);
