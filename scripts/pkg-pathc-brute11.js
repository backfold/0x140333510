// pkg-pathc-brute11.js — ctx 문자열 후보 전수 브루트 (pathC/pathA/pathB × sub/xor)
// 확정: dispatch=0(pathC), src16=tail16, Snow2(std) 인덱스로 검증, SUB, seek=0
// 유일 미지수: ctx = 매니저 트리 노드+0x50 wstring
'use strict';
const fs = require('fs');
function charSum(s) { let x = 0; for (const c of s) x = (x + c.charCodeAt(0)) >>> 0; return x; }
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
function parsePkg(f) {
  const buf = fs.readFileSync(`H:\\SA_Analysis\\target\\pkg_samples\\${f}`);
  const n1 = (charSum(f) % 312) + 30, n2 = ((charSum(f) * 3) % 212) + 33;
  const masked = buf.subarray(0, n1);
  const key0 = Buffer.from(masked); for (let i = 0; i < n1; i++) key0[i] = (masked[i] >> 1) | (masked[i] & 0x80);
  const len = (buf.readUInt32LE(n1 + 1) ^ (key0[0] & 0x80 ? key0[0] - 256 : key0[0])) >>> 0;
  let headerStr = '';
  for (let i = 0; i < len; i++) {
    const k = key0[i % n1] & 0x80 ? key0[i % n1] - 256 : key0[i % n1];
    headerStr += String.fromCharCode(buf.readUInt16LE(n1 + 5 + i * 2) ^ (k & 0xffff));
  }
  const dataStart = n1 + 5 + len * 2, indexStart = dataStart + n2 + 8;
  const str = f + headerStr, L = str.length;
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
  return { buf, headerStr, ents, base: align(indexEnd) };
}
const pkg = parsePkg('texturescripts_00000.pkg');
const HEADER = pkg.headerStr;
function deriveC(ctx, src16) {
  if (!ctx.length) return null;
  const out = Buffer.alloc(128);
  const ctxLen = ctx.length;
  for (let j = 0; j < 128; j++) {
    const t8 = ((src16[j & 15]) - 5 * Math.floor(j / 10) + 2 + j) & 0xff;
    const ts = t8 & 0x80 ? t8 - 256 : t8;
    const cc = (ctx.charCodeAt(j % ctxLen) & 0xff);
    const ccs = cc & 0x80 ? cc - 256 : cc;
    out[j] = ((ts * ccs + j) & 0xff) >>> 0;
  }
  return out;
}
function fnv32(s) { let h = 0x811c9dc5; for (let i = 0; i < s.length; i++) { h = (h ^ (s.charCodeAt(i) & 0xffff)) >>> 0; h = Math.imul(h, 0x01000193) >>> 0; } return h >>> 0; }
function deriveA(ctx, src16, variant) {
  if (!ctx.length) return null;
  const out = Buffer.alloc(128);
  const dg = [];
  let v = variant | 0;
  if (v <= 0) return null;
  do { dg.push(v % 10); v = Math.floor(v / 10); } while (v > 0);
  dg.reverse();
  const dc = dg.length, ctxLen = ctx.length;
  for (let j = 0; j < 128; j++) {
    const A = dg[j % dc] & 1, B = dg[(j + 1) % dc], C = dg[(j + 2) % dc];
    let t = ((B + j) % 10);
    t = (t + src16[(C + j) % 16]) & 0xff;
    t = (t + A) & 0xff;
    const ts = t & 0x80 ? t - 256 : t;
    const cc = (ctx.charCodeAt(j % ctxLen) & 0xff);
    const ccs = cc & 0x80 ? cc - 256 : cc;
    out[j] = ((ts * ccs + j) & 0xff) >>> 0;
  }
  return out;
}
function asciiScore(dec) {
  let g = 0;
  for (let i = 0; i < dec.length; i++) { const c = dec[i]; if ((c >= 0x20 && c < 0x7f) || c === 0x0a || c === 0x0d || c === 0x09) g++; }
  return g / dec.length;
}
const fn = 'texturescripts_00000.pkg';
const slot1 = 'texturescripts', slot2 = '00000';
const base = slot1 + '_' + slot2;
const ctxs = [
  base, base + '.pkg', slot1, slot2, fn, fn + HEADER, base + HEADER,
  slot1 + '\\' + fn, 'data\\' + fn, base.toUpperCase(), slot1.toUpperCase(),
  HEADER, HEADER + base, 'texture', 'script', base.replace('_', ''), slot1 + slot2,
];
const variantsA = { fnvCtx: fnv32(base), fnvHeader: fnv32(HEADER), fnvFn: fnv32(fn) };
const targets = pkg.ents.filter(e => e.name.endsWith('.txt') && !(e.f[1] & 1) && e.f[4] >= 48).slice(0, 3);
let tried = 0, hits = 0;
for (const e of targets) {
  const ct = Buffer.from(pkg.buf.subarray(pkg.base + e.f[2] * 0x400, pkg.base + e.f[2] * 0x400 + Math.min(e.f[4], 128)));
  for (const ctx of ctxs) {
    const keys = { C: deriveC(ctx, e.tail) };
    for (const [vn, vv] of Object.entries(variantsA)) keys['A_' + vn] = deriveA(ctx, e.tail, vv);
    for (const [kn, key128] of Object.entries(keys)) {
      if (!key128) continue;
      for (const keyOff of [0, 16, 64, 112]) {
        const key = key128.subarray(keyOff, keyOff + 16);
        for (const op of ['sub', 'xor']) {
          tried++;
          const c = new Snow2(key);
          const dec = Buffer.from(ct);
          for (let i = 0; i + 4 <= dec.length; i += 4) {
            const ks = c.nextWord();
            dec.writeUInt32LE(op === 'xor' ? ((dec.readUInt32LE(i) ^ ks) >>> 0) : ((dec.readUInt32LE(i) - ks) >>> 0), i);
          }
          const sc = asciiScore(dec.subarray(0, Math.min(dec.length, 48)));
          if (sc > 0.9) {
            hits++;
            console.log(`HIT ${e.name} ctx=${JSON.stringify(ctx)} der=${kn} keyOff=${keyOff} op=${op} score=${sc.toFixed(3)}`);
            console.log('  ' + JSON.stringify(dec.subarray(0, 64).toString('latin1')));
          }
        }
      }
    }
  }
}
console.log(`tried=${tried} hits=${hits}`);
