// pkg-extract16.js — 완전 닫힌 모델 검증:
//   레이어1 (f1&0x04): tail16 키, 0x400 블록 리셋: raw -= ks[w % 256]
//   레이어2 (f1&0x02): tail16 키, 연속:            raw -= ks[w]
//   dispatch: pkg+0x74 = 0 -> deriveC(name, tail16), 1 -> deriveA(name, tail16, fnv32(s0))
//   f1&0x01 -> zlib (stored=f4, plain=f3), else stored=f4(=align4(f3)), real=f3
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
    const cc = (ctx.charCodeAt(j % ctxLen) & 0xff);
    const ccs = cc & 0x80 ? cc - 256 : cc;
    out[j] = ((ts * ccs + j) & 0xff) >>> 0;
  }
  return out;
}
function deriveA(ctx, src16, variant) {
  const out = Buffer.alloc(128);
  const dg = [];
  let v = variant | 0;
  if (v <= 0) return null;
  do { dg.push(v % 10); v = Math.floor(v / 10); } while (v > 0);
  dg.reverse();
  const dc = dg.length, ctxLen = ctx.length;
  for (let j = 0; j < 128; j++) {
    const A = dg[j % dc] & 1, B = dg[(j + 1) % dc], C = dg[(j + 2) % dc];
    let t = ((B + j) % 5);
    t = (t + src16[(C + j) % 16]) & 0xff;
    t = (t + A) & 0xff;
    const ts = t & 0x80 ? t - 256 : t;
    const cc = (ctx.charCodeAt(j % ctxLen) & 0xff);
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
    const vec = [];
    for (let i = 0; i < n && i < 8; i++) { vec.push(Buffer.from(region.subarray(off, off + 16))); off += 16; }
    if (n > 8) off += (n - 8) * 16;
    const tail = Buffer.from(region.subarray(off, off + 16)); off += 16;
    if (f2[1] & 0x10) off += 32;
    ents.push({ name, f: f2, vec, tail });
  }
  const indexEnd = indexStart + off;
  const align = (x) => { const r = x & 0x3ff; return r ? x - r + 0x400 : x; };
  return { buf, s0, ents, base: align(indexEnd), fileSize: buf.length };
}
function decryptEntry(ct, key128, blockReset, layer02, blockWords) {
  // 레이어 순서: raw → sub(블록, f1&0x04) → sub(연속, f1&0x02) → plain
  const d = Buffer.from(ct);
  const nW = d.length >> 2;
  if (blockReset) {
    const cB = new Snow2(key128.subarray(0, 16));
    // 블록 리셋: 각 블록(0x400B=256w)마다 새 스냅샷 — ks[w % 256] 로 재현하려면
    // 세그먼트 경계에서 상태 리셋이 필요. 연속 ks를 쓰되 w%blockWords==0마다 재초기화
    let cur = null;
    for (let w = 0; w < nW; w++) {
      if (w % blockWords === 0) cur = new Snow2(key128.subarray(0, 16));
      const ks = cur.nextWord();
      d.writeUInt32LE((d.readUInt32LE(w * 4) - ks) >>> 0, w * 4);
    }
  }
  if (layer02) {
    const cC = new Snow2(key128.subarray(0, 16));
    for (let w = 0; w < nW; w++)
      d.writeUInt32LE((d.readUInt32LE(w * 4) - cC.nextWord()) >>> 0, w * 4);
  }
  return d;
}
function zlibOk(dec) {
  if (dec.length < 2) return false;
  const cmf = dec[0], flg = dec[1];
  return cmf === 0x78 && ((cmf * 256 + flg) % 31) === 0;
}
for (const pkgFile of ['texturescripts_00000.pkg', 'global_00000.pkg']) {
  const pkg = parsePkg(pkgFile);
  console.log(`\n=== ${pkgFile} s0=${JSON.stringify(pkg.s0)} fnv32(s0)=0x${fnv32(pkg.s0).toString(16)} fnv32(s0).toString()='${fnv32(pkg.s0)}'`);
  for (const e of pkg.ents.slice(0, 4)) {
    const stored = Math.min(e.f[4], pkg.fileSize - (pkg.base + e.f[2] * 0x400));
    const ct = Buffer.from(pkg.buf.subarray(pkg.base + e.f[2] * 0x400, pkg.base + e.f[2] * 0x400 + stored));
    const dispatches = {
      C: deriveC(e.name, e.tail),
      A_fnvS0: deriveA(e.name, e.tail, fnv32(pkg.s0)),
      A_fnvName: deriveA(e.name, e.tail, fnv32(e.name)),
    };
    console.log(`\n-- ${e.name} f1=0x${e.f[1].toString(16)} stored=0x${stored.toString(16)} f3=${e.f[3]}`);
    for (const [dn, key] of Object.entries(dispatches)) {
      if (!key) continue;
      const dec = decryptEntry(ct, key, (e.f[1] & 0x04) !== 0, (e.f[1] & 0x02) !== 0, 256);
      const head = dec.subarray(0, 16);
      const isTxt = /\.txt$/i.test(e.name);
      const asc = dec.subarray(0, 64).toString('latin1').replace(/[^\x20-\x7e]/g, '.');
      let verdict = '';
      if ((e.f[1] & 1) && zlibOk(dec)) verdict = 'ZLIB!';
      else if (isTxt && /^[\x20-\x7e\r\n\t]{16}/.test(dec.subarray(0, 16).toString('latin1'))) verdict = 'ASCII!';
      console.log(`  ${dn}: ${head.toString('hex').slice(0, 32)}  ${JSON.stringify(asc.slice(0, 40))} ${verdict}`);
    }
  }
}
