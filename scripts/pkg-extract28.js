// pkg-extract28.js — SA pkg 전체 익스트랙터 (확정 모델)
//   모델 (전부 verbatim + 실험 확증):
//   헤더: n1=(charSum(file)%312)+30 마스크 key0; s0 @n1+5; indexStart=dataStart+n2+8
//   인덱스: SUB 워드 Snow2(k2), k2=file+s0 역방향 공식
//   엔트리 데이터 F=base+f2*0x400 (base=align400(indexEnd)):
//     연속층(f1&2, c2a0): 전체 [F,F+f4) SUB, 키 K=deriveC(엔트리이름, tail16)[0..16]
//     블록층(f1&4, c4c0): 첫 min(0x400,f4) 추가 SUB, 같은 키 K
//     f1&1: zlib inflate → f3바이트
//     그 외: f3바이트 (f4=align4(f3) 패딩 제거)
'use strict';
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
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
function deriveC(ctx, src16) {
  const out = Buffer.alloc(128);
  const ctxLen = ctx.length;
  for (let j = 0; j < 128; j++) {
    const t8 = ((src16[j & 15]) - 5 * Math.floor(j / 5) + 2 + j) & 0xff;
    const ts = t8 & 0x80 ? t8 - 256 : t8;
    const cc = ctx.charCodeAt(j % ctxLen) & 0xff;
    const ccs = cc & 0x80 ? cc - 256 : cc;
    out[j] = ((ts * ccs + j) & 0xff) >>> 0;
  }
  return out;
}
function parsePkg(f) {
  const buf = fs.readFileSync(f);
  const fname = path.basename(f);
  const n1 = (charSum(fname) % 312) + 30, n2 = ((charSum(fname) * 3) % 212) + 33;
  const masked = buf.subarray(0, n1);
  const key0 = Buffer.from(masked); for (let i = 0; i < n1; i++) key0[i] = (masked[i] >> 1) | (masked[i] & 0x80);
  const len = (buf.readUInt32LE(n1 + 1) ^ (key0[0] & 0x80 ? key0[0] - 256 : key0[0])) >>> 0;
  let s0 = '';
  for (let i = 0; i < len; i++) {
    const k = key0[i % n1] & 0x80 ? key0[i % n1] - 256 : key0[i % n1];
    s0 += String.fromCharCode(buf.readUInt16LE(n1 + 5 + i * 2) ^ (k & 0xffff));
  }
  const dataStart = n1 + 5 + len * 2, indexStart = dataStart + n2 + 8;
  const str = fname + s0, L = str.length;
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
    const segs = [];
    for (let i = 0; i < n; i++) { segs.push([region.readUInt32LE(off), region.readUInt32LE(off+4), region.readUInt32LE(off+8), region.readUInt32LE(off+12)]); off += 16; }
    const tail = Buffer.from(region.subarray(off, off + 16)); off += 16;
    if (f2[1] & 0x10) off += 32;
    ents.push({ name, f: f2, segs, tail });
  }
  const indexEnd = indexStart + off;
  const align = (x) => { const r = x & 0x3ff; return r ? x - r + 0x400 : x; };
  return { buf, file: fname, s0, ents, base: align(indexEnd), fileSize: buf.length };
}
function decryptEntry(pkg, e) {
  const F = pkg.base + e.f[2] * 0x400;
  const stored = Math.min(e.f[4], pkg.fileSize - F);
  if (stored <= 0) return null;
  const key = deriveC(e.name, e.tail).subarray(0, 16);
  const dec = Buffer.from(pkg.buf.subarray(F, F + stored));
  const nwTotal = dec.length >> 2;
  // 연속층(c2a0): 전체
  { const c = new Snow2(key); for (let w = 0; w < nwTotal; w++) dec.writeUInt32LE((dec.readUInt32LE(w*4) - c.nextWord()) >>> 0, w*4); }
  // 블록층(c4c0): 첫 min(0x400, stored) 추가
  const nwHead = Math.min(0x400, stored) >> 2;
  { const c = new Snow2(key); for (let w = 0; w < nwHead; w++) dec.writeUInt32LE((dec.readUInt32LE(w*4) - c.nextWord()) >>> 0, w*4); }
  // f1&1 → inflate
  if (e.f[1] & 1) {
    try { return zlib.inflateSync(dec); }
    catch (err) { return { err: err.message, dec }; }
  }
  return dec.subarray(0, e.f[3]);
}
const OUT = 'H:\\SA_Analysis\\extracted';
const files = process.argv.slice(2);
const list = files.length ? files : ['H:\\SA_Analysis\\target\\pkg_samples\\texturescripts_00000.pkg', 'H:\\SA_Analysis\\target\\pkg_samples\\global_00000.pkg'];
let ok = 0, fail = 0;
for (const pf of list) {
  const pkg = parsePkg(pf);
  const outRoot = path.join(OUT, pkg.file.replace(/\.pkg$/i, ''));
  console.log(`\n=== ${pkg.file} ents=${pkg.ents.length} base=0x${pkg.base.toString(16)}`);
  for (const e of pkg.ents) {
    const r = decryptEntry(pkg, e);
    const out = path.join(outRoot, e.name.replace(/[\\/]/g, '\\'));
    if (r === null) { console.log(`  SKIP(oof) ${e.name}`); fail++; continue; }
    if (r.err) { console.log(`  FAIL ${e.name}: ${r.err}`); fail++; fs.mkdirSync(path.dirname(out), { recursive: true }); fs.writeFileSync(out + '.dec', r.dec); continue; }
    fs.mkdirSync(path.dirname(out), { recursive: true });
    fs.writeFileSync(out, r);
    const expect = e.f[3];
    const mark = r.length === expect ? 'OK' : `LEN?${r.length}!=${expect}`;
    console.log(`  ${mark} ${e.name} (${r.length}B, f1=${e.f[1]})`);
    if (r.length === expect) ok++; else fail++;
  }
}
console.log(`\nOK=${ok} FAIL=${fail}`);
