// pkg-brute14.js — ctx = 엔트리 이름 (a9820이 namesObj+0x8 벡터에 push하는 per-entry 문자열)
// 가설: 파일별 키 = deriveC(entryName, tail16)[0..16], Snow2, SUB, skip 0
'use strict';
const fs = require('fs');
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
function zlibOk(dec) {
  if (dec.length < 2) return false;
  const cmf = dec[0], flg = dec[1];
  return cmf === 0x78 && ((cmf * 256 + flg) % 31) === 0;
}
function asciiScore(dec) {
  let g = 0;
  for (let i = 0; i < dec.length; i++) { const c = dec[i]; if ((c >= 0x20 && c < 0x7f) || c === 0x0a || c === 0x0d || c === 0x09) g++; }
  return g / dec.length;
}
function decrypt(ct, key, op, skipWords) {
  const c = new Snow2(key);
  for (let s = 0; s < skipWords; s++) c.nextWord();
  const dec = Buffer.from(ct);
  for (let i = 0; i + 4 <= dec.length; i += 4) {
    const ks = c.nextWord();
    dec.writeUInt32LE(op === 'xor' ? ((dec.readUInt32LE(i) ^ ks) >>> 0) : ((dec.readUInt32LE(i) - ks) >>> 0), i);
  }
  return dec;
}
for (const pkgFile of ['texturescripts_00000.pkg', 'global_00000.pkg']) {
  const pkg = parsePkg(pkgFile);
  console.log(`\n=== ${pkgFile} (${pkg.ents.length} entries, base=0x${pkg.base.toString(16)})`);
  let tried = 0, hits = 0;
  for (const e of pkg.ents) {
    if (e.f[4] < 16) continue;
    const ct = Buffer.from(pkg.buf.subarray(pkg.base + e.f[2] * 0x400, pkg.base + e.f[2] * 0x400 + Math.min(e.f[4], 1024)));
    // ctx 후보: 엔트리 이름 변형
    const dir = e.name.includes('\\') || e.name.includes('/') ? e.name.replace(/[\\/][^\\/]*$/, '') : null;
    const ctxs = [
      e.name,
      e.name.toLowerCase(),
      e.name.toUpperCase(),
      e.name.replace(/\\/g, '/'),
      e.name.replace(/\//g, '\\'),
      e.name + pkg.headerStr,
      pkg.headerStr + e.name,
      dir, dir ? dir.toLowerCase() : null,
    ].filter(Boolean);
    const variantsA = { fnvName: fnv32(e.name), fnvNameL: fnv32(e.name.toLowerCase()) };
    for (const ctx of ctxs) {
      const keys = { C: deriveC(ctx, e.tail) };
      for (const [vn, vv] of Object.entries(variantsA)) keys['A_' + vn] = deriveA(ctx, e.tail, vv);
      for (const [kn, key128] of Object.entries(keys)) {
        if (!key128) continue;
        for (const keyOff of [0, 16, 64, 112]) {
          const key = key128.subarray(keyOff, keyOff + 16);
          for (const op of ['sub', 'xor']) {
            for (const skipWords of [0, 1, 2]) {
              tried++;
              const dec = decrypt(ct, key, op, skipWords);
              let ok = false, why = '';
              if (zlibOk(dec)) { ok = true; why = 'zlib'; }
              else if (asciiScore(dec) > 0.97) { ok = true; why = 'ascii'; }
              if (ok) {
                hits++;
                console.log(`HIT ${JSON.stringify(e.name)} ctx=${JSON.stringify(ctx)} der=${kn} keyOff=${keyOff} op=${op} skip=${skipWords} [${why}]`);
                console.log('  head: ' + dec.subarray(0, 48).toString('hex'));
                if (why === 'zlib') {
                  try {
                    const d = zlib.inflateSync(dec.subarray(0, Math.min(e.f[4], 1024)));
                    console.log('  inflate OK len=' + d.length + ' preview: ' + JSON.stringify(d.subarray(0, 80).toString('latin1')));
                  } catch (err) { console.log('  inflate failed: ' + err.message); }
                }
              }
            }
          }
        }
      }
    }
  }
  console.log(`${pkgFile}: tried=${tried} hits=${hits}`);
}
