// pkg-extract18.js — deriveA 부호 버그 수정판 (variant는 MOV EBX,R8D → UNSIGNED)
//   a84bc: MOV EBX,R8D (zero-extend) → CVTSI2SD → log10(2223700604)=9.347 → nd=10
//   ⇒ dispatch=1 + variant=fnv32(s0)=0x848afa7c = 2223700604 는 유효경로 (이전엔 |0로 음수화해 null)
// 스윕: dispatch {C, A_fnvS0, A_fnvName} × L1{from0,fromF2x256,fromAbsBlk,resetPerBlk} × L2{from0,fromF2x256,fromAbsBlk}
// L1(0x04레이어)은 처음 min(0x400,stored)바이트만 적용(d750), L2(0x02레이어)는 전체 적용 — 둘 다 SUB.
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
  skip(n) { for (let i = 0; i < n; i++) this.nextWord(); }
}
// deriveC — disasm84 a83f0 정확 재현
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
// deriveA — a84a0: variant는 UNSIGNED (MOV EBX,R8D), digits MSB-first
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
  return { buf, s0, ents, base: align(indexEnd), fileSize: buf.length };
}
// 키스트림 소스들
function mkFrom0(k) { const c = new Snow2(k); return () => c.nextWord(); }
function mkFromSkip(k, words) { const c = new Snow2(k); c.skip(words); return () => c.nextWord(); }
function mkResetPerBlk(k) { let cur = new Snow2(k), w = 0; return () => { if (w > 0 && w % 256 === 0) cur = new Snow2(k); w++; return cur.nextWord(); }; }
function score(dec, f1) {
  if ((f1 & 1) && dec.length >= 2 && dec[0] === 0x78 && ((dec[0] * 256 + dec[1]) % 31) === 0) return 'ZLIB';
  let g = 0; const n = Math.min(dec.length, 64);
  for (let i = 0; i < n; i++) { const c = dec[i]; if ((c >= 0x20 && c < 0x7f) || c === 0x0a || c === 0x0d || c === 0x09 || c === 0) g++; }
  return g / n;
}
for (const pkgFile of ['texturescripts_00000.pkg', 'global_00000.pkg']) {
  const pkg = parsePkg(pkgFile);
  const baseBlk = pkg.base / 0x400;
  const vS0 = fnv32(pkg.s0);
  console.log(`\n=== ${pkgFile} base=0x${pkg.base.toString(16)} baseBlk=${baseBlk} fnv32(s0)=${vS0} (unsigned)`);
  for (const e of pkg.ents) {
    const off = pkg.base + e.f[2] * 0x400;
    const stored = Math.min(e.f[4], pkg.fileSize - off);
    const ct = Buffer.from(pkg.buf.subarray(off, off + stored));
    const keys = {
      C: deriveC(e.name, e.tail),
      A_fnvS0: deriveA(e.name, e.tail, vS0),
      A_fnvName: deriveA(e.name, e.tail, fnv32(e.name)),
    };
    const l1Len = Math.min(0x400, stored);          // 0x04 레이어는 처음 0x400바이트만
    let best = null;
    for (const [kn, k128] of Object.entries(keys)) {
      const k16 = k128.subarray(0, 16);
      for (const [v1, f1] of Object.entries({
        from0: () => mkFrom0(k16),
        fromF2: () => mkFromSkip(k16, e.f[2] * 256),
        fromAbs: () => mkFromSkip(k16, (baseBlk + e.f[2]) * 256),
        resetBlk: () => mkResetPerBlk(k16),
      })) {
        for (const [v2, f2m] of Object.entries({
          from0: () => mkFrom0(k16),
          fromF2: () => mkFromSkip(k16, e.f[2] * 256),
          fromAbs: () => mkFromSkip(k16, (baseBlk + e.f[2]) * 256),
        })) {
          const l1 = f1(), l2 = f2m();
          const n1w = l1Len >> 2, nw = ct.length >> 2;
          const dec = Buffer.from(ct);
          for (let w = 0; w < nw; w++) {
            let v = dec.readUInt32LE(w * 4);
            if (w < n1w) v = (v - l1()) >>> 0;
            v = (v - l2()) >>> 0;
            dec.writeUInt32LE(v, w * 4);
          }
          const s = score(dec, e.f[1]);
          if (s === 'ZLIB' || (typeof s === 'number' && s > 0.9)) {
            console.log(`  HIT ${e.name} key=${kn} L1=${v1} L2=${v2} score=${typeof s === 'number' ? s.toFixed(3) : s} head=${dec.subarray(0, 32).toString('hex')}`);
            if (s === 'ZLIB') {
              try { const d = zlib.inflateSync(dec); console.log(`    inflate OK len=${d.length} head=${JSON.stringify(d.subarray(0, 64).toString('latin1'))}`); }
              catch (err) { console.log(`    inflate fail: ${err.message}`); }
            } else {
              console.log(`    text=${JSON.stringify(dec.subarray(0, 80).toString('latin1'))}`);
            }
          }
        }
      }
    }
  }
  console.log('  (done)');
}
