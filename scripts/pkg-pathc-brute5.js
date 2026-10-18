// pkg-pathc-brute5.js — 확정: 블록 배치 base+f2*0x400 (base=alignUp(indexEnd,0x400)),
// blob 길이 f4, key=f83f0(ctx, tail16=완전난수 시드), f0=체크섬.
// seek 후보 {0, f2, f3/4, f4/4, f0/4, (base+f2*400)/4} × ctx × 레이어1/2
'use strict';
const fs = require('fs');
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
    const oldNext = s[(k+1)%16];
    s[k] = ns; this.r2 = fsmT(this.r1); this.r1 = tmp;
    return (((this.r1 + ns) >>> 0) ^ this.r2 ^ oldNext) >>> 0;
  }
  refresh() { this.ks = new Uint32Array(16); for (let k = 0; k < 16; k++) this.ks[k] = this.ksStep(k); this.ksPos = 0; }
  nextWord() { if (this.ksPos >= 16) this.refresh(); return this.ks[this.ksPos++]; }
  skipWords(n) { for (let i = 0; i < n; i++) this.nextWord(); }
}
function keystream(key, n) { const c = new Snow2(key); const o = new Uint32Array(n); for (let i = 0; i < n; i++) o[i] = c.nextWord(); return o; }
function charSum(s) { let x = 0; for (const c of s) x = (x + c.charCodeAt(0)) >>> 0; return x; }
function deriveF470(concat) { const L = concat.length; const out = Buffer.alloc(16); for (let i = 0; i < 16; i++) out[i] = (i + (concat.charCodeAt(i % L) & 0xff)) & 0xff; return out; }
function deriveF83f0(ctx, src16) {
  const L = ctx.length; if (!L) return null;
  const out = Buffer.alloc(16);
  for (let j = 0; j < 16; j++) {
    const a = (src16[j & 15] - 5 * Math.floor(j / 10) + 2 + j) & 0xff;
    const sa = a >= 128 ? a - 256 : a;
    const cb = ctx.charCodeAt(j % L) & 0xff;
    const scb = cb >= 128 ? cb - 256 : cb;
    out[j] = (sa * scb + j) & 0xff;
  }
  return out;
}
function parseAll(file, path) {
  const buf = fs.readFileSync(file);
  const n1 = (charSum(path) % 312) + 30, n2 = ((charSum(path) * 3) % 212) + 33;
  const masked = buf.subarray(0, n1);
  const key0 = Buffer.from(masked); for (let i = 0; i < n1; i++) key0[i] = (masked[i] >> 1) | (masked[i] & 0x80);
  const len = (buf.readUInt32LE(n1 + 1) ^ (key0[0] & 0x80 ? key0[0] - 256 : key0[0])) >>> 0;
  let headerStr = '';
  for (let i = 0; i < len; i++) {
    const k = key0[i % n1] & 0x80 ? key0[i % n1] - 256 : key0[i % n1];
    headerStr += String.fromCharCode(buf.readUInt16LE(n1 + 5 + i * 2) ^ (k & 0xffff));
  }
  const dataStart = n1 + 5 + len * 2, indexStart = dataStart + n2 + 8;
  const L = (path + headerStr).length, s2 = path + headerStr;
  const k2 = Buffer.alloc(16);
  for (let i = 0; i < 16; i++) k2[i] = ((s2.charCodeAt(L - (i % L) - 1) & 0xff) * ((i % 3) + 2) + i) & 0xff;
  const c2 = new Snow2(k2);
  const region = Buffer.from(buf.subarray(indexStart));
  for (let i = 0; i + 4 <= region.length - (region.length % 4); i += 4)
    region.writeUInt32LE((region.readUInt32LE(i) - c2.nextWord()) >>> 0, i);
  const entries = []; let off = 0;
  while (off + 4 <= region.length) {
    const sl = region.readUInt32LE(off); off += 4;
    if (sl === 0 || sl > 0x400 || off + sl * 2 + 28 > region.length) break;
    let name = '';
    for (let i = 0; i < sl; i++) name += String.fromCharCode(region.readUInt16LE(off + i * 2));
    off += sl * 2;
    const f = []; for (let i = 0; i < 6; i++) { f.push(region.readUInt32LE(off)); off += 4; }
    const n = region.readUInt32LE(off); off += 4;
    if (n > 0x10000) break;
    off += n * 16;
    const tail = Buffer.from(region.subarray(off, off + 16)); off += 16;
    if (f[1] & 0x10) off += 40;
    entries.push({ name, f, tail });
  }
  return { buf, headerStr, dataStart, indexStart, indexEnd: indexStart + off, entries };
}
const alignUp = (x, a) => Math.ceil(x / a) * a;
const asciiScore = (b) => { let c = 0; for (const x of b) if (x === 9 || x === 10 || x === 13 || (x >= 0x20 && x < 0x7f)) c++; return b.length ? c / b.length : 0; };

for (const f of ['texturescripts_00000.pkg', 'global_00000.pkg']) {
  const P = parseAll(`H:\\SA_Analysis\\target\\pkg_samples\\${f}`, f);
  const { buf, headerStr, indexEnd, entries } = P;
  const base = alignUp(indexEnd, 0x400);
  console.log(`\n=== ${f}: 엔트리=${entries.length} indexEnd=${indexEnd} base=0x${base.toString(16)} fileLen=0x${buf.length.toString(16)} (0x${(buf.length/0x400).toString(16)} 블록)`);
  let maxEnd = 0;
  for (const e of entries) maxEnd = Math.max(maxEnd, base + e.f[2] * 0x400 + e.f[4]);
  console.log(`    최대 블록 끝 = 0x${maxEnd.toString(16)} / fileLen = 0x${buf.length.toString(16)} ${maxEnd <= buf.length ? 'OK' : 'OVERFLOW!'}`);
  console.log(`    블록0 원시: ${buf.subarray(base, base + 32).toString('hex')}`);
  const layer1 = Buffer.from(buf.subarray(0)); // f470 레이어: dataStart 기준 워드격자
  const ks1 = keystream(deriveF470(f + headerStr), ((buf.length - 141) >> 2) + 8);
  for (let i = 141; i + 4 <= buf.length; i += 4)
    layer1.writeUInt32LE((layer1.readUInt32LE(i) - ks1[(i - 141) / 4]) >>> 0, i);
  const inner0 = entries[0].name;
  const dir0 = inner0.split('/').slice(0, -1).join('/');
  const ctxCands = {
    pkgname: f, pkgbase: f.replace(/\.pkg$/, ''), header: headerStr, pkg_hdr: f + headerStr,
    game_rel: 'game\\' + f, inner0, inner0_base: inner0.split('/').pop(), dir0,
  };
  const hits = [];
  for (const [ln, src] of [['1', buf], ['2', layer1]]) {
    for (const [cn, ctx] of Object.entries(ctxCands)) {
      for (const e of entries) {
        const st = base + e.f[2] * 0x400;
        const blen = Math.min(e.f[4] & ~3, 256);
        if (blen < 16 || st + blen > src.length) continue;
        const key = deriveF83f0(ctx, e.tail);
        if (!key) continue;
        const skips = {
          z0: 0, f2w: e.f[2], f3w: Math.trunc(e.f[3] / 4), f4w: Math.trunc(e.f[4] / 4),
          f0w: Math.trunc(e.f[0] / 4), absw: Math.trunc((base + e.f[2] * 0x400) / 4),
        };
        for (const [sn, sk] of Object.entries(skips)) {
          const c = new Snow2(key);
          if (sk > 0 && sk < 100000) c.skipWords(sk);
          const out = Buffer.from(src.subarray(st, st + blen));
          for (let i = 0; i + 4 <= out.length; i += 4)
            out.writeUInt32LE((out.readUInt32LE(i) - c.nextWord()) >>> 0, i);
          const sc = asciiScore(out.subarray(0, 64));
          if (sc > 0.8) hits.push({ sc, tag: `L${ln}/${cn}/${sn}`, e, st, out, key });
        }
      }
    }
  }
  hits.sort((a, b) => b.sc - a.sc);
  console.log(`강히트(>0.8) ${hits.length}개${hits.length ? ', 상위 12:' : ''}`);
  for (const h of hits.slice(0, 12))
    console.log(`[${h.sc.toFixed(2)}] ${h.tag} ${h.e.name} @0x${h.st.toString(16)} key=${h.key.toString('hex')}\n   "${h.out.subarray(0, 80).toString('latin1').replace(/[^\x20-\x7e]/g, '.')}"`);
  if (!hits.length) console.log('(강히트 없음)');
}
