// pkg-pathc-brute4.js — FUN_1402a9820/14029c810 확정사항 반영:
//   blockIdx = f2 (×0x400), window length = f3, seek = tail16[0]/4 words, src16 = tail16
//   key = f83f0(ctx, tail16); f0 = 체크섬(사용 안함)
// 배치: blobAbs = base + f2*0x400 (base 후보), 레이어 1(단일)/2(f470 후)
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
  const str = path + headerStr, L = str.length;
  const k2 = Buffer.alloc(16);
  for (let i = 0; i < 16; i++) k2[i] = ((str.charCodeAt(L - (i % L) - 1) & 0xff) * ((i % 3) + 2) + i) & 0xff;
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
    off += n * 16 + 16;
    if (f[1] & 0x10) off += 40;
    entries.push({ name, f });
  }
  return { buf, headerStr, dataStart, indexStart, indexEnd: indexStart + off, entries };
}
const alignUp = (x, a) => Math.ceil(x / a) * a;
const asciiScore = (b) => { let c = 0; for (const x of b) if (x === 9 || x === 10 || x === 13 || (x >= 0x20 && x < 0x7f)) c++; return b.length ? c / b.length : 0; };

for (const f of ['texturescripts_00000.pkg', 'global_00000.pkg']) {
  const P = parseAll(`H:\\SA_Analysis\\target\\pkg_samples\\${f}`, f);
  const { buf, headerStr, dataStart, indexEnd, entries } = P;
  const base0 = f.replace(/\.pkg$/, '');
  console.log(`\n=== ${f}: 엔트리=${entries.length} indexEnd=${indexEnd} fileLen=${buf.length}`);
  // tail16 원시값 인쇄 (seek/source 확인용)
  for (const e of entries.slice(0, 4)) console.log(`  ${e.name}: f2=${e.f[2]} f3=${e.f[3]} f4=${e.f[4]} f1=${e.f[1]}`);
  const ks1 = keystream(deriveF470(f + headerStr), ((buf.length - dataStart) >> 2) + 8);
  const layer1 = Buffer.from(buf.subarray(dataStart));
  for (let i = 0; i + 4 <= layer1.length; i += 4)
    layer1.writeUInt32LE((layer1.readUInt32LE(i) - ks1[i / 4]) >>> 0, i);
  const inner0 = entries[0].name;
  const ctxCands = {
    pkgname: f, pkgbase: base0, header: headerStr, pkg_hdr: f + headerStr,
    inner0, inner0_bs: inner0.replace(/\//g, '\\'), inner0_base: inner0.split('/').pop(),
  };
  const bases = { zero: 0, dStart: dataStart, idxEnd: indexEnd, idxA400: alignUp(indexEnd, 0x400), b400: 0x400 };
  const results = [];
  for (const [layerN, srcBuf] of [['1', buf], ['2', layer1]]) {
    const origin = layerN === '1' ? 0 : dataStart; // layer1은 dataStart 기준
    for (const [bn, base] of Object.entries(bases)) {
      for (const [cn, ctx] of Object.entries(ctxCands)) {
        for (const e of entries) {
          const blobAbs = base + e.f[2] * 0x400;
          const st = blobAbs - origin;
          if (st < 0 || st + 16 > srcBuf.length) continue;
          // tail16: 인덱스에서 다시 읽어야 함 → parseAll이 tail을 안 돌려주므로 여기서 재계산
          results.push({ layerN, bn, base, cn, e, st, ctx });
        }
      }
    }
  }
  // tail16이 필요하므로 파서 확장 대신: 재파싱으로 tail 포함
  const tails = new Map();
  {
    const n1 = (charSum(f) % 312) + 30, n2 = ((charSum(f) * 3) % 212) + 33;
    const masked = buf.subarray(0, n1);
    const key0 = Buffer.from(masked); for (let i = 0; i < n1; i++) key0[i] = (masked[i] >> 1) | (masked[i] & 0x80);
    const len = (buf.readUInt32LE(n1 + 1) ^ (key0[0] & 0x80 ? key0[0] - 256 : key0[0])) >>> 0;
    let hs = '';
    for (let i = 0; i < len; i++) { const k = key0[i % n1] & 0x80 ? key0[i % n1] - 256 : key0[i % n1]; hs += String.fromCharCode(buf.readUInt16LE(n1 + 5 + i * 2) ^ (k & 0xffff)); }
    const ds = n1 + 5 + len * 2, is = ds + n2 + 8;
    const L2 = (f + hs).length, s2 = f + hs;
    const k2 = Buffer.alloc(16);
    for (let i = 0; i < 16; i++) k2[i] = ((s2.charCodeAt(L2 - (i % L2) - 1) & 0xff) * ((i % 3) + 2) + i) & 0xff;
    const c2 = new Snow2(k2);
    const region = Buffer.from(buf.subarray(is));
    for (let i = 0; i + 4 <= region.length - (region.length % 4); i += 4)
      region.writeUInt32LE((region.readUInt32LE(i) - c2.nextWord()) >>> 0, i);
    let off = 0;
    while (off + 4 <= region.length) {
      const sl = region.readUInt32LE(off); off += 4;
      if (sl === 0 || sl > 0x400 || off + sl * 2 + 28 > region.length) break;
      let name = '';
      for (let i = 0; i < sl; i++) name += String.fromCharCode(region.readUInt16LE(off + i * 2));
      off += sl * 2;
      const ff = []; for (let i = 0; i < 6; i++) { ff.push(region.readUInt32LE(off)); off += 4; }
      const n = region.readUInt32LE(off); off += 4;
      if (n > 0x10000) break;
      off += n * 16;
      tails.set(name, Buffer.from(region.subarray(off, off + 16))); off += 16;
      if (ff[1] & 0x10) off += 40;
    }
  }
  const hits = [];
  for (const r of results) {
    const e = r.e;
    const tail = tails.get(e.name);
    if (!tail) continue;
    const tail0 = tail.readUInt32LE(0);
    const key = deriveF83f0(r.ctx, tail);
    if (!key) continue;
    const srcBuf = r.layerN === '1' ? buf : layer1;
    for (const ln of [Math.min(e.f[3], 256), Math.min(e.f[4], 256)]) {
      const blen = Math.min(ln, srcBuf.length - r.st);
      if (blen < 16) continue;
      for (const sk of [Math.trunc(tail0 / 4), 0]) {
        const c = new Snow2(key);
        c.skipWords(sk);
        const out = Buffer.from(srcBuf.subarray(r.st, r.st + (blen & ~3)));
        for (let i = 0; i + 4 <= out.length; i += 4)
          out.writeUInt32LE((out.readUInt32LE(i) - c.nextWord()) >>> 0, i);
        const sc = asciiScore(out.subarray(0, 64));
        if (sc > 0.8) hits.push({ sc, tag: `L${r.layerN}/${r.bn}/${r.cn}/ln${ln}/sk${sk}`, e, st: r.st, out, key, tail0: tail0.toString(16) });
      }
    }
  }
  hits.sort((a, b) => b.sc - a.sc);
  console.log(`강히트(>0.8) ${hits.length}개${hits.length ? ', 상위 12:' : ''}`);
  for (const h of hits.slice(0, 12))
    console.log(`[${h.sc.toFixed(2)}] ${h.tag} ${h.e.name} @${h.st} tail0=0x${h.tail0} key=${h.key.toString('hex')}\n   "${h.out.subarray(0, 80).toString('latin1').replace(/[^\x20-\x7e]/g, '.')}"`);
  if (!hits.length) console.log('(강히트 없음)');
}
