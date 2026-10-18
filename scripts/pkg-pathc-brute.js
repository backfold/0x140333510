// pkg-pathc-brute.js — pathC(f83f0) 파일 데이터 복호화 결정 브루트
// key[j] = ((int8)(src16[j&15] - 5*(j/10) + 2 + j) * (int8)ctx[j%L].low + j) & 0xff  (j=0..15)
// 배치: indexEnd(또는 align)부터 idx 순 f4 적립, skip=f0/4, 오라클=ASCII 비율
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
function charSum(s) { let x = 0; for (const c of s) x = (x + c.charCodeAt(0)) >>> 0; return x; }
function deriveF83f0(ctx, src16) { // pathC
  const L = ctx.length; if (!L) return null;
  const out = Buffer.alloc(16);
  for (let j = 0; j < 16; j++) {
    const a = ((src16[j & 15] - 5 * Math.floor(j / 10) + 2 + j) & 0xff);
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
    const items = [];
    for (let i = 0; i < n; i++) { items.push(Buffer.from(region.subarray(off, off + 16))); off += 16; }
    const tail16 = Buffer.from(region.subarray(off, off + 16)); off += 16;
    if (f[1] & 0x10) off += 40;
    entries.push({ name, f, items, tail16 });
  }
  return { buf, n1, n2, headerStr, dataStart, indexStart, indexEnd: indexStart + off, entries };
}
const alignUp = (x, a) => Math.ceil(x / a) * a;
const asciiScore = (b) => { let c = 0; for (const x of b) if (x === 9 || x === 10 || x === 13 || (x >= 0x20 && x < 0x7f)) c++; return b.length ? c / b.length : 0; };

for (const f of ['texturescripts_00000.pkg', 'global_00000.pkg']) {
  const file = `H:\\SA_Analysis\\target\\pkg_samples\\${f}`;
  const path = f;
  const P = parseAll(file, path);
  const { buf, headerStr, dataStart, indexEnd, entries } = P;
  const base0 = path.replace(/\.pkg$/, '');
  console.log(`\n=== ${f}: 엔트리=${entries.length} indexEnd=${indexEnd}`);
  // ctx 후보
  const inner0 = entries[0].name;
  const ctxCands = {
    pkgname: path, pkgbase: base0, header: headerStr, pkg_hdr: path + headerStr,
    inner0, inner0_bs: inner0.replace(/\//g, '\\'), inner0_base: inner0.split('/').pop(),
    gamedir: 'game\\' + path, abs: 'H:\\Program Files\\Nexon\\SuddenAttack\\game\\' + path,
  };
  // 배치 후보
  const places = [];
  for (const [bn, base] of [['indexEnd', indexEnd], ['a4', alignUp(indexEnd, 4)], ['a16', alignUp(indexEnd, 16)], ['a400', alignUp(indexEnd, 0x400)]]) {
    let cur = base; const m = new Map();
    for (const e of entries) { cur = alignUp(cur, 4); m.set(e, cur); cur += e.f[4]; }
    places.push([bn, m]);
  }
  const results = [];
  for (const [cn, ctx] of Object.entries(ctxCands)) {
    for (const e of entries) {
      if (e.f[1] & 1) continue; // 저장 제외(추후)
      for (const [bn, m] of places) {
        const st = m.get(e);
        const blen = Math.min(e.f[4], 256, buf.length - st);
        if (blen < 16) continue;
        const key = deriveF83f0(ctx, e.tail16);
        if (!key) continue;
        for (const sn of ['f0w', 'zero']) {
          const s2 = new Snow2(key);
          if (sn === 'f0w') s2.skipWords(Math.floor(e.f[0] / 4));
          const out = Buffer.from(buf.subarray(st, st + blen));
          for (let i = 0; i + 4 <= blen; i += 4) out.writeUInt32LE((out.readUInt32LE(i) - s2.nextWord()) >>> 0, i);
          const sc = asciiScore(out.subarray(0, 64));
          if (sc > 0.55) results.push({ sc, tag: `${cn}/${bn}/${sn}`, e, st, out });
        }
      }
    }
  }
  results.sort((a, b) => b.sc - a.sc);
  console.log(`히트 ${results.length}개, 상위 8:`);
  for (const r of results.slice(0, 8)) {
    console.log(`[${r.sc.toFixed(2)}] ${r.tag} ${r.e.name} @${r.st} key16=${deriveF83f0(Object.entries(ctxCands).find(([k]) => r.tag.startsWith(k + '/'))[1], r.e.tail16).toString('hex')}`);
    console.log(`   "${r.out.subarray(0, 64).toString('latin1').replace(/[^\x20-\x7e]/g, '.')}"`);
  }
  if (!results.length) console.log('(히트 없음 — 배치/ctx 가설 재검토 필요)');
}
