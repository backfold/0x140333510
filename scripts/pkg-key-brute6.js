// pkg-key-brute6.js — 2층 암호 가설: plain = ct − 2·ks  (creator#3 + creator#2, 동일키 동일seek)
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
}
function keystream(key, n) { const c = new Snow2(key); const o = new Uint32Array(n); for (let i = 0; i < n; i++) o[i] = c.nextWord(); return o; }
function charSum(s) { let x = 0; for (const c of s) x = (x + c.charCodeAt(0)) >>> 0; return x; }
function parse(file, path) {
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
  const dataStart = n1 + 5 + len * 2;
  const str = path + headerStr, L = str.length;
  const k2 = Buffer.alloc(16);
  for (let i = 0; i < 16; i++) k2[i] = ((str.charCodeAt(L - (i % L) - 1) & 0xff) * ((i % 3) + 2) + i) & 0xff;
  const indexStart = dataStart + n2 + 8;
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
    const tail16 = Buffer.from(region.subarray(off, off + 16)); off += 16;
    if (f[1] & 0x10) off += 40;
    entries.push({ name, f, n, tail16 });
  }
  return { buf, headerStr, indexEnd: indexStart + off, entries };
}
function deriveKeyC(ctxW, src16) {
  const L = ctxW.length;
  if (L === 0) return null;
  const out = Buffer.alloc(128);
  for (let i = 0; i < 128; i++) {
    const q = (i / 10) | 0;
    let t = (src16[i & 0xf] - 5 * q + 2 + i) & 0xff;
    let a = t >= 128 ? t - 256 : t;
    let w = ctxW.charCodeAt(i % L) & 0xff;
    if (w >= 128) w -= 256;
    out[i] = ((a * w) + i) & 0xff;
  }
  return out.subarray(0, 16);
}
const file = process.argv[2], path = process.argv[3] || file.replace(/.*[\\/]/, '');
const { buf, headerStr, indexEnd, entries } = parse(file, path);
const dataBase = Math.ceil(indexEnd / 0x400) * 0x400;
const base = path.replace(/\.pkg$/, '').replace(/^.*[\\/]/, '');
const ctxForms = {
  bare: path, noext: base, upper: path.toUpperCase(), gamedir_bf: 'game\\' + path,
  plusheader: path + headerStr, dot_fs: './' + path,
  nameFull: null, nameBase: null, // 엔트리 이름 (아래 치환)
};
const srcs = {
  tail0_16: (e) => e.tail16,
  tail8_24: (e) => Buffer.from([...e.tail16.slice(8, 16), ...new Array(8).fill(0)]),
  tail0_8: (e) => Buffer.from([...e.tail16.slice(0, 8), ...new Array(8).fill(0)]),
};
const oracle = entries.filter(e => !(e.f[1] & 1) && /\.txt$/i.test(e.name) && e.f[4] >= 32);
console.log(`${path}: dataBase=${dataBase} 오라클 ${oracle.length}개`);
const MAXSKIP = 1024, PROBE_W = 16;
// 결합 후보: 1×(기존), 2×(2층), 3×(만약 3층)
const MULTS = [1, 2, 3];
let best = { sc: -1 }; const hits = [];
for (const [cn, cv0] of Object.entries(ctxForms)) {
  for (const [sn, sf] of Object.entries(srcs)) {
    for (const mult of MULTS) {
      const ksArr = new Map(), ct = new Map();
      for (const e of oracle) {
        let cv = cv0;
        if (cn === 'nameFull') cv = e.name; else if (cn === 'nameBase') cv = e.name.split('/').pop();
        ksArr.set(e, keystream(deriveKeyC(cv, sf(e)), MAXSKIP + PROBE_W + 4));
        const st = dataBase + e.f[2] * 1024;
        ct.set(e, buf.subarray(st, st + Math.min(e.f[4], PROBE_W * 4)));
      }
      for (let skip = 0; skip <= MAXSKIP; skip++) {
        let sum = 0;
        for (const e of oracle) {
          const ks = ksArr.get(e).subarray(skip, skip + PROBE_W);
          const c = ct.get(e);
          let pr = 0;
          for (let w = 0; w < Math.min(c.length >> 2, PROBE_W); w++) {
            const d = (c.readUInt32LE(w * 4) - mult * ks[w]) >>> 0;
            for (const b of [d & 0xff, (d >>> 8) & 0xff, (d >>> 16) & 0xff, (d >>> 24) & 0xff])
              if (b === 9 || b === 10 || b === 13 || (b >= 0x20 && b < 0x7f)) pr++;
          }
          sum += pr / Math.min(c.length, PROBE_W * 4);
        }
        const avg = sum / oracle.length;
        if (avg > best.sc) best = { sc: avg, tag: `${cn}/${sn}/x${mult}/skip${skip}` };
        if (avg > 0.85) { hits.push(best.tag); console.log(`*** 히트: [${best.tag}] ${avg.toFixed(3)}`); }
      }
    }
  }
}
console.log(`\n히트 ${hits.length}개 / 최고: [${best.tag}] ${best.sc.toFixed(3)}`);
{
  const [cn, sn, m, sk] = best.tag.split('/');
  const skip = +sk.replace('skip', '');
  const sf = srcs[sn];
  console.log(`\n[${best.tag}] 샘플:`);
  for (const e of oracle.slice(0, 6)) {
    let cv = ctxForms[cn];
    if (cn === 'nameFull') cv = e.name; else if (cn === 'nameBase') cv = e.name.split('/').pop();
    const ks = keystream(deriveKeyC(cv, sf(e)), skip + PROBE_W).subarray(skip);
    const st = dataBase + e.f[2] * 1024;
    const out = Buffer.from(buf.subarray(st, st + Math.min(e.f[4], 64)));
    for (let w = 0; (w + 1) * 4 <= out.length; w++) out.writeUInt32LE((out.readUInt32LE(w * 4) - (+m.replace('x','')) * ks[w]) >>> 0, w * 4);
    console.log(`  ${e.name.split('/').pop()}: "${out.toString('latin1').replace(/[^\x20-\x7e\n\r\t]/g, '.')}"`);
  }
}
