// pkg-gap-decrypt2.js — 갭 영역 정밀 스윕: concat=path+headerStr 검증된 조합,
// f470/f6b0 × skip 0..65535 (마운트 seek가 클 수 있음), 3워드 프리스크린
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
function deriveF470(concat) {
  const L = concat.length; if (!L) return null;
  const out = Buffer.alloc(16);
  for (let i = 0; i < 16; i++) out[i] = (i + (concat.charCodeAt(i % L) & 0xff)) & 0xff;
  return out;
}
function deriveF6b0(concat) {
  const L = concat.length; if (!L) return null;
  const out = Buffer.alloc(16);
  for (let i = 0; i < 16; i++) {
    let w = concat.charCodeAt(L - 1 - (i % L)) & 0xff; if (w >= 128) w -= 256;
    out[i] = (w * ((i % 3) + 2) + i) & 0xff;
  }
  return out;
}
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
  return { buf, n1, n2, headerStr, dataStart, indexStart: dataStart + n2 + 8 };
}
const file = process.argv[2], path = process.argv[3] || file.replace(/.*[\\/]/, '');
const { buf, n2, headerStr, dataStart, indexStart } = parse(file, path);
const name = path.replace(/\.pkg$/, '');
console.log(`${path}: gap ${n2 + 8}B @0x${dataStart.toString(16)}, header=[${headerStr}]`);
const cands = {
  'name+hdr': path + headerStr,
  'hdr+name': headerStr + path,
  'name+hdr+name': path + headerStr + path,
  'base+hdr': name + headerStr,
  'name+hdr2': path + headerStr + headerStr,
  'gamedir+hdr': 'game\\' + path + headerStr,
};
const gap = buf.subarray(dataStart, indexStart);
const nw = gap.length >> 2;
const PRE = Math.min(3, nw);
const MAXSKIP = 65536;
let best = { sc: -1 };
for (const [tag, s] of Object.entries(cands)) {
  for (const [fn, fd] of [['f470', deriveF470], ['f6b0', deriveF6b0]]) {
    const key = fd(s);
    const ks = keystream(key, MAXSKIP + nw + 2);
    const ctw = new Uint32Array(nw);
    for (let w = 0; w < nw; w++) ctw[w] = gap.readUInt32LE(w * 4);
    for (let skip = 0; skip <= MAXSKIP; skip++) {
      let good = 0, tot = PRE * 4;
      for (let w = 0; w < PRE; w++) {
        const d = (ctw[w] - ks[skip + w]) >>> 0;
        for (const b of [d & 0xff, (d >>> 8) & 0xff, (d >>> 16) & 0xff, (d >>> 24) & 0xff])
          if (b === 0 || b === 9 || b === 10 || b === 13 || (b >= 0x20 && b < 0x7f)) good++;
      }
      if (good / tot < 0.9) continue;
      let g2 = 0;
      for (let w = 0; w < nw; w++) {
        const d = (ctw[w] - ks[skip + w]) >>> 0;
        for (const b of [d & 0xff, (d >>> 8) & 0xff, (d >>> 16) & 0xff, (d >>> 24) & 0xff])
          if (b === 0 || b === 9 || b === 10 || b === 13 || (b >= 0x20 && b < 0x7f)) g2++;
      }
      const sc = g2 / (nw * 4);
      if (sc > best.sc) {
        let hex = '';
        for (let w = 0; w < Math.min(nw, 10); w++) {
          const d = (ctw[w] - ks[skip + w]) >>> 0;
          hex += d.toString(16).padStart(8, '0').replace(/(..)(..)(..)(..)/, '$4$3$2$1') + ' ';
        }
        best = { sc, tag: `${tag}/${fn}/skip${skip}`, hex };
        console.log(`  [${sc.toFixed(3)}] ${best.tag}  ${hex}`);
        if (sc > 0.95) { console.log('*** 히트!'); process.exit(0); }
      }
    }
  }
}
console.log(`최고: [${best.sc.toFixed(3)}] ${best.tag}`);
