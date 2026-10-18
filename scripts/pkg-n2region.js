// pkg-n2region.js — 데이터헤드와 인덱스 사이 N2바이트 영역 해독 시도 (key1 연속 / key1 fresh / key2 fresh)
'use strict';
const fs = require('fs');
// Snow2/파서 — pkg-layout.js 와 동일 (require 회피 위해 인라인 재사용)
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
const file = process.argv[2], path = process.argv[3] || file.replace(/.*[\\/]/, '');
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
const k1 = Buffer.alloc(16), k2 = Buffer.alloc(16);
for (let i = 0; i < 16; i++) {
  k1[i] = (i + (str.charCodeAt(i % L) & 0xff)) & 0xff;
  k2[i] = ((str.charCodeAt(L - (i % L) - 1) & 0xff) * ((i % 3) + 2) + i) & 0xff;
}
const indexStart = dataStart + n2 + 8;
console.log(`${path}: dataStart=${dataStart} N2=${n2} indexStart=${indexStart} — N2영역 [${dataStart + 8},${indexStart})`);
function dec(st, key, skip, blen) {
  const s2 = new Snow2(key); s2.skipWords(skip);
  const out = Buffer.from(buf.subarray(st, st + blen));
  for (let i = 0; i + 4 <= blen; i += 4) out.writeUInt32LE((out.readUInt32LE(i) - s2.nextWord()) >>> 0, i);
  return out;
}
const blen = indexStart - (dataStart + 8);
for (const [tag, key, skip] of [['key1연속(단어2부터)', k1, 2], ['key1 fresh', k1, 0], ['key2 fresh', k2, 0], ['key2 연속', k2, 2]]) {
  const out = dec(dataStart + 8, key, skip, blen - (blen % 4));
  const u32 = []; for (let i = 0; i + 4 <= out.length; i += 4) u32.push(out.readUInt32LE(i));
  const small = u32.filter(x => x < 0x10000).length;
  console.log(`\n[${tag}] u32 ${u32.length}개 중 <0x10000: ${small}`);
  console.log('  hex:', out.subarray(0, 48).toString('hex').match(/../g).join(' '));
  console.log('  u32:', u32.slice(0, 16).join(','));
  const asc = out.subarray(0, 64).toString('latin1').replace(/[^\x20-\x7e]/g, '.');
  console.log('  txt:', asc);
}
// 원본(암호문) 그대로도
console.log('\n[raw] hex:', buf.subarray(dataStart + 8, dataStart + 8 + 48).toString('hex').match(/../g).join(' '));
