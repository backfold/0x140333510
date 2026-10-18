// pkg-gap-k1.js — 갭 영역을 k1 사이퍼로 복호화 시도
'use strict';
const fs = require('fs');
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
for (const f of ['texturescripts_00000.pkg', 'global_00000.pkg']) {
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
  const dataStart = n1 + 5 + len * 2;
  const str = f + headerStr, L = str.length;
  const k1 = Buffer.alloc(16);
  for (let i = 0; i < 16; i++) k1[i] = (i + (str.charCodeAt(i % L) & 0xff)) & 0xff;
  const gapLen = n2 + 8;
  const c = new Snow2(k1);
  const dec = Buffer.from(buf.subarray(dataStart, dataStart + gapLen));
  for (let i = 0; i + 4 <= dec.length; i += 4)
    dec.writeUInt32LE((dec.readUInt32LE(i) - c.nextWord()) >>> 0, i);
  console.log(`\n=== ${f} k1-decrypted gap (${gapLen} bytes):`);
  for (let i = 0; i < gapLen; i += 16)
    console.log(`  +${i.toString(16).padStart(3, '0')}: ${dec.subarray(i, i + 16).toString('hex').match(/../g).join(' ')}`);
  console.log(`  latin1: ${JSON.stringify(dec.toString('latin1'))}`);
  // wstring 리스트 해석: [count32] + 반복 [len32][wchars]
  let off = 0;
  const cnt = dec.readUInt32LE(off); off += 4;
  if (cnt > 0 && cnt < 0x100) {
    console.log(`  count32 = ${cnt}`);
    for (let e = 0; e < cnt && off + 4 <= dec.length; e++) {
      const sl = dec.readUInt32LE(off); off += 4;
      if (sl > 0x100 || off + sl * 2 > dec.length) { console.log(`    [${e}] bad len ${sl}`); break; }
      let s = '';
      for (let i = 0; i < sl; i++) s += String.fromCharCode(dec.readUInt16LE(off + i * 2));
      off += sl * 2;
      console.log(`    [${e}] ${JSON.stringify(s)}`);
    }
  }
}
