// pkg-config-region.js — k1 영역 전체 복호화: [dataStart, indexStart) = 8바이트 헤더 + n2바이트 설정
//   k1 키/공식은 헤더 {A,B,cnt=엔트리수} 검증 완료. 설정 영역에서 [pkg+0x70] variant / [pkg+0x74] dispatch
//   / [pkg+0x78] blockSize / [pkg+0x7c] interval 후보 찾기.
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
  let s0 = '';
  for (let i = 0; i < len; i++) {
    const k = key0[i % n1] & 0x80 ? key0[i % n1] - 256 : key0[i % n1];
    s0 += String.fromCharCode(buf.readUInt16LE(n1 + 5 + i * 2) ^ (k & 0xffff));
  }
  const dataStart = n1 + 5 + len * 2, indexStart = dataStart + n2 + 8;
  const str = f + s0, L = str.length;
  const k1 = Buffer.alloc(16);
  for (let i = 0; i < 16; i++) k1[i] = (i + (str.charCodeAt(i % L) & 0xff)) & 0xff;
  const c1 = new Snow2(k1);
  const regionLen = 8 + n2;
  const region = Buffer.from(buf.subarray(dataStart, dataStart + Math.ceil(regionLen / 4) * 4));
  for (let i = 0; i + 4 <= region.length; i += 4)
    region.writeUInt32LE((region.readUInt32LE(i) - c1.nextWord()) >>> 0, i);
  console.log(`\n=== ${f} dataStart=0x${dataStart.toString(16)} n2=${n2} indexStart=0x${indexStart.toString(16)} ===`);
  console.log(`header: A=${region.readUInt16LE(0)} B=${region.readUInt16LE(2)} cnt=${region.readUInt32LE(4)}`);
  // 설정 영역 덤프 (8..8+n2)
  const cfg = region.subarray(8, 8 + n2);
  for (let i = 0; i < cfg.length; i += 16) {
    const row = cfg.subarray(i, Math.min(i + 16, cfg.length));
    const hex = row.toString('hex').match(/../g).join(' ');
    let ascii = '';
    for (const b of row) ascii += (b >= 0x20 && b < 0x7f) ? String.fromCharCode(b) : '.';
    console.log(`  +${(8 + i).toString(16).padStart(3, '0')}  ${hex.padEnd(47)}  ${ascii}`);
  }
  // dword/u16/wstring 시도 해석
  console.log('  u32:', Array.from({ length: Math.floor(n2 / 4) }, (_, i) => cfg.readUInt32LE(i * 4)).map(x => x.toString(16)).join(' '));
  // UTF-16LE 문자열 시도
  let w = '';
  for (let i = 0; i + 1 < cfg.length; i += 2) {
    const c = cfg.readUInt16LE(i);
    w += (c >= 0x20 && c < 0x7f) ? String.fromCharCode(c) : '·';
  }
  console.log('  utf16:', w);
  let a = '';
  for (let i = 0; i < cfg.length; i++) { const b = cfg[i]; a += (b >= 0x20 && b < 0x7f) ? String.fromCharCode(b) : '·'; }
  console.log('  ascii:', a);
}
