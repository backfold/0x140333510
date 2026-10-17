// verify-kat.js — Python 포트(sa_pkg_crypto.py)에 내장한 KAT 상수를
// 검증된 Node 구현(pkg-parse.js와 동일 코드, 2026-10 실파일 검증 완료)으로
// 교차 확인한다. Python 인터프리터가 본 머신에 없어 이 Node 검증이
// Python 셀프테스트의 대리 증거가 된다.
//
// Usage: node scripts\py\verify-kat.js
'use strict';
const fs = require('fs');

const TABLES = JSON.parse(fs.readFileSync('H:\\SA_Analysis\\evidence\\snow_tables_from_exe.json', 'utf8')).tables;
const T = {
  a: TABLES.snow_alpha_mul.words, ai: TABLES.snow_alphainv_mul.words,
  t0: TABLES.snow_T0.words, t1: TABLES.snow_T1.words, t2: TABLES.snow_T2.words, t3: TABLES.snow_T3.words,
};
const a_mul = (w) => (((w << 8) >>> 0) ^ T.a[(w >>> 24) & 0xff]) >>> 0;
const ainv_mul = (w) => ((w >>> 8) ^ T.ai[w & 0xff]) >>> 0;
const fsmT = (w) => (T.t0[w & 0xff] ^ T.t1[(w >>> 8) & 0xff] ^ T.t2[(w >>> 16) & 0xff] ^ T.t3[(w >>> 24) & 0xff]) >>> 0;

// ---- 이하 pkg-parse.js 에서 복사(검증 완료본) ----
class Snow2 {
  constructor(key16) {
    this.s = new Uint32Array(16); this.r1 = 0; this.r2 = 0;
    const b = key16;
    const sx = (x) => (x & 0x80 ? x - 256 : x) | 0;
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

function deriveKeys(path, headerStr) {
  const str = path + headerStr, L = str.length;
  const k1 = Buffer.alloc(16), k2 = Buffer.alloc(16);
  for (let i = 0; i < 16; i++) {
    k1[i] = (i + (str.charCodeAt(i % L) & 0xff)) & 0xff;
    k2[i] = ((str.charCodeAt(L - (i % L) - 1) & 0xff) * ((i % 3) + 2) + i) & 0xff;
  }
  return { k1, k2 };
}
// ---- 복사 끝 ----

// sa_pkg_crypto.py 의 KAT 상수
const PY_KAT_KEY1 = Buffer.from('676d71656571653738393a3b3a7d7976', 'hex');
const PY_KAT_KS = [0xDE9995EE, 0x381DCAB0];

const { k1, k2 } = deriveKeys('global_00000.pkg', '!dlstps20djr@');
console.log('key1 (node)   =', k1.toString('hex'));
console.log('key1 (python) =', PY_KAT_KEY1.toString('hex'));
if (!k1.equals(PY_KAT_KEY1)) { console.error('FAIL: key1 KAT mismatch'); process.exit(1); }

const c = new Snow2(k1);
const ks = [c.nextWord(), c.nextWord()];
console.log('ks[0:2] (node)   =', ks.map((w) => w.toString(16)).join(' '));
console.log('ks[0:2] (python) =', PY_KAT_KS.map((w) => w.toString(16)).join(' '));
if (ks[0] !== PY_KAT_KS[0] || ks[1] !== PY_KAT_KS[1]) { console.error('FAIL: keystream KAT mismatch'); process.exit(1); }

// end-to-end: 실제 파일의 data head 복호 (dataStart=141)
const pkg = 'H:\\SA_Analysis\\target\\pkg_samples\\global_00000.pkg';
if (fs.existsSync(pkg)) {
  const buf = fs.readFileSync(pkg);
  const head = Buffer.from(buf.subarray(141, 149));
  console.log('cipher @141   =', head.toString('hex'));
  const dec = new Snow2(k1);
  const w0 = (head.readUInt32LE(0) - dec.nextWord()) >>> 0;
  const w1 = (head.readUInt32LE(4) - dec.nextWord()) >>> 0;
  console.log('plain  @141   = checksum=%d count=%d', w0, w1);
  if (w0 !== 524325 || w1 !== 6) { console.error('FAIL: data head mismatch'); process.exit(1); }
  console.log('[OK] 실파일 end-to-end (checksum=524325, count=6)');
}
console.log('[OK] Python KAT 상수가 검증된 Node 구현과 일치 — sa_pkg_crypto.py 셀프테스트 통과 예상');
