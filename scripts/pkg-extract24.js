// pkg-extract24.js — c4c0/d750 검증모델: 헤드 0x400바이트만 Snow2 SUB, 나머지 평문 패스스루
//   근거(verbatim):
//   - ca20 ca86: TEST f1&0x4 → JZ cb3a(비트 없음: 세그/연속 경로); 세팅 → c4c0
//   - c4c0 c677: aba0(reader, stream, cipher, R9D=0x400) → reader+0x20 = 0x400 (블록 잔여)
//   - c4c0 c68e: vtable=140333238 (블록 리더)
//   - d750: [this+0x20] 카운트다운, min(remaining,len)만 d8d0 복호화, 초과분 under스트림 패스스루
//   - d8d0/adbe0: 워드(4B) SUB; cfd0: wordSize=4
//   - deriveC(정정): t = src16[j&15] − 5·(j/5) + 2 + j = src16 + (j%5) + 2
//   - beee0: 16바이트 키 → 빅엔디언 4워드 → Snow2-128 스펙 초기화
'use strict';
const fs = require('fs');
const zlib = require('zlib');
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
function deriveC(ctx, src16) {
  const out = Buffer.alloc(128);
  const ctxLen = ctx.length;
  for (let j = 0; j < 128; j++) {
    const t8 = ((src16[j & 15]) - 5 * Math.floor(j / 5) + 2 + j) & 0xff;
    const ts = t8 & 0x80 ? t8 - 256 : t8;
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
  return { buf, file: f, ents, base: align(indexEnd), fileSize: buf.length };
}
function printableRatio(b) {
  let g = 0; const n = Math.min(b.length, 64); if (!n) return 0;
  for (let i = 0; i < n; i++) { const c = b[i]; if ((c >= 0x20 && c < 0x7f) || c === 0x0a || c === 0x0d || c === 0x09 || c === 0) g++; }
  return g / n;
}
let hits = 0;
for (const pkgFile of ['texturescripts_00000.pkg', 'global_00000.pkg']) {
  const pkg = parsePkg(pkgFile);
  console.log(`\n=== ${pkgFile} base=0x${pkg.base.toString(16)} ents=${pkg.ents.length}`);
  for (const e of pkg.ents) {
    const F = pkg.base + e.f[2] * 0x400;
    const stored = Math.min(e.f[4], pkg.fileSize - F);
    if (stored <= 0) { console.log(`  ${e.name}: OUT OF FILE`); continue; }
    const headLen = Math.min(0x400, stored);
    const ct = pkg.buf.subarray(F, F + stored);
    // f4 > 0x400 이면 테일은 평문 — 즉시 확인
    if (stored > 0x400) {
      const plainTail = ct.subarray(0x400, Math.min(stored, 0x400 + 64));
      console.log(`  [PLAIN-TAIL] ${e.name} f4=0x${e.f[4].toString(16)} tail@0x400: ${plainTail.toString('hex').slice(0, 96)}`);
      console.log(`    as latin1: ${JSON.stringify(plainTail.toString('latin1').slice(0, 64))}`);
    }
    const cands = { name: e.name, nameLower: e.name.toLowerCase(), noext: e.name.replace(/\.[^.]*$/, '') };
    for (const [cn, ctx] of Object.entries(cands)) {
      const key = deriveC(ctx, e.tail).subarray(0, 16);
      const c1 = new Snow2(key);
      const dec = Buffer.from(ct.subarray(0, headLen));
      const nw = headLen >> 2;
      for (let w = 0; w < nw; w++) dec.writeUInt32LE((dec.readUInt32LE(w * 4) - c1.nextWord()) >>> 0, w * 4);
      const isZ = (e.f[1] & 1) && dec.length >= 2 && dec[0] === 0x78 && ((dec[0] * 256 + dec[1]) % 31) === 0;
      const pr = printableRatio(dec);
      if (isZ || pr > 0.85) {
        hits++;
        console.log(`  HIT ${e.name} ctx=${cn} ${isZ ? 'ZLIB' : 'printable=' + pr.toFixed(3)} F=0x${F.toString(16)} f1=${e.f[1]} f3=0x${e.f[3].toString(16)} f4=0x${e.f[4].toString(16)}`);
        console.log(`    head=${dec.subarray(0, 48).toString('hex')}`);
        console.log(`    text=${JSON.stringify(dec.subarray(0, 96).toString('latin1'))}`);
        if (isZ) {
          const full = Buffer.concat([dec, Buffer.from(ct.subarray(headLen, stored))]);
          try { const d = zlib.inflateSync(full); console.log(`    inflate OK len=${d.length} (f3=${e.f[3]}): ${JSON.stringify(d.subarray(0, 80).toString('latin1'))}`); }
          catch (err) {
            try { const d = zlib.inflateRawSync(full); console.log(`    inflateRAW OK len=${d.length}: ${JSON.stringify(d.subarray(0, 80).toString('latin1'))}`); }
            catch (e2) { console.log(`    inflate fail: ${err.message}`); }
          }
        }
        break;
      } else if (cn === 'name') {
        console.log(`  ..  ${e.name} f1=${e.f[1]} f4=0x${e.f[4].toString(16)} pr=${pr.toFixed(2)} head=${dec.subarray(0, 24).toString('hex')}`);
      }
    }
  }
}
console.log(`\ntotal hits: ${hits}`);
