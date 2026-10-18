// pkg-flags15.js — 엔트리 f1 비트/벡터 개수/길이 필드 분포 (c810/ca20 모델 검증용)
'use strict';
const fs = require('fs');
function charSum(s) { let x = 0; for (const c of s) x = (x + c.charCodeAt(0)) >>> 0; return x; }
function parsePkg(f) {
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
  const dataStart = n1 + 5 + len * 2, indexStart = dataStart + n2 + 8;
  const str = f + headerStr, L = str.length;
  const k2 = Buffer.alloc(16);
  for (let i = 0; i < 16; i++) k2[i] = ((str.charCodeAt(L - (i % L) - 1) & 0xff) * ((i % 3) + 2) + i) & 0xff;
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
    const vec = [];
    for (let i = 0; i < n && i < 8; i++) { vec.push(Buffer.from(region.subarray(off, off + 16))); off += 16; }
    if (n > 8) off += (n - 8) * 16;
    const tail = Buffer.from(region.subarray(off, off + 16)); off += 16;
    if (f2[1] & 0x10) off += 32;
    ents.push({ name, f: f2, vec, tail });
  }
  const indexEnd = indexStart + off;
  const align = (x) => { const r = x & 0x3ff; return r ? x - r + 0x400 : x; };
  return { buf, headerStr, s0: headerStr, ents, base: align(indexEnd), fileSize: buf.length };
}
for (const pkgFile of ['texturescripts_00000.pkg', 'global_00000.pkg']) {
  const pkg = parsePkg(pkgFile);
  console.log(`\n=== ${pkgFile}: ${pkg.ents.length} entries, base=0x${pkg.base.toString(16)}, fileSize=0x${pkg.fileSize.toString(16)}`);
  const bits = {};
  const nDist = {};
  for (const e of pkg.ents) {
    const key = [(e.f[1] & 0x04) ? '4' : '-', (e.f[1] & 0x02) ? '2' : '-', (e.f[1] & 0x20) ? '20' : '-', (e.f[1] & 0x10) ? '10' : '-'].join('');
    bits[key] = (bits[key] || 0) + 1;
    nDist[e.vec.length] = (nDist[e.vec.length] || 0) + 1;
  }
  console.log('f1-bit combos (04/02/20/10):', JSON.stringify(bits));
  console.log('vector count dist:', JSON.stringify(nDist));
  console.log('first 8 entries:');
  for (const e of pkg.ents.slice(0, 8)) {
    console.log(`  ${JSON.stringify(e.name)} f=[${e.f.map(x => '0x' + x.toString(16)).join(',')}] n=${e.vec.length} off=0x${(pkg.base + e.f[2] * 0x400).toString(16)} f3=0x${e.f[3].toString(16)} (${e.f[3]}) f4=0x${e.f[4].toString(16)} f5=0x${e.f[5].toString(16)}`);
    console.log(`    tail=${e.tail.toString('hex')}${e.vec.length ? ' vec0=' + e.vec[0].toString('hex') : ''}`);
  }
  // f3가 길이인지 검증: base + f2*0x400 + f3 <= fileSize, 정렬 검사
  let ok3 = 0, bad3 = 0, ok4 = 0, bad4 = 0, maxEnd3 = 0;
  for (const e of pkg.ents) {
    const s = pkg.base + e.f[2] * 0x400;
    if (e.f[3] > 0 && s + e.f[3] <= pkg.fileSize) ok3++; else bad3++;
    if (e.f[4] > 0 && s + e.f[4] <= pkg.fileSize) ok4++; else bad4++;
    maxEnd3 = Math.max(maxEnd3, s + e.f[3]);
  }
  console.log(`f3-as-length: ok=${ok3} bad=${bad3}  f4-as-length: ok=${ok4} bad=${bad4}  maxEnd3=0x${maxEnd3.toString(16)} (fileSize=0x${pkg.fileSize.toString(16)})`);
  // 연속성: f2 정렬/중복 확인
  const f2s = pkg.ents.map(e => e.f[2]).sort((a, b) => a - b);
  console.log('f2 sorted (first 10):', f2s.slice(0, 10).join(','), ' dup?', new Set(f2s).size !== f2s.length);
}
