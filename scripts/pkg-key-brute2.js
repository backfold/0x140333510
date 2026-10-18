// pkg-key-brute2.js — 경로B 키(FUN_1402a84a0) 최종 재구현 + seek 0..1024 전수
// 오라클: zlib 파일(f1&1) 복호화 첫 2바이트 = 78 9c/01/da (결정적)
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
// 키 한 개에 대해 연속 키스트림 배열 생성 (seek 슬라이싱용)
function keystream(key, n) {
  const c = new Snow2(key); const out = new Uint32Array(n);
  for (let i = 0; i < n; i++) out[i] = c.nextWord();
  return out;
}
function charSum(s) { let x = 0; for (const c of s) x = (x + c.charCodeAt(0)) >>> 0; return x; }
function fnv1a16(s) { let h = 0x811c9dc5; for (let i = 0; i < s.length; i++) h = Math.imul(h ^ (s.charCodeAt(i) & 0xffff), 0x1000193) >>> 0; return h >>> 0; }
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
    entries.push({ name, f, tail16 });
  }
  return { buf, headerStr, indexEnd: indexStart + off, entries };
}
// 경로B 키 파생 (FUN_1402a84a0 — disasm8 완전 일치 버전)
function deriveKeyB(nameW, src16, variant, fpName) {
  const fp = fpName === 'log10' ? Math.log10(variant) : fpName === 'log' ? Math.log(variant) : Math.sqrt(variant);
  const v = Math.trunc(fp) | 0;
  const m = v + 1;
  if (m <= 0 || m > 100000) return null;
  const buf = new Int8Array(m);
  if (variant !== 0) {
    let x = variant >>> 0, pos = m - 1;
    while (true) {
      const q = (x / 10) | 0;
      buf[pos--] = x - q * 10;
      x = q;
      if (x === 0) break;
      if (pos < 0) break;
    }
  }
  const L = nameW.length;
  const key = Buffer.alloc(16);
  for (let i = 0; i < 0x80; i++) {
    const par = buf[i % m] & 1;
    const d1 = buf[(i + 1) % m], d2 = buf[(i + 2) % m];
    let a = ((((d1 + i) % 10) + src16[(d2 + i) % 16] + par) & 0xff);
    if (a >= 128) a -= 256;
    let w = nameW.charCodeAt(i % L) & 0xff;
    if (w >= 128) w -= 256;
    key[i % 16] = ((a * w) + i) & 0xff;
  }
  return key;
}
const file = process.argv[2], path = process.argv[3] || file.replace(/.*[\\/]/, '');
const { buf, headerStr, indexEnd, entries } = parse(file, path);
const dataBase = Math.ceil(indexEnd / 0x400) * 0x400;
const fnv = fnv1a16(headerStr);
console.log(`${path}: headerStr="${headerStr}" FNV=${fnv} dataBase=${dataBase} 엔트리=${entries.length}`);

const MAXSKIP = 1024, PROBE = 64;
const fps = ['log10', 'log', 'sqrt'];
// variant: 고정값 또는 엔트리별 함수
const variants = { fnv: () => fnv, fnvPath: () => fnv1a16(path), fnvPathNoExt: () => fnv1a16(path.replace(/\.pkg$/, '')), fnvName: (e) => fnv1a16(e.name), fnvBase: (e) => fnv1a16(e.name.split('/').pop()), zero: () => 0, six: () => 6 };
const names = { full: (e) => e.name, base: (e) => e.name.split('/').pop(), pkgpath: () => path, pkgdir: (e) => e.name.split('/').slice(0, -1).join('/') };
const srcs = { tail0_16: (e) => e.tail16, tail8_24: (e) => Buffer.from([...e.tail16.slice(8, 16), ...new Array(8).fill(0)]) };
const zlibEntries = entries.filter(e => (e.f[1] & 1) && e.f[4] >= 16);
console.log(`zlib 오라클 엔트리: ${zlibEntries.map(e => e.name.split('/').pop()).join(', ')}`);

const hits = [];
for (const fpName of fps) {
  for (const [vn, variant] of Object.entries(variants)) {
    for (const [nn, nf] of Object.entries(names)) {
      for (const [sn, sf] of Object.entries(srcs)) {
        // zlib 엔트리 키스트림 사전 생성
        const ksArr = new Map();
        let ok = true;
        for (const e of zlibEntries) {
          const key = deriveKeyB(nf(e), sf(e), variant(e), fpName);
          if (!key) { ok = false; break; }
          ksArr.set(e, keystream(key, MAXSKIP + PROBE / 4 + 4));
        }
        if (!ok) continue;
        for (let skip = 0; skip <= MAXSKIP; skip++) {
          let all = true;
          for (const e of zlibEntries) {
            const st = dataBase + e.f[2] * 1024;
            const w0 = ksArr.get(e)[skip], w1 = ksArr.get(e)[skip + 1];
            const d0 = (buf.readUInt32LE(st) - w0) >>> 0;
            const d1 = (buf.readUInt32LE(st + 4) - w1) >>> 0;
            const b0 = d0 & 0xff, b1 = (d0 >>> 8) & 0xff, b2 = d1 & 0xff;
            if (b0 !== 0x78 || (b1 !== 0x9c && b1 !== 0x01 && b1 !== 0xda && b1 !== 0x5e)) { all = false; break; }
          }
          if (all) {
            hits.push({ tag: `${fpName}/${vn}/${nn}/${sn}/skip${skip}` });
            console.log(`*** 히트: ${hits[hits.length-1].tag} (b2=0x${(buf.readUInt32LE(dataBase+zlibEntries[0].f[2]*1024+4)>>>0 & 0xff).toString(16)})`);
          }
        }
      }
    }
  }
}
if (!hits.length) {
  console.log('히트 없음 — 부분 오라클(단일 엔트리 78만) 스캔:');
  for (const fpName of fps) {
    for (const [nn, nf] of Object.entries(names)) {
      for (const [sn, sf] of Object.entries(srcs)) {
        for (const e of zlibEntries) {
          const key = deriveKeyB(nf(e), sf(e), fnv, fpName);
          if (!key) continue;
          const ks = keystream(key, MAXSKIP + 8);
          const st = dataBase + e.f[2] * 1024;
          for (let skip = 0; skip <= MAXSKIP; skip++) {
            const d0 = (buf.readUInt32LE(st) - ks[skip]) >>> 0;
            if ((d0 & 0xff) === 0x78) { console.log(`  ${e.name.split('/').pop()} [${fpName}/${nn}/${sn}/skip${skip}]: ${d0.toString(16).padStart(8,'0')}`); }
          }
        }
      }
    }
  }
}
