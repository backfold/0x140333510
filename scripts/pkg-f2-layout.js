// pkg-f2-layout.js — f2×1024+dataBase 배치 검증 (FUN_14029c810: shl ebx,10; add ebx,[this+0x20])
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
  const k1 = Buffer.alloc(16), k2 = Buffer.alloc(16);
  for (let i = 0; i < 16; i++) {
    k1[i] = (i + (str.charCodeAt(i % L) & 0xff)) & 0xff;
    k2[i] = ((str.charCodeAt(L - (i % L) - 1) & 0xff) * ((i % 3) + 2) + i) & 0xff;
  }
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
    const items = [];
    for (let i = 0; i < n; i++) { items.push([...region.subarray(off, off + 16)]); off += 16; }
    const tail16 = [...region.subarray(off, off + 16)]; off += 16;
    if (f[1] & 0x10) off += 40;
    entries.push({ name, f, items, tail16 });
  }
  return { buf, dataStart, k1, k2, indexStart, indexEnd: indexStart + off, entries };
}
const file = process.argv[2], path = process.argv[3] || file.replace(/.*[\\/]/, '');
const { buf, dataStart, k1, k2, indexEnd, entries } = parse(file, path);
const dataBase = Math.ceil(indexEnd / 0x400) * 0x400;
console.log(`${path}: indexEnd=${indexEnd} dataBase=${dataBase} 파일=${buf.length}`);
let maxEnd = 0;
for (const e of entries) maxEnd = Math.max(maxEnd, dataBase + e.f[2] * 1024 + e.f[4]);
console.log(`최대 끝 = ${maxEnd} (파일 ${buf.length}, 차이 ${buf.length - maxEnd})`);
const asc = (b) => { let c = 0; for (const x of b) if (x === 9 || x === 10 || x === 13 || (x >= 0x20 && x < 0x7f)) c++; return b.length ? c / b.length : 0; };
console.log('\n각 엔트리 f2*1024 위치 복호화 (표시: ASCII>0.8만):');
for (const e of entries) {
  const st = dataBase + e.f[2] * 1024;
  const blen = Math.min(e.f[4], 64, buf.length - st);
  if (blen < 16) { console.log(`  ${e.name.split('/').pop()}: 범위 초과 st=${st}`); continue; }
  let best = { sc: -1 };
  for (const [kn, key] of [['k1', k1], ['k2', k2]])
    for (const sn of [0, Math.floor((st - dataStart) / 4), Math.floor(st / 4), Math.floor((st - dataBase) / 4)])
      for (const cb of ['sub', 'xor']) {
        const s2 = new Snow2(key); s2.skipWords(sn);
        const out = Buffer.from(buf.subarray(st, st + blen));
        if (cb === 'sub') { for (let i = 0; i + 4 <= blen; i += 4) out.writeUInt32LE((out.readUInt32LE(i) - s2.nextWord()) >>> 0, i); }
        else { for (let i = 0; i + 4 <= blen; i += 4) out.writeUInt32LE((out.readUInt32LE(i) ^ s2.nextWord()) >>> 0, i); }
        const sc = asc(out);
        if (sc > best.sc) best = { sc, tag: `${kn}/skip${sn}/${cb}`, out };
      }
  const hi = best.sc > 0.8 ? ' ← 고ASCII!' : '';
  console.log(`  ${e.name.split('/').pop().padEnd(16)} st=${String(st).padStart(6)} f4=${String(e.f[4]).padStart(6)} 최고=${best.tag}=${best.sc.toFixed(2)}${hi}`);
  if (best.sc > 0.8) console.log(`     "${best.out.toString('latin1').replace(/[^\x20-\x7e]/g, '.')}"`);
  else console.log(`     ${best.out.subarray(0, 32).toString('hex').match(/../g).join(' ')}`);
}
