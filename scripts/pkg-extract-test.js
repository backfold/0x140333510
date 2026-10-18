// pkg-extract-test.js — 파일 데이터 영역 복호화 전수 조합 (base×order×align×key×skip×combine)
// 오라클: 저장(f1&1==0) 엔트리의 ASCII 점수 + .ltb/.ltc 매직
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
// — 검증된 파서 (pkg-parse.js 로직) —
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
  if (f[1] & 0x10) off += 40;  // FUN_1402b18c0: 16+16+8
  entries.push({ name, f, items, tail16 });
}
const indexEnd = indexStart + off;
console.log(`${path}: dataStart=${dataStart} n2=${n2} indexStart=${indexStart} indexEnd=${indexEnd} 파일=${buf.length} 엔트리=${entries.length}`);
for (const e of entries) console.log(`  ${e.name.padEnd(28)} f0=${String(e.f[0]).padStart(6)} f1=${e.f[1]} f2=${String(e.f[2]).padStart(3)} f3=${String(e.f[3]).padStart(6)} f4=${String(e.f[4]).padStart(6)} items=${e.items.length}`);

const alignUp = (x, a) => Math.ceil(x / a) * a;
const asciiScore = (b) => { let c = 0; for (const x of b) if (x === 9 || x === 10 || x === 13 || (x >= 0x20 && x < 0x7f)) c++; return b.length ? c / b.length : 0; };
const PROBE = 256;
const results = [];
const orders = {
  f2asc: [...entries].sort((a, b) => a.f[2] - b.f[2]),
  f2desc: [...entries].sort((a, b) => b.f[2] - a.f[2]),
  idx: entries,
};
const bases = { indexEnd, align400: alignUp(indexEnd, 0x400), align16: alignUp(indexEnd, 16), dataStart };
for (const [on, order] of Object.entries(orders)) {
  for (const [bn, base] of Object.entries(bases)) {
    for (const fa of [1, 16, 0x400]) {
      // 배치
      let cur = base; const place = new Map();
      for (const e of order) { cur = alignUp(cur, fa); place.set(e, cur); cur += e.f[4]; }
      for (const kn of ['k1', 'k2', 'tail16']) {
        for (const sn of ['fresh0', 'cum', 'f0w']) {
          for (const cb of ['sub', 'xor']) {
            let best = { sc: -1 };
            for (const e of entries) {
              if (e.f[1] & 1) continue;                 // 저장 파일만
              const st = place.get(e);
              const blen = Math.min(e.f[4], PROBE, buf.length - st);
              if (blen < 16) continue;
              const key = kn === 'tail16' ? Buffer.from(e.tail16) : (kn === 'k1' ? k1 : k2);
              const s2 = new Snow2(key);
              if (sn === 'cum') s2.skipWords(Math.floor((st - dataStart) / 4));
              if (sn === 'f0w') s2.skipWords(Math.floor(e.f[0] / 4));
              const out = Buffer.from(buf.subarray(st, st + blen));
              if (cb === 'sub') { for (let i = 0; i + 4 <= blen; i += 4) out.writeUInt32LE((out.readUInt32LE(i) - s2.nextWord()) >>> 0, i); }
              else { for (let i = 0; i + 4 <= blen; i += 4) out.writeUInt32LE((out.readUInt32LE(i) ^ s2.nextWord()) >>> 0, i); }
              const sc = asciiScore(out.subarray(0, Math.min(blen, 64)));
              if (sc > best.sc) best = { sc, e, out, st };
            }
            if (best.sc > 0) results.push({ tag: `${on}/${bn}/a${fa}/${kn}/${sn}/${cb}`, ...best });
          }
        }
      }
    }
  }
}
results.sort((a, b) => b.sc - a.sc);
console.log(`\n조합 ${results.length}개 중 상위 12:`);
for (const r of results.slice(0, 12)) {
  console.log(`[${r.tag}] ASCII=${r.sc.toFixed(2)} ${r.e.name.split('/').pop()} @${r.st}`);
  console.log(`   ${r.out.subarray(0, 48).toString('hex').match(/../g).join(' ')}`);
  console.log(`   "${r.out.subarray(0, 48).toString('latin1').replace(/[^\x20-\x7e]/g, '.')}"`);
}
