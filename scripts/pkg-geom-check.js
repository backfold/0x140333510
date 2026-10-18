// pkg-geom-check.js — 전체 엔트리 + indexEnd/base 기하 검증
'use strict';
const fs = require('fs');
function charSum(s) { let x = 0; for (const c of s) x = (x + c.charCodeAt(0)) >>> 0; return x; }
for (const f of ['texturescripts_00000.pkg', 'global_00000.pkg']) {
  const path = f;
  const buf = fs.readFileSync(`H:\\SA_Analysis\\target\\pkg_samples\\${f}`);
  const n1 = (charSum(path) % 312) + 30, n2 = ((charSum(path) * 3) % 212) + 33;
  const masked = buf.subarray(0, n1);
  const key0 = Buffer.from(masked); for (let i = 0; i < n1; i++) key0[i] = (masked[i] >> 1) | (masked[i] & 0x80);
  const len = (buf.readUInt32LE(n1 + 1) ^ (key0[0] & 0x80 ? key0[0] - 256 : key0[0])) >>> 0;
  let headerStr = '';
  for (let i = 0; i < len; i++) {
    const k = key0[i % n1] & 0x80 ? key0[i % n1] - 256 : key0[i % n1];
    headerStr += String.fromCharCode(buf.readUInt16LE(n1 + 5 + i * 2) ^ (k & 0xffff));
  }
  const dataStart = n1 + 5 + len * 2, indexStart = dataStart + n2 + 8;
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
  const str = path + headerStr, L = str.length;
  const k2 = Buffer.alloc(16);
  for (let i = 0; i < 16; i++) k2[i] = ((str.charCodeAt(L - (i % L) - 1) & 0xff) * ((i % 3) + 2) + i) & 0xff;
  const c2 = new Snow2(k2);
  const region = Buffer.from(buf.subarray(indexStart));
  for (let i = 0; i + 4 <= region.length - (region.length % 4); i += 4)
    region.writeUInt32LE((region.readUInt32LE(i) - c2.nextWord()) >>> 0, i);
  let off = 0, idx = 0;
  const ents = [];
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
    const tail = Buffer.from(region.subarray(off, off + 16)); off += 16;
    if (f[1] & 0x10) off += 40;
    ents.push({ name, f, tail, n });
    idx++;
  }
  const indexEnd = indexStart + off;
  const align = (x) => { const r = x & 0x3ff; return r ? x - r + 0x400 : x; };
  const base = align(indexEnd);
  let maxEnd = 0, badCnt = 0;
  for (const e of ents) {
    const st = base + e.f[2] * 0x400;
    const end = st + e.f[4];
    if (end > maxEnd) maxEnd = end;
    if (end > buf.length) badCnt++;
  }
  console.log(`=== ${f}`);
  console.log(`  fileSize=0x${buf.length.toString(16)} (${buf.length})  n1=${n1} n2=${n2} indexStart=${indexStart} entries=${ents.length}`);
  console.log(`  indexEnd=0x${indexEnd.toString(16)}  base=alignUp(indexEnd,0x400)=0x${base.toString(16)}  maxDataEnd=0x${maxEnd.toString(16)}  overflowEntries=${badCnt}`);
  // 블록 연속성 검증: f2 간격 == ceil(f4/0x400)?
  let seqOk = 0, seqBad = 0;
  for (let i = 1; i < ents.length; i++) {
    const expect = ents[i-1].f[2] + Math.ceil(ents[i-1].f[4] / 0x400);
    if (ents[i].f[2] === expect) seqOk++; else { seqBad++; if (seqBad <= 5) console.log(`  GAP@${i}: prev.f2=${ents[i-1].f[2]} prev.f4=${ents[i-1].f[4]} -> expect ${expect}, got ${ents[i].f[2]} (${ents[i].name})`); }
  }
  console.log(`  block-seq: ok=${seqOk} bad=${seqBad}`);
  console.log(`  last entries:`);
  for (const e of ents.slice(-4)) console.log(`    ${e.name} f=[${e.f.join(',')}]`);
  // 압축/비압축 통계
  const comp = ents.filter(e => e.f[1] & 1).length;
  console.log(`  compressed(f1&1)=${comp}/${ents.length}  f3<f4=${ents.filter(e=>e.f[3]<e.f[4]).length}  f3>f4=${ents.filter(e=>e.f[3]>e.f[4]).length}`);
}
