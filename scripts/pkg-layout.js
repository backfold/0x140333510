// pkg-layout.js — 데이터 배치 가설: f2 순서 + f4(저장크기) 연속 배치, 정렬/기준점/스트림 변형, tail16 키 가설
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
function parseAll(file, path) {
  const buf = fs.readFileSync(file);
  const n1 = (charSum(path) % 312) + 30, n2 = ((charSum(path) * 3) % 212) + 33;
  const masked = buf.subarray(0, n1);
  const versionByte = buf[n1];
  const v1 = (((((masked[0] >> 1) | (masked[0] & 0x80)) ^ versionByte) & 0xff) === 3);
  const key = Buffer.from(masked);
  if (v1) for (let i = 0; i < n1; i++) key[i] = (masked[i] >> 1) | (masked[i] & 0x80);
  let pos = n1 + (v1 ? 1 : 0);
  const len = (buf.readUInt32LE(pos) ^ (key[0] & 0x80 ? key[0] - 256 : key[0])) >>> 0;
  pos += 4;
  let headerStr = '';
  for (let i = 0; i < len; i++) {
    const k = key[i % n1] & 0x80 ? key[i % n1] - 256 : key[i % n1];
    headerStr += String.fromCharCode(buf.readUInt16LE(pos + i * 2) ^ (k & 0xffff));
  }
  const dataStart = pos + len * 2;
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
    if (f[1] & 0x10) off += 32;
    entries.push({ name, f, items, tail16 });
    if (entries.length > 64) break;
  }
  return { buf, dataStart, k1, k2, indexStart, indexEnd: indexStart + off, entries };
}
const alignUp = (x, a) => Math.ceil(x / a) * a;

const file = process.argv[2], path = process.argv[3] || file.replace(/.*[\\/]/, '');
const { buf, dataStart, k1, indexStart, indexEnd, entries } = parseAll(file, path);
console.log(`${path}: dataStart=${dataStart} indexEnd=${indexEnd} file=${buf.length}`);
const sumF4 = entries.reduce((a, e) => a + e.f[4], 0);
console.log(`Σf4(저장크기)=${sumF4}, tail=${buf.length - indexEnd}B, 여유=${buf.length - indexEnd - sumF4}`);

// 구조 점수: 0바이트 비율 + u32 정렬 소정수 비율 + 인쇄가능
function structScore(out) {
  let z = 0, small = 0, pr = 0;
  for (let i = 0; i < out.length; i++) { const b = out[i]; if (b === 0) z++; if (b >= 0x20 && b < 0x7f) pr++; }
  for (let i = 0; i + 4 <= out.length; i += 4) { const w = out.readUInt32LE(i); if (w < 0x10000) small++; }
  const nw = Math.floor(out.length / 4);
  return { z: z / out.length, small: nw ? small / nw : 0, pr: pr / out.length };
}

// 순서: f2 오름차순 (전역 순서). 기준점×정렬×스트림×키 조합
const order = [...entries].sort((a, b) => a.f[2] - b.f[2]);
const bases = { indexEnd, align400: alignUp(indexEnd, 0x400), align16: alignUp(indexEnd, 16), indexStart };
const results = [];
for (const [bn, base] of Object.entries(bases)) {
  for (const fa of [1, 16, 0x400]) {
    for (const stream of ['cont', 'fresh', 'tail16key']) {
      // 레이아웃 계산
      let off = base; const placement = [];
      for (const e of order) { off = alignUp(off, fa); placement.push([e, off]); off += e.f[4]; }
      // 평가: 각 엔트리 복호화 후 평균 구조점수 (압축 파일은 낮을 수 있으므로 비압축 f1&1==0 위주)
      let zS = 0, smS = 0, n2 = 0;
      for (const [e, st] of placement) {
        if (e.f[1] & 1) continue; // 저장(비압축) 파일만 평가
        const blen = e.f[4];
        if (st + blen > buf.length) continue;
        const s2 = new Snow2(stream === 'tail16key' ? Buffer.from(e.tail16) : k1);
        if (stream === 'cont') s2.skipWords(Math.floor((st - dataStart) / 4));
        const out = Buffer.from(buf.subarray(st, st + blen));
        for (let i = 0; i + 4 <= blen; i += 4) out.writeUInt32LE((out.readUInt32LE(i) - s2.nextWord()) >>> 0, i);
        const sc = structScore(out);
        zS += sc.z; smS += sc.small; n2++;
        if (results.length < 9999 && false) {}
        e._last = out;
      }
      if (n2) results.push({ tag: `${bn}/${fa}/${stream}`, z: zS / n2, small: smS / n2, n: n2, placement });
    }
  }
}
results.sort((a, b) => b.z + b.small - (a.z + a.small));
for (const r of results.slice(0, 8)) console.log(`${r.tag.padEnd(28)} 0비율=${r.z.toFixed(2)} 소정수u32=${r.small.toFixed(2)} (n=${r.n})`);

// 최상위 조합의 배치표 + 첫 비압축 파일 헤드 덤프
const best = results[0];
console.log(`\n최상위 [${best.tag}] 배치:`);
for (const [e, st] of best.placement) console.log(`  ${e.name.split('/').pop().padEnd(20)} @${st} len=${e.f[4]} ${e.f[1] & 1 ? '압축' : '저장'}`);
const unc = best.placement.find(([e]) => !(e.f[1] & 1));
if (unc) {
  const [e, st] = unc;
  const s2 = new Snow2(best.tag.endsWith('tail16key') ? Buffer.from(e.tail16) : k1);
  if (best.tag.includes('/cont')) s2.skipWords(Math.floor((st - dataStart) / 4));
  const out = Buffer.from(buf.subarray(st, st + Math.min(e.f[4], 64)));
  for (let i = 0; i + 4 <= out.length; i += 4) out.writeUInt32LE((out.readUInt32LE(i) - s2.nextWord()) >>> 0, i);
  console.log(`${e.name} 헤드: ${out.subarray(0, 32).toString('hex').match(/../g).join(' ')}`);
  console.log(`  텍스트로: ${out.subarray(0, 32).toString('latin1').replace(/[^\x20-\x7e]/g, '.')}`);
}
