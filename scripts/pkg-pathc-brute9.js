// pkg-pathc-brute9.js — beee0 "반복 키 배치" Snow2 변형으로 파일 복호 재시도
// 사실 근거: beee0(1402abee0) 16B 키 경로: s[0..3]=w, s[4..7]=~w, s[8..11]=w, s[12..15]=~w
// (1402abf63..abfd9 + 1402ac182..ac1a7), LFSR 스텝은 표준 snow2 (1402ac296..2d7)
'use strict';
const fs = require('fs');
function charSum(s) { let x = 0; for (const c of s) x = (x + c.charCodeAt(0)) >>> 0; return x; }
const TABLES = JSON.parse(fs.readFileSync('H:\\SA_Analysis\\evidence\\snow_tables_from_exe.json', 'utf8')).tables;
const T = { a: TABLES.snow_alpha_mul.words, ai: TABLES.snow_alphainv_mul.words, t0: TABLES.snow_T0.words, t1: TABLES.snow_T1.words, t2: TABLES.snow_T2.words, t3: TABLES.snow_T3.words };
const a_mul = (w) => (((w << 8) >>> 0) ^ T.a[(w >>> 24) & 0xff]) >>> 0;
const ainv_mul = (w) => ((w >>> 8) ^ T.ai[w & 0xff]) >>> 0;
const fsmT = (w) => (T.t0[w & 0xff] ^ T.t1[(w >>> 8) & 0xff] ^ T.t2[(w >>> 16) & 0xff] ^ T.t3[(w >>> 24) & 0xff]) >>> 0;
class Snow2 {
  constructor(key16, layout) {
    this.s = new Uint32Array(16); this.r1 = 0; this.r2 = 0;
    const b = key16; const sx = (x) => (x & 0x80 ? x - 256 : x) | 0;
    const w = [];
    for (let k = 0; k < 4; k++) w.push(((sx(b[4*k]) << 24) | (sx(b[4*k+1]) << 16) | (sx(b[4*k+2]) << 8) | sx(b[4*k+3])) >>> 0);
    if (layout === 'repeat') {
      // beee0: s[0..3]=w, s[4..7]=~w, s[8..11]=w, s[12..15]=~w
      for (let i = 0; i < 4; i++) { this.s[i] = w[i]; this.s[4+i] = (~w[i]) >>> 0; this.s[8+i] = w[i]; this.s[12+i] = (~w[i]) >>> 0; }
    } else {
      // 표준(인덱스 경로 검증본): s[15-k]=w, s[11-k]=~w, s[7-k]=w, s[3-k]=~w
      for (let k = 0; k < 4; k++) { this.s[15-k] = w[k]; this.s[11-k] = (~w[k]) >>> 0; this.s[7-k] = w[k]; this.s[3-k] = (~w[k]) >>> 0; }
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
// pkg 파싱 공용 (geom-check와 동일)
function parsePkg(f) {
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
  const str = path + headerStr, L = str.length;
  const k2 = Buffer.alloc(16);
  for (let i = 0; i < 16; i++) k2[i] = ((str.charCodeAt(L - (i % L) - 1) & 0xff) * ((i % 3) + 2) + i) & 0xff;
  const c2 = new Snow2(k2, 'std');
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
    const f = []; for (let i = 0; i < 6; i++) { f.push(region.readUInt32LE(off)); off += 4; }
    const n = region.readUInt32LE(off); off += 4;
    if (n > 0x10000) break;
    off += n * 16;
    const tail = Buffer.from(region.subarray(off, off + 16)); off += 16;
    if (f[1] & 0x10) off += 40;
    ents.push({ name, f, tail });
  }
  const indexEnd = indexStart + off;
  const align = (x) => { const r = x & 0x3ff; return r ? x - r + 0x400 : x; };
  return { buf, headerStr, ents, base: align(indexEnd) };
}
// f83f0 (pathC) — disasm31 검증본
function deriveF83f0(ctx, src16) {
  const out = Buffer.alloc(128);
  const ctxLen = ctx.length;
  if (ctxLen === 0) return null;
  for (let j = 0; j < 128; j++) {
    const t8 = ((src16[j & 15]) - 5 * Math.floor(j / 10) + 2 + j) & 0xff;
    const ts = t8 & 0x80 ? t8 - 256 : t8;   // 1402a8466 MOVSX EDX,R9B — 부호 확정!
    const cc = (ctx.charCodeAt(j % ctxLen) & 0xff);
    const ccs = cc & 0x80 ? cc - 256 : cc;
    out[j] = ((ts * ccs + j) & 0xff) >>> 0;
  }
  return out;
}
// f4a0 (pathA) — fnvU 변형
function fnv32(s) { let h = 0x811c9dc5; for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i) & 0xff; h = Math.imul(h, 0x01000193) >>> 0; } return h >>> 0; }
function deriveF4a0(ctx, src16, fnv) {
  const out = Buffer.alloc(128);
  const dg = [];
  let v = fnv;
  if (v === 0) return null;
  do { dg.push(v % 10); v = Math.floor(v / 10); } while (v > 0);
  dg.reverse();
  for (let j = 0; j < 128; j++) {
    const t = ((src16[j & 15]) - 5 * Math.floor(j / 10) + 2 + j) & 0xff;
    const d = dg[j % dg.length];
    out[j] = ((t * (d + 2) + j) & 0xff) >>> 0;
  }
  return out;
}
// 평문 판정: .txt 비압축 엔트리 → ascii 비율
function asciiScore(dec) {
  let good = 0;
  for (let i = 0; i < dec.length; i++) { const c = dec[i]; if ((c >= 0x20 && c < 0x7f) || c === 0x0a || c === 0x0d || c === 0x09) good++; }
  return good / dec.length;
}
const targets = [];
for (const f of ['texturescripts_00000.pkg']) {
  const p = parsePkg(f);
  for (const e of p.ents) {
    if (e.name.endsWith('.txt') && !(e.f[1] & 1) && e.f[4] >= 48) {
      targets.push({ pkg: f, p, e, ct: p.buf.subarray(p.base + e.f[2] * 0x400, p.base + e.f[2] * 0x400 + Math.min(e.f[4], 128)) });
    }
  }
}
console.log(`targets: ${targets.length}`);
const ctxs = ['texturescripts_00000'];
const layouts = ['repeat', 'std'];
const ops = ['sub', 'xor'];
const seeks = [0, 1, 2, 3, 4, 8, 16, 32, 64];
const seeds = { t0: 0 };
let hits = 0, tried = 0;
for (const t of targets.slice(0, 4)) {
  for (const ctx of ctxs) {
    for (const [sname, soff] of Object.entries(seeds)) {
      const src16 = t.e.tail.subarray(soff, soff + 16);
      const derivers = [['C', deriveF83f0(ctx, src16)], ['A', deriveF4a0(ctx, src16, fnv32(ctx))]];
      for (const [dname, key128] of derivers) {
        if (!key128) continue;
        const key = key128.subarray(0, 16);
        for (const layout of layouts) {
          for (const op of ops) {
            for (const seek of seeks) {
              tried++;
              const c = new Snow2(key, layout);
              for (let i = 0; i < seek; i++) c.nextWord();
              const dec = Buffer.from(t.ct);
              let ok = true;
              for (let i = 0; i + 4 <= dec.length; i += 4) {
                const ks = c.nextWord();
                const w = op === 'xor' ? ((dec.readUInt32LE(i) ^ ks) >>> 0) : ((dec.readUInt32LE(i) - ks) >>> 0);
                dec.writeUInt32LE(w, i);
              }
              const sc = asciiScore(dec.subarray(0, Math.min(dec.length, 48)));
              if (sc > 0.9) {
                hits++;
                console.log(`HIT ${t.e.name} ctx=${ctx} seed=${sname} der=${dname} layout=${layout} op=${op} seek=${seek} score=${sc.toFixed(3)}`);
                console.log(`  ${JSON.stringify(dec.subarray(0, 64).toString('latin1'))}`);
              }
            }
          }
        }
      }
    }
  }
}
console.log(`tried=${tried} hits=${hits}`);
