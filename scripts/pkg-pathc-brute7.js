// pkg-pathc-brute7.js — ba50 완전해독 기반 최종 시도
//  확정: dispatch=byte[pkg+0x74]=manager[R13+0xf5]=0(쓰기전무) → pathC(f83f0)
//        seek=[pkg+0x7c]=manager[R13+0x1c4]=0, ctx=pkg+0x50=테이블 문자열=(루트)+'\'+(파일명)
//  신규 ctx: game\global_00000.pkg 형태(루트/구분자/대소문자/확장자 변형) + tail16 오프셋 변형
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
function keystream(key, n) { const c = new Snow2(key); const o = new Uint32Array(n); for (let i = 0; i < n; i++) o[i] = c.nextWord(); return o; }
function charSum(s) { let x = 0; for (const c of s) x = (x + c.charCodeAt(0)) >>> 0; return x; }
function fnv32Byte(s) { let h = 0x811c9dc5; for (let i = 0; i < s.length; i++) { const u = s.charCodeAt(i); h = ((h ^ (u & 0xff)) * 0x01000193) >>> 0; h = ((h ^ (u >>> 8)) * 0x01000193) >>> 0; } return h >>> 0; }
function fnv32Unit(s) { let h = 0x811c9dc5; for (let i = 0; i < s.length; i++) h = ((h ^ s.charCodeAt(i)) * 0x01000193) >>> 0; return h >>> 0; }
function digitsOf(n) { const d = []; if (n <= 0) return [0]; while (n > 0) { d.push(n % 10); n = Math.floor(n / 10); } return d.reverse(); }
function deriveF4a0(ctx, src16, variant) {
  const L = ctx.length; if (!L || variant <= 0) return null;
  const dg = digitsOf(variant), ES = dg.length;
  const out = Buffer.alloc(16);
  for (let j = 0; j < 16; j++) {
    const d1 = dg[j % ES], d2 = dg[(j + 1) % ES], d3 = dg[(j + 2) % ES];
    const t = ((((d2 + j) % 10) + src16[(d3 + j) % 16] + d1) & 0xff);
    const st = t >= 128 ? t - 256 : t;
    const cb = ctx.charCodeAt(j % L) & 0xff;
    const scb = cb >= 128 ? cb - 256 : cb;
    out[j] = (st * scb + j) & 0xff;
  }
  return out;
}
function deriveF83f0(ctx, src16) {
  const L = ctx.length; if (!L) return null;
  const out = Buffer.alloc(16);
  for (let j = 0; j < 16; j++) {
    const a = (src16[j & 15] - 5 * Math.floor(j / 10) + 2 + j) & 0xff;
    const sa = a >= 128 ? a - 256 : a;
    const cb = ctx.charCodeAt(j % L) & 0xff;
    const scb = cb >= 128 ? cb - 256 : cb;
    out[j] = (sa * scb + j) & 0xff;
  }
  return out;
}
function parseAll(file, path) {
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
  const dataStart = n1 + 5 + len * 2, indexStart = dataStart + n2 + 8;
  const L = (path + headerStr).length, s2 = path + headerStr;
  const k2 = Buffer.alloc(16);
  for (let i = 0; i < 16; i++) k2[i] = ((s2.charCodeAt(L - (i % L) - 1) & 0xff) * ((i % 3) + 2) + i) & 0xff;
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
    const tail48 = Buffer.from(region.subarray(off + n * 16, off + n * 16 + 48)); off += n * 16 + 16;
    if (f[1] & 0x10) off += 40;
    entries.push({ name, f, tail48 });
  }
  return { buf, headerStr, indexStart, indexEnd: indexStart + off, entries };
}
const alignUp = (x, a) => Math.ceil(x / a) * a;
const asciiScore = (b) => { let c = 0; for (const x of b) if (x === 9 || x === 10 || x === 13 || (x >= 0x20 && x < 0x7f)) c++; return b.length ? c / b.length : 0; };

const MAXSK = 64, NW = 48;
for (const f of ['texturescripts_00000.pkg', 'global_00000.pkg']) {
  const P = parseAll(`H:\\SA_Analysis\\target\\pkg_samples\\${f}`, f);
  const { buf, headerStr, indexEnd, entries } = P;
  const base = alignUp(indexEnd, 0x400);
  console.log(`\n=== ${f}: base=0x${base.toString(16)} 엔트리=${entries.length} header="${headerStr}"`);
  const noext = f.replace(/\.pkg$/, '');
  const ctxs = {};
  for (const root of ['game', 'Game', 'GAME', 'data', 'resource', '.']) {
    for (const sep of ['\\', '/']) {
      for (const nm of [f, noext, f.toUpperCase()]) ctxs[`${root}${sep}${nm}`] = `${root}${sep}${nm}`;
    }
  }
  ctxs[f] = f; ctxs[f.toUpperCase()] = f.toUpperCase(); ctxs[f + headerStr] = f + headerStr;
  const hits = [];
  for (const e of entries) {
    const st = base + e.f[2] * 0x400;
    const blen = Math.min(e.f[4] & ~3, NW * 4);
    if (blen < 16) continue;
    const ctWords = []; for (let i = 0; i + 4 <= blen; i += 4) ctWords.push(buf.readUInt32LE(st + i));
    const seeds = { t0: e.tail48.subarray(0, 16), t1: e.tail48.subarray(16, 32), t2: e.tail48.subarray(32, 48) };
    for (const [cn, ctx] of Object.entries(ctxs)) {
      const keyC = deriveF83f0(ctx, seeds.t0);
      const kA1 = deriveF4a0(ctx, seeds.t0, fnv32Unit(ctx));
      const kA2 = deriveF4a0(ctx, seeds.t0, fnv32Byte(ctx));
      const cand = [];
      if (keyC) cand.push(['C', keyC]);
      if (kA1) cand.push(['Au', kA1]);
      if (kA2) cand.push(['Ab', kA2]);
      for (const [dn, key] of cand) {
        const ks = keystream(key, MAXSK + NW);
        for (const sk of [0, 1, 2, 3, 4, 8, 16, 32]) {
          for (const xor of [false, true]) {
            const out = Buffer.alloc(ctWords.length * 4);
            let sc = 0;
            const probe = Math.min(16, ctWords.length);
            for (let i = 0; i < ctWords.length; i++) {
              const w = xor ? ((ctWords[i] ^ ks[sk + i]) >>> 0) : ((ctWords[i] - ks[sk + i]) >>> 0);
              out.writeUInt32LE(w, i * 4);
            }
            for (const b of out.subarray(0, probe * 4)) if (b === 9 || b === 10 || b === 13 || (b >= 0x20 && b < 0x7f)) sc++;
            const psc = sc / (probe * 4);
            if (psc > 0.85) {
              const full = asciiScore(out);
              if (full > 0.85) hits.push({ sc: full, tag: `${dn}/${cn}/sk${sk}/${xor ? 'xor' : 'sub'}`, e, st, out, key });
              else if (out[0] === 0x78 && (out[1] === 0x01 || out[1] === 0x9c || out[1] === 0xda)) hits.push({ sc: 0.9, tag: `${dn}/${cn}/sk${sk}/${xor ? 'xor' : 'sub'}/ZLIB`, e, st, out, key });
            }
          }
        }
      }
    }
  }
  hits.sort((a, b) => b.sc - a.sc);
  console.log(`히트 ${hits.length}개${hits.length ? ', 상위 8:' : ''}`);
  for (const h of hits.slice(0, 8))
    console.log(`[${h.sc.toFixed(2)}] ${h.tag} ${h.e.name} @0x${h.st.toString(16)} key=${h.key.toString('hex')}\n   "${h.out.subarray(0, 96).toString('latin1').replace(/[^\x20-\x7e]/g, '.')}"`);
  if (!hits.length) console.log('(히트 없음)');
}
