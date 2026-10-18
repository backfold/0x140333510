// pkg-pathc-brute6.js — f84a0(pathA) 완전 구현 + config {0,2} 동시 스캔
//  pathA: digits=10진(variant); out[j]=((int8)(((d2+j)%10+src16[(d3+j)%16]+d1)&0xff)
//         * (int8)ctx[j%ctxLen].low + j)&0xff, variant=FNV32(ctx)
//  pathC: out[j]=((int8)(src16[j&15]-5*(j/10)+2+j)*(int8)ctx[j%L].low+j)&0xff
//  seek=[pkg+0x7c]/4 (미지) → 0..255워드 스캔, op SUB/XOR, 레이어 단일
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
    off += n * 16;
    const tail = Buffer.from(region.subarray(off, off + 16)); off += 16;
    if (f[1] & 0x10) off += 40;
    entries.push({ name, f, tail });
  }
  return { buf, headerStr, dataStart, indexStart, indexEnd: indexStart + off, entries };
}
const alignUp = (x, a) => Math.ceil(x / a) * a;
const asciiScore = (b) => { let c = 0; for (const x of b) if (x === 9 || x === 10 || x === 13 || (x >= 0x20 && x < 0x7f)) c++; return b.length ? c / b.length : 0; };

const MAXSK = 256, NW = 64; // seek 스캔 범위(워드), 검사 워드 수
for (const f of ['texturescripts_00000.pkg', 'global_00000.pkg']) {
  const P = parseAll(`H:\\SA_Analysis\\target\\pkg_samples\\${f}`, f);
  const { buf, headerStr, indexEnd, entries } = P;
  const base = alignUp(indexEnd, 0x400);
  console.log(`\n=== ${f}: base=0x${base.toString(16)} 엔트리=${entries.length}`);
  const hits = [];
  for (const e of entries) {
    if (e.f[1] & 1) continue; // 압축 제외
    const st = base + e.f[2] * 0x400;
    const blen = Math.min(e.f[4] & ~3, NW * 4);
    const ctWords = []; for (let i = 0; i + 4 <= blen; i += 4) ctWords.push(buf.readUInt32LE(st + i));
    // ctx 후보: 퍼파일(요청경로) + 퍼패키지
    const selfPath = e.name;
    const ctxs = {
      self: selfPath, self_bs: selfPath.replace(/\//g, '\\'), self_base: selfPath.split('/').pop(),
      self_up: selfPath.toUpperCase(),
      pkgname: f, pkgbase: f.replace(/\.pkg$/, ''), header: headerStr, pkg_hdr: f + headerStr,
      dir: selfPath.split('/').slice(0, -1).join('/'),
    };
    for (const [cn, ctx] of Object.entries(ctxs)) {
      const variants = { fnvB: fnv32Byte(ctx), fnvU: fnv32Unit(ctx) };
      for (const [vn, variant] of Object.entries(variants)) {
        const keyA = deriveF4a0(ctx, e.tail, variant);
        const keyC = deriveF83f0(ctx, e.tail);
        for (const [dn, key] of [['A', keyA], ['C', keyC]]) {
          if (!key) continue;
          const ks = keystream(key, MAXSK + NW);
          for (let sk = 0; sk < MAXSK; sk++) {
            for (const [on, xor] of [['sub', false], ['xor', true]]) {
              let sc = 0;
              const probe = Math.min(16, ctWords.length);
              for (let i = 0; i < probe; i++) {
                const w = xor ? (ctWords[i] ^ ks[sk + i]) : ((ctWords[i] - ks[sk + i]) >>> 0);
                const b0 = w & 0xff, b1 = (w >>> 8) & 0xff;
                if (b0 === 9 || b0 === 10 || b0 === 13 || (b0 >= 0x20 && b0 < 0x7f)) sc++;
                if (b1 === 9 || b1 === 10 || b1 === 13 || (b1 >= 0x20 && b1 < 0x7f)) sc++;
              }
              if (sc / (probe * 2) > 0.85) {
                // 전체 64워드 검증
                const out = Buffer.alloc(ctWords.length * 4);
                for (let i = 0; i < ctWords.length; i++) {
                  const w = xor ? (ctWords[i] ^ ks[sk + i]) : ((ctWords[i] - ks[sk + i]) >>> 0);
                  out.writeUInt32LE(w, i * 4);
                }
                const full = asciiScore(out);
                if (full > 0.85) hits.push({ sc: full, tag: `${dn}/${cn}/${vn}/${on}/sk${sk}`, e, st, out, key });
              }
            }
          }
        }
      }
    }
  }
  hits.sort((a, b) => b.sc - a.sc);
  console.log(`강히트 ${hits.length}개${hits.length ? ', 상위 10:' : ''}`);
  for (const h of hits.slice(0, 10))
    console.log(`[${h.sc.toFixed(2)}] ${h.tag} ${h.e.name} @0x${h.st.toString(16)} key=${h.key.toString('hex')}\n   "${h.out.subarray(0, 96).toString('latin1').replace(/[^\x20-\x7e]/g, '.')}"`);
  if (!hits.length) console.log('(히트 없음)');
}
