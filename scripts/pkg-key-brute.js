// pkg-key-brute.js — 경로B 키 파생(FUN_1402a84a0) 완전 재구현 + 미지수 브루트포스
// 미지수: fp(log10/log/sqrt) × variant(패키지 dword 후보) × src16 슬라이스 × 이름 형태 × 시크
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
// — 검증된 헤더/인덱스 파서 —
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
  // 8B 헤드 [checksum][count] — key1 스트림으로
  const c1 = new Snow2(k1);
  const head = Buffer.from(buf.subarray(dataStart + n2, indexStart));
  for (let i = 0; i + 4 <= 8; i += 4) head.writeUInt32LE((head.readUInt32LE(i) - c1.nextWord()) >>> 0, i);
  const checksum = head.readUInt32LE(0), count = head.readUInt32LE(4);
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
    let extra = null;
    if (f[1] & 0x10) { extra = [...region.subarray(off, off + 40)]; off += 40; }
    entries.push({ name, f, items, tail16, extra });
  }
  return { buf, headerStr, checksum, count, dataStart, k1, k2, indexStart, indexEnd: indexStart + off, entries };
}
// — 경로B 키 파생 재구현 (FUN_1402a84a0) —
function deriveKeyB(nameW, src16, variant, fpName) {
  const fp = fpName === 'log10' ? Math.log10(variant) : fpName === 'log' ? Math.log(variant) : Math.sqrt(variant);
  const v = Math.trunc(fp) | 0;
  const m = v + 1;
  if (m <= 0) return null;
  const digits = new Int8Array(m);
  let x = variant >>> 0, pos = m - 1;
  do { digits[pos--] = x % 10; x = (x / 10) | 0; } while (x > 0 && pos >= 0);
  // (버퍼 나머지는 0 — 새 힙 가정)
  const L = nameW.length;
  const key = Buffer.alloc(16);
  for (let i = 0; i < 0x80; i++) {
    const ki = i % 16;
    const par = digits[i % m] & 1;
    const d1 = digits[(i + 1) % m], d2 = digits[(i + 2) % m];
    let a = (((d1 + i) % 10) + src16[(d2 + i) % 16] + par) & 0xff;
    if (a >= 128) a -= 256; // s8
    let w = nameW.charCodeAt(i % L) & 0xff;
    if (w >= 128) w -= 256; // s8 (ASCII 이름이면 그대로)
    const prod = (a * w) | 0;
    key[ki] = (prod + i) & 0xff;
  }
  return key;
}
// FNV-1a 32bit over UTF-16 code units (FUN_1402a8630: h=0x811c9dc5, h=(c^h)*0x1000193)
function fnv1a16(s) {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) h = Math.imul(h ^ (s.charCodeAt(i) & 0xffff), 0x1000193) >>> 0;
  return h >>> 0;
}
const file = process.argv[2], path = process.argv[3] || file.replace(/.*[\\/]/, '');
const { buf, headerStr, checksum, count, dataStart, indexEnd, entries } = parse(file, path);
const dataBase = Math.ceil(indexEnd / 0x400) * 0x400;
const fnv = fnv1a16(headerStr);
console.log(`${path}: headerStr="${headerStr}" FNV1a=${fnv} (0x${fnv.toString(16)}) count=${count} dataBase=${dataBase}`);

// 구조 점수: 인쇄가능 + 0바이트 + 반복
function score(out) {
  let pr = 0, z = 0;
  for (const b of out) { if (b === 9 || b === 10 || b === 13 || (b >= 0x20 && b < 0x7f)) pr++; if (b === 0) z++; }
  return pr / out.length + z / out.length;
}
const variants = { fnv, checksum, count, dataBase, fileSize: buf.length, hlen: headerStr.length };
for (const e of entries) { variants['f0_' + e.f[0]] = e.f[0]; variants['f3_' + e.f[3]] = e.f[3]; variants['f4_' + e.f[4]] = e.f[4]; }
const srcSlices = {
  tail8_24: (e) => Buffer.from([...e.tail16.slice(8, 16), ...new Array(8).fill(0)]),
  tail0_16: (e) => Buffer.from(e.tail16),
  tail0_16z: (e) => Buffer.from([...e.tail16, ...new Array(0).fill(0)]),
  blob0_16: (e) => e.extra ? Buffer.from(e.extra.slice(0, 16)) : Buffer.from([...e.tail16.slice(8, 16), ...new Array(8).fill(0)]),
};
const results = [];
for (const fpName of ['log10', 'log', 'sqrt']) {
  for (const [vn, variant] of Object.entries(variants)) {
    if (!Number.isFinite(variant) || variant < 0) continue;
    for (const [sn, sf] of Object.entries(srcSlices)) {
      for (const nn of ['full', 'base']) {
        let sum = 0, detail = [];
        for (const e of entries) {
          const name = nn === 'full' ? e.name : e.name.split('/').pop();
          const key = deriveKeyB(name, sf(e), variant, fpName);
          if (!key) { sum = -1; break; }
          const st = dataBase + e.f[2] * 1024;
          const blen = Math.min(e.f[4], 64, buf.length - st);
          if (blen < 16) { detail.push(0); continue; }
          const s2 = new Snow2(key);
          const out = Buffer.from(buf.subarray(st, st + blen));
          for (let i = 0; i + 4 <= blen; i += 4) out.writeUInt32LE((out.readUInt32LE(i) - s2.nextWord()) >>> 0, i);
          const sc = score(out.subarray(0, Math.min(blen, 64)));
          sum += sc; detail.push(sc);
        }
        if (sum > 0) results.push({ tag: `${fpName}/${vn}/${sn}/${nn}`, sum, detail });
      }
    }
  }
}
results.sort((a, b) => b.sum - a.sum);
console.log(`조합 ${results.length}개, 상위 10:`);
for (const r of results.slice(0, 10)) console.log(`  [${r.tag}] 총점=${r.sum.toFixed(2)} 개별=${r.detail.map(x => x.toFixed(2)).join(',')}`);
// 최상위 상세 출력
const best = results[0];
if (best) {
  console.log(`\n최상위 [${best.tag}] 복호화 결과:`);
  const [fpName, vn, sn, nn] = best.tag.split('/');
  for (const e of entries.slice(0, 3)) {
    const name = nn === 'full' ? e.name : e.name.split('/').pop();
    const key = deriveKeyB(name, srcSlices[sn](e), variants[vn], fpName);
    const st = dataBase + e.f[2] * 1024;
    const blen = Math.min(e.f[4], 64, buf.length - st);
    const s2 = new Snow2(key);
    const out = Buffer.from(buf.subarray(st, st + blen));
    for (let i = 0; i + 4 <= blen; i += 4) out.writeUInt32LE((out.readUInt32LE(i) - s2.nextWord()) >>> 0, i);
    console.log(`  ${e.name.split('/').pop()}: ${out.subarray(0, 48).toString('hex').match(/../g).join(' ')}`);
    console.log(`    "${out.subarray(0, 48).toString('latin1').replace(/[^\x20-\x7e]/g, '.')}"`);
  }
}

