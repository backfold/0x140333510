// pkg-file-addr.js — Q3 후속: 인덱스 field[3]/field[4] = (시작,끝) 블록 가설 검증
// 재사용: pkg-parse.js 와 동일한 Snow2/헤더/키 파생 (인덱스는 key2 스트림으로 복호화됨)
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
// — pkg-parse.js 검증 로직 그대로 —
function parseHeader(buf, path) {
  const n1 = (charSum(path) % 312) + 30;
  const n2 = ((charSum(path) * 3) % 212) + 33;
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
  return { n1, n2, v1, headerStr, dataStart: pos + len * 2 };
}
function deriveKeys(path, headerStr) {
  const str = path + headerStr, L = str.length;
  const k1 = Buffer.alloc(16), k2 = Buffer.alloc(16);
  for (let i = 0; i < 16; i++) {
    k1[i] = (i + (str.charCodeAt(i % L) & 0xff)) & 0xff;
    k2[i] = ((str.charCodeAt(L - (i % L) - 1) & 0xff) * ((i % 3) + 2) + i) & 0xff;
  }
  return { k1, k2 };
}
function readEntry(region, off) {
  if (off + 4 > region.length) return null;
  const strLen = region.readUInt32LE(off); off += 4;
  if (strLen === 0 || strLen > 0x400 || off + strLen * 2 > region.length) return null;
  let name = '';
  for (let i = 0; i < strLen; i++) name += String.fromCharCode(region.readUInt16LE(off + i * 2));
  off += strLen * 2;
  if (off + 28 > region.length) return null;
  const f = [];
  for (let i = 0; i < 6; i++) { f.push(region.readUInt32LE(off)); off += 4; }
  const n = region.readUInt32LE(off); off += 4;
  if (n > 0x10000 || off + n * 16 + 16 > region.length) return null;
  off += n * 16;
  off += 16; // tail16
  if ((f[1] & 0x10) !== 0) { if (off + 32 > region.length) return null; off += 32; }
  return { name, f, nextOff: off };
}
function load(file, path) {
  const buf = fs.readFileSync(file);
  const hdr = parseHeader(buf, path);
  const { k1, k2 } = deriveKeys(path, hdr.headerStr);
  const indexStart = hdr.dataStart + hdr.n2 + 8;
  const c2 = new Snow2(k2);
  const region = Buffer.from(buf.subarray(indexStart));
  c2.decrypt = undefined; // (사용 안 함 — 아래 직접)
  for (let i = 0; i + 4 <= region.length - (region.length % 4); i += 4)
    region.writeUInt32LE((region.readUInt32LE(i) - c2.nextWord()) >>> 0, i);
  const entries = []; let off = 0;
  for (;;) { const e = readEntry(region, off); if (!e) break; entries.push(e); off = e.nextOff; if (entries.length > 64) break; }
  return { buf, hdr, k1, k2, indexStart, indexEnd: indexStart + off, entries };
}

const file = process.argv[2], path = process.argv[3] || file.replace(/.*[\\/]/, '');
const { buf, hdr, k1, indexStart, indexEnd, entries } = load(file, path);
console.log(`${path}: dataStart=${hdr.dataStart} indexStart=${indexStart} indexEnd=${indexEnd} file=${buf.length} entries=${entries.length}`);
console.log('name(f2,f3,f4):', entries.map(e => `${e.name.split('/').pop()}(${e.f[2]},${e.f[3]},${e.f[4]})`).join(' '));

const asciiScore = (bytes) => { let c = 0; for (const b of bytes) if (b === 9 || b === 10 || b === 13 || (b >= 0x20 && b < 0x7f)) c++; return bytes.length ? c / bytes.length : 0; };
const bases = { dataStart: hdr.dataStart, dataHead: hdr.dataStart + 8, indexEnd };
const results = [];
for (const [bname, base] of Object.entries(bases)) {
  for (const bs of [16, 64]) {
    for (const fresh of [false, true]) {
      let sum = 0, hits = 0, used = 0;
      for (const e of entries) {
        const start = base + e.f[3] * bs, blen = (e.f[4] - e.f[3]) * bs;
        if (blen <= 0 || start + blen > buf.length) continue;
        used++;
        const s2 = new Snow2(k1);
        if (!fresh) s2.skipWords(Math.floor((start - hdr.dataStart) / 4));
        const out = Buffer.from(buf.subarray(start, start + blen));
        for (let i = 0; i + 4 <= blen; i += 4) out.writeUInt32LE((out.readUInt32LE(i) - s2.nextWord()) >>> 0, i);
        const sc = asciiScore(out);
        sum += sc; if (sc > 0.85) hits++;
      }
      results.push({ tag: `${bname}+f3*${bs}/${fresh ? 'fresh' : 'cont'}`, avg: used ? sum / used : 0, hits, used });
    }
  }
}
results.sort((a, b) => b.avg - a.avg);
for (const r of results) console.log(`${r.tag.padEnd(24)} 평균ASCII=${r.avg.toFixed(2)} 85%+적중=${r.hits}/${r.used}`);

// 상위 2조합 + f4*bs 변형(전장=f4-f3 대신 f4) 상세 샘플
console.log('\n--- 상위 조합 .txt 엔트리 샘플 ---');
const txtEntry = entries.find(e => e.name.endsWith('.txt') || e.name.endsWith('.tfs'));
for (const r of results.slice(0, 2)) {
  const [bpart, rest] = r.tag.split('+');
  const bs = +rest.split('*')[1].split('/')[0];
  const fresh = r.tag.endsWith('fresh');
  const base = bases[bpart];
  const start = base + txtEntry.f[3] * bs, blen = (txtEntry.f[4] - txtEntry.f[3]) * bs;
  if (start + blen > buf.length) continue;
  const s2 = new Snow2(k1);
  if (!fresh) s2.skipWords(Math.floor((start - hdr.dataStart) / 4));
  const out = Buffer.from(buf.subarray(start, start + blen));
  for (let i = 0; i + 4 <= blen; i += 4) out.writeUInt32LE((out.readUInt32LE(i) - s2.nextWord()) >>> 0, i);
  console.log(`[${r.tag}] ${txtEntry.name}: ${out.subarray(0, 48).toString('latin1').replace(/[^\x20-\x7e]/g, '.')}`);
}
