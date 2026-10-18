// pkg-gap-decrypt.js — 갭/트레일러 영역 복호화 시도
// f470: out[i] = (i + concat[i%L].lowByte) & 0xff          (갭 키)
// f6b0: out[i] = ((s8)concat[L-1-(i%L)].low * ((i%3)+2) + i) & 0xff (트레일러 키 = 인덱스 k2와 동일식)
// concat = ctx문자열 + 인자문자열 (둘 다 미지 → 후보 조합)
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
function deriveF470(concat) { // out[i] = (i + concat[i%L].lowByte) & 0xff
  const L = concat.length; if (!L) return null;
  const out = Buffer.alloc(16);
  for (let i = 0; i < 16; i++) out[i] = (i + (concat.charCodeAt(i % L) & 0xff)) & 0xff;
  return out;
}
function deriveF6b0(concat) { // out[i] = ((s8)concat[L-1-(i%L)].low * ((i%3)+2) + i) & 0xff
  const L = concat.length; if (!L) return null;
  const out = Buffer.alloc(16);
  for (let i = 0; i < 16; i++) {
    let w = concat.charCodeAt(L - 1 - (i % L)) & 0xff; if (w >= 128) w -= 256;
    out[i] = (w * ((i % 3) + 2) + i) & 0xff;
  }
  return out;
}
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
  const indexStart = dataStart + n2 + 8;
  return { buf, n1, n2, headerStr, dataStart, indexStart };
}
const file = process.argv[2], path = process.argv[3] || file.replace(/.*[\\/]/, '');
const { buf, n2, headerStr, dataStart, indexStart } = parse(file, path);
console.log(`${path}: gap=0x${dataStart.toString(16)}..0x${indexStart.toString(16)} (${n2 + 8}B) header=[${headerStr}]`);
// 갭 첫 16바이트와 일치하는 파일 내 위치 전부 찾기 (트레일러 사본)
const probe = buf.subarray(dataStart, dataStart + 16);
const copies = [];
for (let i = 0; i + 16 <= buf.length; i++) {
  if (buf[i] === probe[0] && buf[i + 1] === probe[1] && buf[i + 2] === probe[2]) {
    let ok = true;
    for (let k = 0; k < 16; k++) if (buf[i + k] !== probe[k]) { ok = false; break; }
    if (ok && i !== dataStart) copies.push(i);
  }
}
console.log(`갭 사본 위치: ${copies.map(c => '0x' + c.toString(16)).join(', ') || '(없음)'}`);
// 대상 영역: 갭 본체 + 각 사본(길이 = n2+8) + 파일 끝 0x400
const regions = [{ name: 'gap', off: dataStart, len: n2 + 8 }];
for (const c of copies) regions.push({ name: `copy@0x${c.toString(16)}`, off: c, len: n2 + 8 });
regions.push({ name: 'tail400', off: buf.length - 0x400, len: 0x400 });
// concat 후보
const name = path.replace(/\.pkg$/, '');
const A = {
  name: path, base: name, gamedir: 'game\\' + path, pkgdir: '..\\game\\' + path,
  abs: 'H:\\Program Files\\Nexon\\SuddenAttack\\game\\' + path, upper: path.toUpperCase(),
};
const B = { empty: '', header: headerStr, name: path, base: name, index: 'index', config: 'config', header2: headerStr + headerStr };
const concats = [];
for (const [an, av] of Object.entries(A)) for (const [bn, bv] of Object.entries(B)) concats.push({ tag: an + '+' + bn, s: av + bv });
for (const [bn, bv] of Object.entries(B)) concats.push({ tag: bn + '+' + 'name', s: bv + path });
const MAXSKIP = 1024;
const results = [];
for (const { tag, s } of concats) {
  for (const [fn, fd] of [['f470', deriveF470], ['f6b0', deriveF6b0]]) {
    const key = fd(s); if (!key) continue;
    const ks = keystream(key, MAXSKIP + 0x400 / 4 + 4);
    for (const reg of regions) {
      const ct = buf.subarray(reg.off, reg.off + reg.len);
      const nw = ct.length >> 2;
      for (let skip = 0; skip <= MAXSKIP; skip++) {
        let good = 0;
        for (let w = 0; w < nw; w++) {
          const d = (ct.readUInt32LE(w * 4) - ks[skip + w]) >>> 0;
          for (const b of [d & 0xff, (d >>> 8) & 0xff, (d >>> 16) & 0xff, (d >>> 24) & 0xff])
            if (b === 0 || b === 9 || b === 10 || b === 13 || (b >= 0x20 && b < 0x7f)) good++;
        }
        const score = good / (nw * 4);
        results.push({ score, tag, fn, reg: reg.name, skip, off: reg.off });
      }
    }
  }
}
results.sort((a, b) => b.score - a.score);
// 최고 스코어들 중 서로 다른 (tag,fn,reg) 조합 상위 출력
const seen = new Set(); let shown = 0;
for (const r of results) {
  const k = r.tag + '/' + r.fn + '/' + r.reg;
  if (seen.has(k)) continue;
  seen.add(k);
  const ct = buf.subarray(r.off, r.off + Math.min(48, regions.find(x => x.name === r.reg).len));
  const ks = keystream(r.fn === 'f470' ? deriveF470(concats.find(c => c.tag === r.tag).s) : deriveF6b0(concats.find(c => c.tag === r.tag).s), r.skip + 12 + 4);
  let hex = '';
  for (let w = 0; w < 12 && w * 4 + 4 <= ct.length; w++) {
    const d = (ct.readUInt32LE(w * 4) - ks[r.skip + w]) >>> 0;
    hex += d.toString(16).padStart(8, '0').replace(/(..)(..)(..)(..)/, '$4$3$2$1') + ' ';
  }
  console.log(`[${r.score.toFixed(3)}] ${r.tag}/${r.fn}/${r.reg}/skip${r.skip}  ${hex}`);
  if (++shown >= 15) break;
}
