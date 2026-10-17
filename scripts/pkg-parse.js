// pkg-parse.js — SuddenAttack .pkg container parser (lapacker / Lambda::PackageLoader)
//
// CONFIRMED container model (sessions 11-26 + empirical validation on
// global_00000.pkg and texturescripts_00000.pkg, 2026-10):
//   [0 .. N1)              masked key bytes; N1 = (Σ UTF-16 chars of path) % 312 + 30   (FUN_14029fa20)
//   [+N1]                  version byte b; v1 (PackageHeader) iff ((masked[0]>>1 arithmetic) ^ b) == 3
//   v1 unmask: key[i] = (masked[i] >> 1) | (masked[i] & 0x80)   (MSVC sar semantics)
//   [+N1+1]                u32 length ^ sext8(key[0])            (FUN_1402b1d40)
//   [+N1+5 .. +2*len)      header string; out16[i] = enc16[i] ^ sext16(key[i % N1])
//                          (FUN_1402b1b50) — decrypts to "!dlstps20djr@" on both samples
//   dataStart = N1 + 1 + 4 + 2*len
//   concat = path + headerString (UTF-16); L = length in chars
//   key1[i] = (i + concat[i % L]) & 0xff         (FUN_14029f470, 128 bytes)
//   key2[i] = (concat[L - (i % L) - 1] * ((i % 3) + 2) + i) & 0xff   (FUN_14029f6b0)
//   DATA region @ dataStart: Snow2(key1[0..15], IV=0, pos=0), subtract keystream:
//          [u32 checksum → header+0x30][u32 fileCount → header+0x34]   (FUN_1402b1d00)
//   INDEX region @ dataStart + N2 + 8:  Snow2(key2[0..15], IV=0, pos=0), subtract;
//          8 = bytes consumed by the data head. count entries of:
//          [u32 strlen][strlen*2 UTF-16LE name][6*u32][u32 n][n*16B][16B]
//          [+32B if entry.field[1] & 0x10]                      (FUN_140290e00/FUN_1402b18c0)
//   File end: ((indexStart - base) + indexSize) aligned up to 0x400 (FUN_1402aa700 tail)
//
// Snow2 = SNOW 2.0-derived stream cipher shared with MapleStory .ms v2
// (all 6 tables byte-exact vs MapleLib Snow2CryptoTransform). Signed key
// load, 32 init clockings, 16-word keystream blocks, additive combining.
//
// Usage: node pkg-parse.js <file.pkg> [pathString]
'use strict';
const fs = require('fs');

const TABLES = JSON.parse(fs.readFileSync('H:\\SA_Analysis\\evidence\\snow_tables_from_exe.json', 'utf8')).tables;
const T = {
  a: TABLES.snow_alpha_mul.words, ai: TABLES.snow_alphainv_mul.words,
  t0: TABLES.snow_T0.words, t1: TABLES.snow_T1.words, t2: TABLES.snow_T2.words, t3: TABLES.snow_T3.words,
};
const a_mul = (w) => (((w << 8) >>> 0) ^ T.a[(w >>> 24) & 0xff]) >>> 0;
const ainv_mul = (w) => ((w >>> 8) ^ T.ai[w & 0xff]) >>> 0;
const fsmT = (w) => (T.t0[w & 0xff] ^ T.t1[(w >>> 8) & 0xff] ^ T.t2[(w >>> 16) & 0xff] ^ T.t3[(w >>> 24) & 0xff]) >>> 0;

// Snow2 — port of MapleLib Snow2CryptoTransform (matches FUN_1402abee0).
// Key load is the signed variant (validated: texturescripts key1 has 0x80
// bytes; unsigned load fails, signed succeeds).
class Snow2 {
  constructor(key16) {
    this.s = new Uint32Array(16); this.r1 = 0; this.r2 = 0;
    const b = key16;
    const sx = (x) => (x & 0x80 ? x - 256 : x) | 0;
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
  decrypt(buf, off, len) { // subtract keystream (decryption direction)
    for (let i = 0; i + 4 <= len + 0 && off + i + 4 <= buf.length; i += 4) {
      buf.writeUInt32LE((buf.readUInt32LE(off + i) - this.nextWord()) >>> 0, off + i);
    }
  }
}

function charSum(str) { let s = 0; for (let i = 0; i < str.length; i++) s = (s + str.charCodeAt(i)) >>> 0; return s >>> 0; }

// Header layer: masked key region + version + length-prefixed header string.
function parseHeader(fileBuf, path) {
  const n1 = (charSum(path) % 312) + 30;
  const n2 = ((charSum(path) * 3) % 212) + 33;
  if (n1 + 8 > fileBuf.length) throw new Error('N1 exceeds file size');
  const masked = fileBuf.subarray(0, n1);
  const versionByte = fileBuf[n1];
  const v1 = (((((masked[0] >> 1) | (masked[0] & 0x80)) ^ versionByte) & 0xff) === 3);
  const key = Buffer.from(masked);
  if (v1) for (let i = 0; i < n1; i++) key[i] = (masked[i] >> 1) | (masked[i] & 0x80);
  let pos = n1 + (v1 ? 1 : 0);
  const len = (fileBuf.readUInt32LE(pos) ^ (key[0] & 0x80 ? key[0] - 256 : key[0])) >>> 0;
  if (len >= 0x400 || pos + 4 + len * 2 > fileBuf.length) throw new Error(`bad header len ${len}`);
  pos += 4;
  let headerStr = '';
  for (let i = 0; i < len; i++) {
    const k = key[i % n1] & 0x80 ? key[i % n1] - 256 : key[i % n1];
    headerStr += String.fromCharCode(fileBuf.readUInt16LE(pos + i * 2) ^ (k & 0xffff));
  }
  return { n1, n2, v1, len, headerStr, dataStart: pos + len * 2 };
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

// Index entry: [u32 strlen][name UTF-16LE][6*u32][u32 n][n*16B][16B][+32B if f1&0x10]
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
  const items = [];
  for (let i = 0; i < n; i++) {
    items.push([...region.subarray(off, off + 16)]);
    off += 16;
  }
  const tail16 = [...region.subarray(off, off + 16)]; off += 16;
  let extra = null;
  if ((f[1] & 0x10) !== 0) {
    if (off + 32 > region.length) return null;
    extra = [...region.subarray(off, off + 32)]; off += 32;
  }
  return { name, fields: f, itemCount: n, items, tail16, extra, nextOff: off };
}

function main() {
  const file = process.argv[2];
  const path = process.argv[3] || file.replace(/.*[\\/]/, '');
  const fileBuf = fs.readFileSync(file);
  const hdr = parseHeader(fileBuf, path);
  console.log(`file=${file}`);
  console.log(`path="${path}" N1=${hdr.n1} N2=${hdr.n2} v1=${hdr.v1} headerStr="${hdr.headerStr}" dataStart=${hdr.dataStart}`);
  const { k1, k2 } = deriveKeys(path, hdr.headerStr);

  // --- data region head ---
  const c1 = new Snow2(k1);
  const dh = Buffer.from(fileBuf.subarray(hdr.dataStart, Math.min(hdr.dataStart + 8, fileBuf.length)));
  c1.decrypt(dh, 0, dh.length);
  const checksum = dh.readUInt32LE(0), count = dh.readUInt32LE(4);
  console.log(`data head: checksum=${checksum} (0x${checksum.toString(16)}), fileCount=${count}`);
  if (count === 0 || count > 0x10000) { console.log('!! implausible file count — header/key likely wrong'); process.exit(1); }

  // --- index region ---
  const indexStart = hdr.dataStart + hdr.n2 + 8;
  console.log(`indexStart=${indexStart} (dataStart + N2 + 8)`);
  const c2 = new Snow2(k2);
  const region = Buffer.from(fileBuf.subarray(indexStart));
  c2.decrypt(region, 0, region.length - (region.length % 4));

  const entries = [];
  let off = 0, bad = null;
  for (let e = 0; e < count; e++) {
    const entry = readEntry(region, off);
    if (!entry) { bad = { entry: e, off }; break; }
    entries.push(entry);
    off = entry.nextOff;
  }
  const indexSize = bad ? null : off;
  console.log(`parsed ${entries.length}/${count} entries${bad ? ` (stopped at entry ${bad.entry}, offset ${bad.off})` : `, indexSize=${indexSize}`}`);
  for (const [i, en] of entries.entries()) {
    console.log(`  [${i}] "${en.name}"`);
    console.log(`      fields=[${en.fields.join(', ')}] items=${en.itemCount}${en.extra ? ' +extra32' : ''}`);
    if (en.itemCount && en.items[0]) console.log(`      item0=${en.items[0].map((b) => b.toString(16).padStart(2, '0')).join(' ')}`);
    console.log(`      tail16=${en.tail16.map((b) => b.toString(16).padStart(2, '0')).join(' ')}`);
  }
  if (indexSize !== null) {
    const end = indexStart + indexSize;
    const aligned = Math.ceil(end / 0x400) * 0x400;
    console.log(`end=${end} (0x${end.toString(16)}), aligned=0x${aligned.toString(16)}, fileLen=${fileBuf.length} (0x${fileBuf.length.toString(16)})`);
    console.log(aligned === fileBuf.length ? 'END MATCHES FILE SIZE (0x400 alignment confirmed)' : 'NOTE: aligned end != file size');
  }
  fs.writeFileSync('H:\\SA_Analysis\\evidence\\pkg_index_dump.json', JSON.stringify({
    file, path, header: hdr, checksum, count, indexStart,
    entries: entries.map((e) => ({ name: e.name, fields: e.fields, itemCount: e.itemCount, tail16: e.tail16, extra: e.extra })),
    parsedCount: entries.length, indexSize,
  }, null, 1));
  console.log('dumped evidence/pkg_index_dump.json');
}
main();
