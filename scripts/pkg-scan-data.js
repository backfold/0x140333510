// pkg-scan-data.js — decrypt the data region (key1) and look for known
// LithTech signatures (.ltb/.ltc/.tfs) to locate where per-file data lives.
'use strict';
const fs = require('fs');
const { execSync } = require('child_process');

// reuse Snow2 from a shared inline copy (identical to pkg-parse.js)
const TABLES = JSON.parse(fs.readFileSync('H:\\SA_Analysis\\evidence\\snow_tables_from_exe.json', 'utf8')).tables;
const T = {
  a: TABLES.snow_alpha_mul.words, ai: TABLES.snow_alphainv_mul.words,
  t0: TABLES.snow_T0.words, t1: TABLES.snow_T1.words, t2: TABLES.snow_T2.words, t3: TABLES.snow_T3.words,
};
const a_mul = (w) => (((w << 8) >>> 0) ^ T.a[(w >>> 24) & 0xff]) >>> 0;
const ainv_mul = (w) => ((w >>> 8) ^ T.ai[w & 0xff]) >>> 0;
const fsmT = (w) => (T.t0[w & 0xff] ^ T.t1[(w >>> 8) & 0xff] ^ T.t2[(w >>> 16) & 0xff] ^ T.t3[(w >>> 24) & 0xff]) >>> 0;
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
  decrypt(buf, off, len) {
    for (let i = 0; off + i + 4 <= buf.length && i < len; i += 4) {
      buf.writeUInt32LE((buf.readUInt32LE(off + i) - this.nextWord()) >>> 0, off + i);
    }
  }
}
function charSum(s) { let x = 0; for (const c of s) x = (x + c.charCodeAt(0)) >>> 0; return x; }

const file = process.argv[2], path = process.argv[3] || file.replace(/.*[\\/]/, '');
const buf = fs.readFileSync(file);
const n1 = (charSum(path) % 312) + 30;
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
const k1 = Buffer.alloc(16);
for (let i = 0; i < 16; i++) k1[i] = (i + (str.charCodeAt(i % L) & 0xff)) & 0xff;
const tail = Buffer.from(buf.subarray(dataStart));
new Snow2(k1).decrypt(tail, 0, tail.length - (tail.length % 4));
console.log(`file=${file} dataStart=${dataStart} decrypted ${tail.length} bytes`);

// 1) ASCII strings in the decrypted region
const runs = [];
let cur = '';
for (let i = 0; i < tail.length; i++) {
  const b = tail[i];
  if (b >= 0x20 && b < 0x7f) cur += String.fromCharCode(b);
  else { if (cur.length >= 5) runs.push([dataStart + i - cur.length, cur]); cur = ''; }
}
if (cur.length >= 5) runs.push([tail.length + dataStart - cur.length, cur]);
console.log(`ASCII runs >= 5: ${runs.length}`);
for (const [off, s] of runs.slice(0, 40)) console.log(`  @${off} (data+${off - dataStart}) "${s.slice(0, 90)}"`);

// 2) known signatures
const SIGS = ['LTMO', 'ANIM', 'LTSR', 'LTUR', 'LTLT', 'LTRT', 'LTPT', 'LTBR', 'LTSP', 'OTTL', 'LTOC', 'LTCR', 'LTAV', 'LTEX', 'MAGIC', 'DXT1', 'DXT3', 'DXT5', 'PETC', 'PK\x03\x04', '\x1f\x8b'];
for (const sig of SIGS) {
  let idx = 0; const found = [];
  while ((idx = tail.indexOf(Buffer.from(sig, 'latin1'), idx)) !== -1 && found.length < 5) { found.push(dataStart + idx); idx++; }
  if (found.length) console.log(`  sig "${sig.replace(/[^\x20-\x7e]/g, '.')}" at file offsets: ${found.join(', ')} (data+${found.map((f) => f - dataStart).join(', ')})`);
}

// 3) entropy windows — find low-entropy (structured) regions after the index
// (index end read from the dump if present)
try {
  const dump = JSON.parse(fs.readFileSync('H:\\SA_Analysis\\evidence\\pkg_index_dump.json', 'utf8'));
  if (dump.file === file && dump.indexSize) {
    const after = tail.subarray(dump.indexStart + dump.indexSize - dataStart);
    console.log(`\nregion after index: ${after.length} bytes (file [${dump.indexStart + dump.indexSize}, ${buf.length})`);
    for (let i = 0; i + 64 <= Math.min(after.length, 512); i += 64) {
      const hex = [...after.subarray(i, i + 32)].map((b) => b.toString(16).padStart(2, '0')).join(' ');
      console.log(`  data+${dump.indexStart + dump.indexSize - dataStart + i}: ${hex}`);
    }
    fs.writeFileSync('H:\\SA_Analysis\\evidence\\pkg_data_' + path.replace(/[^\w]/g, '_') + '.bin', after);
    console.log('  dumped full after-index region');
  }
} catch (e) { console.log('(no index dump: ' + e.message + ')'); }
