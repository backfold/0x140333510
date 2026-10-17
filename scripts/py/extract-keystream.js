// extract-keystream.js — 16바이트 주기 XOR 키스트림 가설 검증
// 하트비트(type 0x8, 평문 상수 추정)에서 KS 추출 → 다른 패킷 XOR → 구조/ASCII/토큰 탐색
import fs from 'fs';
const XTEA_KEY = [0x64363531, 0x38376665, 0x33323039, 0x34636261];
function xteaEnc(v0, v1) {
  let sum = 0;
  for (let i = 0; i < 32; i++) {
    v0 = (v0 + (((((v1 << 4) ^ (v1 >>> 5)) + v1) ^ ((sum + XTEA_KEY[sum & 3]) >>> 0)))) >>> 0;
    v1 = (v1 + (((((v0 << 4) ^ (v0 >>> 5)) + v0) ^ (((sum + 0x9E3779B9) >>> 0) + XTEA_KEY[((sum + 0x9E3779B9) >>> 11) & 3])) >>> 0)) >>> 0;
    sum = (sum + 0x9E3779B9) >>> 0;
  }
  return [v0, v1];
}
function parseFirst(n) {
  const raw = fs.readFileSync('H:/SA_Analysis/logs/run1/packets.log', 'utf8');
  const out = []; let dir = null, inRaw = false, bytes = [];
  for (const line of raw.split('\n')) {
    if (out.length >= n) break;
    if (line.startsWith('#') && line.includes('conn=')) { const m = line.match(/^#(\d+)\s+(C2S|S2C)/); if (m) { dir = m[2]; inRaw = false; bytes = []; } continue; }
    if (line.includes('-- RAW --')) { inRaw = true; continue; }
    if (line.startsWith('--')) { if (inRaw && dir && bytes.length) out.push({ dir, raw: Uint8Array.from(bytes) }); inRaw = false; continue; }
    if (inRaw) { const m = line.match(/^\s*[0-9a-f]{4}\s+((?:[0-9a-f]{2,8}[ ])+)/); if (m) for (const h of m[1].trim().split(/\s+/)) if (/^[0-9a-f]{2}$/.test(h)) bytes.push(parseInt(h, 16)); }
  }
  return out;
}
function deobf(f) {
  const len = f[0] | (f[1] << 8);
  const body = f.subarray(2, 2 + len);
  const w = body.slice(0, len - 2).reverse();
  const key = (w[3] | (w[4] << 8) | (w[5] << 16) | (w[6] << 24)) >>> 0;
  const plain = new Uint8Array(len - 10);
  let prev = 0;
  for (let i = 0; i < plain.length; i++) { const c = w[8 + i]; plain[i] = (key ^ prev ^ c) & 0xff; prev = c; }
  return { type: w[1], plain };
}
function asciiRun(b) { // 최장 ASCII run
  let best = 0, cur = 0, bs = 0;
  for (let i = 0; i < b.length; i++) {
    if (b[i] >= 0x20 && b[i] < 0x7f) { cur++; if (cur > best) { best = cur; bs = i - cur + 1; } } else cur = 0;
  }
  return { best, s: best >= 6 ? String.fromCharCode(...b.slice(bs, bs + best)) : '' };
}

const pkts = parseFirst(24);
const plains = pkts.map(p => ({ dir: p.dir, ...deobf(p.raw) }));

// 후보 키스트림 목록
const KS = new Map();
// 1) 하트비트 평문에서: #4의 obf평문 [1..17) (주기 패턴) — 하트비트 평문이 0이라 가정
{
  const hb = plains.find(p => p.dir === 'C2S' && p.type === 0x8);
  if (hb) {
    KS.set('heartbeat-pattern', hb.plain.slice(1, 17));
    KS.set('heartbeat-full0', hb.plain.slice(0, 16));
  }
}
// 2) XTEA_E(카운터) 후보
for (const [c0, c1] of [[0, 0], [1, 0], [0, 1], [1, 1], [2, 0], [0, 2]]) {
  const [e0, e1] = xteaEnc(c0, c1);
  const b = new Uint8Array(8); new DataView(b.buffer).setUint32(0, e0, true); new DataView(b.buffer).setUint32(4, e1, true);
  KS.set(`xteaE(${c0},${c1})`, b);
}
// 3) S2C 벌크(#16) 패턴
{
  const bl = plains.filter(p => p.dir === 'S2C' && p.type === 0x8e)[0];
  if (bl) KS.set('s2c-bulk-pattern', bl.plain.slice(1, 17));
}

// 각 패킷 × 각 KS(16B로 확장) XOR → ASCII run / 토큰 탐색
for (const [name, ks8] of KS) {
  const ks = new Uint8Array(16);
  ks.set(ks8.subarray(0, Math.min(8, ks8.length)));
  if (ks8.length < 16) { const [e0, e1] = xteaEnc(1, 0); } // placeholder
  const k16 = ks8.length >= 16 ? ks8 : (() => { const t = new Uint8Array(16); t.set(ks8); return t; })();
  console.log(`\n=== KS "${name}": ${[...k16].map(x => x.toString(16).padStart(2, '0')).join(' ')}`);
  for (const [idx, p] of plains.entries()) {
    if (p.plain.length < 8) continue;
    const x = new Uint8Array(p.plain.length);
    for (let i = 0; i < x.length; i++) x[i] = p.plain[i] ^ k16[i % 16];
    const r = asciiRun(x);
    const toks = ['NP11', 'nest', '1326428154', 'SA'].filter(t => Buffer.from(x).includes(t));
    if (r.best >= 8 || toks.length) {
      console.log(`  #${idx} ${p.dir} type=0x${p.type.toString(16)}: run=${r.best} "${r.s}"${toks.length ? ' 토큰=' + toks.join(',') : ''}`);
    }
  }
}
// 하트비트 평문끼리 비교 (동일성 재확인 + 다른 키 같은 평문?)
const hbs = plains.map((p, i) => ({ i, p })).filter(x => x.p.dir === 'C2S' && x.p.type === 0x8);
if (hbs.length >= 2) {
  console.log('\n하트비트 obf평문 동일성:');
  for (let k = 1; k < hbs.length; k++) {
    const a = hbs[0].p.plain, b = hbs[k].p.plain;
    let same = a.length === b.length;
    if (same) for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) { same = false; break; }
    console.log(`  #${hbs[0].i} vs #${hbs[k].i}: ${same ? '완전 동일' : '상이'}`);
  }
}
