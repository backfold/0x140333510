// scan-inner-layer.js — obf 평문에서 내부 암호층 탐지: 전 8B 윈도우 XTEA 복호화 + 구조 점수
import fs from 'fs';
const XTEA_KEY = [0x64363531, 0x38376665, 0x33323039, 0x34636261];
function xteaDec(v0, v1) {
  let sum = 0xC6EF3720 >>> 0;
  for (let i = 0; i < 32; i++) {
    v1 = (v1 - ((((v0 << 4) ^ (v0 >>> 5)) + v0) ^ ((sum + XTEA_KEY[(sum >>> 11) & 3]) >>> 0))) >>> 0;
    sum = (sum - 0x61C88647) >>> 0;
    v0 = (v0 - ((((v1 << 4) ^ (v1 >>> 5)) + v1) ^ ((sum + XTEA_KEY[sum & 3]) >>> 0))) >>> 0;
  }
  return [v0, v1];
}
// packets.log 에서 처음 N개 패킷 raw + obf 복호화 (v2-VM 모델)
function parseFirst(n) {
  const raw = fs.readFileSync('H:/SA_Analysis/logs/run1/packets.log', 'utf8');
  const out = [];
  let dir = null, inRaw = false, bytes = [];
  const lines = raw.split('\n');
  for (const line of lines) {
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
  const type = w[1];
  const key = (w[3] | (w[4] << 8) | (w[5] << 16) | (w[6] << 24)) >>> 0;
  const plain = new Uint8Array(len - 10);
  let prev = 0;
  for (let i = 0; i < plain.length; i++) { const c = w[8 + i]; plain[i] = (key ^ prev ^ c) & 0xff; prev = c; }
  return { type, key, plain };
}
const pkts = parseFirst(24);
for (const [idx, p] of pkts.entries()) {
  const { type, key, plain } = deobf(p.raw);
  console.log(`\n### 패킷#${idx} ${p.dir} len=${plain.length} type=0x${type.toString(16)} key=0x${key.toString(16)}`);
  // 전체 평문 덤프 (처음 3개 패킷만)
  if (idx < 3) {
    for (let i = 0; i < plain.length; i += 16) {
      const row = [...plain.slice(i, i + 16)];
      console.log(`${i.toString(16).padStart(4, '0')}  ` + row.map(x => x.toString(16).padStart(2, '0')).join(' ').padEnd(47) + '  ' + row.map(x => x >= 0x20 && x < 0x7f ? String.fromCharCode(x) : '.').join(''));
    }
  }
  // 모든 8B 윈도우 XTEA 복호화 → ASCII run ≥5 탐지
  let found = 0;
  for (let off = 0; off + 8 <= plain.length && found < 6; off++) {
    const dv = new DataView(plain.buffer, plain.byteOffset + off, 8);
    const [d0, d1] = xteaDec(dv.getUint32(0, true), dv.getUint32(4, true));
    const b = new Uint8Array(8);
    new DataView(b.buffer).setUint32(0, d0, true); new DataView(b.buffer).setUint32(4, d1, true);
    let run = 0, best = 0, start = 0, bs = 0;
    for (let i = 0; i < 8; i++) { if (b[i] >= 0x20 && b[i] < 0x7f) { run++; if (run > best) { best = run; bs = i - run + 1; } } else run = 0; }
    if (best >= 5) {
      console.log(`  XTEA@+0x${off.toString(16)} → ${[...b].map(x => x.toString(16).padStart(2, '0')).join(' ')}  "${String.fromCharCode(...[...b.slice(bs, bs + best)])}"`);
      found++;
    }
    // 제로/구조: 절반 이상이 0x00/0x20
    const zeros = [...b].filter(x => x === 0 || x === 0x20).length;
    if (zeros >= 5 && found < 6) { console.log(`  XTEA@+0x${off.toString(16)} → 제로성 ${[...b].map(x => x.toString(16).padStart(2, '0')).join(' ')}`); found++; }
  }
}
