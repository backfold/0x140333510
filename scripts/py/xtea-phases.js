// xtea-phases.js — obf 평문을 8가지 위상으로 전체 XTEA-ECB 복호화해 구조 비교
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
function scoreAscii(b) { let r = 0; for (const x of b) if (x >= 0x20 && x < 0x7f) r++; return r / b.length; }

const which = process.argv[2] ? process.argv[2].split(',').map(Number) : [0, 1, 2, 16];
const pkts = parseFirst(Math.max(...which) + 1);
for (const idx of which) {
  const p = pkts[idx]; if (!p) continue;
  const { type, plain } = deobf(p.raw);
  console.log(`\n############ 패킷#${idx} ${p.dir} type=0x${type.toString(16)} plain=${plain.length}B ############`);
  // 평문 헤더 후보: 앞 16바이트
  console.log('obf평문 헤더:', [...plain.slice(0, 16)].map(x => x.toString(16).padStart(2, '0')).join(' '));
  for (let phase = 0; phase < 8; phase++) {
    const nBlocks = Math.floor((plain.length - phase) / 8);
    if (nBlocks < 1) continue;
    const dec = new Uint8Array(nBlocks * 8);
    for (let b = 0; b < nBlocks; b++) {
      const dv = new DataView(plain.buffer, plain.byteOffset + phase + b * 8, 8);
      const [d0, d1] = xteaDec(dv.getUint32(0, true), dv.getUint32(4, true));
      new DataView(dec.buffer).setUint32(b * 8, d0, true);
      new DataView(dec.buffer).setUint32(b * 8 + 4, d1, true);
    }
    const asc = scoreAscii(dec);
    const head = [...dec.slice(0, 24)].map(x => x.toString(16).padStart(2, '0')).join(' ');
    console.log(`위상 ${phase}: ascii=${(asc * 100).toFixed(0)}%  ${head}`);
  }
  // 최고 위상 상세 덤프 (ascii 점수 기준)
  let best = -1, bestPhase = 0;
  for (let phase = 0; phase < 8; phase++) {
    const nBlocks = Math.floor((plain.length - phase) / 8); if (nBlocks < 1) continue;
    const dec = new Uint8Array(nBlocks * 8);
    for (let b = 0; b < nBlocks; b++) {
      const dv = new DataView(plain.buffer, plain.byteOffset + phase + b * 8, 8);
      const [d0, d1] = xteaDec(dv.getUint32(0, true), dv.getUint32(4, true));
      new DataView(dec.buffer).setUint32(b * 8, d0, true);
      new DataView(dec.buffer).setUint32(b * 8 + 4, d1, true);
    }
    const s = scoreAscii(dec);
    if (s > best) { best = s; bestPhase = phase; }
  }
  console.log(`--- 최고 위상 ${bestPhase} 전체 덤프 ---`);
  const nBlocks = Math.floor((plain.length - bestPhase) / 8);
  const dec = new Uint8Array(nBlocks * 8); const dcv = new DataView(dec.buffer);
  for (let b = 0; b < nBlocks; b++) {
    const dv = new DataView(plain.buffer, plain.byteOffset + bestPhase + b * 8, 8);
    const [d0, d1] = xteaDec(dv.getUint32(0, true), dv.getUint32(4, true));
    dcv.setUint32(b * 8, d0, true); dcv.setUint32(b * 8 + 4, d1, true);
  }
  for (let i = 0; i < dec.length; i += 16) {
    const row = [...dec.slice(i, i + 16)];
    console.log(`${(bestPhase + i).toString(16).padStart(4, '0')}  ` + row.map(x => x.toString(16).padStart(2, '0')).join(' ').padEnd(47) + '  ' + row.map(x => x >= 0x20 && x < 0x7f ? String.fromCharCode(x) : '.').join(''));
  }
}
