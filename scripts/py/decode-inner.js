// decode-inner.js — 방향별 16B 마스크로 내부층 복호화 → 전 패킷 P 덤프
import fs from 'fs';
const M_C2S = Buffer.from('85a3520d83db99b93ae96247c74f7c03', 'hex');
const M_S2C = Buffer.from('f2596446d34b7b6469cc4ef7ca42dc46', 'hex');
function parseFirst(n) {
  const raw = fs.readFileSync('H:/SA_Analysis/logs/run1/packets.log', 'utf8');
  const out = []; let dir = null, inRaw = false, bytes = [];
  for (const line of raw.split('\n')) {
    if (out.length >= n) break;
    if (line.startsWith('#') && line.includes('conn=')) { const m = line.match(/^#(\d+)\s+(C2S|S2C)/); if (m) { dir = m[2]; inRaw = false; bytes = []; } continue; }
    if (line.includes('-- RAW --')) { inRaw = true; continue; }
    if (line.startsWith('--')) { if (inRaw && dir && bytes.length) out.push({ dir, raw: Uint8Array.from(bytes) }); inRaw = false; bytes = []; continue; }
    if (inRaw) { const m = line.match(/^\s*[0-9a-f]{4}\s+((?:[0-9a-f]{2,8}[ ])+)/); if (m) for (const h of m[1].trim().split(/\s+/)) if (/^[0-9a-f]{2}$/.test(h)) bytes.push(parseInt(h, 16)); }
  }
  return out;
}
const pkts = parseFirst(46);
for (const [i, p] of pkts.entries()) {
  const f = p.raw;
  const len = f[0] | (f[1] << 8);
  const body = f.subarray(2, 2 + len);
  const w = body.slice(0, len - 2).reverse();
  const key = (w[3] | (w[4] << 8) | (w[5] << 16) | (w[6] << 24)) >>> 0;
  const plain = new Uint8Array(len - 10);
  let prev = 0;
  for (let j = 0; j < plain.length; j++) { const c = w[8 + j]; plain[j] = (key ^ prev ^ c) & 0xff; prev = c; }
  const M = p.dir === 'C2S' ? M_C2S : M_S2C;
  const P = Buffer.from(plain.map((b, j) => b ^ M[j % 16]));
  const asc = P.toString('latin1').replace(/[^\x20-\x7e]/g, '.');
  const printN = Math.min(P.length, 128);
  console.log(`#${i} ${p.dir} type=0x${w[1].toString(16)} key=0x${key.toString(16).padStart(8, '0')} len=${P.length}`);
  console.log(`   P: ${P.subarray(0, printN).toString('hex')}${P.length > printN ? '...' : ''}`);
  if (/[\x20-\x7e]{6,}/.test(asc)) console.log(`   A: ${asc.slice(0, 80)}`);
}
