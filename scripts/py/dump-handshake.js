// dump-handshake.js — 초반 패킷(접속~로그인) obf평문 시퀀스 덤프: 핸드셰이크 재료 찾기
import fs from 'fs';
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
function deobf(f) {
  const len = f[0] | (f[1] << 8);
  const body = f.subarray(2, 2 + len);
  const w = body.slice(0, len - 2).reverse();
  const key = (w[3] | (w[4] << 8) | (w[5] << 16) | (w[6] << 24)) >>> 0;
  const plain = new Uint8Array(len - 10);
  let prev = 0;
  for (let i = 0; i < plain.length; i++) { const c = w[8 + i]; plain[i] = (key ^ prev ^ c) & 0xff; prev = c; }
  return { type: w[1], hdr: Buffer.from(w.slice(0, 8)), key, plain };
}
const pkts = parseFirst(40);
pkts.forEach((p, i) => {
  const d = deobf(p.raw);
  const hex = Buffer.from(d.plain).toString('hex');
  const asc = Buffer.from(d.plain).toString('latin1').replace(/[^\x20-\x7e]/g, '.');
  console.log(`#${i} ${p.dir} type=0x${d.type.toString(16)} key=0x${d.key.toString(16).padStart(8, '0')} len=${d.plain.length}`);
  console.log(`   hdr=${d.hdr.toString('hex')}`);
  console.log(`   ${hex.slice(0, 96)}${hex.length > 96 ? '...' : ''}`);
  if (/[\x20-\x7e]{4,}/.test(asc)) console.log(`   asc: ${asc.slice(0, 60)}`);
});
