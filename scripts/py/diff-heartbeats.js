// diff-heartbeats.js — 하트비트(type 0x8) obf평문 차분: 어느 위치가 변하는가
import fs from 'fs';
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
  return { type: w[1], key, plain };
}
const pkts = parseFirst(24).map(p => ({ dir: p.dir, ...deobf(p.raw) }));
const hbs = pkts.map((p, i) => ({ i, ...p })).filter(x => x.dir === 'C2S' && x.type === 0x8);
console.log('하트비트:', hbs.map(h => `#${h.i} key=0x${h.key.toString(16)}`).join(', '));
// 상호 차분
for (let a = 0; a < hbs.length; a++) {
  for (let b = a + 1; b < hbs.length; b++) {
    const A = hbs[a].plain, B = hbs[b].plain;
    if (A.length !== B.length) continue;
    const diffPos = [];
    for (let i = 0; i < A.length; i++) if (A[i] !== B[i]) diffPos.push(i);
    const sameKey = hbs[a].key === hbs[b].key;
    console.log(`#${hbs[a].i}${sameKey ? '≡' : '≠'}#${hbs[b].i} (key ${sameKey ? '동일' : '상이'}): 차이 ${diffPos.length}곳 ${diffPos.length <= 40 ? '→ ' + diffPos.map(i => '0x' + i.toString(16)).join(' ') : '(0x' + diffPos[0].toString(16) + ' ~ 0x' + diffPos[diffPos.length - 1].toString(16) + ')'}'`);
  }
}
// 16바이트 유닛(1..17) 추출 per key
const units = new Map();
for (const h of hbs) {
  const u = [...h.plain.slice(1, 17)].map(x => x.toString(16).padStart(2, '0')).join(' ');
  const k = '0x' + h.key.toString(16);
  if (!units.has(k)) units.set(k, new Set());
  units.get(k).add(u);
}
console.log('\nkey별 16B 유닛:');
for (const [k, s] of units) console.log(`  key=${k}: ${[...s].join(' | ')}`);
