// decode-all.js — packets.log 전체 → 3계층 완전 복호화 로그 (logs/run1/decoded.log)
// 계층: [u16 LEN] 프레이밍 → reverse+rolling XOR (obf) → 방향별 16B 세션 마스크 XOR
import fs from 'fs';
import readline from 'readline';
const M_C2S = Buffer.from('85a3520d83db99b93ae96247c74f7c03', 'hex');
const M_S2C = Buffer.from('f2596446d34b7b6469cc4ef7ca42dc46', 'hex');
const inPath = 'H:/SA_Analysis/logs/run1/packets.log';
const outPath = 'H:/SA_Analysis/logs/run1/decoded.log';
const rl = readline.createInterface({ input: fs.createReadStream(inPath, 'utf8') });
const out = fs.createWriteStream(outPath, { flags: 'w' });
let dir = null, inRaw = false, bytes = [];
let n = 0, decoded = 0, skipped = 0, byteIn = 0, byteOut = 0;
let t0 = Date.now();
function onFrame(f) {
  n++;
  if (f.length < 12) { skipped++; return; }
  const len = f[0] | (f[1] << 8);
  if (len + 2 > f.length || len < 12) { skipped++; return; }
  const body = f.subarray(2, 2 + len);
  const w = body.slice(0, len - 2).reverse();
  const key = (w[3] | (w[4] << 8) | (w[5] << 16) | (w[6] << 24)) >>> 0;
  const M = dir === 'C2S' ? M_C2S : M_S2C;
  const plen = len - 10;
  // hex 라인들 만들면서 즉시 복호화
  let lines = '';
  lines += `#${n} ${dir} type=0x${w[1].toString(16).padStart(2, '0')} key=0x${key.toString(16).padStart(8, '0')} plen=${plen}\n`;
  let prev = 0;
  const P = Buffer.allocUnsafe(Math.min(plen, 4096));
  const lim = Math.min(plen, 4096);
  for (let j = 0; j < plen; j++) {
    const c = w[8 + j];
    const ob = (key ^ prev ^ c) & 0xff;
    prev = c;
    if (j < lim) P[j] = ob ^ M[j % 16];
  }
  for (let o = 0; o < lim; o += 32) {
    const row = P.subarray(o, Math.min(o + 32, lim));
    const hex = [...row].map(b => b.toString(16).padStart(2, '0')).join(' ');
    const asc = row.toString('latin1').replace(/[^\x20-\x7e]/g, '.');
    lines += `${o.toString(16).padStart(4, '0')}  ${hex.padEnd(95)}  ${asc}\n`;
  }
  if (plen > lim) lines += `... (+${plen - lim}B 생략)\n`;
  out.write(lines);
  decoded++;
  byteOut += lines.length;
}
for await (const line of rl) {
  byteIn += line.length;
  if (line.startsWith('#') && line.includes('conn=')) { const m = line.match(/^#(\d+)\s+(C2S|S2C)/); if (m) { dir = m[2]; inRaw = false; bytes = []; } continue; }
  if (line.includes('-- RAW --')) { inRaw = true; continue; }
  if (line.startsWith('--')) { if (inRaw && dir && bytes.length) onFrame(Uint8Array.from(bytes)); inRaw = false; bytes = []; continue; }
  if (inRaw) { const m = line.match(/^\s*[0-9a-f]{4}\s+((?:[0-9a-f]{2,8}[ ])+)/); if (m) for (const h of m[1].trim().split(/\s+/)) if (/^[0-9a-f]{2}$/.test(h)) bytes.push(parseInt(h, 16)); }
}
out.end();
console.log(`프레임 ${n} 복호화 ${decoded} 스킵 ${skipped} — ${((Date.now() - t0) / 1000).toFixed(1)}s, out=${(byteOut / 1048576).toFixed(1)}MB → ${outPath}`);
