// protocol-census.js — decoded.log 전체 스캔: (dir,type)별 개수/길이 분포 + 대표 헤더바이트
import fs from 'fs';
const lines = fs.readFileSync('H:/SA_Analysis/logs/run1/decoded.log', 'latin1').split('\n');
const stat = {};
let cur = null;
function close() {
  if (!cur) return;
  const k = `${cur.dir} ${cur.type}`;
  const s = stat[k] = stat[k] || { n: 0, lens: {}, head: [] };
  s.n++;
  s.lens[cur.len] = (s.lens[cur.len] || 0) + 1;
  if (s.head.length < 3) s.head.push(cur.first8);
}
for (const line of lines) {
  const m = line.match(/^#(\d+) (C2S|S2C) type=(0x[0-9a-f]+) key=0x[0-9a-f]+ plen=(\d+)/);
  if (m) { close(); cur = { dir: m[2], type: m[3], len: +m[4], first8: '' }; continue; }
  if (cur && /^[0-9a-f]{4}\s/.test(line) && !cur.first8) {
    cur.first8 = line.slice(6, 30).replace(/\s+/g, '');
  }
}
close();
const rows = Object.entries(stat).sort((a, b) => b[1].n - a[1].n);
console.log(`총 ${(rows.reduce((a, [, s]) => a + s.n, 0))} 프레임, ${rows.length}개 (dir,type)\n`);
console.log('dir type    | count | len(상위)                    | first8 샘플');
for (const [k, s] of rows.slice(0, 60)) {
  const lens = Object.entries(s.lens).sort((a, b) => b[1] - a[1]).slice(0, 4).map(([l, c]) => `${l}×${c}`).join(' ');
  console.log(`${k.padEnd(10)} | ${String(s.n).padStart(5)} | ${lens.padEnd(28)} | ${s.head.map(h => h.slice(0, 12)).join(' ')}`);
}
fs.writeFileSync('H:/SA_Analysis/logs/protocol-census.txt', rows.map(([k, s]) => `${k}\t${s.n}\t${JSON.stringify(s.lens)}\t${s.head.join(',')}`).join('\n'), 'utf8');
console.log('\n전체 → logs/protocol-census.txt');
