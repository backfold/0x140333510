// sample-tags.js — 주요 태그별 대표 패킷 구조 샘플링
import fs from 'fs';
const tags = process.argv.slice(2);
const lines = fs.readFileSync('H:/SA_Analysis/logs/run1/decoded.log', 'latin1').split('\n');
for (const t of tags) {
  const tt = t.startsWith('0x') ? t : '0x' + t;
  const re = new RegExp(`^#(\\d+) (C2S|S2C) type=${tt} `);
  let found = 0;
  for (let i = 0; i < lines.length && found < 1; i++) {
    const m = lines[i].match(re);
    if (m) {
      found++;
      console.log(`\n=== ${tt} #${m[1]} ${m[2]} ===`);
      let j = i + 1;
      while (j < lines.length && /^[0-9a-f]{4}\s/.test(lines[j])) { console.log(lines[j].slice(0, 160)); j++; }
    }
  }
  if (!found) console.log(`\n=== ${tt} 없음 ===`);
}
