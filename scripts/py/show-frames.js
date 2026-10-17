// show-frames.js — decoded.log에서 지정 프레임 번호 전체 출력
import fs from 'fs';
const wants = process.argv.slice(2).map(Number);
const lines = fs.readFileSync('H:/SA_Analysis/logs/run1/decoded.log', 'latin1').split('\n');
for (const want of wants) {
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i].match(new RegExp(`^#${want} (C2S|S2C) type=0x([0-9a-f]+) key=0x([0-9a-f]+) plen=(\\d+)`));
    if (m) {
      console.log(`=== #${want} ${m[1]} type=0x${m[2]} key=0x${m[3]} plen=${m[4]} ===`);
      let j = i + 1;
      while (j < lines.length && /^[0-9a-f]{4}\s/.test(lines[j])) { console.log(lines[j]); j++; }
      console.log();
      break;
    }
  }
}
