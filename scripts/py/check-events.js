// check-events.js — events.jsonl 종류/카운트 + chunk 오프셋 흐름
import fs from 'fs';
const L = fs.readFileSync('H:/SA_Analysis/logs/run1/events.jsonl', 'latin1').trim().split('\n');
console.log('events:', L.length);
const ev = {};
for (const l of L) { try { const j = JSON.parse(l); ev[j.ev] = (ev[j.ev] || 0) + 1; } catch { ev.parse_err = (ev.parse_err || 0) + 1; } }
console.log(JSON.stringify(ev));
const chunks = L.filter(l => l.includes('"ev":"chunk"'));
console.log(`chunk 이벤트 ${chunks.length}개`);
for (const c of chunks.slice(0, 3)) console.log(c.slice(0, 140));
console.log('…');
for (const c of chunks.slice(-2)) console.log(c.slice(0, 140));
const lastOff = {};
for (const c of chunks) { const j = JSON.parse(c); lastOff[j.dir] = j.off; }
console.log('마지막 off:', JSON.stringify(lastOff));
