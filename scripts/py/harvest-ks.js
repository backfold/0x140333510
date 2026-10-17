// harvest-ks.js — 전 패킷에서 (obf key, 16B 반복 유닛=KS⊕상수평문) 표본 수집
// 조건: obf평문에 16바이트 유닛이 3회 이상 연속 반복되는 구간 → 해당 구간 평문 상수 가정
import fs from 'fs';
import readline from 'readline';

async function main() {
  const rl = readline.createInterface({ input: fs.createReadStream('H:/SA_Analysis/logs/run1/packets.log', 'utf8') });
  let dir = null, inRaw = false, bytes = [];
  const samples = new Map(); // keyHex -> { units:Set, dirs:Set }
  let pkts = 0;
  let frames = 0;
  const onFrame = (d, f) => {
    pkts++;
    const len = f[0] | (f[1] << 8);
    if (len < 56) return; // 유닛 3회 + 헤더 여유 필요
    frames++;
    const body = f.subarray(2, 2 + len);
    const w = body.slice(0, len - 2).reverse();
    const key = (w[3] | (w[4] << 8) | (w[5] << 16) | (w[6] << 24)) >>> 0;
    const plain = new Uint8Array(len - 10);
    let prev = 0;
    for (let i = 0; i < plain.length; i++) { const c = w[8 + i]; plain[i] = (key ^ prev ^ c) & 0xff; prev = c; }
    // 모든 위상(0..15)에서 16B 유닛 3회 연속 반복 탐색
    for (let ph = 0; ph < 16; ph++) {
      const n = Math.floor((plain.length - ph) / 16);
      let run = 1, best = 1, bestAt = -1;
      for (let i = 1; i < n; i++) {
        let same = true;
        for (let j = 0; j < 16; j++) if (plain[ph + (i - 1) * 16 + j] !== plain[ph + i * 16 + j]) { same = false; break; }
        if (same) { run++; if (run > best) { best = run; bestAt = i - run + 1; } } else run = 1;
      }
      if (best >= 3) {
        const unit = Buffer.from(plain.slice(ph + bestAt * 16, ph + bestAt * 16 + 16)).toString('hex');
        const k = key.toString(16);
        if (!samples.has(k)) samples.set(k, { units: new Set(), dirs: new Set(), n: 0 });
        const s = samples.get(k);
        s.units.add(unit); s.dirs.add(d); s.n++;
        break; // 첫 히트 위상만
      }
    }
  };
  for await (const line of rl) {
    if (line.startsWith('#') && line.includes('conn=')) { const m = line.match(/^#(\d+)\s+(C2S|S2C)/); if (m) { dir = m[2]; inRaw = false; bytes = []; } continue; }
    if (line.includes('-- RAW --')) { inRaw = true; continue; }
    if (line.startsWith('--')) { if (inRaw && dir && bytes.length) onFrame(dir, Uint8Array.from(bytes)); inRaw = false; bytes = []; continue; }
    if (inRaw) { const m = line.match(/^\s*[0-9a-f]{4}\s+((?:[0-9a-f]{2,8}[ ])+)/); if (m) for (const h of m[1].trim().split(/\s+/)) if (/^[0-9a-f]{2}$/.test(h)) bytes.push(parseInt(h, 16)); }
  }
  console.log(`패킷 ${pkts}, 유효프레임 ${frames}, 고유 key ${samples.size}`);
  const multi = [...samples.entries()].filter(([, s]) => s.units.size > 1);
  console.log(`유닛이 2개 이상인 key: ${multi.length}개 (모델 위반 시 가설 기각)`);
  const list = [...samples.entries()].slice(0, 40);
  for (const [k, s] of list) console.log(`key=0x${k.padStart(8, '0')} dir=${[...s.dirs].join('/')} n=${s.n} unit=${[...s.units][0]}`);
}
main();
