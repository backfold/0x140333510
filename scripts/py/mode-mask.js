// mode-mask.js — 방향별/타입별 obf평문 바이트 최빈값 → 세션 마스크 추정
import fs from 'fs';
import readline from 'readline';
async function main() {
  const rl = readline.createInterface({ input: fs.createReadStream('H:/SA_Analysis/logs/run1/packets.log', 'utf8') });
  let dir = null, inRaw = false, bytes = [];
  // [dir][tag][i%16] → 카운트 맵; 그리고 [dir][i%16] 전체 누적
  const acc = { C2S: { all: [] }, S2C: { all: [] } }; // all: 16개 Map
  for (const d of ['C2S', 'S2C']) for (let i = 0; i < 16; i++) acc[d].all.push(new Map());
  const tagAcc = {}; // `${dir}:${tag}` → 16 Map
  function bump(maps, plain, off) { // off: 마스크 정렬 오프셋(0 또는 1)
    for (let i = off; i < plain.length; i++) {
      const p = i % 16;
      const v = plain[i];
      const m = maps[p];
      m.set(v, (m.get(v) || 0) + 1);
    }
  }
  let n = 0;
  const onFrame = f => {
    n++;
    const len = f[0] | (f[1] << 8);
    if (len < 34) return;
    const body = f.subarray(2, 2 + len);
    const w = body.slice(0, len - 2).reverse();
    const key = (w[3] | (w[4] << 8) | (w[5] << 16) | (w[6] << 24)) >>> 0;
    const plain = new Uint8Array(len - 10);
    let prev = 0;
    for (let i = 0; i < plain.length; i++) { const c = w[8 + i]; plain[i] = (key ^ prev ^ c) & 0xff; prev = c; }
    const tag = w[1];
    bump(acc[dir].all, plain, 0);
    const tk = `${dir}:0x${tag.toString(16)}`;
    if (!tagAcc[tk]) tagAcc[tk] = Array.from({ length: 16 }, () => new Map());
    bump(tagAcc[tk], plain, 0);
  };
  for await (const line of rl) {
    if (line.startsWith('#') && line.includes('conn=')) { const m = line.match(/^#(\d+)\s+(C2S|S2C)/); if (m) { dir = m[2]; inRaw = false; bytes = []; } continue; }
    if (line.includes('-- RAW --')) { inRaw = true; continue; }
    if (line.startsWith('--')) { if (inRaw && dir && bytes.length) onFrame(Uint8Array.from(bytes)); inRaw = false; bytes = []; continue; }
    if (inRaw) { const m = line.match(/^\s*[0-9a-f]{4}\s+((?:[0-9a-f]{2,8}[ ])+)/); if (m) for (const h of m[1].trim().split(/\s+/)) if (/^[0-9a-f]{2}$/.test(h)) bytes.push(parseInt(h, 16)); }
  }
  console.log(`프레임 ${n}개 분석`);
  const top = (maps, k = 3) => maps.map(m => {
    const e = [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, k);
    return e.map(([v, c]) => `${v.toString(16).padStart(2, '0')}(${(100 * c / [...m.values()].reduce((s, x) => s + x, 0)).toFixed(0)}%)`).join(',');
  });
  for (const d of ['C2S', 'S2C']) {
    console.log(`\n[${d} 전체] 위치별 최빈값 (p=0..15):`);
    const t = top(acc[d].all, 2);
    for (let i = 0; i < 16; i++) console.log(`  p${i}: ${t[i]}`);
  }
  // 주요 태그만
  const tagsByVol = Object.entries(tagAcc).filter(([, maps]) => maps[0].size + maps[8].size > 0);
  console.log(`\n태그 종류: ${Object.keys(tagAcc).length}개`);
  for (const [tk, maps] of Object.entries(tagAcc).slice(0, 12)) {
    const tot = maps.reduce((s, m) => s + [...m.values()].reduce((a, b) => a + b, 0), 0);
    console.log(`  ${tk} (바이트 ${tot}): ${top(maps, 1).join(' ')}`);
  }
}
main();
