// find-v1-alignment.js — 실제 패킷에서 v1 블록(tag=1) 정렬 브루트포스
// 가설: 프레임 body = [prefix k바이트][v1 block][suffix s바이트]
//   v1 block 역순 후 work[1]==1 (tag). 체크섬은 v1 블록 자체 끝 2바이트.
import fs from 'fs';

const raw = fs.readFileSync('H:/SA_Analysis/logs/run1/packets.log', 'utf8');
// 첫 400패킷의 RAW만 파싱
const frames = { C2S: [], S2C: [] };
{
  let dir = null, inRaw = false, bytes = [];
  for (const line of raw.split('\n')) {
    if (line.startsWith('#') && line.includes('conn=')) { const m = line.match(/^#(\d+)\s+(C2S|S2C)/); if (m) { dir = m[2]; inRaw = false; bytes = []; } continue; }
    if (line.includes('-- RAW --')) { inRaw = true; continue; }
    if (line.startsWith('--')) { if (inRaw && dir && bytes.length && frames[dir].length < 400) frames[dir].push(Uint8Array.from(bytes)); inRaw = false; continue; }
    if (inRaw) { const m = line.match(/^\s*[0-9a-f]{4}\s+((?:[0-9a-f]{2,8}[ ])+)/); if (m) for (const h of m[1].trim().split(/\s+/)) if (/^[0-9a-f]{2}$/.test(h)) bytes.push(parseInt(h, 16)); }
  }
}

for (const dir of ['C2S', 'S2C']) {
  console.log(`\n===== ${dir} (${frames[dir].length}프레임) =====`);
  const hits = new Map();
  for (const f of frames[dir]) {
    const len = f[0] | (f[1] << 8);
    const body = f.subarray(2, 2 + len);
    for (let k = 0; k <= 24 && k < len - 12; k++) {
      for (let s = 0; s <= 8 && k + s + 12 <= len; s++) {
        const seg = body.slice(k, len - s);
        // v1: [reversed block][cksum2] → seg 마지막 2 = cksum, block = seg[..seg.len-2]
        const w = seg.slice(0, seg.length - 2).reverse();
        if (w[1] === 1) {
          const key = (w[3] | (w[4] << 8) | (w[5] << 16) | (w[6] << 24)) >>> 0;
          const kk = `${k},${s}`;
          if (!hits.has(kk)) hits.set(kk, []);
          hits.get(kk).push({ frameLen: len, key: '0x' + key.toString(16), cksumField: '0x' + (seg[seg.length - 2] | (seg[seg.length - 1] << 8)).toString(16) });
        }
      }
    }
  }
  const sorted = [...hits.entries()].sort((a, b) => b[1].length - a[1].length);
  for (const [kk, list] of sorted.slice(0, 6)) {
    console.log(`prefix=${kk.split(',')[0]} suffix=${kk.split(',')[1]} → tag=1 히트 ${list.length}/${frames[dir].length}`);
    console.log(`   예시: ${list.slice(0, 3).map(x => `len=${x.frameLen} key=${x.key} cksum=${x.cksumField}`).join(' | ')}`);
  }
}
