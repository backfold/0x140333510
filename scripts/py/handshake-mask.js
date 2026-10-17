// handshake-mask.js — 초기 핸드셰이크 패킷(#12~#31) 서브셋 모드 분석 → 초기 마스크 가설 복원
import fs from 'fs';
const M_C2S = Buffer.from('85a3520d83db99b93ae96247c74f7c03', 'hex');
const M_S2C = Buffer.from('f2596446d34b7b6469cc4ef7ca42dc46', 'hex');
const raw = fs.readFileSync('H:/SA_Analysis/logs/run1/packets.log', 'utf8');
const pkts = []; let dir = null, inRaw = false, bytes = [];
for (const line of raw.split('\n')) {
  if (line.startsWith('#') && line.includes('conn=')) { const m = line.match(/^#(\d+)\s+(C2S|S2C)/); if (m) { dir = m[2]; inRaw = false; bytes = []; } continue; }
  if (line.includes('-- RAW --')) { inRaw = true; continue; }
  if (line.startsWith('--')) { if (inRaw && dir && bytes.length) pkts.push({ idx: pkts.length, dir, raw: Uint8Array.from(bytes) }); inRaw = false; bytes = []; continue; }
  if (inRaw) { const m = line.match(/^\s*[0-9a-f]{4}\s+((?:[0-9a-f]{2,8}[ ])+)/); if (m) for (const h of m[1].trim().split(/\s+/)) if (/^[0-9a-f]{2}$/.test(h)) bytes.push(parseInt(h, 16)); }
}
function obfPlain(f) {
  const len = f[0] | (f[1] << 8);
  if (len < 12) return null;
  const body = f.subarray(2, 2 + len);
  const w = body.slice(0, len - 2).reverse();
  const key = (w[3] | (w[4] << 8) | (w[5] << 16) | (w[6] << 24)) >>> 0;
  const plain = new Uint8Array(len - 10);
  let prev = 0;
  for (let j = 0; j < plain.length; j++) { const c = w[8 + j]; plain[j] = (key ^ prev ^ c) & 0xff; prev = c; }
  return { tag: w[1], key, plain };
}
// 1) #10~#35 패킷별 현재 마스크 복호화 품질(인쇄가능 비율) 출력
console.log('== 현재 마스크로 본 #10~#35 (P[0..47] hex / 인쇄가능%) ==');
for (let i = 10; i < Math.min(36, pkts.length); i++) {
  const r = obfPlain(pkts[i].raw); if (!r) continue;
  const M = pkts[i].dir === 'C2S' ? M_C2S : M_S2C;
  const P = Buffer.from(r.plain.map((b, j) => b ^ M[j % 16]));
  const pr = [...P].filter(b => b >= 0x20 && b < 0x7f).length / P.length;
  console.log(`#${i} ${pkts[i].dir} 0x${r.tag.toString(16).padStart(2,'0')} len=${P.length} 인쇄=${(pr*100).toFixed(0)}%  ${P.subarray(0,48).toString('hex')}`);
}
// 2) 핸드셰이크 서브셋(0xbe/0xbc 중 초기 #12~#21) 위치별 최빈값
console.log('\n== 핸드셰이크 서브셋 위치별 최빈값 (obf평문 기준) ==');
const subsets = { 'S2C 초기(10..21)': i => pkts[i].dir==='S2C' && i>=10 && i<=21, 'C2S 초기(10..21)': i => pkts[i].dir==='C2S' && i>=10 && i<=21 };
for (const [name, pred] of Object.entries(subsets)) {
  const maps = Array.from({length:16},()=>new Map());
  for (let i=0;i<pkts.length;i++){ if(!pred(i)) continue; const r=obfPlain(pkts[i].raw); if(!r) continue;
    for(let j=0;j<r.plain.length;j++){ const m=maps[j%16]; m.set(r.plain[j],(m.get(r.plain[j])||0)+1); } }
  const modes = maps.map(m=>{ const e=[...m.entries()].sort((a,b)=>b[1]-a[1]); return {v:e[0]?.[0],c:e[0]?.[1]||0,tot:[...m.values()].reduce((a,b)=>a+b,0)}; });
  console.log(name+':');
  modes.forEach((m,k)=>console.log(`  p${k}: ${m.v?.toString(16).padStart(2,'0')} (${m.c}/${m.tot})`));
  // 패딩 가설별 초기 마스크 후보
  for (const [hn,hv] of [['0x00',0x00],["'0'",0x30],["'H'",0x48],["'8'",0x38],["'|'",0x7c],["0xfe",0xfe]]) {
    const Mh = Buffer.from(modes.map(m=>((m.v??0)^hv)&0xff));
    console.log(`  pad=${hn} → M_early=${Mh.toString('hex')}`);
  }
}
