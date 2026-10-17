// analyze-tables.js — 4테이블 구조 분석: 바이트열 전치성, Twofish MDS 감정, 16비트 분해
import fs from 'fs';
const raw = fs.readFileSync('H:/SA_Analysis/evidence/cipher_tables_0x1803333f0.bin');
const T = [0, 1, 2, 3].map(k => Array.from({ length: 256 }, (_, i) => raw.readUInt32LE(k * 1024 + i * 4)));
// 1) 각 바이트 열이 전치인가?
for (let t = 0; t < 4; t++) for (let b = 0; b < 4; b++) {
  const seen = new Set();
  for (let x = 0; x < 256; x++) seen.add((T[t][x] >>> (8 * b)) & 0xff);
  if (seen.size !== 256) console.log(`T${t} 바이트${b}: 전치 아님 (${seen.size}/256)`);
}
console.log('바이트열 전치 검사 완료 (출력 없으면 전부 전치)');
// 2) 16비트 반워드 분해: L(x), H(x) — L,H 각각이 전치?
for (let t of [0, 1]) {
  const L = T[t].map(v => v & 0xffff), H = T[t].map(v => v >>> 16);
  console.log(`T${t}: |L|=${new Set(L).size} |H|=${new Set(H).size}`);
}
// 3) GF(2^8) 아핀 검사: 열(x) = A·x ⊕ c (A 선형)? — 차분 분포로 선형성 확인
//    선형이면 col(x)^col(y) = col(x^z)^col(y^z) ∀z
function colLinear(col) {
  const base = col(0) ^ col(1); // x=0,1
  for (let z = 1; z < 256; z++) {
    if ((col(0) ^ col(1)) !== (col(0 ^ z) ^ col(1 ^ z))) return false;
  }
  return true;
}
for (let t = 0; t < 4; t++) for (let b = 0; b < 4; b++) {
  const lin = colLinear(x => (T[t][x] >>> (8 * b)) & 0xff);
  if (lin) console.log(`T${t} 바이트${b}: GF(2)-선형 (MDS 곱셈열 가능성)`);
}
// 4) T0/T1의 L,H 16비트가 서로 어떤 관계? L_T0(x) vs L_T1(x) 등 XOR/ROT 관계 스캔
const rel = (a, b) => {
  const xor = new Set(), xs = [];
  let allXorConst = true;
  for (let x = 0; x < 256; x++) { const d = a(x) ^ b(x); if (!xor.has(d)) { xor.add(d); xs.push(x); } if (xor.size > 1) { allXorConst = false; break; } }
  return allXorConst ? `XOR-상수(${xs.length ? a(0) ^ b(0) : ''})` : null;
};
const f16 = t => x => T[t][x] & 0xffff, h16 = t => x => T[t][x] >>> 16;
for (const [na, fa, nb, fb] of [['T0L', f16(0), 'T0H', h16(0)], ['T1L', f16(1), 'T1H', h16(1)], ['T0L', f16(0), 'T1L', f16(1)], ['T0H', h16(0), 'T1H', h16(1)], ['T0L', f16(0), 'T1H', h16(1)], ['T0H', h16(0), 'T1L', f16(1)]]) {
  const r = rel(fa, fb);
  if (r) console.log(`${na} ⊕ ${nb} = ${r}`);
}
// 5) 전체 처음 32개 엔트리 풀 덤프 (구조 육안 확인용)
for (let t of [0, 1]) {
  console.log(`\nT${t}[0..31]:`);
  for (let r = 0; r < 4; r++) console.log('  ' + T[t].slice(r * 8, r * 8 + 8).map(v => v.toString(16).padStart(8, '0')).join(' '));
}
