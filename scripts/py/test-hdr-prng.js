// test-hdr-prng.js — 헤더 스트림 = srand(key32) MSVC rand() 출력인가?
const SAMPLES = [
  { k: 0xf4a5c72d, hdr: 'cc08472dc7a5f4da' }, // type=08
  { k: 0xd2caf3d3, hdr: 'cc0838d3f3cad242' },
  { k: 0xc291f515, hdr: 'f83d7615f591c2e8' },
  { k: 0x54bfca37, hdr: '758ef737cabf5425' },
  { k: 0x783448ac, hdr: 'e08eddac4834782b' },
  { k: 0x288efc4b, hdr: '09bbc74bfc8e2816' },
];
function randStream(seed, n) {
  let s = seed >>> 0; const out = [];
  for (let i = 0; i < n; i++) { s = (Math.imul(s, 214013) + 2531011) >>> 0; out.push((s >>> 16) & 0x7fff); }
  return out;
}
for (const { k, hdr } of SAMPLES) {
  const H = Buffer.from(hdr, 'hex');
  const want = [H[0], H[2], H[7]]; // w0, w2, w7 (type 제외)
  const layouts = [
    ['lo8 나열', r => r.map(x => x & 0xff)],
    ['hi8 나열', r => r.map(x => (x >> 8) & 0xff)],
    ['15bit→2B LE', r => r.flatMap(x => [x & 0xff, (x >> 8) & 0xff])],
    ['15bit→2B BE', r => r.flatMap(x => [(x >> 8) & 0xff, x & 0xff])],
  ];
  for (const [name, f] of layouts) {
    for (const skip of [0, 1, 2]) {
      const b = f(randStream(k, 12)).slice(skip);
      if (b[0] === want[0] && b[1] === want[1]) console.log(`key=0x${k.toString(16)} ${name} skip=${skip}: w0,w2 일치! ${b.slice(0, 8).map(x => x.toString(16).padStart(2, '0')).join(' ')}`);
      if (b.length > 7 && b[0] === want[0] && b[7] === want[2]) console.log(`key=0x${k.toString(16)} ${name} skip=${skip}: w0,w7 일치!`);
    }
  }
  // 역방향: 헤더 앞 3바이트가 rand출력이라면 seed 역산 — w0,w2가 연속 출력 (s1,s2)인 seed 찾기 (2^32 불가) → 대신 w2가 key 관련 함수인지 비교만
  console.log(`key=0x${k.toString(16)} hdr=${hdr} → w0=${want[0].toString(16)} w2=${want[1].toString(16)} w7=${want[2].toString(16)} key0=${H[3].toString(16)}`);
}
// 추가 가설: w0/w2/w7 = key의 1바이트 함수? 전 샘플에서 k와 w들 상관 출력
for (const { k, hdr } of SAMPLES) {
  const H = Buffer.from(hdr, 'hex');
  const kb = [k & 0xff, (k >>> 8) & 0xff, (k >>> 16) & 0xff, (k >>> 24) & 0xff];
  console.log(`k=0x${k.toString(16)} kb=${kb.map(x => x.toString(16)).join(',')} w0=${H[0].toString(16)} w2=${H[2].toString(16)} w7=${H[7].toString(16)} XORs: w0^k0=${(H[0] ^ kb[0]).toString(16)} w0^k1=${(H[0] ^ kb[1]).toString(16)} w0^k2=${(H[0] ^ kb[2]).toString(16)} w0^k3=${(H[0] ^ kb[3]).toString(16)}`);
}
