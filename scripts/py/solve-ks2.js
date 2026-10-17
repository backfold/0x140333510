// solve-ks2.js — KS = MSVC rand() LCG 확산 가설 검증
// srand(key) 후 연속 rand() 출력 8개 × 2B = 16B KS (바이트 순서 변형 포함)
function msvcRandStream(seed, n) {
  let s = seed >>> 0;
  const out = [];
  for (let i = 0; i < n; i++) {
    s = (Math.imul(s, 214013) + 2531011) >>> 0;
    out.push((s >>> 16) & 0x7fff);
  }
  return out;
}
const OBS = [
  { key: 0xf4a5c72d, ks: 'a3520d83db7ac956e96247c74f7c43c5' },
  { key: 0xd2caf3d3, ks: '5dacf37d31980c6417e338f32aaadadb' },
];
for (const { key, ks } of OBS) {
  console.log(`\nkey=0x${key.toString(16)} 목표: ${ks}`);
  const r = msvcRandStream(key, 10);
  // 변형: [lo,hi] 쌍 / [hi,lo] 쌍 / u16 LE / u16 BE
  const lohi = Buffer.alloc(16), hilo = Buffer.alloc(16);
  for (let i = 0; i < 8; i++) {
    lohi[i * 2] = r[i] & 0xff; lohi[i * 2 + 1] = r[i] >> 8;
    hilo[i * 2] = r[i] >> 8; hilo[i * 2 + 1] = r[i] & 0xff;
  }
  console.log(`  srand(key) rand[0..8] lohi: ${lohi.toString('hex')}${lohi.toString('hex') === ks ? '  *** 일치 ***' : ''}`);
  console.log(`  srand(key) rand[0..8] hilo: ${hilo.toString('hex')}${hilo.toString('hex') === ks ? '  *** 일치 ***' : ''}`);
  // 4바이트 시드 2개(rand 2개당 u32)도 시도
  const u32s = [];
  for (let i = 0; i < 4; i++) u32s.push(r[2 * i] | (r[2 * i + 1] << 16));
  const byU32 = Buffer.alloc(16);
  for (let i = 0; i < 4; i++) byU32.writeUInt32LE(u32s[i] >>> 0, i * 4);
  console.log(`  rand 2개씩 u32LE: ${byU32.toString('hex')}${byU32.toString('hex') === ks ? '  *** 일치 ***' : ''}`);
}
// 역방향: key가 rand()의 N번째 출력이라면 state 역산 — 두 키가 연속 출력인지 확인
// key2 = f(key1)? srand(x) 후 첫 출력이 key1, 이후가 key2… 인 x 탐색은 불가(64비트).
// 대신 key가 srand 인자가 아니라 rand 출력 자체일 수 있음: state 역산 시도
for (const { key } of OBS) {
  // state 역산: key = (s>>16)&0x7fff 인 s는 2^17개 — 그 s에서 다음 출력들 확인
  console.log(`\nkey=0x${key.toString(16)} → 이 key를 출력한 state들의 다음 rand 분포 (첫 3개 시론):`);
  let shown = 0;
  for (let hi = 0; hi < 0x20000 && shown < 2; hi++) {
    // s의 하위 16비트는 미지 — 상위 15비트가 key
    // 역산: s = ((key<<16) | lo16) 인데 lo16 모름 → 임의 lo 시도
    const lo = 0x1234; // 예시
    let s = (((key & 0x7fff) << 16) | lo) >>> 0;
    const r = msvcRandStream(s - 0 >>> 0, 3); // s 자체를 state로 쓰는 게 아니라 srand(seed)는 state=seed(0)
    // srand(seed)는 state=seed 부터: out = ((state*214013+2531011)>>16)&0x7fff
    shown++;
  }
}
console.log('\n(역산 루프는 패턴 확인용 — 아래 직접 매칭으로 대체)');
// 직접: srand(t) 후 연속 출력 (o1,o2,...) 에서 o1=key1이고 o5=key2? 등 관계 스캔
// key1=f4a5c72d는 15비트 초과 → rand 출력이 아님 → 이 경로는 폐기 가능성 출력
console.log('key1=0x' + OBS[0].key.toString(16), '> 0x7fff:', (OBS[0].key > 0x7fff), '| key2:', (OBS[1].key > 0x7fff));
