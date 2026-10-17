// solve-mask.js — M_c2s/M_s2c = SEED_E(K, B) 유도 검증 배터리
import crypto from 'crypto';
import { seedInitKey, seedEncrypt, seedDecrypt } from './seed.js';
const M_C2S = Buffer.from('85a3520d83db99b93ae96247c74f7c03', 'hex');
const M_S2C = Buffer.from('f2596446d34b7b6469cc4ef7ca42dc46', 'hex');
const Z = Buffer.alloc(16);
const KEYS = new Map([
  ['fixed_xtea_str', Buffer.from('156def789023abc4', 'latin1')],
  ['zeros', Z],
  ['ones', Buffer.alloc(16).fill(1)],
  ['0123456789abcdef', Buffer.from('0123456789abcdef')],
  ['seed_str', Buffer.from('SEEDSEEDSEEDSEED', 'latin1')],
  ['md5_156def', crypto.createHash('md5').update('156def789023abc4').digest()],
  ['ff', Buffer.alloc(16).fill(0xff)],
]);
const BLOCKS = new Map([
  ['zeros', Z],
  ['ones', Buffer.alloc(16).fill(1)],
  ['c2s_mask', M_C2S],
  ['s2c_mask', M_S2C],
  ['xor_masks', (() => { const b = Buffer.alloc(16); for (let i = 0; i < 16; i++) b[i] = M_C2S[i] ^ M_S2C[i]; return b; })()],
]);
for (const [mn, M] of [['M_c2s', M_C2S], ['M_s2c', M_S2C]]) {
  console.log(`\n=== ${mn} = ${M.toString('hex')} ===`);
  for (const [kn, K] of KEYS) {
    const ks = seedInitKey(K);
    for (const [bn, B] of BLOCKS) {
      const e = seedEncrypt(ks, B), d = seedDecrypt(ks, B);
      if (e.equals(M)) console.log(`*** ${mn} = E(${kn}, ${bn}) !!!`);
      if (d.equals(M)) console.log(`*** ${mn} = D(${kn}, ${bn}) !!!`);
    }
    // 역방향: D(K, M)이 구조적(제로/아스키)인지
    const dz = seedDecrypt(ks, M), ez = seedEncrypt(ks, M);
    const zLike = dz.equals(Z) || ez.equals(Z);
    const aLike = [...dz].every(b => b >= 0x20 && b < 0x7f) || [...ez].every(b => b >= 0x20 && b < 0x7f);
    if (zLike) console.log(`*** D/E(${kn}, ${mn}) = 0^16 !!! 세션키 발견`);
    if (aLike) console.log(`D(${kn}, ${mn})=${dz.toString('latin1')} / E=${ez.toString('latin1')} ← 아스키!`);
  }
}
// 마스크 상호관계: M_s2c = E(K=?, M_c2s) 여부는 키 몰라 불가 — XOR/rot 관계라도
const x = Buffer.alloc(16);
for (let i = 0; i < 16; i++) x[i] = M_C2S[i] ^ M_S2C[i];
console.log('\nM_c2s^M_s2c =', x.toString('hex'));
// 각 마스크가 자기 자신의 SEED 암호문인지 (self-encrypt 불가) — 대신 바이트 구조: 4바이트 워드 덤프
for (const [n, M] of [['c2s', M_C2S], ['s2c', M_S2C]]) {
  console.log(`${n} 워드BE: ${[0, 1, 2, 3].map(i => M.readUInt32BE(i * 4).toString(16).padStart(8, '0')).join(' ')}`);
  console.log(`${n} 워드LE: ${[0, 1, 2, 3].map(i => M.readUInt32LE(i * 4).toString(16).padStart(8, '0')).join(' ')}`);
}
