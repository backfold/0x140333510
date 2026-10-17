// solve-seed-ks2.js — 2차 배터리: 헤더 파생 key/block + XTEA 고정키 마스크 변형
import crypto from 'crypto';
import { seedInitKey, seedEncrypt, seedDecrypt } from './seed.js';

const XTEA_KEY = [0x64363531, 0x38376665, 0x33323039, 0x34636261]; // "156def789023abc4"
function xteaEnc(v0, v1) {
  let sum = 0;
  for (let i = 0; i < 32; i++) {
    const f1 = (((((v1 << 4) ^ (v1 >>> 5)) + v1) >>> 0) ^ ((sum + XTEA_KEY[sum & 3]) >>> 0)) >>> 0;
    v0 = (v0 + f1) >>> 0;
    const f2 = (((((v0 << 4) ^ (v0 >>> 5)) + v0) >>> 0) ^ ((((sum + 0x9E3779B9) >>> 0) + XTEA_KEY[((sum + 0x9E3779B9) >>> 11) & 3]) >>> 0)) >>> 0;
    v1 = (v1 + f2) >>> 0;
    sum = (sum + 0x9E3779B9) >>> 0;
  }
  return [v0 >>> 0, v1 >>> 0];
}
function xteaDec(v0, v1) {
  let sum = 0xC6EF3720;
  for (let i = 0; i < 32; i++) {
    const t0a = ((((v0 << 4) ^ (v0 >>> 5)) + v0) >>> 0);
    const t0b = (((sum + 0x9E3779B9) >>> 0) + XTEA_KEY[((sum + 0x9E3779B9) >>> 11) & 3]) >>> 0;
    const a = (t0a ^ t0b) >>> 0;
    v1 = (v1 - a) >>> 0;
    const t1a = ((((v1 << 4) ^ (v1 >>> 5)) + v1) >>> 0);
    const t1b = ((sum + XTEA_KEY[sum & 3]) >>> 0);
    const b = (t1a ^ t1b) >>> 0;
    v0 = (v0 - b) >>> 0;
    sum = (sum - 0x9E3779B9) >>> 0;
  }
  return [v0 >>> 0, v1 >>> 0];
}
const pack2 = (a, b) => { const x = Buffer.alloc(8); x.writeUInt32LE(a, 0); x.writeUInt32LE(b, 4); return x; };

// 표본: (key32, hdr(패킷에서 관측), 안정 유닛들)
const SAMPLES = [
  { k: 0xf4a5c72d, hdr: 'cc08472dc7a5f4da', units: ['a3520d83db7ac956e96247c74f7c43c5', 'a3520d83db99b93ae96247c74f7c0385'] },
  { k: 0xd2caf3d3, hdr: 'cc0838d3f3cad242', units: ['5dacf37d31980c6417e338f32aaadadb'] },
  { k: 0xc291f515, hdr: 'f83d7615f591c2e8', units: ['bd9b6a35bbe3a18102d15a7fff77443b'] },
  { k: 0x54bfca37, hdr: '758ef737cabf5425', units: ['f2596446d34b7b6469cc4ef7ca42dc46'] },
  { k: 0x783448ac, hdr: 'e08eddac4834782b', units: ['d7596446d34b7b6469cc4ef7ca42dc46'.slice(0, 32)] },
];
const u32le = v => { const b = Buffer.alloc(4); b.writeUInt32LE(v >>> 0, 0); return b; };
function maskScore(out, units) {
  let best = 0;
  for (const uh of units) {
    const t = Buffer.from(uh, 'hex');
    let m = 0;
    for (let i = 0; i < 16; i++) if (out[i] === t[i]) m++;
    if (m > best) best = m;
  }
  return best;
}
let bestAll = { n: 0 };
for (const s of SAMPLES) {
  const k = s.k, H = Buffer.from(s.hdr, 'hex');
  const H0 = H.subarray(0, 1), H2 = H.subarray(2, 3), H7 = H.subarray(7, 8);
  const kle = u32le(k);
  const variants = new Map();
  // key/block 후보 (hdr 포함)
  const blocks = new Map([
    ['zeros', Buffer.alloc(16)],
    ['H||H', Buffer.concat([H, H])],
    ['H||zeros', Buffer.concat([H, Buffer.alloc(8)])],
    ['H||0x10s', Buffer.concat([H, Buffer.alloc(8).fill(0x10)])],
    ['Hr||Hr', Buffer.concat([Buffer.from([...H].reverse()), Buffer.from([...H].reverse())])],
    ['kle*4', Buffer.concat([kle, kle, kle, kle])],
  ]);
  const keys = new Map([
    ['zeros', Buffer.alloc(16)],
    ['H||H', Buffer.concat([H, H])],
    ['H||zeros', Buffer.concat([H, Buffer.alloc(8)])],
    ['Hr||Hr', Buffer.concat([Buffer.from([...H].reverse()), Buffer.from([...H].reverse())])],
    ['fixed_xtea', Buffer.from('156def789023abc4', 'latin1')],
    ['md5H', crypto.createHash('md5').update(H).digest()],
  ]);
  for (const [kn, kb] of keys) {
    const ks = seedInitKey(kb);
    for (const [bn, bb] of blocks) {
      for (const [fn, f] of [['E', seedEncrypt], ['D', seedDecrypt]]) {
        const out = f(ks, bb);
        const sc = maskScore(out, s.units);
        if (sc >= 10) console.log(`SEED key=${kn} blk=${bn} ${fn} k=0x${k.toString(16)}: ${sc}/16 일치 ${out.toString('hex')}`);
        if (sc > bestAll.n) bestAll = { n: sc, desc: `SEED ${kn}/${bn}/${fn}` };
      }
    }
  }
  // XTEA 고정키 변형: 8B유닛 2개 = {t,?} 조합 — 하트비트 8B 유닛 u0=앞8바이트 u1=뒤8바이트
  for (const uh of s.units) {
    const u = Buffer.from(uh, 'hex');
    const u0 = [u.readUInt32LE(0), u.readUInt32LE(4)];
    const u1 = [u.readUInt32LE(8), u.readUInt32LE(12)];
    // 목표: u0 = xteaE(?, ?) — 평문 0이면 u0=E(B0) → B0 = xteaD(u0); B0이 k/H와 어떤 관계?
    for (const [fn, f] of [['E', xteaEnc], ['D', xteaDec]]) {
      const d0 = f(...u0), d1 = f(...u1);
      const d0b = pack2(...d0), d1b = pack2(...d1);
      for (const [name, ref] of [['kle', kle], ['H3_7', H.subarray(3, 7)], ['H0_3', H.subarray(0, 4)], ['H4_7', H.subarray(4, 8)]]) {
        if (d0b.subarray(0, 4).equals(ref)) console.log(`XTEA-${fn}: 유닛전반 역산체크=D(${u0}) 앞4B==${name}!!`);
        if (d1b.subarray(0, 4).equals(ref)) console.log(`XTEA-${fn}: 유닛후반 역산체크=D(${u1}) 앞4B==${name}!!`);
      }
      // 역산값이 k 관련 상수인지 (전체 8B)
      const cands = { 'k,0': pack2(k, 0), '0,k': pack2(0, k), 'k,k': pack2(k, k) };
      for (const [cn, cb] of Object.entries(cands)) {
        if (d0b.equals(cb)) console.log(`XTEA-${fn}: D(유닛전반) == ${cn}!! 완전구조 발견`);
        if (d1b.equals(cb)) console.log(`XTEA-${fn}: D(유닛후반) == ${cn}!! 완전구조 발견`);
      }
    }
  }
}
console.log(`최고: ${bestAll.n}/16 (${bestAll.desc})`);
