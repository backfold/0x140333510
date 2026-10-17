// solve-seed-ks.js — 내부층 KS(key32) = SEED_E(key유도, block유도) 후보 배터리
// 목표: 안정바이트(패킷 2개에서 동일한 위치 = 평문 상수 위치) 부분일치 허용
import crypto from 'crypto';
import { seedInitKey, seedEncrypt, seedDecrypt } from './seed.js';

// 표본: (key32, 16B유닛 후보들)
const SAMPLES = [
  { k: 0xf4a5c72d, units: ['a3520d83db7ac956e96247c74f7c43c5', 'a3520d83db99b93ae96247c74f7c0385'] },
  { k: 0xd2caf3d3, units: ['5dacf37d31980c6417e338f32aaadadb'] },
  { k: 0xc291f515, units: ['bd9b6a35bbe3a18102d15a7fff77443b'] },
  { k: 0x54bfca37, units: ['f2596446d34b7b6469cc4ef7ca42dc46'] },
];
// 안정 위치 = 두 유닛이 일치하는 곳 (첫 샘플만 2유닛)
function stableMask(units) {
  if (units.length === 1) return Array(16).fill(true);
  return Array.from({ length: 16 }, (_, i) => units.every(u => u.slice(2 * i, 2 * i + 2) === units[0].slice(2 * i, 2 * i + 2)));
}

const u32le = v => { const b = Buffer.alloc(4); b.writeUInt32LE(v >>> 0, 0); return b; };
const u32be = v => { const b = Buffer.alloc(4); b.writeUInt32BE(v >>> 0, 0); return b; };
const rep = (b, n) => Buffer.concat(Array(n).fill(b));

function keys(k) {
  const map = new Map();
  map.set('rep4le', rep(u32le(k), 4));
  map.set('rep4be', rep(u32be(k), 4));
  map.set('k000le', Buffer.concat([u32le(k), Buffer.alloc(12)]));
  map.set('k000be', Buffer.concat([u32be(k), Buffer.alloc(12)]));
  map.set('000kle', Buffer.concat([Buffer.alloc(12), u32le(k)]));
  map.set('000kbe', Buffer.concat([Buffer.alloc(12), u32be(k)]));
  map.set('md5le', crypto.createHash('md5').update(u32le(k)).digest());
  map.set('md5be', crypto.createHash('md5').update(u32be(k)).digest());
  map.set('md5hex', crypto.createHash('md5').update(k.toString(16)).digest());
  map.set('fixed_xtea_str', Buffer.from('156def789023abc4', 'latin1'));
  map.set('zeros', Buffer.alloc(16));
  return map;
}
function blocks(k) {
  const map = new Map();
  map.set('zeros', Buffer.alloc(16));
  map.set('rep4le', rep(u32le(k), 4));
  map.set('rep4be', rep(u32be(k), 4));
  map.set('k000le', Buffer.concat([u32le(k), Buffer.alloc(12)]));
  map.set('k000be', Buffer.concat([u32be(k), Buffer.alloc(12)]));
  map.set('k000be_mix', Buffer.concat([u32be(k), u32le(k), u32be(k), u32le(k)]));
  map.set('md5le', crypto.createHash('md5').update(u32le(k)).digest());
  map.set('md5hex', crypto.createHash('md5').update(k.toString(16)).digest());
  map.set('inc_ctr', Buffer.concat([u32be(0), u32be(0), u32be(0), u32be(k)])); // counter+k
  return map;
}
let tried = 0, best = { n: 0 };
for (const s of SAMPLES) {
  const mask = stableMask(s.units);
  const targets = s.units.map(u => Buffer.from(u, 'hex'));
  for (const [kn, kb] of keys(s.k)) {
    const ks = seedInitKey(kb);
    for (const [bn, bb] of blocks(s.k)) {
      for (const [fn, f] of [['E', seedEncrypt], ['D', seedDecrypt]]) {
        tried++;
        const out = f(ks, bb);
        for (const [ti, t] of targets.entries()) {
          let m = 0;
          for (let i = 0; i < 16; i++) if (mask[i] && out[i] === t[i]) m++;
          const needed = mask.filter(Boolean).length;
          if (m >= Math.min(8, needed)) {
            console.log(`부분일치 ${m}/${needed}: key=${kn} block=${bn} ${fn} → ${out.toString('hex')} vs 표본${ti} ${t.toString('hex')}`);
          }
          if (m === needed) { console.log(`*** 완전 일치(안정위치) *** key=${s.k.toString(16)} key=${kn} block=${bn} ${fn}`); }
          if (m > best.n) best = { n: m, desc: `${kn}/${bn}/${fn}` };
        }
      }
    }
  }
}
console.log(`시도 ${tried}조합, 최고 부분일치: ${best.n} (${best.desc})`);
