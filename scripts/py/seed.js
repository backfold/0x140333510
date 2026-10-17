// seed.js — SEED 블록암호 (RFC 4269 / KISA) — cshell.dll 0x1814967b0 테이블 사용
// 테이블은 바이너리에서 추출한 것 = Oryx ss0..ss3과 동일 검증됨
import fs from 'fs';
const tbl = fs.readFileSync('H:/SA_Analysis/evidence/cipher_tables_0x1803333f0.bin');
// 파일 내 순서: T0(SS0) T1(SS1) T2(SS2) T3(SS3) — 단, VA 순서는 67b0(SS0) 6bb0(SS1) 6fb0(SS2) 73b0(SS3)
const ss = [0, 1, 2, 3].map(k => Array.from({ length: 256 }, (_, i) => tbl.readUInt32LE(k * 1024 + i * 4)));
const KC = [
  0x9E3779B9, 0x3C6EF373, 0x78DDE6E6, 0xF1BBCDCC, 0xE3779B99, 0xC6EF3733, 0x8DDE6E67, 0x1BBCDCCF,
  0x3779B99E, 0x6EF3733C, 0xDDE6E678, 0xBBCDCCF1, 0x779B99E3, 0xEF3733C6, 0xDE6E678D, 0xBCDCCF1B,
];
const G = x => ((ss[0][x & 0xff] ^ ss[1][(x >>> 8) & 0xff] ^ ss[2][(x >>> 16) & 0xff] ^ ss[3][(x >>> 24) & 0xff]) >>> 0);

export function seedInitKey(key16) { // Buffer 16B (big-endian 해석) → ks[32]
  if (key16.length !== 16) throw new Error('SEED 키는 16바이트');
  let k0 = key16.readUInt32BE(0), k1 = key16.readUInt32BE(4), k2 = key16.readUInt32BE(8), k3 = key16.readUInt32BE(12);
  const ks = new Uint32Array(32);
  for (let i = 0; i < 16; i++) {
    ks[2 * i] = G((k0 + k2 - KC[i]) >>> 0);
    ks[2 * i + 1] = G((k1 - k3 + KC[i]) >>> 0);
    let t;
    if (i % 2) { t = ((k3 << 8) | (k2 >>> 24)) >>> 0; k2 = ((k2 << 8) | (k3 >>> 24)) >>> 0; k3 = t; }
    else { t = ((k1 >>> 8) | (k0 << 24)) >>> 0; k0 = ((k0 >>> 8) | (k1 << 24)) >>> 0; k1 = t; }
  }
  return ks;
}
function core(ks, l0, l1, r0, r1, fwd) {
  for (let i = 0; i < 16; i++) {
    const ki = fwd ? 2 * i : 30 - 2 * i;
    let t1 = (((r0 ^ ks[ki]) ^ (r1 ^ ks[ki + 1])) >>> 0);
    t1 = G(t1);
    let t0 = (t1 + ((r0 ^ ks[ki]) >>> 0)) >>> 0;
    t0 = G(t0);
    t1 = (t1 + t0) >>> 0;
    t1 = G(t1);
    t0 = (t0 + t1) >>> 0;
    t0 = (t0 ^ l0) >>> 0; t1 = (t1 ^ l1) >>> 0;
    l0 = r0; l1 = r1; r0 = t0; r1 = t1;
  }
  return [r0, r1, l0, l1];
}
export function seedEncrypt(ks, block16) {
  const [r0, r1, l0, l1] = core(ks, block16.readUInt32BE(0), block16.readUInt32BE(4), block16.readUInt32BE(8), block16.readUInt32BE(12), true);
  const out = Buffer.alloc(16);
  out.writeUInt32BE(r0, 0); out.writeUInt32BE(r1, 4); out.writeUInt32BE(l0, 8); out.writeUInt32BE(l1, 12);
  return out;
}
export function seedDecrypt(ks, block16) {
  const [r0, r1, l0, l1] = core(ks, block16.readUInt32BE(0), block16.readUInt32BE(4), block16.readUInt32BE(8), block16.readUInt32BE(12), false);
  const out = Buffer.alloc(16);
  out.writeUInt32BE(r0, 0); out.writeUInt32BE(r1, 4); out.writeUInt32BE(l0, 8); out.writeUInt32BE(l1, 12);
  return out;
}
// === RFC 4269 Appendix B KAT ===
if (process.argv[1].endsWith('seed.js') && process.argv[2] === 'kat') {
  const V = [
    { k: '00000000000000000000000000000000', p: '000102030405060708090A0B0C0D0E0F', c: '5EBAC6E0054E166819AFF1CC6D346CDB' },
    { k: '000102030405060708090A0B0C0D0E0F', p: '00000000000000000000000000000000', c: 'C11F22F2014050508448359704370F43' },
    { k: '4706480851E61BE85D74BFB3FD956185', p: '83A2F8A288641FB9A4E9A5CC2F131C7D', c: 'EE54D13EBCAE706D226BC3142CD40D4A' },
    { k: '28DBC3BC49FFD87DCFA509B11D422BE7', p: 'B41E6BE2EBA84A148E2EED84593C5EC7', c: '9B9B7BFCD181 3CB95D0B3618F40F5122'.replace(' ', '') },
  ];
  let pass = 0;
  for (const v of V) {
    const ks = seedInitKey(Buffer.from(v.k, 'hex'));
    const c = seedEncrypt(ks, Buffer.from(v.p, 'hex'));
    const ok = c.toString('hex').toUpperCase() === v.c;
    console.log(`key=${v.k} pt=${v.p}\n  → ct=${c.toString('hex').toUpperCase()} 기대=${v.c} ${ok ? '*** KAT 통과 ***' : '불일치'}`);
    if (ok) pass++;
  }
  console.log(`${pass}/${V.length} KAT 통과`);
}
