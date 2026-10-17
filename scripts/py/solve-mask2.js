// solve-mask2.js — M = E/D(K, 고정IV) 형태 검증 배터리 + 해시 기반 K 후보
import fs from 'fs';
import crypto from 'crypto';
import { seedInitKey, seedEncrypt, seedDecrypt } from './seed.js';

const M_c2s = Buffer.from('85a3520d83db99b93ae96247c74f7c03', 'hex');
const M_s2c = Buffer.from('f2596446d34b7b6469cc4ef7ca42dc46', 'hex');
const key16 = Buffer.from('73dc7ace854f40bd72d34a0fa4667afc', 'hex');
const sdat16 = Buffer.from('SDAT.NEXON.COM..', 'latin1');
const hello = Buffer.from('90fc4958b2acba5406687df4d65368707deb5ee2edc15a78572e00b1', 'hex');
const blob = Buffer.from('c0e98d1fc0479affc03190', 'hex');
const rep = Buffer.from('9152a3609152a360', 'hex');
const zeros = Buffer.alloc(16);
const b64str = Buffer.from('c9x6zoVPQL1y00oPpGZ6/A==', 'latin1');
const xtea8 = Buffer.from('156def789023abc4', 'latin1');

// K 후보 16B
const kc = {};
kc.key16 = key16; kc.sdat = sdat16; kc.hello16 = hello.subarray(0, 16); kc.helloT = Buffer.concat([hello.subarray(12, 28), Buffer.alloc(4)]);
kc.rep16 = Buffer.concat([rep, rep]); kc.blobPad = Buffer.concat([blob, Buffer.alloc(5)]);
kc.blob38 = Buffer.concat([blob, Buffer.from('3838383838', 'latin1')]);
kc.md5_blob = crypto.createHash('md5').update(blob).digest();
kc.md5_hello = crypto.createHash('md5').update(hello).digest();
kc.md5_key = crypto.createHash('md5').update(key16).digest();
kc.md5_sdat = crypto.createHash('md5').update(sdat16).digest();
kc.md5_b64 = crypto.createHash('md5').update(b64str).digest();
kc.md5_xtea = crypto.createHash('md5').update(xtea8).digest();
kc.sha1_hello = crypto.createHash('sha1').update(hello).digest().subarray(0, 16);
kc.sha256_key = crypto.createHash('sha256').update(key16).digest().subarray(0, 16);
kc.zeros = zeros;
// M 자체/조합도 K 후보
kc.M_c2s = M_c2s; kc.M_s2c = M_s2c; kc.Mxor = Buffer.from(M_c2s.map((b, i) => b ^ M_s2c[i]));

// IV 후보
const ivs = { zeros, sdat: sdat16, hello16: hello.subarray(0, 16), helloT16: kc.helloT, M_c2s, M_s2c, rep16: kc.rep16, blobPad: kc.blobPad };

let found = 0;
for (const [kn, k] of Object.entries(kc)) {
  if (!k || k.length !== 16) continue;
  const ks = seedInitKey(k);
  for (const [ivn, iv] of Object.entries(ivs)) {
    for (const [mn, m] of Object.entries({ M_c2s, M_s2c })) {
      if (Buffer.compare(seedEncrypt(ks, Buffer.from(iv)), m) === 0) { console.log(`★ E(${kn}, ${ivn}) = ${mn}`); found++; }
      if (Buffer.compare(seedDecrypt(ks, Buffer.from(iv)), m) === 0) { console.log(`★ D(${kn}, ${ivn}) = ${mn}`); found++; }
    }
  }
  // M이 해시 그 자체인지
  for (const [mn, m] of Object.entries({ M_c2s, M_s2c })) {
    for (const h of ['md5', 'sha1', 'sha256']) {
      for (const [sn, src] of Object.entries({ hello, blob, b64str, sdat: sdat16, key: key16, xtea: xtea8, hello_blob: Buffer.concat([hello, blob]), blob_hello: Buffer.concat([blob, hello]) })) {
        const d = crypto.createHash(h).update(src).digest().subarray(0, 16);
        if (Buffer.compare(d, m) === 0) { console.log(`★ ${h}(${sn})[:16] = ${mn}`); found++; }
      }
    }
  }
}
// M과 hello/재료의 단순 XOR 관계
const xor = (a, b) => Buffer.from(a.map((x, i) => x ^ b[i % b.length]));
for (const [mn, m] of Object.entries({ M_c2s, M_s2c })) {
  for (const [sn, s] of Object.entries({ hello16: hello.subarray(0, 16), key16, sdat: sdat16, zeros, rep: rep })) {
    if (Buffer.compare(xor(m, s), M_c2s) === 0 || Buffer.compare(xor(m, s), M_s2c) === 0) console.log(`★ XOR 관계: ${mn}^${sn}`);
  }
}
console.log(found ? `발견 ${found}개` : '전부 탈락 — 세션키는 관측 바이트 밖 또는 파생 경로 비-SEED');
