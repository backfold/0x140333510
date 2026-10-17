// solve-ks.js — KS(key) 16바이트 유도 함수 역산
// 관측: KS(0xf4a5c72d)=a3520d83db7ac956e96247c74f7c43c5 (하트비트 #5 평문=0 가정)
//       KS(0xd2caf3d3)=5dacf37d31980c6417e338f32aaadadb
import fs from 'fs';
import crypto from 'crypto';
const XTEA_KEY = [0x64363531, 0x38376665, 0x33323039, 0x34636261];
function xteaEnc(v0, v1) {
  let sum = 0;
  for (let i = 0; i < 32; i++) {
    v0 = (v0 + (((((v1 << 4) ^ (v1 >>> 5)) + v1) ^ ((sum + XTEA_KEY[sum & 3]) >>> 0)))) >>> 0;
    v1 = (v1 + (((((v0 << 4) ^ (v0 >>> 5)) + v0) ^ (((sum + 0x9E3779B9) >>> 0) + XTEA_KEY[((sum + 0x9E3779B9) >>> 11) & 3])) >>> 0)) >>> 0;
    sum = (sum + 0x9E3779B9) >>> 0;
  }
  return [v0, v1];
}
function u32le(v) { const b = Buffer.alloc(4); b.writeUInt32LE(v >>> 0, 0); return b; }
function u32be(v) { const b = Buffer.alloc(4); b.writeUInt32BE(v >>> 0, 0); return b; }
function u64le(a, b) { const x = Buffer.alloc(8); x.writeUInt32LE(a >>> 0, 0); x.writeUInt32LE(b >>> 0, 4); return x; }
function xteaBlockBuf(a, b) { const [e0, e1] = xteaEnc(a, b); return u64le(e0, e1); }

const OBS = [
  { key: 0xf4a5c72d, ks: Buffer.from('a3520d83db7ac956e96247c74f7c43c5', 'hex') },
  { key: 0xd2caf3d3, ks: Buffer.from('5dacf37d31980c6417e338f32aaadadb', 'hex') },
];
function testAll(k) {
  const cands = new Map();
  cands.set('md5(le)', crypto.createHash('md5').update(u32le(k)).digest());
  cands.set('md5(be)', crypto.createHash('md5').update(u32be(k)).digest());
  cands.set('md5(hex)', crypto.createHash('md5').update(k.toString(16)).digest());
  cands.set('md5(dec)', crypto.createHash('md5').update(String(k)).digest());
  cands.set('sha1[:16]', crypto.createHash('sha1').update(u32le(k)).digest().subarray(0, 16));
  cands.set('sha256[:16]', crypto.createHash('sha256').update(u32le(k)).digest().subarray(0, 16));
  cands.set('xteaE(k,k)x2', Buffer.concat([xteaBlockBuf(k, k), xteaBlockBuf(k, k)]));
  cands.set('xteaE(k,0)+xteaE(0,k)', Buffer.concat([xteaBlockBuf(k, 0), xteaBlockBuf(0, k)]));
  cands.set('xteaE(k,0)x2', Buffer.concat([xteaBlockBuf(k, 0), xteaBlockBuf(k, 0)]));
  cands.set('xteaE(0,k)x2', Buffer.concat([xteaBlockBuf(0, k), xteaBlockBuf(0, k)]));
  cands.set('xteaE(k,1)+xteaE(k,2)', Buffer.concat([xteaBlockBuf(k, 1), xteaBlockBuf(k, 2)]));
  // rc4(le)
  class RC4 { constructor(key) { const S = [...Array(256).keys()]; let j = 0; for (let i = 0; i < 256; i++) { j = (j + S[i] + key[i % key.length]) & 0xff; [S[i], S[j]] = [S[j], S[i]]; } this.S = S; this.i = 0; this.j = 0; } next() { this.i = (this.i + 1) & 0xff; this.j = (this.j + this.S[this.i]) & 0xff; [this.S[this.i], this.S[this.j]] = [this.S[this.j], this.S[this.i]]; return this.S[(this.S[this.i] + this.S[this.j]) & 0xff]; } stream(n) { return Buffer.from(Array.from({ length: n }, () => this.next())); } }
  cands.set('rc4(le)', new RC4(u32le(k)).stream(16));
  cands.set('rc4(hexascii)', new RC4(Buffer.from(k.toString(16))).stream(16));
  return cands;
}
for (const { key, ks } of OBS) {
  console.log(`\nkey=0x${key.toString(16)} 목표 KS: ${ks.toString('hex')}`);
  for (const [name, buf] of testAll(key)) {
    const pre8 = buf.subarray(0, 8).toString('hex') === ks.subarray(0, 8).toString('hex');
    const full = buf.toString('hex') === ks.toString('hex');
    if (pre8 || full) console.log(`  ${full ? '*** 완전 일치 ***' : '앞 8B 일치'} ← ${name}: ${buf.toString('hex')}`);
  }
}
// 추가: 두 관측 KS의 XOR — 구조 단서
const x = Buffer.alloc(16);
for (let i = 0; i < 16; i++) x[i] = OBS[0].ks[i] ^ OBS[1].ks[i];
console.log('\nKS1^KS2 =', x.toString('hex'));
// KS가 4바이트 주기인지 (key LE 반복과의 관계)
const kle = u32le(OBS[0].key);
const xk = Buffer.alloc(16);
for (let i = 0; i < 16; i++) xk[i] = OBS[0].ks[i] ^ kle[i % 4];
console.log('KS1^key1le반복 =', xk.toString('hex'));
