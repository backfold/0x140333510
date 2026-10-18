// pkg-header-list.js — 헤더 영역: wstring#0 이후 구조 탐색
'use strict';
const fs = require('fs');
function charSum(s) { let x = 0; for (const c of s) x = (x + c.charCodeAt(0)) >>> 0; return x; }
function sx(b) { return b & 0x80 ? b - 256 : b; }
for (const f of ['texturescripts_00000.pkg', 'global_00000.pkg']) {
  const buf = fs.readFileSync(`H:\\SA_Analysis\\target\\pkg_samples\\${f}`);
  const n1 = (charSum(f) % 312) + 30;
  const masked = buf.subarray(0, n1);
  const key0 = Buffer.from(masked); for (let i = 0; i < n1; i++) key0[i] = (masked[i] >> 1) | (masked[i] & 0x80);
  const len = (buf.readUInt32LE(n1 + 1) ^ (key0[0] & 0x80 ? key0[0] - 256 : key0[0])) >>> 0;
  let s0 = '';
  for (let i = 0; i < len; i++) {
    const k = sx(key0[i % n1]);
    s0 += String.fromCharCode(buf.readUInt16LE(n1 + 5 + i * 2) ^ (k & 0xffff));
  }
  const after = n1 + 5 + len * 2;
  console.log(`\n=== ${f} n1=${n1} len0=${len} s0=${JSON.stringify(s0)} after=0x${after.toString(16)}`);
  console.log(`bytes [${after}..${after + 64}):`);
  for (let i = 0; i < 64; i += 16)
    console.log(`  +${i.toString(16).padStart(2, '0')}: ${buf.subarray(after + i, after + i + 16).toString('hex').match(/../g).join(' ')}`);
  // n1+1 앞의 1바이트(n1)도 출력
  console.log(`buf[n1-2..n1+6]: ${buf.subarray(n1 - 2, n1 + 7).toString('hex').match(/../g).join(' ')}`);
  // 시도: len2 = u32@after ^ sx(key0[len % n1]) 계속 마스크 인덱스
  const j = len % n1;
  for (const [lbl, l2] of [
    ['xor key0[len%n1]', (buf.readUInt32LE(after) ^ (key0[j] & 0x80 ? key0[j] - 256 : key0[j])) >>> 0],
    ['xor key0[0]', (buf.readUInt32LE(after) ^ (key0[0] & 0x80 ? key0[0] - 256 : key0[0])) >>> 0],
    ['raw', buf.readUInt32LE(after)],
  ]) {
    if (l2 < 0x40) {
      let s2 = '';
      for (let i = 0; i < l2 && after + 4 + i * 2 + 1 < buf.length; i++) {
        const k = sx(key0[(len + 1 + i) % n1]);
        s2 += String.fromCharCode(buf.readUInt16LE(after + 4 + i * 2) ^ (k & 0xffff));
      }
      console.log(`  len2(${lbl})=${l2} → ${JSON.stringify(s2)}`);
    } else {
      console.log(`  len2(${lbl})=0x${l2.toString(16)} (부적절)`);
    }
  }
}
