// pkg-gap-dump.js — pkg 파일 내 미해석 영역 덤프: n2 정크, 인덱스 직전 8바이트,
// 파일 끝 400B 슬랙. 목적: pkg+0x70/0x74/0x78/0x7c 후보 값 탐색.
'use strict';
const fs = require('fs');
function charSum(s) { let x = 0; for (const c of s) x = (x + c.charCodeAt(0)) >>> 0; return x; }
function parse(file, path) {
  const buf = fs.readFileSync(file);
  const n1 = (charSum(path) % 312) + 30, n2 = ((charSum(path) * 3) % 212) + 33;
  const masked = buf.subarray(0, n1);
  const key0 = Buffer.from(masked); for (let i = 0; i < n1; i++) key0[i] = (masked[i] >> 1) | (masked[i] & 0x80);
  const len = (buf.readUInt32LE(n1 + 1) ^ (key0[0] & 0x80 ? key0[0] - 256 : key0[0])) >>> 0;
  let headerStr = '';
  for (let i = 0; i < len; i++) {
    const k = key0[i % n1] & 0x80 ? key0[i % n1] - 256 : key0[i % n1];
    headerStr += String.fromCharCode(buf.readUInt16LE(n1 + 5 + i * 2) ^ (k & 0xffff));
  }
  const dataStart = n1 + 5 + len * 2;
  const indexStart = dataStart + n2 + 8;
  return { buf, n1, n2, len, headerStr, dataStart, indexStart };
}
function hex(buf, base, off, n) {
  for (let r = 0; r < n; r += 16) {
    const row = buf.subarray(off + r, off + r + 16);
    let h = '', a = '';
    for (const b of row) { h += b.toString(16).padStart(2, '0') + ' '; a += (b >= 0x20 && b < 0x7f) ? String.fromCharCode(b) : '.'; }
    console.log(`  ${(base + off + r).toString(16).padStart(8, '0')}  ${h.padEnd(48)} ${a}`);
  }
}
const file = process.argv[2], path = process.argv[3] || file.replace(/.*[\\/]/, '');
const { buf, n1, n2, len, headerStr, dataStart, indexStart } = parse(file, path);
console.log(`=== ${path} (size 0x${buf.length.toString(16)}) ===`);
console.log(`n1=${n1} n2=${n2} len=${len} dataStart=0x${dataStart.toString(16)} indexStart=0x${indexStart.toString(16)}`);
console.log(`headerStr (${len}자): [${headerStr}]`);
console.log(`\n-- 정크+갭 dataStart..indexStart (n2+8=${n2 + 8}바이트):`);
hex(buf, 0, dataStart, n2 + 8);
console.log(`\n-- 인덱스 첫 64바이트 (암호화 상태):`);
hex(buf, 0, indexStart, 64);
const tail = 400;
console.log(`\n-- 파일 끝 ${tail}바이트 (0x${(buf.length - tail).toString(16)}..):`);
hex(buf, 0, buf.length - tail, tail);
