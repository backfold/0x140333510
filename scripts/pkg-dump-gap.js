// pkg-dump-gap.js — 헤더 wstring과 인덱스 사이 (n2+8) 바이트 영역 덤프
'use strict';
const fs = require('fs');
function charSum(s) { let x = 0; for (const c of s) x = (x + c.charCodeAt(0)) >>> 0; return x; }
for (const f of ['texturescripts_00000.pkg', 'global_00000.pkg']) {
  const buf = fs.readFileSync(`H:\\SA_Analysis\\target\\pkg_samples\\${f}`);
  const n1 = (charSum(f) % 312) + 30, n2 = ((charSum(f) * 3) % 212) + 33;
  const masked = buf.subarray(0, n1);
  const key0 = Buffer.from(masked); for (let i = 0; i < n1; i++) key0[i] = (masked[i] >> 1) | (masked[i] & 0x80);
  const len = (buf.readUInt32LE(n1 + 1) ^ (key0[0] & 0x80 ? key0[0] - 256 : key0[0])) >>> 0;
  let headerStr = '';
  for (let i = 0; i < len; i++) {
    const k = key0[i % n1] & 0x80 ? key0[i % n1] - 256 : key0[i % n1];
    headerStr += String.fromCharCode(buf.readUInt16LE(n1 + 5 + i * 2) ^ (k & 0xffff));
  }
  const dataStart = n1 + 5 + len * 2;
  const gapLen = n2 + 8;
  const gap = buf.subarray(dataStart, dataStart + gapLen);
  console.log(`\n=== ${f} n1=${n1} len=${len} n2=${n2} header=${JSON.stringify(headerStr)}`);
  console.log(`gap [0x${dataStart.toString(16)}..+${gapLen}] hex:`);
  for (let i = 0; i < gapLen; i += 16) {
    console.log(`  +${i.toString(16).padStart(3, '0')}: ${gap.subarray(i, i + 16).toString('hex').match(/../g).join(' ')}`);
  }
  // 해석 시도 1: UTF-16 wchars (key0 마스크)
  let s1 = '';
  for (let i = 0; i * 2 + 1 < gapLen; i++) {
    const k = key0[i % n1] & 0x80 ? key0[i % n1] - 256 : key0[i % n1];
    s1 += String.fromCharCode(gap.readUInt16LE(i * 2) ^ (k & 0xffff));
  }
  console.log(`  as key0-masked wchars: ${JSON.stringify(s1)}`);
  // 해석 2: 그냥 wchars
  let s2 = '';
  for (let i = 0; i * 2 + 1 < gapLen; i++) s2 += String.fromCharCode(gap.readUInt16LE(i * 2));
  console.log(`  as raw wchars: ${JSON.stringify(s2)}`);
  // 해석 3: ASCII
  console.log(`  as latin1: ${JSON.stringify(gap.toString('latin1'))}`);
  // 해석 4: 첫 4바이트 = sl(문자열 길이) + wchars?
  const sl = gap.readUInt32LE(0);
  if (sl > 0 && sl < 0x40 && 4 + sl * 2 <= gapLen) {
    let s4 = '';
    for (let i = 0; i < sl; i++) s4 += String.fromCharCode(gap.readUInt16LE(4 + i * 2));
    console.log(`  [len32=${sl}] wchars: ${JSON.stringify(s4)}`);
  }
  // 해석 5: n1+5+len*2+? — 8바이트 오프셋 후 len32
  const sl2 = gap.readUInt32LE(8);
  if (sl2 > 0 && sl2 < 0x40 && 12 + sl2 * 2 <= gapLen) {
    let s5 = '';
    for (let i = 0; i < sl2; i++) s5 += String.fromCharCode(gap.readUInt16LE(12 + i * 2));
    console.log(`  [+8 len32=${sl2}] wchars: ${JSON.stringify(s5)}`);
  }
}
