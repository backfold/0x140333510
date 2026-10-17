// find-funcs.js — .text에서 int3(cc) 패딩으로 함수 경계 탐색 (0x180333000~0x180334000)
import fs from 'fs';
const buf = fs.readFileSync('H:/SA_Analysis/target/cshell.dll');
const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
const e_lfanew = dv.getUint32(0x3c, true);
const numSections = dv.getUint16(e_lfanew + 6, true);
const optSize = dv.getUint16(e_lfanew + 20, true);
const imageBase64 = dv.getBigUint64(e_lfanew + 24 + 24, true);
const secOff = e_lfanew + 24 + optSize;
function va2off(va) {
  const rva = Number(BigInt(va) - imageBase64);
  for (let i = 0; i < numSections; i++) {
    const s = secOff + i * 40;
    const vsize = dv.getUint32(s + 8, true), vaddr = dv.getUint32(s + 12, true);
    const rawsize = dv.getUint32(s + 16, true), rawptr = dv.getUint32(s + 20, true);
    if (rva >= vaddr && rva < vaddr + Math.max(vsize, rawsize)) return rawptr + (rva - vaddr);
  }
  return null;
}
// 함수 시작 후보: cccc 패딩 직후의 첫 바이트
const START = 0x180330000, END = 0x180334400;
const off = va2off(START);
const len = END - START;
const region = buf.subarray(off, off + len);
const funcs = [];
for (let i = 2; i < len - 1; i++) {
  if (region[i] === 0xcc && region[i + 1] !== 0xcc) {
    // 패딩 끝 → 다음 함수 시작 (단, 코드 내부 cc는 드묾)
    const va = START + i + 1;
    const b = region[i + 1];
    // 전형적 프롤로그: 48 89 5c / 48 83 ec / 55 / 41 57 / 48 8b / 53 / 56 / 57 / 4c 8b dc
    if (/^(48 89|48 83|55 |41 5|48 8b|53 |56 |57 |4c 8b|40 |44 )/.test([b, region[i + 2], region[i + 3]].map(x => x.toString(16).padStart(2, '0')).join(' ').slice(0, 5)) || b === 0x55 || b === 0x53 || b === 0x56 || b === 0x57) funcs.push(va);
  }
}
console.log('함수 시작 후보 (cc패딩 직후):');
console.log(funcs.map(f => '0x' + f.toString(16)).join('\n'));
console.log(`\n총 ${funcs.length}개`);
// 0x180333510/0x180333252 직전 cc 위치도 확인
for (const probe of [0x180333252, 0x180333510, 0x1803333f0]) {
  const o = va2off(probe);
  console.log(`\n0x${probe.toString(16)} 주변: ${buf.subarray(o - 16, o + 16).toString('hex').match(/../g).join(' ')}`);
}
