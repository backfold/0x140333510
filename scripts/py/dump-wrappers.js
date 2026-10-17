// dump-wrappers.js — 0x180333250 전체(체인 스텝 확인) + 호출 타깃 계산
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
const va = 0x180333250, off = va2off(va);
const bytes = buf.subarray(off, off + 480);
// 호출 타깃 자동 검출: e8 rel32
console.log('=== 0x180333250 hex (480B) ===');
for (let i = 0; i < bytes.length; i += 16) {
  const row = bytes.subarray(i, i + 16);
  console.log(`0x${(va + i).toString(16)}: ${[...row].map(b => b.toString(16).padStart(2, '0')).join(' ')}`);
}
console.log('\n=== 내부 call 타깃 ===');
for (let i = 0; i < bytes.length - 4; i++) {
  if (bytes[i] === 0xe8) {
    const rel = dv.getInt32(off + i + 1, true);
    const tgt = va + i + 5 + rel;
    if (tgt > 0x180000000 && tgt < 0x182000000) console.log(`0x${(va + i).toString(16)}: call 0x${tgt.toString(16)}`);
  }
  // ff 15 rip-relative call
  if (bytes[i] === 0xff && bytes[i + 1] === 0x15) {
    const rel = dv.getInt32(off + i + 2, true);
    console.log(`0x${(va + i).toString(16)}: call [rip+0x${rel.toString(16)}] → ptr@0x${(va + i + 6 + rel).toString(16)}`);
  }
}
