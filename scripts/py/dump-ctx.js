// dump-ctx.js — seedInit 호출부 주변 인자 셋업 덤프
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
// wrapper_332b40: seedInit@0x180332beb — 직전 0x60부터; wrapper_332ee0: seedInit@0x180332f68
for (const [name, callVa, pre] of [
  ['wrapper_332b40 → seedInit', 0x180332beb, 0xa0],
  ['wrapper_332ee0 → seedInit', 0x180332f68, 0x90],
  ['wrapper_332b40 전체 중간부', 0x180332c40, 0x100],
]) {
  const start = callVa - pre, off = va2off(start), bytes = buf.subarray(off, off + pre + 0x60);
  console.log(`\n=== ${name} (0x${start.toString(16)} ~ +${(pre + 0x60).toString(16)}) ===`);
  for (let i = 0; i < bytes.length; i += 16) {
    const row = bytes.subarray(i, i + 16);
    const mark = (start + i <= callVa && callVa < start + i + 16) ? ' <<CALL' : '';
    console.log(`0x${(start + i).toString(16)}: ${[...row].map(b => b.toString(16).padStart(2, '0')).join(' ')}${mark}`);
  }
}
