// dump-callsite.js — 외부 호출부(0x1801aa456, 0x18018ae96) 직전 컨텍스트
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
for (const [name, callVa, pre] of [
  ['0x1801a9fa0 → wrapper_332ee0 호출부', 0x1801aa456, 0xb0],
  ['0x180189760 → ctor_3340d0 호출부', 0x18018ae96, 0xb0],
]) {
  const start = callVa - pre, off = va2off(start), bytes = buf.subarray(off, off + pre + 0x30);
  console.log(`\n=== ${name} (호출 0x${callVa.toString(16)}, 직전 ${pre}B) ===`);
  for (let i = 0; i < bytes.length; i += 16) {
    const row = bytes.subarray(i, i + 16);
    const mark = (start + i <= callVa && callVa < start + i + 16) ? ' <<CALL' : '';
    console.log(`0x${(start + i).toString(16)}: ${[...row].map(b => b.toString(16).padStart(2, '0')).join(' ')}${mark}`);
  }
}
