// dump-vtables.js — cshell.dll .rdata 의 CStreamCryptor vftable 군 직접 덤프 (VA→파일 오프셋)
import fs from 'fs';
const path = 'H:/SA_Analysis/target/cshell.dll';
const buf = fs.readFileSync(path);
const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);

// PE 헤더
const e_lfanew = dv.getUint32(0x3c, true);
const numSections = dv.getUint16(e_lfanew + 6, true);
const optSize = dv.getUint16(e_lfanew + 20, true);
const imageBase64 = dv.getBigUint64(e_lfanew + 24 + 24, true);
const secOff = e_lfanew + 24 + optSize;
function va2off(va) {
  const rva = Number(BigInt(va) - imageBase64);
  for (let i = 0; i < numSections; i++) {
    const s = secOff + i * 40;
    const name = buf.toString('ascii', s, s + 8).replace(/\0+$/, '');
    const vsize = dv.getUint32(s + 8, true), vaddr = dv.getUint32(s + 12, true);
    const rawsize = dv.getUint32(s + 16, true), rawptr = dv.getUint32(s + 20, true);
    if (rva >= vaddr && rva < vaddr + Math.max(vsize, rawsize)) return { off: rawptr + (rva - vaddr), name };
  }
  return null;
}
console.log(`ImageBase=0x${imageBase64.toString(16)}, 섹션 ${numSections}개`);

// 0x181658e00 ~ 0x181659300 u64 포인터 덤프 (vftable 군)
const start = 0x181658e00n, end = 0x181659300n;
let line = '', lineStart = 0n;
const marked = new Set(['181658f58', '181658f98', '181658fd8']);
for (let va = start; va < end; va += 8n) {
  const m = va2off(va);
  if (!m) continue;
  const v = dv.getBigUint64(m.off, true);
  const tag = marked.has(va.toString(16)) ? '  <=== 기존 식별 vftable' : '';
  const vs = v === 0n ? '0' : `0x${v.toString(16)}`;
  const inCode = v >= 0x180001000n && v < 0x183000000n;
  console.log(`0x${va.toString(16)}: ${vs.padStart(12)}${inCode ? '' : ''}${tag}`);
}
