// find-lea.js — 함수 범위에서 lea reg,[rbp+disp8] 위치 전수 스캔
import fs from 'fs';
const [vaStartArg, vaEndArg, dispArg] = process.argv.slice(2);
const vaStart = parseInt(vaStartArg, 16), vaEnd = parseInt(vaEndArg, 16);
const want = dispArg !== undefined ? parseInt(dispArg, 16) : null;
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
const o0 = va2off(vaStart), o1 = va2off(vaEnd);
const REGS = ['rax','rcx','rdx','rbx','rsp','rbp','rsi','rdi'];
let n = 0;
for (let i = o0; i < o1 - 8; i++) {
  const va = vaStart + (i - o0);
  const b = buf;
  // 48/4c 8d 45 disp8 / 4d disp8 (lea r,[rbp+disp8])
  for (const rex of [0x48, 0x4c, 0x49, 0x4d]) {
    if (b[i] === rex && b[i+1] === 0x8d) {
      const modrm = b[i+2];
      if ((modrm & 0xc7) !== 0x45) continue; // [rbp+disp8], reg
      const disp = b[i+3] << 24 >> 24;
      if (want !== null && disp !== want) continue;
      const reg = ((rex & 4) << 1) | ((modrm >> 3) & 7);
      console.log(`0x${va.toString(16)}: lea r${reg}${REGS[reg] ? '(' + REGS[reg] + ')' : ''}, [rbp${disp >= 0 ? '+' : ''}${disp.toString(16)}h]`);
      n++;
    }
  }
}
console.log(`총 ${n}개`);
