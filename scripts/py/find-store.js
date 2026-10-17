// find-store.js — 함수 범위에서 [rbp+disp] 저장 명패턴 스캔 (키 초기화 위치 탐색)
import fs from 'fs';
const [vaStartArg, vaEndArg] = process.argv.slice(2);
const vaStart = parseInt(vaStartArg, 16), vaEnd = parseInt(vaEndArg, 16);
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
// rbp+8 저장 후보: mov [rbp+8],reg = REX? 89 45 08 / 4d 08 ; imm 저장 = c7 45 08 imm32 / 48 c7 45 08 imm32 ; movabs 후 저장도 있음
const pats = [];
for (let i = o0; i < o1 - 8; i++) {
  const va = vaStart + (i - o0);
  const b = buf;
  if (b[i] === 0x89 && b[i+1] === 0x45 && b[i+2] === 0x08) pats.push({ va, txt: 'mov [rbp+8],eax' });
  else if (b[i] === 0x89 && b[i+1] === 0x4d && b[i+2] === 0x08) pats.push({ va, txt: 'mov [rbp+8],ecx' });
  else if (b[i] === 0x48 && b[i+1] === 0x89 && b[i+2] === 0x45 && b[i+3] === 0x08) pats.push({ va, txt: 'mov [rbp+8],rax' });
  else if (b[i] === 0x48 && b[i+1] === 0x89 && b[i+2] === 0x4d && b[i+3] === 0x08) pats.push({ va, txt: 'mov [rbp+8],rcx' });
  else if (b[i] === 0x4c && b[i+1] === 0x89 && b[i+2] === 0x45 && b[i+3] === 0x08) pats.push({ va, txt: 'mov [rbp+8],r8' });
  else if (b[i] === 0x4c && b[i+1] === 0x89 && b[i+2] === 0x4d && b[i+3] === 0x08) pats.push({ va, txt: 'mov [rbp+8],r9' });
  else if (b[i] === 0xc7 && b[i+1] === 0x45 && b[i+2] === 0x08) pats.push({ va, txt: `mov dword[rbp+8],${dv.getUint32(i+2,true).toString(16)}` });
  else if (b[i] === 0x48 && b[i+1] === 0xc7 && b[i+2] === 0x45 && b[i+3] === 0x08) pats.push({ va, txt: `mov qword[rbp+8],${dv.getUint32(i+4,true).toString(16)}` });
  else if (b[i] === 0x48 && b[i+1] === 0xb8) pats.push({ va, txt: `movabs rax,${dv.getBigUint64(i+2,true).toString(16)}` });
  else if (b[i] === 0x48 && b[i+1] === 0xb9) pats.push({ va, txt: `movabs rcx,${dv.getBigUint64(i+2,true).toString(16)}` });
}
for (const p of pats) console.log(`0x${p.va.toString(16)}: ${p.txt}`);
console.log(`총 ${pats.length}개`);
