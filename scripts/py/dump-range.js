// dump-range.js — 임의 VA 범위 헥스덤프 + e8/e9 rel32 콜 주석
import fs from 'fs';
const [vaStart, lenArg] = process.argv.slice(2);
const len = parseInt(lenArg || '0x200', 16);
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
const start = parseInt(vaStart, 16);
const off = va2off(start);
const KNOWN = { 0x180330d10: 'seedBlockEnc', 0x180331bb0: 'seedBlockDec', 0x1803333f0: 'seedInit', 0x180333250: 'methodCFB', 0x180332a50: 'helper32a50', 0x180333ff0: 'modeProc', 0x180332b40: 'wrapperEnc', 0x180332ee0: 'wrapperDec', 0x1803340d0: 'ctor0d0', 0x180334180: 'ctor180', 0x180334220: 'ctor220', 0x18137536e: 'tail37536e', 0x1801aac80: 'stage2_1aac80' };
for (let i = 0; i < len; i += 16) {
  const va = start + i;
  const bytes = [...buf.subarray(off + i, off + i + 16)];
  const hex = bytes.map(b => b.toString(16).padStart(2, '0')).join(' ').padEnd(47);
  const asc = bytes.map(b => (b >= 0x20 && b < 0x7f) ? String.fromCharCode(b) : '.').join('');
  let note = '';
  for (let k = 0; k < 15; k++) {
    const b = bytes[k];
    if (b === 0xe8 || b === 0xe9) {
      const rel = dv.getInt32(off + i + k + 1, true);
      const tgt = va + k + 5 + rel;
      if (tgt >= 0x180001000 && tgt < 0x1818c0000) note += `  <${b === 0xe8 ? 'call' : 'jmp'} 0x${tgt.toString(16)}${KNOWN[tgt] ? '=' + KNOWN[tgt] : ''} @+${k}>`;
      continue;
    }
    // rip 상대 메모리 연산: REX.W(48/4c/49/4d) opcode modrm=00rrm101 disp32
    if ((b === 0x48 || b === 0x4c || b === 0x49 || b === 0x4d) && k + 7 < 16) {
      const op = bytes[k + 1], modrm = bytes[k + 2];
      if ((modrm & 0xc7) === 0x05) {
        const rel = dv.getInt32(off + i + k + 3, true);
        const tgt = va + k + 7 + rel;
        const OPS = { 0x8d: 'lea', 0x8b: 'mov', 0x89: 'mov', 0x3d: undefined, 0x39: 'cmp', 0x83: 'cmpq', 0x81: 'cmpq', 0x0f: undefined, 0xff: 'call[]', 0x63: 'movsxd', 0x03: 'add', 0x2b: 'sub' };
        if (op === 0x83 && (modrm >> 3 & 7) === 7) note += `  <cmp qword[0x${tgt.toString(16)}],imm8 @+${k}>`;
        else if (op === 0x8d) note += `  <lea r${(modrm >> 3) & 7},[0x${tgt.toString(16)}] @+${k}>`;
        else if (op === 0x8b || op === 0x89) note += `  <mov [rip],r → 0x${tgt.toString(16)} @+${k}>`;
        else if (op === 0xff && (modrm >> 3 & 7) === 2) note += `  <call qword[0x${tgt.toString(16)}] @+${k}>`;
        else note += `  <rip-op@0x${tgt.toString(16)} @+${k}>`;
      }
    }
  }
  console.log(`${va.toString(16)}  ${hex}  ${asc}${note}`);
}
