// scan-rip-refs.js — .text 전체에서 특정 VA 범위를 가리키는 rip 상대 참조 전수 스캔
import fs from 'fs';
const [loArg, hiArg] = process.argv.slice(2);
const LO = parseInt(loArg, 16), HI = parseInt(hiArg, 16);
const buf = fs.readFileSync('H:/SA_Analysis/target/cshell.dll');
const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
const e_lfanew = dv.getUint32(0x3c, true);
const numSections = dv.getUint16(e_lfanew + 6, true);
const optSize = dv.getUint16(e_lfanew + 20, true);
const imageBase64 = dv.getBigUint64(e_lfanew + 24 + 24, true);
const secOff = e_lfanew + 24 + optSize;
let text = null;
for (let i = 0; i < numSections; i++) {
  const s = secOff + i * 40;
  const name = buf.toString('latin1', s, s + 8).replace(/\0+$/, '');
  if (name === '.text') text = { vsize: dv.getUint32(s + 8, true), vaddr: dv.getUint32(s + 12, true), rawsize: dv.getUint32(s + 16, true), rawptr: dv.getUint32(s + 20, true) };
}
const textVa = Number(imageBase64) + text.vaddr;
const hits = [];
const tb = text.rawptr, te = text.rawptr + text.rawsize;
for (let i = tb; i < te - 8; i++) {
  const b0 = buf[i];
  if (b0 !== 0x48 && b0 !== 0x4c && b0 !== 0x49 && b0 !== 0x4d) continue;
  const op = buf[i + 1];
  if (op !== 0x8d && op !== 0x8b && op !== 0x89 && op !== 0x83 && op !== 0x39 && op !== 0x3b && op !== 0xff && op !== 0x63) continue;
  const modrm = buf[i + 2];
  if ((modrm & 0xc7) !== 0x05) continue;
  const disp = dv.getInt32(i + 3, true);
  const va = textVa + (i - tb);
  const tgt = va + 7 + disp;
  if (tgt >= LO && tgt <= HI) hits.push({ va, tgt, op, reg: (modrm >> 3) & 7 });
}
const OPN = { 0x8d: 'lea', 0x8b: 'mov-load', 0x89: 'mov-store', 0x83: 'cmp/imm', 0x39: 'cmp', 0x3b: 'cmp', 0xff: 'indirect', 0x63: 'movsxd' };
for (const h of hits) console.log(`0x${h.va.toString(16)}: ${OPN[h.op]} → 0x${h.tgt.toString(16)} reg=${h.reg}`);
console.log(`총 ${hits.length}개`);
