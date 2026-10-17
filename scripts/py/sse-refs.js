// sse-refs.js — 초기화 썽크 내 SSE rip 상대 로드(.rdata 소스) 타깃 산출
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
const ranges = [[0x18000cb90, 0x70], [0x18000cc00, 0x50], [0x18000cc50, 0x60]];
for (const [va, len] of ranges) {
  const off = va2off(va);
  console.log(`\n=== 썽크 0x${va.toString(16)} ===`);
  for (let i = off; i < off + len - 8; i++) {
    const cur = va + (i - off);
    let tgt = null, kind = '';
    if (buf[i] === 0x0f && (buf[i+1] === 0x28 || buf[i+1] === 0x10 || buf[i+1] === 0x11) && (buf[i+2] & 0xc7) === 0x05) {
      tgt = cur + 7 + dv.getInt32(i + 3, true); kind = 'sse' + buf[i+1].toString(16);
    } else if (buf[i] === 0xf2 && buf[i+1] === 0x0f && (buf[i+2] === 0x10 || buf[i+2] === 0x11) && (buf[i+3] & 0xc7) === 0x05) {
      tgt = cur + 8 + dv.getInt32(i + 4, true); kind = 'sse66f2';
    } else if (buf[i] === 0xf3 && buf[i+1] === 0x0f && (buf[i+2] === 0x10 || buf[i+2] === 0x11) && (buf[i+3] & 0xc7) === 0x05) {
      tgt = cur + 8 + dv.getInt32(i + 4, true); kind = 'ssef3';
    }
    if (tgt && tgt >= 0x181438000 && tgt < 0x1818c0000) {
      const to = va2off(tgt);
      const data = [...buf.subarray(to, to + 24)];
      console.log(`  0x${cur.toString(16)} ${kind} → 0x${tgt.toString(16)} : ${data.map(b => b.toString(16).padStart(2, '0')).join(' ')}  |${data.map(b => b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : '.').join('')}|`);
    }
  }
}
