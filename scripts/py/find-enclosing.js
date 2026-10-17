// find-enclosing.js — 주어진 주소를 포함하는 함수 시작: 직전 cc패딩 역스캔
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
for (const probe of [0x1801aa456, 0x18018ae96]) {
  const off = va2off(probe);
  // 역방향: cc 연속 2개 이상 직후 첫 바이트 = 함수 시작 후보
  let i = off;
  const found = [];
  while (off - i < 0x3000) {
    if (buf[i] === 0xcc && buf[i - 1] === 0xcc) {
      // 앞쪽 패딩 확인 후 다음 non-cc
      let j = i;
      while (buf[j] === 0xcc) j++;
      found.push({ start: probe - (off - j), gap: off - j });
      if (found.length >= 3) break;
      i = j;
    }
    i--;
  }
  console.log(`0x${probe.toString(16)} 인클로징 후보:`);
  for (const f of found) {
    const b = buf.subarray(va2off(f.start), va2off(f.start) + 12);
    console.log(`  시작 0x${f.start.toString(16)} (호출부에서 -0x${f.gap.toString(16)}B): ${[...b].map(x => x.toString(16).padStart(2, '0')).join(' ')}`);
  }
}
