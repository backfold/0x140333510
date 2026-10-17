// scan-vm-refs.js — .rdata VM 바이트코드 영역에서 코드-범위 VA 피연산자 스캔 (오프셋 보정 수정)
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
// 검증: va2off(0x18188be20) 주변이 위 hexdump와 동일한지
const chk = va2off(0x18188be20);
console.log(`va2off(0x18188be20)=0x${chk.toString(16)} 검증바이트: ${[...buf.subarray(chk, chk + 8)].map(x => x.toString(16).padStart(2, '0')).join(' ')}`);
const LO = 0x180001000, HI = 0x181438000;
const startVa = 0x181880000, regionLen = 0x30000; // 0x181880000~0x1818b0000 (.rdata 끝 0x1818bb158 직전)
const off = va2off(startVa);
const hits = [];
for (let i = 0; i < regionLen - 4; i++) {
  const v = dv.getUint32(off + i, true);
  if (v >= LO && v <= HI) hits.push({ va: startVa + i, target: v, aligned: i % 4 === 0 });
}
console.log(`후보 ${hits.length}개 (정렬 ${hits.filter(h => h.aligned).length})`);
const al = hits.filter(h => h.aligned);
const byT = {};
for (const h of al) (byT[h.target] = byT[h.target] || []).push(h.va);
const KNOWN = { 0x180330d10: 'seedBlockEnc', 0x180331bb0: 'seedBlockDec', 0x1803333f0: 'seedInit', 0x180333250: 'method333250', 0x180332b40: 'wrapperEnc', 0x180332ee0: 'wrapperDec', 0x181272bc0: 'cksum', 0x181272e40: 'v1enc', 0x181272fa0: 'v1dec', 0x180d5ef00: 'xteaEnc', 0x180d5e9c0: 'xteaDec', 0x1803340d0: 'ctor', 0x180333ff0: 'modeProc' };
console.log('알려진 함수 참조:');
for (const [k, n] of Object.entries(KNOWN)) {
  const c = hits.filter(h => h.target === +k);
  console.log(`  ${n}: ${c.length}회${c.length ? ' @ ' + c.slice(0, 5).map(h => '0x' + h.va.toString(16)).join(',') : ''}`);
}
const ents = Object.entries(byT).sort((a, b) => b[1].length - a[1].length);
console.log('\n정렬 타깃 상위 30:');
for (const [t, v] of ents.slice(0, 30)) console.log(`  0x${(+t).toString(16)}: ${v.length}회 첫@0x${v[0].toString(16)}`);
