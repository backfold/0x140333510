// scan-vtable.js — SEED 스위트 함수 VA의 8바이트 포인터 참조(가상테이블) 탐색 + .text lea rip 참조 스캔
import fs from 'fs';
const path = process.argv[2] || 'H:/SA_Analysis/target/cshell.dll';
const buf = fs.readFileSync(path);
const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
const e_lfanew = dv.getUint32(0x3c, true);
const numSections = dv.getUint16(e_lfanew + 6, true);
const optSize = dv.getUint16(e_lfanew + 20, true);
const imageBase64 = dv.getBigUint64(e_lfanew + 24 + 24, true);
const secOff = e_lfanew + 24 + optSize;
const secs = [];
for (let i = 0; i < numSections; i++) {
  const s = secOff + i * 40;
  const name = buf.toString('latin1', s, s + 8).replace(/\0+$/, '');
  secs.push({ name, vsize: dv.getUint32(s + 8, true), vaddr: dv.getUint32(s + 12, true), rawsize: dv.getUint32(s + 16, true), rawptr: dv.getUint32(s + 20, true) });
}
function off2va(off) {
  for (const s of secs) if (off >= s.rawptr && off < s.rawptr + s.rawsize) return Number(imageBase64) + s.vaddr + (off - s.rawptr);
  return null;
}
function va2off(va) {
  const rva = Number(BigInt(va) - imageBase64);
  for (const s of secs) if (rva >= s.vaddr && rva < s.vaddr + Math.max(s.vsize, s.rawsize)) return s.rawptr + (rva - s.vaddr);
  return null;
}
const text = secs.find(s => s.name === '.text');
console.log(`sections: ${secs.map(s => s.name).join(' ')}  imageBase=0x${imageBase64.toString(16)}`);

// 1) 함수 VA를 가리키는 8바이트 정렬 포인터 전체 스캔 (.rdata 등)
const TARGETS = {
  0x180330d10: 'seedBlockEnc', 0x180331bb0: 'seedBlockDec', 0x1803333f0: 'seedInit',
  0x180333250: 'methodCFB', 0x180332a50: 'helper32a50', 0x180333ff0: 'modeProc',
  0x180332b40: 'wrapperEnc', 0x180332ee0: 'wrapperDec',
  0x180334060: 'ctor060', 0x1803340d0: 'ctor0d0', 0x180334180: 'ctor180', 0x180334220: 'ctor220',
};
const hits = [];
for (let off = 0; off + 8 <= buf.length; off += 4) {
  const v = Number(dv.getBigUint64(off, true));
  if (TARGETS[v]) hits.push({ off, va: off2va(off), fn: TARGETS[v] });
}
console.log(`\n포인터 참조 ${hits.length}개:`);
for (const h of hits) console.log(`  ${h.fn} (@ptr 0x${h.va ? h.va.toString(16) : '??'} = file 0x${h.off.toString(16)})`);

// 2) 첫 히트 주변 ±0x60을 포인터 배열로 덤프 (vtable 후보)
for (const h of hits.slice(0, 3)) {
  const base = h.off - (h.off % 8) - 0x30;
  console.log(`\n--- ${h.fn} 포인터 주변 (file 0x${base.toString(16)}) ---`);
  for (let o = base; o < base + 0x70; o += 8) {
    const v = Number(dv.getBigUint64(o, true));
    const t = TARGETS[v] || (v >= 0x180001000 && v < 0x181438000 ? `code+0x${(v - 0x1801a0000).toString(16)}` : '');
    console.log(`  file 0x${o.toString(16)} va ${off2va(o) ? '0x' + off2va(o).toString(16) : '????'}: 0x${v.toString(16)} ${t}`);
  }
}

// 3) .text에서 lea reg,[rip+disp32] (48/4c 8d /0: modrm 00reg101) 로 위 포인터 VA들을 참조하는 코드
const ptrVAs = new Set(hits.map(h => h.va).filter(Boolean));
const leaHits = [];
const tb = text.rawptr, te = text.rawptr + text.rawsize;
for (let i = tb; i < te - 7; i++) {
  // REX.W(48/4c/49/4d) 8d modrm(00 r 101) disp32
  const b0 = buf[i];
  if (b0 !== 0x48 && b0 !== 0x4c && b0 !== 0x49 && b0 !== 0x4d) continue;
  if (buf[i + 1] !== 0x8d) continue;
  const modrm = buf[i + 2];
  if ((modrm & 0xc7) !== 0x05) continue;
  const disp = dv.getInt32(i + 3, true);
  const va = off2va(i);
  const target = va + 7 + disp;
  if (ptrVAs.has(target)) leaHits.push({ va, target, reg: (modrm >> 3) & 7 });
}
console.log(`\nlea 참조 ${leaHits.length}개:`);
for (const l of leaHits) console.log(`  0x${l.va.toString(16)}: lea r${l.reg}, [0x${l.target.toString(16)}]`);
