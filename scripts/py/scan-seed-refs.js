// scan-seed-refs.js — SEED SS 테이블 변위(LE) 참조 위치 스캔 + 함수 귀속
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
function off2va(off) {
  const rva0 = null;
  for (let i = 0; i < numSections; i++) {
    const s = secOff + i * 40;
    const vsize = dv.getUint32(s + 8, true), vaddr = dv.getUint32(s + 12, true);
    const rawsize = dv.getUint32(s + 16, true), rawptr = dv.getUint32(s + 20, true);
    if (off >= rawptr && off < rawptr + rawsize) return { va: Number(imageBase64) + vaddr + (off - rawptr), sec: buf.toString('ascii', s, s + 8).replace(/\0+$/, '') };
  }
  return null;
}
// .text 전체에서 4개 테이블 VA의 LE 32bit 인코딩 검색 (RIP상대는 변위라 절대VA 안 나옴 → 변위 형태만)
// 전략: seedInit 내부에서 봤던 형태 = [base+idx*4+0x181497xxx] → 변위 하위 3바이트 패턴 (b0 73 49 / b0 6f 49 / b0 6b 49 / b0 67 49)
const PATTERNS = [
  ['SS3(0x1814973b0)', Buffer.from('b0734901', 'hex').subarray(0, 4)],
  ['SS2(0x181496fb0)', Buffer.from('b06f4901', 'hex').subarray(0, 4)],
  ['SS1(0x181496bb0)', Buffer.from('b06b4901', 'hex').subarray(0, 4)],
  ['SS0(0x1814967b0)', Buffer.from('b0674901', 'hex').subarray(0, 4)],
];
const FUNCSTARTS = [0x180332a50, 0x180332b40, 0x180332ee0, 0x180333250, 0x1803333f0, 0x180333ff0, 0x180334060, 0x1803340d0, 0x180334180, 0x180334220, 0x1803342e0];
for (const [name, pat] of PATTERNS) {
  const hits = [];
  let pos = 0;
  // .text 범위 스캔: 0x180001000~0x181437000 (rva 0x1000~0x1437000)
  const textOff = va2off(0x180001000), textEnd = va2off(0x181437000);
  const text = buf.subarray(textOff, textEnd);
  while ((pos = text.indexOf(pat, pos)) >= 0) {
    const m = off2va(textOff + pos);
    if (m) hits.push(m.va);
    pos++;
  }
  console.log(`${name}: ${hits.length}개 히트`);
  for (const h of hits) {
    let f = FUNCSTARTS.filter(s => s <= h).pop();
    console.log(`  0x${h.toString(16)} ${f ? `(함수 0x${f.toString(16)} 내부)` : ''}`);
  }
}
// 전체 .text에서 SS0 하위패턴이 다른 곳(비seedInit)에도 있는지 광역 스캔은 변위 오프셋이 달라 감지 불가 —
// 대신 함수 후보들 내부에 'G패턴'(4연속 테이블 XOR)이 있는지 변위 무관히: movzx+xor+lea 체인은 수동.
// 추가: 함수 후보별 크기와 앞 32바이트
for (const f of FUNCSTARTS) {
  const o = va2off(f);
  console.log(`0x${f.toString(16)}: ${buf.subarray(o, o + 24).toString('hex').match(/../g).join(' ')}`);
}
