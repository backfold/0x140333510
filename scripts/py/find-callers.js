// find-callers.js — .text 전체 e8/e9 rel32 스캔으로 SEED 스위트 호출부 탐색 (Ghidra xrefs 대체)
import fs from 'fs';
const buf = fs.readFileSync('H:/SA_Analysis/target/cshell.dll');
const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
const e_lfanew = dv.getUint32(0x3c, true);
const numSections = dv.getUint16(e_lfanew + 6, true);
const optSize = dv.getUint16(e_lfanew + 20, true);
const imageBase64 = dv.getBigUint64(e_lfanew + 24 + 24, true);
const secOff = e_lfanew + 24 + optSize;
let textOff = null, textVa = 0n, textSize = 0;
for (let i = 0; i < numSections; i++) {
  const s = secOff + i * 40;
  const name = buf.subarray(s, s + 8).toString('latin1').replace(/\0+$/, '');
  if (name === '.text') { textOff = dv.getUint32(s + 20, true); textVa = imageBase64 + BigInt(dv.getUint32(s + 12, true)); textSize = dv.getUint32(s + 16, true); }
}
console.log(`.text: VA=0x${textVa.toString(16)} size=0x${textSize.toString(16)} off=0x${textOff.toString(16)}`);
const TARGETS = new Map([
  [0x180330d10n, 'seedBlockEnc'],
  [0x180331bb0n, 'seedBlockDec'],
  [0x180332a50n, 'helper_332a50'],
  [0x180332b40n, 'wrapper_332b40'],
  [0x180332ee0n, 'wrapper_332ee0'],
  [0x180333250n, 'method_333250'],
  [0x1803333f0n, 'seedInit'],
  [0x180333ff0n, 'modeProc_333ff0'],
  [0x180334060n, 'ctor_334060'],
  [0x1803340d0n, 'ctor_3340d0'],
  [0x180334180n, 'ctor_334180'],
  [0x180334220n, 'ctor_334220'],
]);
const hits = [];
for (let i = 0; i < textSize - 5; i++) {
  const op = buf[textOff + i];
  if (op !== 0xe8 && op !== 0xe9) continue;
  const rel = BigInt(dv.getInt32(textOff + i + 1, true));
  const tgt = textVa + BigInt(i) + 5n + rel;
  const nm = TARGETS.get(tgt);
  if (nm) hits.push({ va: textVa + BigInt(i), op: op === 0xe8 ? 'call' : 'jmp', tgt, nm });
}
for (const h of hits) console.log(`0x${h.va.toString(16)}: ${h.op} ${h.nm} (0x${h.tgt.toString(16)})`);
console.log(`\n총 ${hits.length}개`);
// 호출부 주소 → 같은 페이지군으로 클러스터 (함수 근처 cc 패딩 역방향 탐색은 생략, 주소대역만)
const byRegion = {};
for (const h of hits) { const r = '0x' + (h.va & ~0xfffn).toString(16); (byRegion[r] = byRegion[r] || []).push(h); }
console.log('\n지역별:', Object.entries(byRegion).map(([r, v]) => `${r}: ${v.length} (${[...new Set(v.map(x => x.nm))].join(',')})`).join('\n'));
