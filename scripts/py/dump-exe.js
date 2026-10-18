// dump-exe.js — suddenattack.exe .text 영역 VA 헥스덤프 + e8/e9 콜 주석 (dump-range가 exe에서 va2off 실패해 긴급 대체)
import fs from 'fs';
const buf = fs.readFileSync('H:/SA_Analysis/target/suddenattack.exe');
const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
const e_lfanew = dv.getUint32(0x3c, true);
const numSections = dv.getUint16(e_lfanew + 6, true);
const optSize = dv.getUint16(e_lfanew + 20, true);
const imageBase64 = dv.getBigUint64(e_lfanew + 24 + 24, true);
const secOff = e_lfanew + 24 + optSize;
const secs = [];
for (let i = 0; i < numSections; i++) {
  const s = secOff + i * 40;
  secs.push({
    name: buf.subarray(s, s + 8).toString('latin1').replace(/\0+$/, ''),
    va: imageBase64 + BigInt(dv.getUint32(s + 12, true)),
    vsize: dv.getUint32(s + 8, true),
    off: dv.getUint32(s + 20, true),
    rsize: dv.getUint32(s + 16, true),
  });
}
const va = BigInt('0x' + process.argv[2]);
const len = parseInt(process.argv[3], 16);
const sec = secs.find(s => va >= s.va && va < s.va + BigInt(s.vsize));
if (!sec) { console.log('VA가 어떤 섹션에도 없음:', secs.map(s => `${s.name}@${s.va.toString(16)}+${s.vsize.toString(16)}`).join(' ')); process.exit(1); }
const start = Number(va - sec.va) + sec.off;
console.log(`섹션 ${sec.name} (va=${sec.va.toString(16)} off=${sec.off.toString(16)}) — 0x${va.toString(16)} → 파일오프셋 0x${start.toString(16)}`);
for (let i = 0; i < len; i += 16) {
  const row = [];
  let ann = '';
  for (let j = 0; j < 16 && i + j < len; j++) {
    const b = buf[start + i + j];
    row.push(b.toString(16).padStart(2, '0'));
    if (b === 0xe8 || b === 0xe9) {
      const rel = dv.getInt32(start + i + j + 1, true);
      if (i + j + 5 <= len) ann += ` [${i + j}:${b === 0xe8 ? 'call' : 'jmp'} 0x${(va + BigInt(i + j + 5) + BigInt(rel)).toString(16)}]`;
    }
  }
  console.log(`${(va + BigInt(i)).toString(16)}  ${row.join(' ').padEnd(47)}${ann}`);
}
