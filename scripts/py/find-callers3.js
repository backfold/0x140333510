// find-callers3.js — find-callers2의 exe 버전: suddenattack.exe .text e8/e9 스캔
import fs from 'fs';
const buf = fs.readFileSync('H:/SA_Analysis/target/suddenattack.exe');
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
const TARGETS = new Map();
const args = process.argv.slice(2);
if (args.length) {
  for (const a of args) { const m = a.match(/(.+)=((?:0x)?[0-9a-f]+)$/i); if (m) TARGETS.set(BigInt(m[2]), m[1]); }
} else {
  for (const [n, v] of Object.entries({ cipherStream: 0x14029aba0, snowLoadKey: 0x1402abee0, checkpoint: 0x1402ad020 })) TARGETS.set(BigInt(v), n);
}
const hits = [];
for (let i = 0; i < textSize - 5; i++) {
  const op = buf[textOff + i];
  if (op !== 0xe8 && op !== 0xe9) continue;
  const rel = BigInt(dv.getInt32(textOff + i + 1, true));
  const tgt = textVa + BigInt(i) + 5n + rel;
  const nm = TARGETS.get(tgt);
  if (nm) hits.push({ va: textVa + BigInt(i), op: op === 0xe8 ? 'call' : 'jmp', nm });
}
for (const h of hits) console.log(`0x${h.va.toString(16)}: ${h.op} ${h.nm}`);
console.log(`총 ${hits.length}개`);
