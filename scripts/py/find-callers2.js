// find-callers2.js — 임의 타깃 집합에 대한 e8/e9 호출부 스캔 (인자: name=va ...; 없으면 기본 XTEA/v1 클러스터)
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
const TARGETS = new Map();
const args = process.argv.slice(2);
if (args.length) {
  for (const a of args) { const m = a.match(/(.+)=((?:0x)?[0-9a-f]+)$/i); if (m) TARGETS.set(BigInt(m[2]), m[1]); }
} else {
  for (const [n, v] of Object.entries({ xteaEnc: 0x180d5ef00, xteaDec: 0x180d5e9c0, cksum_181272bc0: 0x181272bc0, v1enc_181272e40: 0x181272e40, v1dec_181272fa0: 0x181272fa0, wrapperEnc: 0x180332b40, wrapperDec: 0x180332ee0, initUI_3342e0: 0x1803342e0, init2_b2eaf0: 0x180b2eaf0, d4cf20: 0x180d4cf20 })) TARGETS.set(BigInt(v), n);
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
const byNm = {};
for (const h of hits) (byNm[h.nm] = byNm[h.nm] || []).push('0x' + h.va.toString(16));
for (const [n, v] of Object.entries(byNm)) console.log(`${n}: ${v.length} — ${v.slice(0, 12).join(', ')}${v.length > 12 ? ' …' : ''}`);
