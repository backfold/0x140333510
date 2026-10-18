// check-fp-ptr.js — 0x1402ff0d0 IAT 엔트리 정체 확인 (바이트 + 임포트 매핑)
'use strict';
const fs = require('fs');
const exe = fs.readFileSync('H:\\SA_Analysis\\target\\suddenattack.exe');
const peOff = exe.readUInt32LE(0x3c);
const numSec = exe.readUInt16LE(peOff + 6);
const optSize = exe.readUInt16LE(peOff + 20);
const secBase = peOff + 24 + optSize;
const sections = [];
for (let i = 0; i < numSec; i++) {
  const s = secBase + i * 40;
  sections.push({ va: exe.readUInt32LE(s + 12), vsize: exe.readUInt32LE(s + 8), raw: exe.readUInt32LE(s + 20), rsize: exe.readUInt32LE(s + 16) });
}
const IMG = 0x140000000n;
function va2off(va) {
  const rva = va - IMG;
  for (const s of sections) if (rva >= s.va && rva < s.va + Math.max(s.vsize, s.rsize)) return s.raw + Number(rva - BigInt(s.va));
  return null;
}
// 임포트 디렉터리
const optHdr = peOff + 24;
const dataDir = optHdr + 112; // PE32+ data directories
const impRva = exe.readUInt32LE(dataDir);
const impSize = exe.readUInt32LE(dataDir + 4);
console.log(`Import dir RVA 0x${impRva.toString(16)} size 0x${impSize.toString(16)}`);
const iatThunks = new Map(); // thunkVA → "dll!name"
if (impRva) {
  const impOff = va2off(IMG + BigInt(impRva));
  for (let d = 0; ; d++) {
    const ent = impOff + d * 20;
    const origThunk = exe.readUInt32LE(ent), nameRva = exe.readUInt32LE(ent + 12), fwd = exe.readUInt32LE(ent + 16);
    if (!origThunk && !nameRva && !fwd) break;
    const dll = exe.toString('ascii', va2off(IMG + BigInt(nameRva))).replace(/\0.*$/, '');
    const tOff = va2off(IMG + BigInt(origThunk || fwd));
    for (let t = 0; ; t++) {
      const lo = exe.readBigUInt64LE(tOff + t * 8);
      if (lo === 0n) break;
      if (!(lo & 0x8000000000000000n)) {
        const nmOff = va2off(IMG + BigInt(Number(lo & 0xffffffffn)));
        const nm = exe.toString('ascii', nmOff + 2).replace(/\0.*$/, '');
        iatThunks.set(IMG + BigInt(origThunk + t * 8), dll + '!' + nm);
        iatThunks.set(IMG + BigInt(fwd + t * 8), dll + '!' + nm);
      }
    }
  }
}
console.log(`IAT 엔트리 ${iatThunks.size}개`);
const targets = [0x1402ff0d0n, 0x1402ff160n, 0x1403eef38n];
for (const va of targets) {
  const off = va2off(va);
  const val = off !== null ? exe.readBigUInt64LE(off) : null;
  console.log(`[0x${va.toString(16)}] file=0x${off ? off.toString(16) : '?'} 값=0x${val ? val.toString(16) : '?'} 매핑=${iatThunks.get(va) || '(IAT 아님)'}`);
}
// 근처 IAT 엔트리들 출력 (0x1402ff000-0x1402ff200)
console.log('\n0x1402ff000..0x1402ff200 근처 IAT:');
for (const [va, nm] of iatThunks) if (va >= 0x1402ff000n && va < 0x1402ff200n) console.log(`  0x${va.toString(16)} = ${nm}`);
