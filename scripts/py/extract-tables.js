// extract-tables.js — 0x1803333f0 키스케줄이 참조하는 4개 256×u32 테이블 추출 + 식별
import fs from 'fs';
const path = 'H:/SA_Analysis/target/cshell.dll';
const buf = fs.readFileSync(path);
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
const TADDR = [0x1814967b0, 0x181496bb0, 0x181496fb0, 0x1814973b0];
const T = TADDR.map(a => {
  const off = va2off(a);
  if (off == null) throw new Error(`미매핑 VA 0x${a.toString(16)}`);
  const t = [];
  for (let i = 0; i < 256; i++) t.push(dv.getUint32(off + i * 4, true));
  return t;
});
fs.writeFileSync('H:/SA_Analysis/evidence/cipher_tables_0x1803333f0.bin', (() => { const b = Buffer.alloc(4096); T.forEach((t, k) => t.forEach((v, i) => b.writeUInt32LE(v, k * 1024 + i * 4))); return b; })());
const hex = t => t.slice(0, 4).map(x => x.toString(16).padStart(8, '0')).join(' ');
T.forEach((t, i) => console.log(`T${i} @0x${TADDR[i].toString(16)}: ${hex(t)} ... ${t[255].toString(16).padStart(8, '0')}`));

// === 식별 시험 1: AES T-table? T0[x]=2·S[x] (LE 바이트배열 c6 63 63 a5) ===
const AES_S = Buffer.from('637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b27509832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cfd0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdbe0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9ee1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16', 'hex');
// AES 인코딩 T-table (T0[x] = [2S, S, S, 3S] 컬럼): 상위바이트=2*S → LE u32 = 0x{S}{S}{3S}{2S}? 표준: T0[x]=02·S[x]<<24 | S<<16 | S<<8 | 03·S
const aesT0 = [];
for (let x = 0; x < 256; x++) { const s = AES_S[x]; aesT0.push((((s << 1) & 0x1ff) ^ (s >= 128 ? 0x1b : 0)) * 0x1000000 | s * 0x10000 | s * 0x100 | (((s << 1) ^ (s >= 128 ? 0x1b : 0) ^ s) & 0xff)); }
const eq = (a, b) => a.every((v, i) => v === b[i]);
console.log('\nAES T0와 일치?', eq(T[0], aesT0) || T.some(t => eq(t, aesT0)));
// 관계 검사: T1[x] == ROR(T0[x], 8)? (AES/Twoﬁsh류 열회전 구조)
const ror = (v, n) => ((v >>> n) | (v << (32 - n))) >>> 0;
for (let a = 0; a < 4; a++) for (let b = 0; b < 4; b++) {
  if (a === b) continue;
  for (const n of [8, 16, 24]) if (T[a].every((v, i) => ror(v, n) === T[b][i])) console.log(`T${b}[x] == ROR(T${a}[x], ${n})`);
}
// 바이트 단위 구조: 각 테이블의 [x]에서 x=0..3 값과, 테이블 간 바이트 재배치 관계 (Twofish MDS/큐 특성)
for (let i = 0; i < 4; i++) console.log(`T${i}[0..3] =`, T[i].slice(0, 4).map(x => x.toString(2).padStart(32, '0')).join(' '));
// XOR 구조: T0[x]^T0[y] 패턴은 불필요. 대신: 테이블이 GF(2^8) 스칼라배 관계인지 (MDS 열): T1[x] == 0xEF*T0[x] 성분별? — 일단 비트 카운트 분포만
const popc = v => (v.toString(2).match(/1/g) || []).length;
console.log('\npopcount 분포 (첫 16):', T[0].slice(0, 16).map(popc).join(','));
