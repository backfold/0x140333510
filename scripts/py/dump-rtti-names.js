// dump-rtti-names.js v2 — COL→TypeDescriptor→이름
import fs from 'fs';
const buf = fs.readFileSync('H:/SA_Analysis/target/cshell.dll');
const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
const e = dv.getUint32(0x3c, true);
const n = dv.getUint16(e + 6, true), os = dv.getUint16(e + 20, true);
const ib = dv.getBigUint64(e + 24 + 24, true);
const secOff = e + 24 + os;
function va2off(va) {
  const rva = va - Number(ib); // va: Number (안전 범위)
  for (let i = 0; i < n; i++) {
    const s = secOff + i * 40;
    const vsize = dv.getUint32(s + 8, true), vaddr = dv.getUint32(s + 12, true);
    const rawsize = dv.getUint32(s + 16, true), rawptr = dv.getUint32(s + 20, true);
    if (rva >= vaddr && rva < vaddr + Math.max(vsize, rawsize)) return rawptr + (rva - vaddr);
  }
  return null;
}
function cstr(va, max = 128) {
  const o = va2off(va); if (o == null) return null;
  let s = ''; for (let i = 0; i < max && buf[o + i]; i++) { const c = buf[o + i]; if (c < 0x20 || c > 0x7e) return null; s += String.fromCharCode(c); }
  return s.length ? s : null;
}
// vftable 목록: [COL 주소(-1 슬롯)] 에서 COL 해석
const vtabs = [0x181658f58, 0x181658f98, 0x181658fd8, 0x181658f38,
  0x181659058, 0x1816590a0, 0x181659158, 0x1816591a0, 0x1816591e8,
  0x181659230, 0x181659278, 0x1816592c0];
for (const vt of vtabs) {
  const colPtr = dv.getBigUint64(va2off(vt), true);
  const colVa = Number(colPtr);
  const o = va2off(colVa);
  if (o == null) { console.log(`vftable 0x${vt.toString(16)}: COL 0x${colVa.toString(16)} — 변환 실패`); continue; }
  const sig = dv.getUint32(o, true);
  const tdRva = dv.getUint32(o + 12, true);
  const tdVa = Number(ib) + tdRva;
  const name = cstr(tdVa + 16);
  console.log(`vftable 0x${vt.toString(16)}: COL 0x${colVa.toString(16)} sig=0x${sig.toString(16)} TD 0x${tdVa.toString(16)} → ${name ?? '?'}`);
}
