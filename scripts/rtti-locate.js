// rtti-locate.js — walk MSVC RTTI for the CStreamCryptor / CPHObject classes in
// cshell.dll: type_descriptor (name string) <- complete_object_locator <-
// vftable[-1] <- vftable. Local static analysis; no execution.
'use strict';
const fs = require('fs');
const exe = fs.readFileSync(process.argv[2] || 'H:\\SA_Analysis\\target\\cshell.dll');
const peOff = exe.readUInt32LE(0x3c);
const numSections = exe.readUInt16LE(peOff + 6);
const optSize = exe.readUInt16LE(peOff + 20);
const imageBase = exe.readBigUInt64LE(peOff + 24 + 24);
const secOff = peOff + 24 + optSize;
console.log(`imageBase=0x${imageBase.toString(16)} sections=${numSections}`);
const secs = [];
for (let i = 0; i < numSections; i++) {
  const s = secOff + i * 40;
  const name = exe.toString('latin1', s, s + 8).replace(/\0+$/, '');
  secs.push({ name, vsize: exe.readUInt32LE(s + 8), vaddr: exe.readUInt32LE(s + 12), rawsize: exe.readUInt32LE(s + 16), rawptr: exe.readUInt32LE(s + 20) });
  console.log(`  ${name.padEnd(8)} va=0x${secs[i].vaddr.toString(16)} vsize=0x${secs[i].vsize.toString(16)} raw=0x${secs[i].rawptr.toString(16)} rawsize=0x${secs[i].rawsize.toString(16)}`);
}
function vaToFile(va) {
  for (const s of secs) if (va >= s.vaddr && va < s.vaddr + Math.max(s.vsize, s.rawsize)) return s.rawptr + (va - s.vaddr);
  return null;
}
function fileToRva(off) {
  for (const s of secs) if (off >= s.rawptr && off < s.rawptr + s.rawsize) return s.vaddr + (off - s.rawptr);
  return null;
}
const fileToVa = (off) => { const r = fileToRva(off); return r === null ? null : r + Number(imageBase); };
// find all 8-byte-aligned pointers equal to value (search whole image)
function findPtrs(val) {
  const needle = Buffer.alloc(8);
  needle.writeBigUInt64LE(val);
  const hits = [];
  let i = 0;
  while ((i = exe.indexOf(needle, i)) !== -1) { if (i % 8 === 0) hits.push(i); i += 1; }
  return hits;
}

const NAMES = ['CPHObject_XOR_1', 'CPHObject_XOR_2', 'CStreamCryptor', 'CStreamCryptor_v0', 'CStreamCryptor_v1'];
for (const nm of NAMES) {
  const pat = `.?AV${nm}@@`;
  const idx = exe.indexOf(Buffer.from(pat, 'latin1'));
  if (idx === -1) { console.log(`\n${nm}: string not found`); continue; }
  const nameVa = BigInt(fileToVa(idx));
  const descVa = nameVa - 0x10n; // type_descriptor {vftable, spare, name}
  console.log(`\n=== ${nm} ===`);
  console.log(`  type_descriptor @VA 0x${descVa.toString(16)} (name @0x${nameVa.toString(16)}, file 0x${idx.toString(16)})`);
  const tdFile = vaToFile(Number(descVa));
  if (tdFile !== null) {
    const colRefVftable = exe.readBigUInt64LE(tdFile);
    console.log(`  descriptor.vftable(ptr)=0x${colRefVftable.toString(16)} (type_info::vftable)`);
  }
  // complete_object_locator references descriptor at offset +0x0c (image-relative in PE32+? no —
  // in PE32+ (x64) the COL fields pTypeDescriptor etc. are IMAGE-RELATIVE 32-bit offsets)
  const colHits = [];
  for (const f of findPtrs(descVa)) colHits.push(f); // direct pointer (rare in x64 COL)
  // x64 COL uses 32-bit RVAs: search 4-byte RVA of descriptor
  const descRva = descVa - imageBase;
  const needle4 = Buffer.alloc(4);
  needle4.writeUInt32LE(Number(descRva));
  let j = 0;
  const colRvaHits = [];
  while ((j = exe.indexOf(needle4, j)) !== -1) { colRvaHits.push(j); j += 1; }
  console.log(`  RVA-of-descriptor refs: ${colRvaHits.length}`);
  for (const h of colRvaHits.slice(0, 6)) {
    // COL layout x64: sig(4) offset(4) cdOffset(4) pTypeDescriptor(4RVA) pClassDescriptor(4RVA) pSelf(4RVA)
    // descriptor RVA field at COL+0x0c → COL start = h-0x0c
    const colStart = h - 0x0c;
    const colVa = BigInt(fileToVa(colStart));
    const selfRva = exe.readUInt32LE(colStart + 0x14);
    const colRva = Number(colVa - imageBase);
    const isCol = selfRva === colRva;
    console.log(`    candidate COL @file 0x${colStart.toString(16)} VA 0x${colVa.toString(16)} self-check=${isCol}`);
    if (!isCol) continue;
    // vftable[-1] = image base + COL VA (absolute pointer)
    const colAbs = imageBase + BigInt(colRva);
    const vfHits = findPtrs(colAbs);
    for (const vf of vfHits) {
      const vfEntryVa = BigInt(fileToVa(vf));
      console.log(`    vftable @file 0x${vf.toString(16)} VA 0x${vfEntryVa.toString(16)} (entry[-1]=COL)`);
      // dump following function pointers (vftable slots)
      const slots = [];
      for (let k = 0; k < 10; k++) {
        const p = exe.readBigUInt64LE(vf + 8 + k * 8);
        if (p < imageBase || p > imageBase + 0x10000000n) break;
        slots.push(p);
      }
      slots.forEach((p, k) => console.log(`      slot[${k}] = 0x${p.toString(16)}`));
    }
  }
}
