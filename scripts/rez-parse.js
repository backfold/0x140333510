// rez-parse.js — LithTech RezMgr (Sudden Attack variant) directory parser
// Format per Luigi Auriemma's public QuickBMS script rezmgr.bms (SA variant):
//   [0..1] = 0x0a3f ; goto 0x16 ; DUMMY, INFO_OFFSET, INFO_SIZE (LE u32)
//   dir listing at INFO_OFFSET/size INFO_SIZE, entries:
//     TYPE(u32): 0 = file -> OFFSET,SIZE,DUMMY(u64),EXT(8 reversed),NAME(cstr),FOLDER(cstr)
//                else dir  -> INFO_OFFSET,INFO_SIZE,DUMMY(u32),NAME(cstr) ; recurse
'use strict';
const fs = require('fs');
const file = process.argv[2];
const buf = fs.readFileSync(file);

const u32 = (o) => buf.readUInt32LE(o);
const cstr = (o) => { let e = o; while (e < buf.length && buf[e] !== 0) e++; return [buf.toString('latin1', o, e), e + 1]; };

const type = buf.readUInt16LE(0);
if (type !== 0x0a3f) { console.error(`unknown RezMgr version 0x${type.toString(16)}`); process.exit(1); }
console.log(`# RezMgr SuddenAttack variant (0x0a3f), size=${buf.length}`);
const hdrOff = 0x16;
const dummy = u32(hdrOff), infoOff = u32(hdrOff + 4), infoSize = u32(hdrOff + 8);
console.log(`# header@0x16: dummy=0x${dummy.toString(16)} info_offset=0x${infoOff.toString(16)} info_size=0x${infoSize.toString(16)}`);

const files = [];
function walk(off, size, prefix) {
  const end = off + size;
  let p = off;
  let guard = 0;
  while (p < end && guard++ < 4096) {
    const t = u32(p); p += 4;
    if (t === 0) { // file entry
      const fo = u32(p), fsz = u32(p + 4); p += 8;
      p += 8; // dummy u64
      const ext = buf.toString('latin1', p, p + 8).replace(/\0+$/, ''); p += 8; // reversed ext
      let name, folder;
      [name, p] = cstr(p);
      [folder, p] = cstr(p);
      files.push({ path: prefix + name + (ext ? '.' + [...ext].reverse().join('') : ''), offset: fo, size: fsz, folder });
    } else { // dir entry
      const dOff = u32(p), dSize = u32(p + 4); p += 8;
      p += 4; // dummy u32
      let name; [name, p] = cstr(p);
      walk(dOff, dSize, prefix + name + '/');
    }
  }
  if (p !== end) console.log(`# note: listing 0x${off.toString(16)} ended at 0x${p.toString(16)} (expected 0x${end.toString(16)})`);
}
walk(infoOff, infoSize, '');
console.log(`# ${files.length} file entries`);
for (const f of files) {
  const ascii = [...buf.slice(f.offset, Math.min(f.offset + 16, buf.length))].map((b) => (b >= 0x20 && b <= 0x7e) ? String.fromCharCode(b) : '.').join('');
  console.log(`${f.offset.toString(16).padStart(6)} ${String(f.size).padStart(7)}  ${f.path.padEnd(40)} | ${ascii}`);
}
