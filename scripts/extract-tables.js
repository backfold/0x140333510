// Extract the six Snow2 tables from suddenattack.exe .rdata and cross-check
// them against the MapleLib Snow2CryptoTransform tables (Nexon shared crypto).
// Read-only analysis aid for REA evidence (session 25 follow-up).
'use strict';
const fs = require('fs');

const EXE = 'H:\\SA_Analysis\\target\\suddenattack.exe';
const OUT = 'H:\\SA_Analysis\\evidence\\snow_tables_from_exe.json';
const MAPLE = 'H:\\SA_Analysis\\evidence\\maplelib_Snow2CryptoTransform.cs';

const TABLES = [
  ['snow_alpha_mul', 0x1403ef1a0],
  ['snow_alphainv_mul', 0x1403ef5a0],
  ['snow_T0', 0x1403ef9a0],
  ['snow_T1', 0x1403efda0],
  ['snow_T2', 0x1403f01a0],
  ['snow_T3', 0x1403f05a0],
];

// --- PE: map VA -> file offset via section table ---
const exe = fs.readFileSync(EXE);
const peOff = exe.readUInt32LE(0x3c);
if (exe.readUInt32LE(peOff) !== 0x4550) throw new Error('not a PE');
const numSections = exe.readUInt16LE(peOff + 6);
const optSize = exe.readUInt16LE(peOff + 20);
const imageBase = exe.readBigUInt64LE(peOff + 24 + 24); // PE+ optional header: ImageBase at offset 24
const secOff = peOff + 24 + optSize;
function vaToFile(va) {
  const rva = va - Number(imageBase);
  for (let i = 0; i < numSections; i++) {
    const s = secOff + i * 40;
    const vsize = exe.readUInt32LE(s + 8);
    const vaddr = exe.readUInt32LE(s + 12);
    const rawsize = exe.readUInt32LE(s + 16);
    const rawptr = exe.readUInt32LE(s + 20);
    if (rva >= vaddr && rva < vaddr + Math.max(vsize, rawsize)) {
      const off = rawptr + (rva - vaddr);
      if (off + 4 <= exe.length) return off;
    }
  }
  throw new Error('VA not mapped: 0x' + va.toString(16));
}

// --- MapleLib tables from the downloaded source ---
const mapleRaw = fs.readFileSync(MAPLE, 'utf8');
const compact = mapleRaw.replace(/\r?\n/g, '').replace(/\s+/g, ' ');
const mapleTables = {};
for (const m of compact.matchAll(/uint\[\] (snow_\w+) = \{([^}]*)\}/g)) {
  mapleTables[m[1]] = m[2].split(',').map((s) => parseInt(s.trim(), 16) >>> 0);
}

// --- extract + compare ---
const result = { source: 'suddenattack.exe', extracted_at: new Date().toISOString(), tables: {} };
let allMatch = true;
for (const [name, va] of TABLES) {
  const off = vaToFile(va);
  const words = [];
  for (let i = 0; i < 256; i++) words.push(exe.readUInt32LE(off + i * 4) >>> 0);
  const ref = mapleTables[name];
  let match = ref ? words.every((w, i) => w === ref[i]) : false;
  let refLen = ref ? ref.length : 0;
  if (!match) allMatch = false;
  result.tables[name] = {
    va: '0x' + va.toString(16),
    file_offset: '0x' + off.toString(16),
    first8_hex: words.slice(0, 8).map((w) => w.toString(16).padStart(8, '0')).join(' '),
    maplelib_full_match: match,
    maplelib_entries: refLen,
    words,
  };
  console.log(`${name.padEnd(18)} @${'0x' + va.toString(16)} file@0x${off.toString(16)} maplelib-match=${match} (${refLen} entries)`);
}
result.all_tables_match_maplelib = allMatch;
console.log(allMatch ? 'ALL 6 TABLES BYTE-EXACT vs MapleLib Snow2' : 'MISMATCH — inspect');
fs.writeFileSync(OUT, JSON.stringify(result, null, 1));
