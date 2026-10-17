// pe-triage.js — raw PE header/section/import triage without executing the target.
// Usage: node pe-triage.js <file>
'use strict';
const fs = require('fs');
const path = process.argv[2];
if (!path) { console.error('usage: node pe-triage.js <file>'); process.exit(2); }
const buf = fs.readFileSync(path);

function u16(o) { return buf.readUInt16LE(o); }
function u32(o) { return buf.readUInt32LE(o); }
function u64(o) { return Number(buf.readBigUInt64LE(o)); }
function entropy(b) {
  if (!b.length) return 0;
  const f = new Array(256).fill(0);
  for (const x of b) f[x]++;
  let h = 0;
  for (const c of f) { if (!c) continue; const p = c / b.length; h -= p * Math.log2(p); }
  return h;
}
function rvaToOff(rva, sections) {
  for (const s of sections) {
    const va = parseInt(s.virtualAddress, 16);
    const span = Math.max(s.virtualSize || 0, s.rawSize || 0);
    if (rva >= va && rva < va + span)
      return s.rawPointer + (rva - va);
  }
  return -1;
}

const out = { file: path, size: buf.length };
// DOS header
if (buf.readUInt16LE(0) !== 0x5A4D) { console.error('not MZ'); process.exit(1); }
const e_lfanew = u32(0x3c);
out.dos = { e_lfanew, stub_entropy: entropy(buf.slice(0x40, e_lfanew)) };
// Rich header detection (DOS stub between 0x80 and e_lfanew)
out.dos.rich_offset = buf.indexOf(Buffer.from('Rich'), 0x80, 'ascii') >= 0 ? buf.indexOf(Buffer.from('Rich'), 0x80, 'ascii') : null;

const peOff = e_lfanew;
if (buf.readUInt32LE(peOff) !== 0x4550) { console.error('bad PE signature'); process.exit(1); }
const coff = peOff + 4;
const machine = u16(coff), numSections = u16(coff + 2), timestamp = u32(coff + 4);
const symPtr = u32(coff + 8), numSyms = u32(coff + 12), optSize = u16(coff + 16), chars = u16(coff + 18);
out.coff = {
  machine: '0x' + machine.toString(16), numSections, timestamp,
  timestamp_utc: new Date(timestamp * 1000).toISOString(), timestamp_local: new Date(timestamp * 1000).toString(),
  symPtr, numSyms, characteristics: '0x' + chars.toString(16)
};

const opt = coff + 20;
const magic = u16(opt);
const plus = magic === 0x20b;
out.optional = { magic: '0x' + magic.toString(16), format: plus ? 'PE32+' : 'PE32' };
const entryRva = u32(opt + 16);
const imageBase = plus ? u64(opt + 24) : u32(opt + 28);
const sizeOfImage = u32(opt + 56), sizeOfHeaders = u32(opt + 60);
out.optional.entryPointRva = '0x' + entryRva.toString(16);
out.optional.imageBase = '0x' + imageBase.toString(16);
out.optional.sizeOfImage = '0x' + sizeOfImage.toString(16);
out.optional.sizeOfHeaders = '0x' + sizeOfHeaders.toString(16);
out.optional.checksum = '0x' + u32(opt + 64).toString(16);
out.optional.subsystem = u16(opt + 68);
// data directories
const ddOff = opt + (plus ? 112 : 96);
const numDirs = u32(opt + (plus ? 108 : 92));
const dirNames = ['Export','Import','Resource','Exception','Security','BaseReloc','Debug','Architecture','GlobalPtr','TLS','LoadConfig','BoundImport','IAT','DelayImport','CLR','Reserved'];
out.dataDirectories = [];
for (let i = 0; i < Math.min(numDirs, 16); i++) {
  const rva = u32(ddOff + i * 8), size = u32(ddOff + i * 8 + 4);
  if (rva || size) out.dataDirectories.push({ index: i, name: dirNames[i], rva: '0x' + rva.toString(16), size });
}

// sections
const secOff = opt + optSize;
out.sections = [];
for (let i = 0; i < numSections; i++) {
  const s = secOff + i * 40;
  const name = buf.slice(s, s + 8).toString('ascii').replace(/\0+$/, '');
  const vs = u32(s + 8), va = u32(s + 12), rs = u32(s + 16), pr = u32(s + 20);
  const flags = u32(s + 36);
  const data = buf.slice(pr, pr + Math.min(rs, 4 * 1024 * 1024));
  out.sections.push({
    name, virtualSize: vs, virtualAddress: '0x' + va.toString(16),
    rawSize: rs, rawPointer: pr,
    entropy: +entropy(data).toFixed(3),
    flags: '0x' + flags.toString(16),
    flagsHuman: [
      flags & 0x20 ? 'CODE' : '', flags & 0x40 ? 'IDATA' : '', flags & 0x80 ? 'UDATA' : '',
      flags & 0x02000000 ? 'DISCARDABLE' : '', flags & 0x04000000 ? 'NOT_CACHED' : '',
      flags & 0x10000000 ? 'SHARED' : '', flags & 0x20000000 ? 'EXEC' : '', flags & 0x40000000 ? 'READ' : '', flags & 0x80000000 ? 'WRITE' : ''
    ].filter(Boolean).join('|'),
    rawEntropyFull: rs > 4 * 1024 * 1024 ? null : undefined
  });
}

// overlay
const maxRaw = Math.max(...out.sections.map(s => s.rawPointer + s.rawSize));
out.overlay = { startOffset: maxRaw, size: buf.length > maxRaw ? buf.length - maxRaw : 0 };

// entry section
out.entryInSection = out.sections.find(s => entryRva >= parseInt(s.virtualAddress) && entryRva < parseInt(s.virtualAddress) + Math.max(s.virtualSize, s.rawSize))?.name || 'unknown';

// imports
function cstr(o) { const e = buf.indexOf(0, o); return buf.slice(o, e).toString('ascii'); }
out.imports = [];
const importDir = out.dataDirectories.find(d => d.name === 'Import');
if (importDir) {
  const ioff = rvaToOff(parseInt(importDir.rva), out.sections);
  if (ioff < 0) {
    out.importParseError = `Import dir RVA ${importDir.rva} outside section raw map (virtual-only)`;
    out.importDirOutsideSections = true;
  }
  for (let i = 0; ioff >= 0; i++) {
    const d = ioff + i * 20;
    if (d + 20 > buf.length) break;
    const origThunk = u32(d), time = u32(d + 4), fwd = u32(d + 8), nameRva = u32(d + 12), thunk = u32(d + 16);
    if (!origThunk && !nameRva) break;
    const nameOff = rvaToOff(nameRva, out.sections);
    const dllName = nameOff >= 0 ? cstr(nameOff) : '<unresolved>';
    const funcs = [];
    const toff = rvaToOff(origThunk || thunk, out.sections);
    if (toff >= 0) {
      for (let j = 0; j < 4096; j++) {
        let val;
        try { val = plus ? u64(toff + j * (plus ? 8 : 4)) : u32(toff + j * 4); } catch { break; }
        if (!val) break;
        if (plus) {
          const q = buf.readBigUInt64LE(toff + j * 8);
          if (q & 0x8000000000000000n) { funcs.push(`ord${q & 0xffffn}`); continue; }
        } else if (val & 0x80000000) { funcs.push(`ord${val & 0xffff}`); continue; }
        const fo = rvaToOff(val, out.sections);
        if (fo < 0) { funcs.push('<rva-unresolved>'); continue; }
        funcs.push(cstr(fo + 2));
      }
    }
    out.imports.push({ dll: dllName, count: funcs.length, functions: funcs.slice(0, 400) });
  }
}

// TLS directory
const tlsDir = out.dataDirectories.find(d => d.name === 'TLS');
if (tlsDir) {
  const toff = rvaToOff(parseInt(tlsDir.rva), out.sections);
  if (toff >= 0 && !plus) {
    out.tls = {
      startEnd: [u32(toff), u32(toff + 4)].map(v => '0x' + v.toString(16)),
      indexAddr: '0x' + u32(toff + 8).toString(16),
      callbacksRva: '0x' + u32(toff + 12).toString(16),
      callbacks: []
    };
    const cbs = rvaToOff(u32(toff + 12), out.sections);
    if (cbs >= 0) {
      for (let i = 0; i < 64; i++) {
        let v; try { v = plus ? u64(cbs + i * 8) : u32(cbs + i * 4); } catch { break; }
        if (!v) break;
        out.tls.callbacks.push('0x' + v.toString(16));
      }
    }
  } else if (toff >= 0 && plus) {
    out.tls = {
      startEnd: [u64(toff), u64(toff + 8)],
      indexAddr: '0x' + u64(toff + 16).toString(16),
      callbacksRva: '0x' + u64(toff + 24).toString(16),
      callbacks: []
    };
    const cbs = rvaToOff(u64(toff + 24), out.sections);
    if (cbs >= 0) {
      for (let i = 0; i < 64; i++) {
        let v; try { v = u64(cbs + i * 8); } catch { break; }
        if (!v) break;
        out.tls.callbacks.push('0x' + v.toString(16));
      }
    }
  }
} else out.tls = null;

// quick string scan for packer markers
function scanStrings(enc) {
  const res = [];
  const text = enc === 'u16' ? buf.toString('utf16le') : buf.toString('latin1');
  const re = /[ -~]{6,}/g;
  const seen = new Set();
  let m;
  while ((m = re.exec(text)) && res.length < 100000) {
    const s = m[0];
    if (/themida|winlicense|oreans|VMProtect|upx|nsp|themid|WinLicen/i.test(s) || /themida|winlicense|oreans/i.test(s)) {
      if (!seen.has(s)) { seen.add(s); res.push(s); }
    }
  }
  return res;
}
out.packerMarkerStrings_ascii = scanStrings('ascii').slice(0, 50);
out.packerMarkerStrings_utf16 = scanStrings('u16').slice(0, 50);

console.log(JSON.stringify(out, null, 2));
