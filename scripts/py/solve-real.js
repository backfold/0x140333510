// solve-real.js — 확보된 상수(키=b64 "c9x6zoVPQL1y00oPpGZ6/A==", IV="SDAT.NEXON.COM..")로
// 불투명 패킷 SEED 복호화 시도 + 마스크 유출 관계 검증
import fs from 'fs';
import { seedInitKey, seedEncrypt, seedDecrypt } from './seed.js';
const seedEncryptBlock = (blk, key) => seedEncrypt(seedInitKey(key), blk);
const seedDecryptBlock = (blk, key) => seedDecrypt(seedInitKey(key), blk);

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
function b64dec(s) {
  s = s.replace(/=+$/, '');
  const bits = [];
  for (const ch of s) { const v = B64.indexOf(ch); if (v < 0) throw new Error('bad ' + ch); for (let i = 5; i >= 0; i--) bits.push((v >> i) & 1); }
  const out = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) { let b = 0; for (let j = 0; j < 8; j++) b = (b << 1) | bits[i + j]; out.push(b); }
  return Buffer.from(out);
}
const key16 = b64dec('c9x6zoVPQL1y00oPpGZ6/A==');
const iv16 = Buffer.from('SDAT.NEXON.COM..', 'latin1');
console.log(`key16 = ${key16.toString('hex')} (${key16.length}B)`);
console.log(`iv16  = ${iv16.toString('hex')} "${iv16.toString('latin1')}"`);

// decoded.log에서 프레임 페이로드 추출
function getFrame(n) {
  const lines = fs.readFileSync('H:/SA_Analysis/logs/run1/decoded.log', 'latin1').split('\n');
  const re = new RegExp(`^#${n} (C2S|S2C) type=(0x[0-9a-f]+) `);
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i].match(re);
    if (m) {
      const bytes = [];
      let j = i + 1;
      while (j < lines.length && /^[0-9a-f]{4}\s/.test(lines[j])) {
        const hexPart = lines[j].slice(6, 6 + 96).trim().split(/\s+/);
        for (const h of hexPart) { const b = parseInt(h, 16); if (!Number.isNaN(b)) bytes.push(b); }
        j++;
      }
      return { n, dir: m[1], type: m[2], bytes: Buffer.from(bytes) };
    }
  }
  return null;
}

function printable(buf) { let c = 0; for (const b of buf) if (b === 9 || b === 10 || b === 13 || (b >= 0x20 && b < 0x7f)) c++; return c / buf.length; }
function xor(a, b) { return Buffer.from(a.map((x, i) => x ^ b[i % b.length])); }
function blocks(buf) { const r = []; for (let i = 0; i + 16 <= buf.length; i += 16) r.push(buf.subarray(i, i + 16)); return r; }

const cfbDecStd = (ct) => { // 표준 CFB 복호화: p_i = E(prev)^c_i, prev=c_i  … 그러나 path A는 BlockDec 기반이므로 아래 변형들
  let mask = iv16; const out = [];
  for (const c of blocks(ct)) { const d = seedDecryptBlock(mask, key16); const p = xor(c, d); out.push(...p); mask = c; }
  return Buffer.from(out);
};
const cfbDecDbc = (ct) => { // 관측된 path A 순서: x=c^mask; x=D(x); mask=x  (mask=평문)
  let mask = iv16; const out = [];
  for (const c of blocks(ct)) { let x = xor(c, mask); x = seedDecryptBlock(x, key16); out.push(...x); mask = x; }
  return Buffer.from(out);
};
const cfbEncB = (ct) => { // path B 암호화 역적용: c=E(p)^mask, mask=p → p 복구는? (mask 알 수 없어 역산 불가) 대신 E로 마스크 생성 시도
  let mask = iv16; const out = [];
  for (const c of blocks(ct)) { const e = seedEncryptBlock(mask, key16); const p = xor(c, e); out.push(...p); mask = p; }
  return Buffer.from(out);
};
const cbcDec = (ct) => { let prev = iv16; const out = []; for (const c of blocks(ct)) { const d = seedDecryptBlock(c, key16); out.push(...xor(d, prev)); prev = c; } return Buffer.from(out); };
const ecbDec = (ct) => Buffer.from(blocks(ct).flatMap(b => [...seedDecryptBlock(b, key16)]));

const targets = [3, 4]; // + 타입별 탐색
const typeWanted = { '0x34': 1, '0xbf': 1, '0x37': 1, '0xca': 1, '0xf7': 1 };
{
  const lines = fs.readFileSync('H:/SA_Analysis/logs/run1/decoded.log', 'latin1').split('\n');
  for (let i = 0; i < lines.length && Object.keys(typeWanted).length; i++) {
    const m = lines[i].match(/^#(\d+) (C2S|S2C) type=(0x[0-9a-f]+) /);
    if (m && typeWanted[m[3]]) { targets.push(+m[1]); delete typeWanted[m[3]]; }
  }
}
for (const n of targets) {
  const f = getFrame(n);
  if (!f) { console.log(`#${n} 없음`); continue; }
  console.log(`\n=== #${f.n} ${f.dir} ${f.type} len=${f.bytes.length} ===`);
  console.log(`  head: ${f.bytes.subarray(0, 32).toString('hex')}`);
  const tries = { cfbDecStd, cfbDecDbc, cfbEncB, cbcDec, ecbDec };
  for (const [name, fn] of Object.entries(tries)) {
    try {
      const pt = fn(f.bytes);
      const score = printable(pt);
      console.log(`  ${name}: pr=${(score * 100).toFixed(0)}% head=${pt.subarray(0, 32).toString('hex')} |${pt.subarray(0, 48).toString('latin1').replace(/[^\x20-\x7f]/g, '.')}|`);
    } catch (e) { console.log(`  ${name}: ERR ${e.message}`); }
  }
}

// 마스크 유출 검증: E/D(key16, 여러 IV) vs M_c2s/M_s2c
const M_c2s = Buffer.from('85a3520d83db99b93ae96247c74f7c03', 'hex');
const M_s2c = Buffer.from('f2596446d34b7b6469cc4ef7ca42dc46', 'hex');
console.log('\n=== 마스크 관계 검증 ===');
const ivs = { SDAT: iv16, zeros: Buffer.alloc(16), M_c2s, M_s2c };
for (const [n, iv] of Object.entries(ivs)) {
  const e = seedEncryptBlock(iv, key16), d = seedDecryptBlock(iv, key16);
  console.log(`  ${n}: E=${e.toString('hex')} D=${d.toString('hex')}`);
}
console.log(`  M_c2s=${M_c2s.toString('hex')}`);
console.log(`  M_s2c=${M_s2c.toString('hex')}`);
