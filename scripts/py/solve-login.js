// solve-login.js — 0x42/0x51 불투명 페이로드 SEED-CFB/ECB 브루트 배터리
import fs from 'fs';
import { seedInitKey, seedEncrypt, seedDecrypt } from './seed.js';
const lines = fs.readFileSync('H:/SA_Analysis/logs/run1/decoded.log', 'latin1').split('\n');
function getFrame(n) {
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].startsWith(`#${n} `)) {
      const bytes = [];
      let j = i + 1;
      while (j < lines.length && /^[0-9a-f]{4}\s/.test(lines[j])) {
        for (const h of lines[j].slice(6, 6 + 95).trim().split(/\s+/)) if (/^[0-9a-f]{2}$/.test(h)) bytes.push(parseInt(h, 16));
        j++;
      }
      return Buffer.from(bytes);
    }
  }
  return null;
}
const hello = getFrame(1);    // S2C 0x0d 28B
const login = getFrame(2);    // C2S 0x3d
const p42 = getFrame(3);      // C2S 0x42
const p51 = getFrame(4);      // C2S 0x51
console.log(`0x0d(${hello.length}B) ${hello.toString('hex')}`);
console.log(`0x42(${p42.length}B) ${p42.subarray(0, 32).toString('hex')}...`);

const blob12 = Buffer.from('c0e98d1fc0479affc03190', 'hex');
const rep = Buffer.from('9152a360', 'hex');
function pair(name, buf) { return buf && buf.length === 16 ? [name, buf] : null; }
const keyList = [
  pair('blob+0000', Buffer.concat([blob12, Buffer.alloc(4)])),
  pair('blob+3838', Buffer.concat([blob12, Buffer.from('8888', 'latin1')])),
  pair('9152a360x4', Buffer.concat([rep, rep, rep, rep])),
  pair('hello[0:16]', hello.subarray(0, 16)),
  pair('hello[12:28]', hello.subarray(12, 28)),
  pair('login3d[0:16]', login.subarray(0, 16)),
  pair('xtea_str', Buffer.from('156def789023abc4', 'latin1')),
  pair('zeros', Buffer.alloc(16)),
].filter(Boolean);
const ivList = [
  pair('hello[0:16]', hello.subarray(0, 16)),
  pair('hello[12:28]', hello.subarray(12, 28)),
  pair('blob+0000', Buffer.concat([blob12, Buffer.alloc(4)])),
  pair('zeros', Buffer.alloc(16)),
  pair('9152a360x4', Buffer.concat([rep, rep, rep, rep])),
].filter(Boolean);
const KEYS = new Map(keyList), IVS = new Map(ivList);

function score(buf) {
  let pr = 0, runs8 = 0, zeros = 0;
  for (const b of buf) { if (b >= 0x20 && b < 0x7f) pr++; if (b === 0x38) runs8++; if (b === 0) zeros++; }
  return { pr: pr / buf.length, runs8: runs8 / buf.length, zeros: zeros / buf.length };
}
let hits = 0;
for (const tgt of [[0x42, p42], [0x51, p51]]) {
  for (const [kn, K] of KEYS) {
    const ks = seedInitKey(K);
    for (let o = 0; o + 16 <= tgt[1].length; o += 16) {
      const d = seedDecrypt(ks, tgt[1].subarray(o, o + 16));
      const s = score(d);
      if (s.pr > 0.85 || s.runs8 > 0.6 || s.zeros > 0.6) { console.log(`0x${tgt[0].toString(16)} ECB-D K=${kn} @${o}: ${d.toString('hex')}`); hits++; }
    }
    for (const [ivn, IV] of IVS) {
      for (const fb of ['plain', 'cipher']) {
        for (const op of ['D', 'E']) {
          const out = Buffer.alloc(tgt[1].length - (tgt[1].length % 16));
          let mask = Buffer.from(IV);
          for (let o = 0; o + 16 <= tgt[1].length; o += 16) {
            const blk = tgt[1].subarray(o, o + 16);
            const x = Buffer.alloc(16);
            for (let i = 0; i < 16; i++) x[i] = blk[i] ^ mask[i];
            const r = op === 'D' ? seedDecrypt(ks, x) : seedEncrypt(ks, x);
            out.set(r, o);
            mask = Buffer.from(fb === 'plain' ? r : blk);
          }
          const s = score(out);
          if (s.pr > 0.9 || s.runs8 > 0.5 || s.zeros > 0.5) {
            console.log(`0x${tgt[0].toString(16)} CFB-${op} fb=${fb} K=${kn} IV=${ivn}: ${out.subarray(0, 32).toString('hex')} (인쇄${(s.pr * 100) | 0}% 8=${(s.runs8 * 100) | 0}% 0=${(s.zeros * 100) | 0}%)`);
            hits++;
          }
        }
      }
    }
  }
}
console.log(hits ? `${hits}건 구조 발견` : '구조 발견 없음 — 키는 관측재료 밖(세션 상태)');
