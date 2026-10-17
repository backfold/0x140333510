// Verify SnowCipher table constants (session 25, read_bytes @0x1403ef1a0..0x1403f09a0)
// against known cipher T-table constructions. Read-only analysis aid.
'use strict';

// --- observed bytes (session25.jsonl, normalized_result.bytes_hex) ---
const observed = {
  '0x1403ef1a0': '0000000013cf9fe12637976b35f8088a4c6e87d65fa118376a5910bd79968f5c',
  '0x1403ef5a0': '00000000cd400f1833801e30fec0112866a93c60abe933785529225098692d48',
  '0x1403ef9a0': 'c66363a5f87c7c84ee777799f67b7b8dfff2f20dd66b6bbdde6f6fb191c5c554',
  '0x1403efda0': 'a5c6636384f87c7c99ee77778df67b7b0dfff2f2bdd66b6bb1de6f6f5491c5c5',
  '0x1403f01a0': '63a5c6637c84f87c7799ee777b8df67bf20dfff26bbdd66b6fb1de6fc55491c5',
  '0x1403f05a0': '6363a5c67c7c84f8777799ee7b7b8df6f2f20dff6b6bbdd66f6fb1dec5c55491',
  '0x1403f09a0': '0100000000000000000000000000000028a93240010000000000000000000000',
};
function dwords(hex) {
  const out = [];
  for (let i = 0; i + 8 <= hex.length; i += 8) out.push(BigInt('0x' + hex.slice(i, i + 8)));
  return out;
}

// --- GF(2^8) with AES poly 0x11b ---
function gmul(a, b) {
  a >>>= 0; b >>>= 0;
  let p = 0;
  for (let i = 0; i < 8; i++) {
    if (b & 1) p ^= a;
    const hi = a & 0x80;
    a = (a << 1) & 0xff;
    if (hi) a ^= 0x1b;
    b >>= 1;
  }
  return p >>> 0;
}

// --- AES S-box (standard construction) ---
const S = new Array(256).fill(0);
{
  let p = 1, q = 1;
  const rot8 = (v, n) => ((v << n) | (v >>> (8 - n))) & 0xff;
  do {
    // multiply p by 3, divide q by 3 (== multiply by 0xf6) in GF(2^8)
    p = gmul(p, 3);
    q = gmul(q, 0xf6);
    S[p] = (q ^ rot8(q, 1) ^ rot8(q, 2) ^ rot8(q, 3) ^ rot8(q, 4) ^ 0x63) & 0xff;
  } while (p !== 1);
  S[0] = 0x63;
}
if (S[1] !== 0x7c || S[255] !== 0x16) throw new Error('S-box self-check failed');
const InvS = new Array(256);
for (let i = 0; i < 256; i++) InvS[S[i]] = i;

const rotl32 = (x, n) => ((x << n) | (x >>> (32 - n))) >>> 0;
const be = (b0, b1, b2, b3) => (((b0 << 24) | (b1 << 16) | (b2 << 8) | b3) >>> 0);

// AES T-tables (rijndael-alg-fst.c convention)
const Te = [[], [], [], []], Td = [[], [], [], []];
for (let x = 0; x < 256; x++) {
  const s = S[x], is = InvS[x];
  const t0 = be(gmul(s, 2), s, s, gmul(s, 3));
  const d0 = be(gmul(is, 14), gmul(is, 9), gmul(is, 13), gmul(is, 11));
  for (let k = 0; k < 4; k++) {
    Te[k][x] = rotl32(t0, 8 * k);
    Td[k][x] = rotl32(d0, 8 * k);
  }
}

function report(name, table, addr) {
  const obs = dwords(observed[addr]);
  let match = 0;
  for (let i = 0; i < 8; i++) if (BigInt(table[i]) === obs[i]) match++;
  const first3 = table.slice(0, 3).map((v) => v.toString(16).padStart(8, '0')).join(' ');
  console.log(`${name.padEnd(10)} vs ${addr}: ${match}/8 dwords match | gen: ${first3}`);
}

for (let k = 0; k < 4; k++) {
  report(`Te${k}`, Te[k], ['0x1403ef9a0', '0x1403efda0', '0x1403f01a0', '0x1403f05a0'][k]);
  report(`Td${k}`, Td[k], ['0x1403ef9a0', '0x1403efda0', '0x1403f01a0', '0x1403f05a0'][k]);
}

// mystery tables: test assorted constructions
console.log('\n--- mystery tables 0x1403ef1a0 / 0x1403ef5a0 ---');
for (const addr of ['0x1403ef1a0', '0x1403ef5a0']) {
  const obs = dwords(observed[addr]);
  console.log(`${addr}: ${obs.slice(0, 4).map((v) => v.toString(16).padStart(8, '0')).join(' ')}`);
}
// hypothesis A: InvMixColumns applied to Te-column (S then 14/9/13/11), all rotations
for (const addr of ['0x1403ef1a0', '0x1403ef5a0']) {
  const obs = dwords(observed[addr]);
  const cands = {};
  for (let x = 1; x < 8; x++) {
    const s = S[x], is = InvS[x];
    const variants = {
      'S:14/11/13/9': be(gmul(s, 14), gmul(s, 11), gmul(s, 13), gmul(s, 9)),
      'S:9/13/11/14': be(gmul(s, 9), gmul(s, 13), gmul(s, 11), gmul(s, 14)),
      'iS:14/11/13/9': be(gmul(is, 14), gmul(is, 11), gmul(is, 13), gmul(is, 9)),
      'S:2/1/1/3': be(gmul(s, 2), s, s, gmul(s, 3)),
      'S:3/2/1/1': be(gmul(s, 3), gmul(s, 2), s, s),
    };
    for (const [nm, v] of Object.entries(variants)) {
      for (let r = 0; r < 4; r++) {
        const rv = rotl32(v, 8 * r);
        if (BigInt(rv) === obs[x]) cands[`${nm} rot${r * 8}`] = (cands[`${nm} rot${r * 8}`] || 0) + 1;
      }
    }
  }
  console.log(`${addr} construction matches at x=1..7:`, cands);
}
// hypothesis B: per-byte multiply tables (x*m in each byte lane)
for (const addr of ['0x1403ef1a0', '0x1403ef5a0']) {
  const obs = dwords(observed[addr]);
  const found = [];
  for (const m of [1, 2, 3, 9, 11, 13, 14, 19, 25]) {
    let ok = true;
    for (let x = 0; x < 8; x++) {
      const expect = be(gmul(x, m), gmul(x, m), gmul(x, m), gmul(x, m));
      if (BigInt(expect) !== obs[x]) { ok = false; break; }
    }
    if (ok) found.push('uniform x*' + m);
    // rotated lanes
    const perms = [[9, 13, 11, 14], [14, 9, 13, 11], [11, 13, 9, 14], [13, 11, 14, 9], [2, 1, 1, 3], [3, 2, 1, 1], [1, 3, 2, 1], [1, 1, 3, 2]];
    for (const pm of perms) {
      let ok2 = true;
      for (let x = 0; x < 8; x++) {
        const e = be(gmul(x, pm[0]), gmul(x, pm[1]), gmul(x, pm[2]), gmul(x, pm[3]));
        if (BigInt(e) !== obs[x]) { ok2 = false; break; }
      }
      if (ok2) found.push('x*[' + pm.join(',') + ']');
    }
  }
  console.log(`${addr} byte-lane table:`, found.length ? found : 'none of the tested lane combos');
}
