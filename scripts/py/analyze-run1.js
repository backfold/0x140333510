// analyze-run1.js — packets.log 재해석 (오프라인 정밀 분석)
// 1) "-- RAW --" 헥스덤프에서 패킷 원문 바이트 재조립 → 방향별 스트림 복원
//    (프록시의 c2s.bin/s2c.bin 미기록 버그를 우회)
// 2) u16 길이 프레이밍 검증: 전 스트림 체인 확인
// 3) obf v1 복호화(정확한 경계): cksum=body 마지막 2B, work=reverse(body[..-2]),
//    tag=work[1], key=work[3..7] u32LE, payload = 롤링 XOR
// 4) 페이로드 구조 통계 + XTEA(고정키) 8B 블록 복호화 시도
import fs from 'fs';
import readline from 'readline';

const PACKETS = process.argv[2] || 'H:/SA_Analysis/logs/run1/packets.log';
const XTEA_KEY = [0x64363531, 0x38376665, 0x33323039, 0x34636261]; // "156def789023abc4"

function xteaDecryptBlock(v0, v1) {
  let sum = 0xC6EF3720 >>> 0;
  for (let i = 0; i < 32; i++) {
    v1 = (v1 - ((((v0 << 4) ^ (v0 >>> 5)) + v0) ^ ((sum + XTEA_KEY[(sum >>> 11) & 3]) >>> 0))) >>> 0;
    sum = (sum - 0x61C88647) >>> 0;
    v0 = (v0 - ((((v1 << 4) ^ (v1 >>> 5)) + v1) ^ ((sum + XTEA_KEY[sum & 3]) >>> 0))) >>> 0;
  }
  return [v0, v1];
}

function hexdump(b, max = 64) {
  const n = Math.min(b.length, max);
  const lines = [];
  for (let i = 0; i < n; i += 16) {
    const row = [...b.slice(i, i + 16)];
    const hex = row.map(x => x.toString(16).padStart(2, '0')).join(' ').padEnd(47);
    const asc = row.map(x => (x >= 0x20 && x < 0x7f) ? String.fromCharCode(x) : '.').join('');
    lines.push(`${i.toString(16).padStart(4, '0')}  ${hex}  ${asc}${i + 16 < n ? '' : ''}`);
  }
  if (b.length > max) lines.push(`... (${b.length} bytes total)`);
  return lines.join('\n');
}

// ---- 1) packets.log 파싱 → 스트림 재조립 ----
const streams = { C2S: [], S2C: [] }; // arrays of Uint8Array (raw frame bytes incl. len field)
let pktCount = { C2S: 0, S2C: 0 };

async function parse() {
  const rl = readline.createInterface({ input: fs.createReadStream(PACKETS, 'utf8') });
  let dir = null, inRaw = false, bytes = [];
  let cur = 0;
  for await (const line of rl) {
    if (line.startsWith('#') && line.includes('conn=')) {
      const m = line.match(/^#(\d+)\s+(C2S|S2C)/);
      if (m) { cur = +m[1]; dir = m[2]; inRaw = false; bytes = []; }
      continue;
    }
    if (line.includes('-- RAW --')) { inRaw = true; continue; }
    if (line.startsWith('--')) { // 다음 섹션(DEOBF/strings) 시작 → 패킷 확정
      if (inRaw && dir && bytes.length) {
        streams[dir].push({ id: cur, raw: Uint8Array.from(bytes) });
        pktCount[dir]++;
      }
      inRaw = false;
      continue;
    }
    if (inRaw) {
      const m = line.match(/^\s*[0-9a-f]{4}\s+((?:[0-9a-f]{2,8}[ ])+)/);
      if (m) for (const h of m[1].trim().split(/\s+/)) if (/^[0-9a-f]{2}$/.test(h)) bytes.push(parseInt(h, 16));
    }
  }
}

// ---- 2) 프레임 체인 재검증 + obf 복호화 ----
function analyze(dir) {
  // 스트림으로 합침
  const total = streams[dir].reduce((a, p) => a + p.raw.length, 0);
  const buf = new Uint8Array(total);
  let off = 0;
  for (const p of streams[dir]) { buf.set(p.raw, off); off += p.raw.length; }

  // 프레임 체인 검증: u16le len(자기 자신 미포함) 가정
  let pos = 0, frames = 0, chainOk = 0;
  const payloads = [];
  while (pos + 2 <= buf.length) {
    const len = buf[pos] | (buf[pos + 1] << 8);
    if (len < 10 || pos + 2 + len > buf.length) break;
    const body = buf.subarray(pos + 2, pos + 2 + len);
    // obf v1
    const cksum = body[len - 2] | (body[len - 1] << 8);
    const work = body.slice(0, len - 2).reverse();
    const tag = work[1];
    const key = (work[3] | (work[4] << 8) | (work[5] << 16) | (work[6] << 24)) >>> 0;
    const plain = new Uint8Array(len - 10);
    let prev = 0;
    for (let i = 0; i < plain.length; i++) {
      const c = work[8 + i];
      plain[i] = (key ^ prev ^ c) & 0xff;
      prev = c;
    }
    payloads.push({ len, tag, key, cksum, plain });
    frames++; chainOk++;
    pos += 2 + len;
  }
  return { total, frames, chained: pos, tail: buf.length - pos, payloads };
}

// ---- 4) 결과 출력 ----
await parse();
console.log(`파싱: C2S ${pktCount.C2S}패킷, S2C ${pktCount.S2C}패킷`);

for (const dir of ['C2S', 'S2C']) {
  const r = analyze(dir);
  console.log(`\n===== ${dir}: ${r.total} bytes, 프레임 ${r.frames}개 (체인 ${r.chained}B, 잔여 ${r.tail}B) =====`);
  if (!r.frames) continue;
  // 통계
  const tags = new Map(), keys = new Set(), cks = new Map();
  const lens = new Map();
  for (const p of r.payloads) {
    tags.set(p.tag, (tags.get(p.tag) || 0) + 1);
    keys.add(p.key);
    cks.set(p.cksum, (cks.get(p.cksum) || 0) + 1);
    lens.set(p.len, (lens.get(p.len) || 0) + 1);
  }
  console.log(`tag 분포: ${[...tags.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8).map(([t, c]) => `0x${t.toString(16)}×${c}`).join(' ')}`);
  console.log(`고유 key 수: ${keys.size} / ${r.frames},  고유 cksum 수: ${cks.size}`);
  console.log(`cksum 상위: ${[...cks.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5).map(([c, n]) => `0x${c.toString(16)}×${n}`).join(' ')}`);
  console.log(`len 상위: ${[...lens.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6).map(([l, c]) => `${l}B×${c}`).join(' ')}`);
  // 처음 8개 + 중간 4개 상세
  const show = [...r.payloads.slice(0, 8), ...[Math.floor(r.frames / 2), Math.floor(r.frames / 2) + 1, r.frames - 2, r.frames - 1].filter(i => i >= 8 && i < r.frames).map(i => r.payloads[i])];
  for (const [i, p] of (r.payloads.slice(0, 8).entries())) {
    console.log(`\n[${dir} #${i}] len=${p.len} tag=0x${p.tag.toString(16)} key=0x${p.key.toString(16)} cksum=0x${p.cksum.toString(16)}`);
    console.log('plain:'); console.log(hexdump(p.plain, 96));
    // XTEA 시도 (첫 8/16바이트)
    if (p.plain.length >= 8) {
      const dv = new DataView(p.plain.buffer, p.plain.byteOffset, p.plain.length);
      const [d0, d1] = xteaDecryptBlock(dv.getUint32(0, true), dv.getUint32(4, true));
      const h = [d0, d1].map(x => (x >>> 0).toString(16).padStart(8, '0')).join(' ');
      console.log(`XTEA dec blk0: ${h}`);
    }
  }
}
console.log('\n완료');
