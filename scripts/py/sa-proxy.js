#!/usr/bin/env node
// sa-proxy.js — SuddenAttack 서버 트래픽 캡처용 로컬 TCP 중계 프록시 (Node판).
// scripts/py/sa_proxy.py 와 동일 기능 + 확정된 패킷 난독화 자동 복호 시도.
//
// 근거 (REA session 28, cshell.dll):
//   CStreamCryptor_v1 (vftable 0x181658fd8)
//     +0x08 enc 0x181272e40: 헤더{rand,tag,rand,key32,rand} + 페이로드 롤링XOR
//                             → 전체 리버스 → u16 체크섬(0x181272bc0) append
//     +0x10 dec 0x181272fa0: 그 역연산. 키가 패킷 안에 포함(자기기술적).
//   XTEA-32 고정키 "156def789023abc4" (로그인용 8바이트 블록, 0x180d5ef00/9c0)
//
// Usage:
//   node sa-proxy.js --listen 127.0.0.1:12000 --upstream 175.207.21.11:12000
//   node sa-proxy.js --selftest
'use strict';
const net = require('net');
const fs = require('fs');
const path = require('path');

// ---------------------------------------------------------------------------
// [확정] XTEA-32 (코어 FUN_180d5ef00/0x180d5e9c0 포팅)
// ---------------------------------------------------------------------------
const DELTA = 0x9E3779B9;
const XTEA_KEY = [0x64363531, 0x38376665, 0x33323039, 0x34636261]; // "156def789023abc4"

function xteaEncryptBlock(data8, key = XTEA_KEY) {
  if (data8.length !== 8) throw new Error('XTEA 블록은 8바이트');
  let v0 = data8.readUInt32LE(0), v1 = data8.readUInt32LE(4), sum = 0;
  for (let i = 0; i < 32; i++) {
    v0 = (v0 + ((((((v1 << 4) >>> 0) ^ (v1 >>> 5)) + v1) >>> 0) ^ ((sum + key[sum & 3]) >>> 0))) >>> 0;
    sum = (sum + DELTA) >>> 0;
    v1 = (v1 + ((((((v0 << 4) >>> 0) ^ (v0 >>> 5)) + v0) >>> 0) ^ ((sum + key[(sum >>> 11) & 3]) >>> 0))) >>> 0;
  }
  const out = Buffer.alloc(8); out.writeUInt32LE(v0, 0); out.writeUInt32LE(v1, 4); return out;
}
function xteaDecryptBlock(data8, key = XTEA_KEY) {
  if (data8.length !== 8) throw new Error('XTEA 블록은 8바이트');
  let v0 = data8.readUInt32LE(0), v1 = data8.readUInt32LE(4), sum = (DELTA * 32) >>> 0;
  for (let i = 0; i < 32; i++) {
    v1 = (v1 - ((((((v0 << 4) >>> 0) ^ (v0 >>> 5)) + v0) >>> 0) ^ ((sum + key[(sum >>> 11) & 3]) >>> 0))) >>> 0;
    sum = (sum - DELTA) >>> 0;
    v0 = (v0 - ((((((v1 << 4) >>> 0) ^ (v1 >>> 5)) + v1) >>> 0) ^ ((sum + key[sum & 3]) >>> 0))) >>> 0;
  }
  const out = Buffer.alloc(8); out.writeUInt32LE(v0, 0); out.writeUInt32LE(v1, 4); return out;
}

// ---------------------------------------------------------------------------
// [확정] CStreamCryptor_v1 패킷 난독화 (FUN_181272e40/fa0 포팅)
// ---------------------------------------------------------------------------
function obfEncrypt(payload, tag, key = Math.floor(Math.random() * 0x8000)) {
  const buf = Buffer.alloc(8 + payload.length);
  buf[0] = Math.floor(Math.random() * 256);
  buf[1] = tag & 0xFF;
  buf[2] = Math.floor(Math.random() * 256);
  buf.writeUInt32LE(key >>> 0, 3);
  buf[7] = Math.floor(Math.random() * 256);
  let prev = 0;
  for (let i = 0; i < payload.length; i++) {
    prev = ((key ^ payload[i] ^ prev) & 0xFF);
    buf[8 + i] = prev;
  }
  return Buffer.concat([Buffer.from(buf).reverse(), Buffer.from([0, 0])]); // 체크섬 플레이스홀더
}
function obfDecrypt(pkt) {
  if (pkt.length < 11) throw new Error('패킷 너무 짧음(' + pkt.length + ')');
  const body = pkt.subarray(0, pkt.length - 2);
  const checksum = pkt.subarray(pkt.length - 2);
  const buf = Buffer.from(body).reverse();
  const tag = buf[1];
  const key = buf.readUInt32LE(3);
  const payload = Buffer.alloc(buf.length - 8);
  let prev = 0;
  for (let i = 8; i < buf.length; i++) {
    payload[i - 8] = (key ^ prev ^ buf[i]) & 0xFF;
    prev = buf[i];
  }
  return { payload, tag, key, checksum };
}

// ---------------------------------------------------------------------------
// 로깅 유틸
// ---------------------------------------------------------------------------
const ASCII_RE = /[\x20-\x7e]{4,}/g;
const UTF16_RE = /(?:[\x20-\x7e]\x00){4,}/g;
function extractStrings(buf) {
  const out = [];
  let m; ASCII_RE.lastIndex = 0;
  while ((m = ASCII_RE.exec(buf)) !== null) out.push(['ascii', m.index, m[0]]);
  UTF16_RE.lastIndex = 0;
  while ((m = UTF16_RE.exec(buf)) !== null) out.push(['utf16le', m.index, m[0].toString('utf16le')]);
  out.sort((a, b) => a[1] - b[1]);
  return out;
}
function hexdump(data, limit = 512) {
  const lines = []; const n = Math.min(data.length, limit);
  for (let i = 0; i < n; i += 16) {
    const c = data.subarray(i, i + 16);
    const h = [...c].map((b) => b.toString(16).padStart(2, '0')).join(' ').padEnd(47);
    const a = [...c].map((b) => (b >= 0x20 && b < 0x7f) ? String.fromCharCode(b) : '.').join('');
    lines.push(i.toString(16).padStart(4, '0') + '  ' + h + '  ' + a);
  }
  if (data.length > n) lines.push('... (' + (data.length - n) + ' more bytes)');
  return lines.join('\n');
}

class Framer {
  constructor(spec) { this.spec = spec; this.buf = Buffer.alloc(0); this.desync = false; }
  get name() { return this.spec; }
  feed(data) {
    if (this.spec === 'raw') return [data];
    this.buf = Buffer.concat([this.buf, data]);
    const w = this.spec.startsWith('u16') ? 2 : 4;
    const inclHdr = this.spec.endsWith('h');
    const out = [];
    while (!this.desync) {
      if (this.buf.length < w) break;
      const n = w === 2 ? this.buf.readUInt16LE(0) : this.buf.readUInt32LE(0);
      const total = inclHdr ? n : n + w;
      if (n === 0 || total > 0x20000) { this.desync = true; break; }
      if (this.buf.length < total) break;
      out.push(this.buf.subarray(0, total));
      this.buf = this.buf.subarray(total);
    }
    if (this.desync && this.buf.length) { out.push(this.buf); this.buf = Buffer.alloc(0); }
    return out;
  }
}

class SessionLog {
  constructor(outdir) {
    this.outdir = outdir; this.seq = 0;
    fs.mkdirSync(outdir, { recursive: true });
    this.raw = { C2S: fs.openSync(path.join(outdir, 'c2s.bin'), 'a'), S2C: fs.openSync(path.join(outdir, 's2c.bin'), 'a') };
    this.rawSize = { C2S: 0, S2C: 0 };
    this.evF = fs.openSync(path.join(outdir, 'events.jsonl'), 'a');
    this.pkF = fs.openSync(path.join(outdir, 'packets.log'), 'a');
    this.stF = fs.openSync(path.join(outdir, 'strings.log'), 'a');
  }
  event(o) { o.ts = new Date().toISOString(); fs.writeSync(this.evF, JSON.stringify(o) + '\n'); }
  chunk(conn, dir, data) {
    fs.writeSync(this.raw[dir], data); this.rawSize[dir] += data.length;
    this.event({ ev: 'chunk', conn, dir, len: data.length, off: this.rawSize[dir] });
  }
  packet(conn, dir, pkt, framerName) {
    this.seq++;
    let deobf = null;
    try { deobf = obfDecrypt(pkt); } catch (e) { deobf = null; }
    const strs = extractStrings(pkt);
    const dstrs = deobf ? extractStrings(deobf.payload) : [];
    const hdr = '='.repeat(72) + '\n#' + this.seq + '  ' + dir + '  conn=' + conn +
      '  ' + new Date().toISOString() + '  ' + pkt.length + ' bytes  (' + framerName + ')\n';
    let body = '-- RAW --\n' + hexdump(pkt) + '\n';
    if (deobf) {
      body += '-- DEOBF v1 (tag=0x' + deobf.tag.toString(16).padStart(2, '0') +
        ' key=0x' + deobf.key.toString(16) + ' cksum=' + deobf.checksum.toString('hex') + ') --\n' +
        hexdump(deobf.payload) + '\n';
    } else if (pkt.length >= 11) {
      body += '-- DEOBF v1: 구조 불일치(리버스 후 태그/크기 검증 실패) — RAW 프레이밍 재검토 필요\n';
    }
    if (strs.length) { body += '-- strings(raw) --\n'; for (const [k, o, s] of strs) body += '  ' + k.padEnd(7) + ' +0x' + o.toString(16).padStart(4, '0') + ' ' + JSON.stringify(s) + '\n'; }
    if (dstrs.length) { body += '-- strings(deobf) --\n'; for (const [k, o, s] of dstrs) body += '  ' + k.padEnd(7) + ' +0x' + o.toString(16).padStart(4, '0') + ' ' + JSON.stringify(s) + '\n'; }
    fs.writeSync(this.pkF, hdr + body + '\n');
    if (strs.length || dstrs.length) {
      for (const [k, o, s] of strs) fs.writeSync(this.stF, dir + ' #' + this.seq + ' +' + o.toString(16) + ' ' + k + ' ' + JSON.stringify(s) + '\n');
      for (const [k, o, s] of dstrs) fs.writeSync(this.stF, dir + '(deobf) #' + this.seq + ' +' + o.toString(16) + ' ' + k + ' ' + JSON.stringify(s) + '\n');
    }
  }
}

function pump(src, dst, dir, slog, conn, framer) {
  src.on('data', (d) => {
    slog.chunk(conn, dir, d);
    for (const p of framer.feed(d)) slog.packet(conn, dir, p, framer.name);
    dst.write(d);
  });
  src.on('close', () => { slog.event({ ev: 'half_close', conn, dir }); try { dst.end(); } catch (e) {} });
  src.on('error', (e) => { slog.event({ ev: 'pump_error', conn, dir, err: String(e) }); try { dst.destroy(); } catch (e2) {} });
}

function startProxy(opts) {
  const slog = new SessionLog(opts.outdir);
  fs.writeFileSync(path.join(opts.outdir, 'meta.json'), JSON.stringify({
    listen: opts.listenHost + ':' + opts.listenPort,
    upstream: opts.upstreamHost + ':' + opts.upstreamPort,
    framing: opts.framing, started: new Date().toISOString(),
  }, null, 2));
  const srv = net.createServer((client) => {
    const conn = ++startProxy.connSeq;
    slog.event({ ev: 'open', conn, peer: client.remoteAddress + ':' + client.remotePort });
    const up = net.connect(opts.upstreamPort, opts.upstreamHost, () => {
      slog.event({ ev: 'upstream_ok', conn });
    });
    up.on('error', (e) => { slog.event({ ev: 'upstream_fail', conn, err: String(e) }); client.destroy(); });
    up.on('close', () => { slog.event({ ev: 'close', conn }); client.destroy(); });
    const fC = new Framer(opts.framing), fS = new Framer(opts.framing);
    pump(client, up, 'C2S', slog, conn, fC);
    pump(up, client, 'S2C', slog, conn, fS);
  });
  startProxy.connSeq = 0;
  srv.listen(opts.listenPort, opts.listenHost);
  return { srv, slog };
}
startProxy.connSeq = 0;

function parseArgs() {
  const a = process.argv.slice(2);
  const o = { listen: '127.0.0.1:12000', upstream: '175.207.21.11:12000', framing: 'u16', outdir: null, selftest: false };
  for (let i = 0; i < a.length; i++) {
    if (a[i] === '--listen') o.listen = a[++i];
    else if (a[i] === '--upstream') o.upstream = a[++i];
    else if (a[i] === '--framing') o.framing = a[++i];
    else if (a[i] === '--outdir') o.outdir = a[++i];
    else if (a[i] === '--selftest') o.selftest = true;
  }
  const [lh, lp] = o.listen.split(':'); o.listenHost = lh; o.listenPort = parseInt(lp, 10);
  const [uh, up2] = o.upstream.split(':'); o.upstreamHost = uh; o.upstreamPort = parseInt(up2, 10);
  if (!o.outdir) o.outdir = path.join('H:', 'SA_Analysis', 'logs', 'session_' + new Date().toISOString().replace(/[-:T.]/g, '').slice(0, 14));
  return o;
}

async function selftest() {
  // 1) XTEA 왕복
  for (let i = 0; i < 64; i++) {
    const msg = Buffer.alloc(8);
    msg.writeBigUInt64LE((0x0123456789ABCDEFn * BigInt(i + 1)) & 0xFFFFFFFFFFFFFFFFn);
    const ct = xteaEncryptBlock(msg);
    if (!xteaDecryptBlock(ct).equals(msg)) throw new Error('XTEA 왕복 실패 @' + i);
  }
  console.log('[OK] XTEA-32 왕복 (고정키 "156def789023abc4")');

  // 2) 패킷 난독화 왕복
  for (const n of [1, 7, 64, 300]) {
    const payload = Buffer.alloc(n); for (let i = 0; i < n; i++) payload[i] = (i * 31 + 7) & 0xff;
    const pkt = obfEncrypt(payload, 0x5A, 0x1234);
    if (pkt.length !== n + 10) throw new Error('크기 불일치');
    const r = obfDecrypt(pkt);
    if (!r.payload.equals(payload) || r.key !== 0x1234 || r.tag !== 0x5A) throw new Error('난독화 왕복 실패 n=' + n);
  }
  console.log('[OK] 패킷 난독화 왕복 (롤링 XOR + 리버스, 키 내장)');

  // 3) 가짜 upstream + 프록시 + 가짜 client — 난독화 패킷이 로그에 복호되는지
  const upSrv = net.createServer((s) => {
    s.on('data', (d) => {
      let off = 0;
      while (off + 2 <= d.length) {
        const n = d.readUInt16LE(off);
        const payload = d.subarray(off + 2, off + 2 + n);
        off += 2 + n;
        const resp = Buffer.alloc(2 + 1 + payload.length);
        resp.writeUInt16LE(1 + payload.length, 0); resp[2] = 0xAA; payload.copy(resp, 3);
        s.write(resp);
      }
    });
  });
  await new Promise((r) => upSrv.listen(0, '127.0.0.1', r));
  const upPort = upSrv.address().port;
  const outdir = path.join('H:', 'SA_Analysis', 'logs', 'selftest_' + Date.now());
  const { srv } = startProxy({ listenHost: '127.0.0.1', listenPort: 0, upstreamHost: '127.0.0.1', upstreamPort: upPort, framing: 'u16', outdir });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const pxPort = srv.address().port;

  const sent = ['hello proxy', 'SECOND-packet!'];
  const cli = net.connect(pxPort, '127.0.0.1');
  const got = [];
  await new Promise((resolve) => {
    let buf = Buffer.alloc(0);
    cli.on('data', (d) => {
      buf = Buffer.concat([buf, d]);
      while (buf.length >= 2) {
        const n = buf.readUInt16LE(0);
        if (buf.length < 2 + n) break;
        const body = buf.subarray(2, 2 + n); // [0]=0xAA 접두 + 난독화 블록
        got.push(obfDecrypt(body.subarray(1)).payload.toString('latin1'));
        buf = buf.subarray(2 + n);
      }
      if (got.length >= sent.length) resolve();
    });
    // 보내는 패킷을 실제 프로토콜처럼 "난독화 + u16 프레임"으로 구성
    for (const s of sent) {
      const obf = obfEncrypt(Buffer.from(s, 'latin1'), 0x5A, 0x4242);
      const p = Buffer.alloc(2 + obf.length); p.writeUInt16LE(obf.length, 0); obf.copy(p, 2);
      cli.write(p);
    }
  });
  cli.destroy(); srv.close(); upSrv.close();
  await new Promise((r) => setTimeout(r, 300));

  if (JSON.stringify(got) !== JSON.stringify(sent)) throw new Error('echo 불일치: ' + JSON.stringify(got));
  const c2s = fs.readFileSync(path.join(outdir, 'c2s.bin'));
  const s2c = fs.readFileSync(path.join(outdir, 's2c.bin'));
  const pk = fs.readFileSync(path.join(outdir, 'packets.log'), 'utf8');
  if (!pk.includes('DEOBF v1 (tag=0x5a key=0x4242')) throw new Error('DEOBF 헤더 없음');
  if (!pk.includes('hello proxy') || !pk.includes('SECOND-packet!')) throw new Error('DEOBF 페이로드 문자열 없음');
  const pktCount = (pk.match(/^#\d+/gm) || []).length;
  if (pktCount !== sent.length * 2) throw new Error('패킷 수 불일치: ' + pktCount);
  const ev = fs.readFileSync(path.join(outdir, 'events.jsonl'), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
  if (!ev.some((e) => e.ev === 'open') || !ev.some((e) => e.ev === 'upstream_ok')) throw new Error('연결 이벤트 누락');
  console.log('[OK] 프록시 파이프라인: 난독화 패킷 자동 복호 확인 (echo=' + JSON.stringify(got) + ')');
  console.log('     c2s=%dB s2c=%dB packets=%d events=%d, 로그: %s', c2s.length, s2c.length, pktCount, ev.length, outdir);
  console.log('[OK] selftest 통과');
}

if (require.main === module) {
  const o = parseArgs();
  if (o.selftest) { selftest().catch((e) => { console.error('[FAIL]', e); process.exit(1); }); return; }
  const { srv } = startProxy(o);
  console.log('[*] 수신 중 %s:%d → %s:%d', o.listenHost, o.listenPort, o.upstreamHost, o.upstreamPort);
  console.log('[*] 로그 디렉터리: %s', o.outdir);
  console.log('[*] 종료: Ctrl+C');
  process.on('SIGINT', () => { console.log('[*] 종료됨'); srv.close(() => process.exit(0)); setTimeout(() => process.exit(0), 1000); });
}
module.exports = { startProxy, SessionLog, Framer, xteaEncryptBlock, xteaDecryptBlock, obfEncrypt, obfDecrypt };
