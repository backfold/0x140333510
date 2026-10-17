#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sa_proxy.py — SuddenAttack 서버 트래픽 캡처용 로컬 TCP 중계(MITM) 프록시.

구조:
    게임 클라이언트 ──> 127.0.0.1:<listen> (프록시) ──> <upstream 호스트:포트> (실제 서버)
    양방향 바이트는 그대로 전달(pass-through) 하면서:
      - 원문 스트림:  logs/<session>/c2s.bin, s2c.bin
      - 이벤트 로그:  logs/<session>/events.jsonl  (연결/청크/패킷/종료)
      - 패킷 로그:    logs/<session>/packets.log   (hexdump + 복호화 시도 + 문자열 추출)
      - 문자열 로그:  logs/<session>/strings.log

복호화:
    keys.json (선택) 에 키를 넣으면 패킷 단위 XXTEA 복호를 시도한다.
    현재(2026-10-18) XXTEA 키 파생 경로는 REA session 28 디컴파일 확정 전이므로
    기본 동작은 "원문 캡처 + 문자열 추출 + 프레이밍 통계" 이다.
    keys.json 형식:
        {
          "xxtea_c2s": "<32 hex chars — 16바이트 키>",
          "xxtea_s2c": "<32 hex chars>",
          "byteorder": "little"
        }

프레이밍:
    --framing u16|u32|raw  (기본 u16). 길이 접두사 규격은 아직 와이어 확인 전
    [추정] 이다. desync(비정상 길이) 감지 시 해당 방향을 raw 청크로 자동 전환하고
    warn 이벤트를 남긴다.

실행 예:
    python sa_proxy.py --listen 127.0.0.1:12000 --upstream 175.207.21.11:12000
    python sa_proxy.py --listen 127.0.0.1:12000 --upstream 175.207.21.11:12000 \
        --keys keys.json --framing u16

주의: 게임 실행 인자(-passarg)의 서버 주소를 127.0.0.1 로 바꿔 실행해야
      프록시로 유입된다. 자세한 방법은 PROXY_USAGE.md.
"""

from __future__ import print_function

import argparse
import json
import os
import re
import socket
import struct
import sys
import threading
import time

try:
    from sa_net_crypto import obf_decrypt  # 같은 디렉터리 (CStreamCryptor_v1)
except Exception:
    obf_decrypt = None

ASCII_RE = re.compile(rb'[\x20-\x7e]{4,}')
UTF16_RE = re.compile(rb'(?:[\x20-\x7e]\x00){4,}')

DIRECTIONS = ('C2S', 'S2C')


def now_iso():
    t = time.time()
    return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(t)) + '.%03d' % int((t % 1) * 1000)


def hexdump(data, limit=512):
    lines = []
    n = min(len(data), limit)
    for i in range(0, n, 16):
        chunk = data[i:i + 16]
        h = ' '.join('%02x' % b for b in chunk)
        h = h.ljust(47)
        a = ''.join(chr(b) if 0x20 <= b < 0x7f else '.' for b in chunk)
        lines.append('%04x  %s  %s' % (i, h, a))
    if len(data) > n:
        lines.append('... (%d more bytes)' % (len(data) - n))
    return '\n'.join(lines)


def extract_strings(data):
    out = []
    for m in ASCII_RE.finditer(data):
        out.append(('ascii', m.start(), m.group().decode('ascii')))
    for m in UTF16_RE.finditer(data):
        out.append(('utf16le', m.start(), m.group().decode('utf-16-le')))
    out.sort(key=lambda x: x[1])
    return out


# ---------------------------------------------------------------------------
# 프레이밍 [추정 — 와이어 확인 전]
# ---------------------------------------------------------------------------
class RawFramer(object):
    name = 'raw'

    def feed(self, data):
        return [data]


class LenPrefixedFramer(object):
    """u16/u32 리틀엔디언 길이 접두사 프레이머. desync 시 raw 전환."""

    def __init__(self, width, includes_header=False, max_frame=0x20000):
        self.width = width
        self.includes_header = includes_header
        self.max_frame = max_frame
        self.buf = bytearray()
        self.desync = False

    @property
    def name(self):
        return 'u%d%s' % (self.width * 8, '+hdr' if self.includes_header else '')

    def feed(self, data):
        self.buf.extend(data)
        out = []
        while not self.desync:
            if len(self.buf) < self.width:
                break
            if self.width == 2:
                n = struct.unpack_from('<H', self.buf, 0)[0]
            else:
                n = struct.unpack_from('<I', self.buf, 0)[0]
            total = n if self.includes_header else n + self.width
            if n == 0 or total > self.max_frame:
                self.desync = True
                break
            if len(self.buf) < total:
                break
            out.append(bytes(self.buf[:total]))
            del self.buf[:total]
        if self.desync and self.buf:
            out.append(bytes(self.buf))
            del self.buf[:]
        return out


def make_framer(spec):
    if spec == 'raw':
        return RawFramer()
    if spec == 'u16':
        return LenPrefixedFramer(2)
    if spec == 'u16h':
        return LenPrefixedFramer(2, includes_header=True)
    if spec == 'u32':
        return LenPrefixedFramer(4)
    if spec == 'u32h':
        return LenPrefixedFramer(4, includes_header=True)
    raise ValueError('알 수 없는 framing: %s' % spec)


# ---------------------------------------------------------------------------
# 세션 로거
# ---------------------------------------------------------------------------
class SessionLog(object):
    def __init__(self, outdir, keys):
        self.outdir = outdir
        self.keys = keys or {}
        self.lock = threading.Lock()
        self.pkt_seq = 0
        os.makedirs(outdir, exist_ok=True)
        self.raw = {d: open(os.path.join(outdir, d.lower() + '.bin'), 'wb')
                    for d in DIRECTIONS}
        self.events_f = open(os.path.join(outdir, 'events.jsonl'), 'a')
        self.packets_f = open(os.path.join(outdir, 'packets.log'), 'a')
        self.strings_f = open(os.path.join(outdir, 'strings.log'), 'a')

    def close(self):
        for f in list(self.raw.values()) + [self.events_f, self.packets_f, self.strings_f]:
            try:
                f.close()
            except Exception:
                pass

    def event(self, obj):
        obj['ts'] = now_iso()
        with self.lock:
            self.events_f.write(json.dumps(obj, ensure_ascii=False) + '\n')
            self.events_f.flush()

    def chunk(self, conn_id, direction, data):
        with self.lock:
            self.raw[direction].write(data)
        self.event({'ev': 'chunk', 'conn': conn_id, 'dir': direction,
                    'len': len(data),
                    'off': self.raw[direction].tell()})

    def packet(self, conn_id, direction, pkt, framer_name):
        with self.lock:
            self.pkt_seq += 1
            seq = self.pkt_seq
        dec = self._try_decrypt(direction, pkt)
        strs = extract_strings(pkt)
        dec_strs = extract_strings(dec['payload']) if isinstance(dec, dict) else []
        with self.lock:
            w = self.packets_f.write
            w('=' * 72 + '\n')
            w('#%d  %s  conn=%d  %s  %d bytes  (%s)\n'
              % (seq, direction, conn_id, now_iso(), len(pkt), framer_name))
            w('-- RAW --\n%s\n' % hexdump(pkt))
            if isinstance(dec, dict):
                w('-- DEOBF v1 (tag=0x%02x key=0x%x cksum=%s) --\n%s\n'
                  % (dec['tag'], dec['key'], dec['checksum'].hex()),
                  hexdump(dec['payload']))
            elif dec is not None:
                w('-- DEOBF v1: %r\n' % (dec,))
            if strs:
                w('-- strings(raw) --\n')
                for kind, off, s in strs:
                    w('  %-7s +0x%04x %r\n' % (kind, off, s))
            if dec_strs:
                w('-- strings(deobf) --\n')
                for kind, off, s in dec_strs:
                    w('  %-7s +0x%04x %r\n' % (kind, off, s))
            w('\n')
            self.packets_f.flush()
            if strs or dec_strs:
                for kind, off, s in strs:
                    self.strings_f.write('%s #%d %s +0x%04x %s %r\n'
                                         % (now_iso(), seq, direction, off, kind, s))
                for kind, off, s in dec_strs:
                    self.strings_f.write('%s #%d %s(dec) +0x%04x %s %r\n'
                                         % (now_iso(), seq, direction, off, kind, s))
                self.strings_f.flush()

    def _key_name(self, direction):
        return 'xxtea_%s' % direction.lower()

    def _try_decrypt(self, direction, pkt):
        """CStreamCryptor_v1 난독화 자동 복호 시도 (키가 패킷에内장)."""
        if obf_decrypt is None or len(pkt) < 11:
            return None
        try:
            return obf_decrypt(pkt)
        except Exception as e:
            return ('error', repr(e))


# ---------------------------------------------------------------------------
# 프록시
# ---------------------------------------------------------------------------
def pump(src, dst, direction, slog, conn_id, framer):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            slog.chunk(conn_id, direction, data)
            try:
                pkts = framer.feed(data)
            except Exception as e:
                slog.event({'ev': 'framer_error', 'conn': conn_id,
                            'dir': direction, 'err': repr(e)})
                pkts = []
            for p in pkts:
                slog.packet(conn_id, direction, p, framer.name)
            dst.sendall(data)
    except Exception as e:
        slog.event({'ev': 'pump_error', 'conn': conn_id,
                    'dir': direction, 'err': repr(e)})
    finally:
        slog.event({'ev': 'half_close', 'conn': conn_id, 'dir': direction})
        try:
            dst.shutdown(socket.SHUT_WR)
        except Exception:
            pass


def handle_conn(client, addr, args, slog, conn_id):
    slog.event({'ev': 'open', 'conn': conn_id,
                'peer': '%s:%d' % (addr[0], addr[1])})
    try:
        upstream = socket.create_connection((args.upstream_host,
                                             args.upstream_port), timeout=15)
    except Exception as e:
        slog.event({'ev': 'upstream_fail', 'conn': conn_id, 'err': repr(e)})
        try:
            client.close()
        except Exception:
            pass
        return
    for s in (client, upstream):
        try:
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except Exception:
            pass
    framers = {'C2S': make_framer(args.framing), 'S2C': make_framer(args.framing)}
    slog.event({'ev': 'upstream_ok', 'conn': conn_id,
                'upstream': '%s:%d' % (args.upstream_host, args.upstream_port)})
    t = threading.Thread(target=pump,
                         args=(client, upstream, 'C2S', slog, conn_id, framers['C2S']))
    t.daemon = True
    t.start()
    pump(upstream, client, 'S2C', slog, conn_id, framers['S2C'])
    t.join(timeout=5)
    for s in (client, upstream):
        try:
            s.close()
        except Exception:
            pass
    slog.event({'ev': 'close', 'conn': conn_id})


def parse_endpoint(s, default_host='127.0.0.1'):
    if ':' in s:
        h, p = s.rsplit(':', 1)
        return (h, int(p))
    return (default_host, int(s))


def main():
    ap = argparse.ArgumentParser(description='SuddenAttack TCP 캡처 프록시')
    ap.add_argument('--listen', default='127.0.0.1:12000',
                    help='로컬 수신 주소 (기본 127.0.0.1:12000)')
    ap.add_argument('--upstream', default='175.207.21.11:12000',
                    help='실제 서버 주소 (기본 175.207.21.11:12000)')
    ap.add_argument('--outdir', default=None,
                    help='로그 디렉터리 (기본 H:\\SA_Analysis\\logs\\session_시각)')
    ap.add_argument('--keys', default=None,
                    help='keys.json (xxtea_c2s/xxtea_s2c hex)')
    ap.add_argument('--framing', default='u16',
                    choices=['raw', 'u16', 'u16h', 'u32', 'u32h'],
                    help='패킷 길이 접두사 추정 방식 [추정]')
    args = ap.parse_args()

    args.listen_host, args.listen_port = parse_endpoint(args.listen)
    args.upstream_host, args.upstream_port = parse_endpoint(args.upstream)

    if args.outdir is None:
        args.outdir = os.path.join(
            'H:' + os.sep + 'SA_Analysis', 'logs',
            'session_' + time.strftime('%Y%m%d_%H%M%S'))
    keys = None
    if args.keys:
        with open(args.keys, 'r') as f:
            keys = json.load(f)

    slog = SessionLog(args.outdir, keys)
    with open(os.path.join(args.outdir, 'meta.json'), 'w') as f:
        json.dump({'listen': '%s:%d' % (args.listen_host, args.listen_port),
                   'upstream': '%s:%d' % (args.upstream_host, args.upstream_port),
                   'framing': args.framing,
                   'keys_loaded': sorted(keys.keys()) if keys else [],
                   'xxtea_module': xxtea_decrypt is not None,
                   'started': now_iso()}, f, indent=2)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.listen_host, args.listen_port))
    srv.listen(8)
    print('[*] 수신 중 %s:%d → %s:%d' % (args.listen_host, args.listen_port,
                                        args.upstream_host, args.upstream_port))
    print('[*] 로그 디렉터리: %s' % args.outdir)
    print('[*] 종료: Ctrl+C')
    slog.event({'ev': 'proxy_start'})

    conn_id = 0
    try:
        while True:
            client, addr = srv.accept()
            conn_id += 1
            print('[+] conn#%d from %s:%d' % (conn_id, addr[0], addr[1]))
            t = threading.Thread(target=handle_conn,
                                 args=(client, addr, args, slog, conn_id))
            t.daemon = True
            t.start()
    except KeyboardInterrupt:
        pass
    finally:
        slog.event({'ev': 'proxy_stop'})
        slog.close()
        srv.close()
        print('[*] 종료됨')


if __name__ == '__main__':
    main()
