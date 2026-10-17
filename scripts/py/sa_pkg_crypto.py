# -*- coding: utf-8 -*-
"""
sa_pkg_crypto.py — SuddenAttack .pkg 컨테이너 암호화 (Nexon Snow2) Python 구현.

근거 (H:\SA_Analysis, REA sessions 11-26):
  - Lambda::SnowCipher = Nexon "Snow2" (SNOW 2.0 파생, MapleStory .ms v2와 동일 원시).
    suddenattack.exe .rdata 6개 테이블이 MapleLib Snow2CryptoTransform 테이블과
    바이트 단위로 일치 (evidence/snow_tables_from_exe.json, all_tables_match_maplelib=true).
  - 키 유도/N1/N2/헤더 복호화: FUN_14029f470 / FUN_14029f6b0 / FUN_14029f920 /
    FUN_14029fa20 / FUN_1402b1b50 / FUN_1402a9fc0 디컴파일.
  - 실제 파일 검증: global_00000.pkg (6/6 엔트리), texturescripts_00000.pkg (16/16).

테이블이 없으면 파일을 읽어 자체 생성하지 않는다 — 검증된 테이블 JSON
(evidence/snow_tables_from_exe.json) 또는 아래 내장 첫 워드로 로드한다.
내장 KAT(known-answer test): global_00000.pkg key1의 첫 키스트림 2워드.

사용 예:
    from sa_pkg_crypto import Snow2, derive_keys, parse_header
    hdr = parse_header(open('global_00000.pkg','rb').read(), 'global_00000.pkg')
    k1, k2 = derive_keys(hdr['path'], hdr['header_str'])
    plain = Snow2(k1).decrypt(open('global_00000.pkg','rb').read()[hdr['data_start']:])
"""

import struct

DELTA_MASK = 0xFFFFFFFF


def _load_tables(json_path):
    """evidence/snow_tables_from_exe.json 에서 6개 테이블(words 배열)을 로드."""
    import json
    with open(json_path, 'r') as f:
        data = json.load(f)
    t = data['tables']
    return {name: t[name]['words'] for name in t}


class Snow2:
    """SNOW 2.0 (Nexon 변형, MapleLib Snow2CryptoTransform 포팅).

    - 16바이트 키를 부호 있는 바이트(signed char)로 확장해 BE 워드 4개 생성,
      나머지 LFSR은 키/보수로 채움 (s15..s12=키, s11..s8=~키, s7..s4=키, s3..s0=~키).
    - IV 없음(0), 초기 32 클록(init 모드: FSM 출력이 LFSR 피드백에 XOR).
    - 키스트림은 16워드 블록 단위 생성(keystream 모드: FSM 피드백 없음).
    - 데이터와의 결합은 32비트 덧셈(암호화)/뺄셈(복호화), 리틀엔디언 워드.
    """

    def __init__(self, key16, tables):
        assert len(key16) == 16
        s = [0] * 16
        for k in range(4):
            b = key16[4 * k:4 * k + 4]
            w = 0
            for x in b:
                # 부호 확장: MSVC (char)x<<n 의 시맨틱. 파이썬은 임의 정수라 마스크로 시뮬레이션.
                sx = x - 256 if x & 0x80 else x
                w = ((w << 8) | (sx & 0xFF)) & DELTA_MASK
            s[15 - k] = w
            s[11 - k] = (~w) & DELTA_MASK
            s[7 - k] = w
            s[3 - k] = (~w) & DELTA_MASK
        self.s = s
        self.r1 = 0
        self.r2 = 0
        self._t = tables
        self._ks = []
        self._ks_pos = 16  # 다음 next_word()에서 블록 재생성
        for k in range(32):
            self._init_step(k % 16)

    # --- 테이블 헬퍼 ---
    def _a_mul(self, w):
        return (((w << 8) & DELTA_MASK) ^ self._t['snow_alpha_mul'][(w >> 24) & 0xFF]) & DELTA_MASK

    def _ainv_mul(self, w):
        return ((w >> 8) ^ self._t['snow_alphainv_mul'][w & 0xFF]) & DELTA_MASK

    def _fsm_t(self, w):
        t = self._t
        return (t['snow_T0'][w & 0xFF] ^ t['snow_T1'][(w >> 8) & 0xFF]
                ^ t['snow_T2'][(w >> 16) & 0xFF] ^ t['snow_T3'][(w >> 24) & 0xFF]) & DELTA_MASK

    def _init_step(self, k):
        s = self.s
        out = ((self.r1 + s[(k + 15) % 16]) & DELTA_MASK) ^ self.r2
        ns = (self._a_mul(s[k]) ^ s[(k + 2) % 16] ^ self._ainv_mul(s[(k + 11) % 16]) ^ out) & DELTA_MASK
        tmp = (self.r2 + s[(k + 5) % 16]) & DELTA_MASK
        s[k] = ns
        self.r2 = self._fsm_t(self.r1)
        self.r1 = tmp

    def _ks_step(self, k):
        s = self.s
        ns = (self._a_mul(s[k]) ^ s[(k + 2) % 16] ^ self._ainv_mul(s[(k + 11) % 16])) & DELTA_MASK
        tmp = (self.r2 + s[(k + 5) % 16]) & DELTA_MASK
        old_next = s[(k + 1) % 16]
        s[k] = ns
        self.r2 = self._fsm_t(self.r1)
        self.r1 = tmp
        return (((self.r1 + ns) & DELTA_MASK) ^ self.r2 ^ old_next) & DELTA_MASK

    def next_word(self):
        if self._ks_pos >= 16:
            self._ks = [self._ks_step(k) for k in range(16)]
            self._ks_pos = 0
        w = self._ks[self._ks_pos]
        self._ks_pos += 1
        return w

    # --- 공개 인터페이스 ---
    def keystream(self, n_words):
        return [self.next_word() for _ in range(n_words)]

    def encrypt(self, data):
        """데이터(길이 4의 배수 권장)에 키스트림을 더해 암호문 반환."""
        out = bytearray(data)
        for i in range(0, len(out) - 3, 4):
            w = struct.unpack_from('<I', out, i)[0]
            w = (w + self.next_word()) & DELTA_MASK
            struct.pack_into('<I', out, i, w)
        return bytes(out)

    def decrypt(self, data):
        """암호문에서 키스트림을 빼 평문 반환."""
        out = bytearray(data)
        for i in range(0, len(out) - 3, 4):
            w = struct.unpack_from('<I', out, i)[0]
            w = (w - self.next_word()) & DELTA_MASK
            struct.pack_into('<I', out, i, w)
        return bytes(out)


def char_sum(s):
    """UTF-16 코드유닛 합 (N1/N2 계산용; 경로는 BMP 내 ASCII 가정)."""
    return sum(ord(c) for c in s) & DELTA_MASK


def n1_of(path):
    """N1 = (Σ chars) mod 312 + 30   (FUN_14029fa20)."""
    return char_sum(path) % 312 + 30


def n2_of(path):
    """N2 = (3·Σ chars) mod 212 + 33  (FUN_14029f920)."""
    return (char_sum(path) * 3) % 212 + 33


def unmask_byte(b):
    """v1 마스크 해제: (b >> 1) 산술 시프트 = (b >> 1) | (b & 0x80)."""
    return (b >> 1) | (b & 0x80)


def sext8(b):
    return b - 256 if b & 0x80 else b


def sext16(b):
    v = sext8(b)
    return v & 0xFFFF


def parse_header(buf, path):
    """.pkg 헤더 레이어 파싱 → dict (data_start 까지)."""
    n1 = n1_of(path)
    masked = buf[:n1]
    version_byte = buf[n1]
    v1 = ((unmask_byte(masked[0]) ^ version_byte) & 0xFF) == 3
    key = bytearray(unmask_byte(b) if v1 else b for b in masked)
    pos = n1 + (1 if v1 else 0)
    raw_len = struct.unpack_from('<I', buf, pos)[0]
    length = (raw_len ^ (sext8(key[0]) & DELTA_MASK)) & DELTA_MASK
    pos += 4
    chars = []
    for i in range(length):
        enc = struct.unpack_from('<H', buf, pos + i * 2)[0]
        k = sext16(key[i % n1])
        chars.append(enc ^ k)
    header_str = ''.join(chr(c & 0xFFFF) for c in chars)
    return {
        'path': path, 'n1': n1, 'n2': n2_of(path), 'v1': v1,
        'length': length, 'header_str': header_str,
        'data_start': pos + length * 2,
    }


def derive_keys(path, header_str):
    """key1/key2 (각 128바이트 중 하위 16바이트만 Snow2에 사용).

    concat = path + header_str (UTF-16 코드유닛열), L = 길이.
    key1[i] = (i + concat[i mod L]) mod 256                  (FUN_14029f470)
    key2[i] = (concat[L-(i mod L)-1]·((i mod 3)+2) + i) mod 256  (FUN_14029f6b0)
    """
    concat = [ord(c) & 0xFF for c in (path + header_str)]
    L = len(concat)
    k1 = bytearray(16)
    k2 = bytearray(16)
    for i in range(16):
        k1[i] = (i + concat[i % L]) & 0xFF
        k2[i] = (concat[L - (i % L) - 1] * ((i % 3) + 2) + i) & 0xFF
    return bytes(k1), bytes(k2)


# ---------------------------------------------------------------------------
# Known-answer test — 2026-10-18 실측값 (evidence/snow2_identification.md).
# global_00000.pkg, path="global_00000.pkg", header="!dlstps20djr@" 일 때
#   key1 = 67 6d 71 65 65 71 65 37 38 39 3a 3b 3a 7d 79 76
#   첫 키스트림 2워드 (LE 데이터 워드 복호 결과에서 역산):
#     data_start(141)의 암호문 13 96 a1 de | b6 ca 1d 38
#     평문                     25 00 08 00 | 06 00 00 00  ([checksum=524325][count=6])
#     → ks[0]=0xDE9995EE, ks[1]=0x381DCAB0
# ---------------------------------------------------------------------------
KAT_KEY1 = bytes.fromhex('676d71656571653738393a3b3a7d7976')
KAT_KEYSTREAM = [0xDE9995EE, 0x381DCAB0]


def self_test(tables):
    k1, _ = derive_keys('global_00000.pkg', '!dlstps20djr@')
    assert k1 == KAT_KEY1, 'key1 KAT 불일치: %s' % k1.hex()
    c = Snow2(k1, tables)
    ks = c.keystream(2)
    assert ks == KAT_KEYSTREAM, 'keystream KAT 불일치: got %s want %s' % (
        [hex(x) for x in ks], [hex(x) for x in KAT_KEYSTREAM])
    # 왕복 테스트
    msg = b'Hello, SuddenAttack pkg! xx'  # 28바이트 = 7워드
    enc = Snow2(k1, tables).encrypt(msg)
    dec = Snow2(k1, tables).decrypt(enc)
    assert dec == msg, 'round-trip 실패'
    print('[OK] Snow2 KAT + round-trip 통과')
    print('     key1 =', k1.hex())
    print('     ks[0:2] =', ' '.join('%08x' % w for w in ks))


if __name__ == '__main__':
    import sys
    tbl = _load_tables(sys.argv[1] if len(sys.argv) > 1
                       else 'snow_tables_from_exe.json')
    self_test(tbl)
