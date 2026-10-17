# -*- coding: utf-8 -*-
"""
sa_net_crypto.py — SuddenAttack 네트워크 암호 (cshell.dll) Python 구현.

근거 (H:\SA_Analysis, REA sessions 27-28 + 로컬 정적 분석, 2026-10-18):

【확정】XTEA-32 (로그인용 8바이트 블록 암호)
    - 코어 enc 0x180d5ef00 / dec 0x180d5e9c0 (cshell.dll). 표준 XTEA 32라운드.
      enc: v0 += (((v1<<4)^(v1>>5))+v1) ^ (sum + k[sum&3]); sum+=Δ;
           v1 += (((v0<<4)^(v0>>5))+v0) ^ (sum + k[(sum>>11)&3])
      dec: 초기 sum=0xC6EF3720(=Δ*32), 역순.
    - 하드코딩 키 u32[4] = {0x64363531, 0x38376665, 0x33323039, 0x34636261}
      → 리틀엔디언 바이트열 "156def789023abc4".
    - 래퍼 enc 0x180d5e0e0: 8바이트 값 → XTEA → "%02X" 대문자 헥스 16자
      (포맷 문자열 @0x1815ffd30) + "SA" 접미 (@0x1815ffd38) → std::string.
      dec 0x180d5e2e0: 문자열 끝 2자("SA") 제거 → 헥스 디코드(0x180d5e6c0)
      → XTEA 복호 → 8바이트. 로그인 비밀번호/토큰 난독화로 추정 [추론].
    - xrefs: .vlizer(VM 보호 영역) 0x18215b904/0x18215b910 에서도 호출.

【확정】CStreamCryptor_v1 패킷 난독화 (enc 0x181272e40 / dec 0x181272fa0,
         vftable 0x181658fd8 각각 +0x08/+0x10 슬롯)
    암호화(payload, 태그바이트 T):
      1. srand(GetTickCount()); key = rand()  [MSVC rand → 0..0x7FFF, 15비트]
      2. buf[0]=rand()&0xff, buf[1]=T, buf[2]=rand()&0xff,
         buf[3..7)=key(u32 LE), buf[7]=rand()&0xff          ← 헤더 8바이트
      3. buf[8+i] = key ^ payload[i] ^ buf[8+i-1]  (buf[8-1]=0; 롤링 XOR)
      4. out = reverse(buf[0 .. 8+len))                     ← 전체 리버스
      5. out[8+len .. 8+len+2) = u16 체크섬(this, out, 8+len)  [0x181272bc0 —
         세션 29 대기, 검증 생략 가능]
      최종 크기 = len + 10.
    복호화: 체크섬(마지막 u16) 검증 → (size-2)바이트 리버스 → buf[1]==태그 확인
      → key = u32@buf[3] → plain[i] = key ^ prev ^ buf[8+i] (prev=직전 암호문바이트).
      ※ 키가 패킷 헤더 안에 있어 자기기술적 — 키 몰라도 복호 가능.
    v1 태그바이트 게터 = vftable+0x18 → 0x181273720 (세션 29 디컴파일 대기).

【확정】CPHObject 헤더 XOR (기계어 직독, session 27)
    - XOR_1 @0x1811996e0: [rcx+0x38]^[rcx+0x30]^[rcx+8]
    - XOR_2 @0x1811999b0: [rcx+0x40]^[rcx+0x38]^[rcx+8]

【대기 — 세션 29】u16 체크섬 0x181272bc0, v1 태그값(0x181273720),
    v0/v1 나머지 슬롯, enc/dec 호출자(xrefs) → 실제 와이어 사용 여부.

※ 세션 27 단계의 "XXTEA" 식별은 오류였음을 정정: 0x9E3779B9 상수와
  언롤 구조만 보고 XXTEA로 추정했으나 디컴파일 결과 64비트 블록
  표준 XTEA가 맞다.
"""

import struct

M = 0xFFFFFFFF
DELTA = 0x9E3779B9

# ---------------------------------------------------------------------------
# [확정] XTEA-32 (cshell.dll 0x180d5ef00 / 0x180d5e9c0)
# ---------------------------------------------------------------------------
XTEA_KEY_WORDS = (0x64363531, 0x38376665, 0x33323039, 0x34636261)
XTEA_KEY_BYTES = struct.pack('<4I', *XTEA_KEY_WORDS)  # b'156def789023abc4'


def xtea_encrypt_block(data8, key_words=XTEA_KEY_WORDS):
    """8바이트 블록 1개 암호화 (LE u32 두 개). FUN_180d5ef00."""
    if len(data8) != 8:
        raise ValueError('XTEA 블록은 8바이트')
    v0, v1 = struct.unpack('<2I', data8)
    k = key_words
    total = 0
    for _ in range(32):
        v0 = (v0 + (((((v1 << 4) & M) ^ (v1 >> 5)) + v1 & M) ^ ((total + k[total & 3]) & M))) & M
        total = (total + DELTA) & M
        v1 = (v1 + (((((v0 << 4) & M) ^ (v0 >> 5)) + v0 & M) ^ ((total + k[(total >> 11) & 3]) & M))) & M
    return struct.pack('<2I', v0, v1)


def xtea_decrypt_block(data8, key_words=XTEA_KEY_WORDS):
    """8바이트 블록 1개 복호화. FUN_180d5e9c0."""
    if len(data8) != 8:
        raise ValueError('XTEA 블록은 8바이트')
    v0, v1 = struct.unpack('<2I', data8)
    k = key_words
    total = (DELTA * 32) & M
    for _ in range(32):
        v1 = (v1 - (((((v0 << 4) & M) ^ (v0 >> 5)) + v0 & M) ^ ((total + k[(total >> 11) & 3]) & M))) & M
        total = (total - DELTA) & M
        v0 = (v0 - (((((v1 << 4) & M) ^ (v1 >> 5)) + v1 & M) ^ ((total + k[total & 3]) & M))) & M
    return struct.pack('<2I', v0, v1)


def xtea_encrypt_to_sa(value8):
    """FUN_180d5e0e0: 8바이트 → XTEA → 대문자 헥스 16자 + "SA"."""
    return ''.join('%02X' % b for b in xtea_encrypt_block(value8)) + 'SA'


def xtea_decrypt_from_sa(s):
    """FUN_180d5e2e0 역: "...SA" → 헥스 16자 → 8바이트 복호."""
    if len(s) < 18 or not s.upper().endswith('SA'):
        raise ValueError('SA 접미 없음')
    hexpart = s[:-2]
    if len(hexpart) != 16:
        raise ValueError('헥스 길이 16 아님')
    return xtea_decrypt_block(bytes.fromhex(hexpart))


# ---------------------------------------------------------------------------
# [확정] CStreamCryptor_v1 패킷 난독화
#   enc FUN_181272e40 / dec FUN_181272fa0
# ---------------------------------------------------------------------------
class PacketObfuscationError(Exception):
    pass


def obf_encrypt(payload, tag, key=None, pad=None):
    """FUN_181272e40 재현.

    key: 15비트 정수(0..0x7FFF). None이면 임의 선택(실제 코드는 rand()).
    pad: 헤더 랜덤 4바이트([0],[2],[7]). None이면 임의.
    반환: 난독화된 패킷(페이로드+10바이트). 체크섬은 0으로 채움
          (체크섬 함수 0x181272bc0는 세션 29 대기 — 수신측 검증 통과
          필요시 session29 결과로 갱신할 것).
    """
    import random
    if key is None:
        key = random.randint(0, 0x7FFF)
    if pad is None:
        pad = bytes(random.randint(0, 255) for _ in range(3))
    buf = bytearray(8 + len(payload))
    buf[0] = pad[0]
    buf[1] = tag & 0xFF
    buf[2] = pad[1]
    struct.pack_into('<I', buf, 3, key & M)
    buf[7] = pad[2]
    prev = 0
    for i, p in enumerate(payload):
        prev = (key ^ p ^ prev) & 0xFF
        buf[8 + i] = prev
    out = bytes(buf[::-1]) + b'\x00\x00'  # 리버스 + 체크섬 플레이스홀더
    return out


def obf_decrypt(pkt, verify_checksum=False, expected_tag=None):
    """FUN_181272fa0 재현(체크섬 검증 생략 가능).

    반환: dict(payload=bytes, tag=int, key=int, checksum=bytes)
    예외: PacketObfuscationError — 크기/구조 문제.
    """
    if len(pkt) < 11:
        raise PacketObfuscationError('패킷 너무 짧음(%d)' % len(pkt))
    body = pkt[:-2]
    checksum = pkt[-2:]
    buf = body[::-1]  # 언리버스
    tag = buf[1]
    key = struct.unpack_from('<I', buf, 3)[0]
    if expected_tag is not None and tag != (expected_tag & 0xFF):
        raise PacketObfuscationError('태그 불일치 0x%02x' % tag)
    if verify_checksum:
        # FUN_181272bc0 결과와 비교 — 세션 29 확정 전 미구현
        raise NotImplementedError('체크섬 검증은 세션 29 결과로 추가 예정')
    payload = bytearray()
    prev = 0
    for c in buf[8:]:
        payload.append((key ^ prev ^ c) & 0xFF)
        prev = c
    return {'payload': bytes(payload), 'tag': tag, 'key': key,
            'checksum': checksum}


# ---------------------------------------------------------------------------
# [확정] CPHObject 패킷헤더 XOR (session 27, 기계어 직독)
# ---------------------------------------------------------------------------
def ph_xor_1(q_off8, q_0x30, q_0x38):
    """CPHObject_XOR_1 @0x1811996e0."""
    return q_0x38 ^ q_0x30 ^ q_off8


def ph_xor_2(q_off8, q_0x38, q_0x40):
    """CPHObject_XOR_2 @0x1811999b0."""
    return q_0x40 ^ q_0x38 ^ q_off8


# ---------------------------------------------------------------------------
# vftable 주소 기록 (참조용)
# ---------------------------------------------------------------------------
VF_CSTREAM_BASE = 0x181658F58   # CStreamCryptor (순수가상 7슬롯)
VF_CSTREAM_V0 = 0x181658F98     # v0: +0x18 태그=0(ret), +0x20=0x1fca34, +0x28=0x8a119e
VF_CSTREAM_V1 = 0x181658FD8     # v1: +0x08 enc(0x181272e40), +0x10 dec(0x181272fa0)


# ---------------------------------------------------------------------------
# 셀프테스트 — python sa_net_crypto.py
# ---------------------------------------------------------------------------
if __name__ == '__main__':
    # 0) 실측 KAT (Node 재현 sa-proxy.js xteaEncryptBlock, 2026-10-18)
    KAT_IN = bytes(range(8))
    KAT_CT = bytes.fromhex('2791E5CD0DFFFB98')
    assert xtea_encrypt_block(KAT_IN) == KAT_CT, 'XTEA KAT 불일치'
    assert xtea_decrypt_block(KAT_CT) == KAT_IN, 'XTEA KAT 역방향 불일치'
    assert xtea_encrypt_to_sa(KAT_IN) == '2791E5CD0DFFFB98SA'
    print('[OK] XTEA KAT (2791E5CD0DFFFB98 / ...SA)')

    # 1) XTEA 왕복 + SA 래퍼 왕복
    assert XTEA_KEY_BYTES == b'156def789023abc4', XTEA_KEY_BYTES
    for i in range(64):
        msg = struct.pack('<Q', (0x0123456789ABCDEF * (i + 1)) & 0xFFFFFFFFFFFFFFFF)
        ct = xtea_encrypt_block(msg)
        assert xtea_decrypt_block(ct) == msg, 'XTEA 왕복 실패 @%d' % i
        s = xtea_encrypt_to_sa(msg)
        assert len(s) == 18 and s.endswith('SA') and s[:16] == s[:16].upper()
        assert xtea_decrypt_from_sa(s) == msg
    print('[OK] XTEA-32 블록/SA래퍼 왕복 (고정키 "156def789023abc4")')

    # 2) 패킷 난독화 왕복 + 자기기술적 복호
    for n in (1, 7, 64, 300):
        payload = bytes((i * 31 + 7) & 0xFF for i in range(n))
        pkt = obf_encrypt(payload, tag=0x5A, key=0x1234)
        assert len(pkt) == n + 10
        r = obf_decrypt(pkt, expected_tag=0x5A)
        assert r['payload'] == payload and r['key'] == 0x1234 and r['tag'] == 0x5A
    print('[OK] 패킷 난독화 왕복 (롤링 XOR+리버스, 키=패킷내장)')

    # 3) CPHObject XOR 공식
    a8, b30, c38, d40 = 0x1122334455667788, 0x0102030405060708, \
        0xF0F1F2F3F4F5F6F7, 0xA0A1A2A3A4A5A6A7
    assert ph_xor_1(a8, b30, c38) == (c38 ^ b30 ^ a8)
    assert ph_xor_2(a8, c38, d40) == (d40 ^ c38 ^ a8)
    print('[OK] CPHObject XOR_1/XOR_2 헤더 공식')

    print()
    print('대기 항목(세션 29): u16 체크섬(0x181272bc0), v1 태그값(0x181273720),')
    print('enc/dec 호출자 → 실제 와이어 사용 지점, v0/v1 나머지 슬롯.')
