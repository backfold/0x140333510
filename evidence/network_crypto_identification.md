# 네트워크 암호 식별 — cshell.dll (sessions 27–29)

질문: "suddenattack.exe TCP 서버 통신 메시지 암호화 되어서 송수신되는데
복호화 부분 찾아줘" (2026-10-18)

## 결론 요약

| 항목 | 내용 | 상태 |
|---|---|---|
| 암호화 위치 | suddenattack.exe 아님 → **cshell.dll** | 확정 |
| 패킷 난독화 | CStreamCryptor_v1: 롤링 XOR + 리버스 + u16 체크섬, **키 패킷 내장(자기기술적)** | 확정 (체크섬 함수본체 session 29) |
| 값 암호 | XTEA-32, 고정키 `"156def789023abc4"`, 헥스+"SA" 래퍼 | 확정 |
| 헤더 난독화 | CPHObject_XOR_1/2 qword 3개 XOR | 확정 (기계어 직독) |
| 와이어 사용 지점 | enc/dec 호출자 xrefs | session 29 대기 |

## 식별 경로 (재현 스텝)

1. `search_strings "LoginEncrypt"` → cshell.dll 0x181602ed0 (Ghidra 미등록
   문자열 — 로컬 파일 오프셋 0x16022d0 → VA 산출).
2. `crypto-constants-scan.js`: TEA/XTEA delta 0x9E3779B9 히트 다수.
3. `rtti-locate.js` (MSVC RTTI: descriptor→COL→vftable→slots):
   - CStreamCryptor(베이스, 순수가상) 0x181658f58
   - CStreamCryptor_v0 0x181658f98 (7슬롯)
   - CStreamCryptor_v1 0x181658fd8 (7슬롯)
   - CPHObject_XOR_1 0x18164d0e8 / XOR_2 0x18164d108 (Normal/Index/Divide 계열도 존재)
4. `pdata-funcs.js`로 함수 경계 확정, `callers-scan.js`(E8/E9 rel32)로 호출자 탐색.
5. REA session 28 `batch_decompile` 12개 함수 → 아래 알고리즘 확정.

## XTEA-32 (FUN_180d5ef00 enc / FUN_180d5e9c0 dec)

- 64비트 블록(u32 2개 LE), 32라운드, 표준 XTEA.
- **하드코딩 키**: u32[4] = {0x64363531, 0x38376665, 0x33323039, 0x34636261}
  = LE 바이트열 `156def789023abc4` (스택 즉시값, 디컴파일 라인 24-27).
- enc 라운드: `v0 += (((v1<<4)^(v1>>5))+v1) ^ (sum + k[sum&3]); sum+=Δ;
  v1 += (((v0<<4)^(v0>>5))+v0) ^ (sum + k[(sum>>11)&3])` (Δ=0x9E3779B9,
  2루프 × 16라운드 언롤).
- dec: 초기 sum=0xC6EF3720, 역순 (디컴파일의 `+0x61c88647` 폴딩 = sum−Δ).
- 래퍼 FUN_180d5e0e0: 8바이트 → XTEA → `"%02X"`(대문자, @0x1815ffd30) 8회
  → `"SA"`(@0x1815ffd38) 접미 std::string 반환. FUN_180d5e2e0가 역변환
  (끝 2자 제거 → 헥스 디코드 FUN_180d5e6c0 → XTEA dec).
- 용도: 로그인 비밀번호/PIN 등 값 단위 난독화로 추정 [추론 — 호출자
  xrefs 중 0x18215b904/0x18215b910 은 .vlizer(VM 보호) 영역].
- KAT: `bytes(range(8))` → `2791E5CD0DFFFB98` → `"2791E5CD0DFFFB98SA"`.

## CStreamCryptor_v1 패킷 난독화 (FUN_181272e40 enc / FUN_181272fa0 dec)

vftable 0x181658fd8: +0x00=0x181273680, **+0x08=enc**, **+0x10=dec**,
+0x18=0x181273720(태그 게터, session 29), +0x20=0x181273700,
+0x28=0x1812736e0, +0x30=0x1812736c0(최대크기, session 29).

암호화(python `sa_net_crypto.obf_encrypt` 대응):
```
srand(GetTickCount()); key = rand()          # MSVC rand → 0..0x7FFF (15비트)
buf[0]=rand&0xff; buf[1]=태그; buf[2]=rand&0xff; buf[3..7)=key(u32LE); buf[7]=rand&0xff
buf[8+i] = key ^ payload[i] ^ buf[8+i-1]     # 롤링 XOR (prev=0 시작)
out = reverse(buf[0..8+len))                 # 전체 리버스 (디컴파일 루프 확인)
out += u16 체크섬(this,out,8+len)            # FUN_181272bc0 — session 29
# 최종 크기 = payload+10
```
복호화: 체크섬 검증 → 리버스 해제 → buf[1]==태그 확인 →
`plain[i] = key ^ prev_cipher ^ buf[8+i]`.
**키·태그·랜덤 패딩이 전부 패킷 안에 있음 → 수신 측(프록시)은 아무
사전 지식 없이 복호 가능.**

v0 (0x181658f98) 슬롯: +0x08/+0x10 = ret 0, +0x18 = ret 0(태그 0),
+0x20 = ret 0x1fca34 (2,075,956), +0x28 = ret 0x8a119e (8,951,966),
+0x30 = identity — v0는 무변환(pass-through) 구현으로 해석 [추론].

## CPHObject 헤더 XOR (session 27, 원시 기계어 직독)

- XOR_1 slot2 @0x1811996e0: `mov rax,[rcx+0x38]; xor rax,[rcx+0x30]; xor rax,[rcx+8]; ret`
- XOR_2 slot2 @0x1811999b0: `mov rax,[rcx+0x40]; xor rax,[rcx+0x38]; xor rax,[rcx+8]; ret`
- this+8 은 키/시드 역할 추정 [추론].

## 정정 기록

- session 27 단계 "XXTEA" 식별은 **오류**였음: delta 상수 + "×6 언롤"
  추정만으로 XXTEA로 단정했으나 session 28 디컴파일 결과 64비트 블록
  표준 XTEA. (XXTEA는 가변 블록 btea — 실제 코드는 2워드 고정 블록.)
- `sa_net_crypto.py` 초안의 XXTEA 구현은 제거하고 XTEA로 대체 완료.

## 산출물

- `scripts/py/sa_net_crypto.py` — XTEA/SA래퍼/패킷 난독화/CPHObject (KAT 포함)
- `scripts/py/sa_proxy.py`, `scripts/py/sa-proxy.js` — 캡처 프록시(자동 복호)
- `scripts/py/sa-proxy.js --selftest` — 전 파이프라인 검증 통과 (2026-10-18)
- `decompiled/FUN_180d5e*_cshell.c`, `FUN_18127*_cshell.c` — 원본 의사코드

## 남은 것 (session 29 진행 중)

- FUN_181272bc0 (u16 체크섬) — 확정 후 obf_encrypt 체크섬 채움
- 0x181273720 (v1 태그값), 0x1812736c0 (최대 패킷 크기)
- xrefs: enc/dec/vftable 호출자 → 실제 와이어 프로토콜과의 연결 확인
- 0x180333423 — 별도 TEA 변형 (정체 미상)
