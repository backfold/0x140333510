# Session 29–30 — 실제 서버 트래픽 캡처 & 12000 포트 실전 코덱 분석

날짜: 2026-10-18 (KST). 도구: ngm 프로토콜 시먼 + sa-proxy.js (MITM) + Ghidra REA batch (session29.jsonl).

## 1. 캡처 체인 (전부 실측)

1. sa.nexon.com 게임시작 → `gamestart.aspx` 응답 `argument="175.207.21.11 12000 1 -1 1326428154"`.
2. 웹이 ngm:// URL 생성 (신규 NP11 토큰 포함) → HKCU `ngm` 프로토콜 오버라이드가
   `ngm-shim.ps1` 호출 (`H:\SA_Analysis\scripts\py\ngm-shim.ps1`) — passarg IP만 127.0.0.1로
   치환 후 진짜 `NGM64.exe`에 전달 (로그: `logs\ngm-shim.log`, "REWRITE passarg IP …").
3. NGM64가 정상 런처 컨텍스트로 클라이언트 실행 (05:25:05) → 클라이언트가
   **127.0.0.1:12000 접속** (events.jsonl: `open` conn=1 05:25:37) → 프록시가
   175.207.21.11:12000에 업스트림 연결 (`upstream_ok`).
4. 13초 통신(17.24 MB) 후 업스트림 RST (`upstream_fail ECONNRESET`), 클라이언트 정상 종료
   (errorlog 20261018_052601_13884.log — 그래픽 해제 루틴만, 오류 없음).
   - 토큰이 직전 런처 실행(05:22, PID 10100)에서 이미 소진/만료되었을 가능성이 있어
     재접속은 게임시작 재클릭으로 수행해야 함 (시먼이 자동 가로챔).

캡처 산출물 (`logs\run1\`, gitignore됨 — 개인 토큰/계정 포함 가능):
- `events.jsonl` 27 KB (chunk 이벤트 160+), `packets.log` 202 MB / 4,150,064줄,
  패킷 83,130개(전부 u16 프레이밍으로 로그됨), **DEOBF v1 섹션 160,192개**.
- 결함: `c2s.bin`/`s2c.bin` 0바이트 (SessionLog 미기록 버그) → `analyze-run1.js`가
  packets.log RAW 헥스덤프에서 스트림을 재조립해 우회.

## 2. 전선(와이어) 형식 — 실측으로 확정된 부분

프레임 (C2S 전체 2,538B가 **끊김 없이 체인 검증** — 13/13프레임, 잔여 0B):

```
[u16le LEN][BODY × LEN 바이트]
```

BODY = `reverse(H) || T`:
- `H[0]`=rand, `H[1]`=**type(메시지 종류, 패킷마다 변함)**, `H[2]`=rand,
  `H[3..7]`=**key u32LE (롤링 XOR 키, 패킷에 실려 전송)**, `H[7]`=rand.
- `cipher[i] = key ^ plain[i] ^ cipher[i-1]`, `cipher[-1]=0` (prev 리셋 확정:
  같은 key+같은 내용 패킷들이 동일 평문 출력).
- `T` = **상수 2바이트 `10 10`** (전 3,309 체인 프레임에서 동일 — 체크섬 아님).

관측된 type 분포: C2S `0x3d,0x42,0x51`(로그인 3연타) → `0x8`×10(하트비트);
S2C `0xd`(첫 인사 38B), `0xbe,0xbc`(핸드셰이크), `0x8e`(벌크 다운로드 다수) 등 20+종.
key는 연속 패킷에서 유지되다 가끔 변경 (C2S 13패킷에서 고유 key 6개 — srand(GetTickCount())
재시드 특성상 밀리초 충돌 시 동일 key, 또는 조건부 재생성).

프록시의 Framer는 83,130패킷 전부 u16으로 복구함(디동크 리스캔 포함).
엄격 체인은 S2C 673,065B(3,296프레임) 후 break — 이 지점 이후 대형 전송(65,536B TCP
청크 다수)에서 프록시 프레이밍과 엄격 체인 해석이 갈림. 정확한 경계 규칙은 미해결.

## 3. 이 코덱은 CStreamCryptor_v1이 아니다 (사실)

session29 디컴파일 (`decompiled/*_s29.c`):
- `FUN_181273720` (v1 태그 게터, vftable+0x18) = **`return 1`** — 그러나 캡처된 전
  패킷의 `H[1]`은 0x0d/0x3d/0x8/0x8e/0xbe… 전부 ≠1.
- v1 (FUN_181272e40/FA0) 구조: 체크섬 = FUN_181272bc0(역순 블록) — 내용 의존 해시
  (SIMD ADD+XOR 폴드, `(~Σadd<<1)|⊕xor`) → 매 패킷 달라야 함. 실제 트레일러는 상수
  `10 10`이므로 v1 체크섬이 아님.
- 정렬 브루트포스 (`find-v1-alignment.js`, prefix 0–24 × suffix 0–8, C2S 13 + S2C 400):
  **tag=1이 되는 정렬 0건** (C2S), S2C 1건(우연) → v1 블록이 프레임 안에 존재하지 않음.

RTTI 전수 조사 (`dump-vtables.js`, `dump-rtti-names.js` — .rdata 직접 덤프):
- CStreamCryptor 계열 vftable은 **3개뿐**: base `0x181658f58`(.?AVCStreamCryptor@@),
  v0 `0x181658f98`(패스스루), v1 `0x181658fd8`.
- 주변 8슬롯 vftable 군(0x181659058~0x1816592c0 등)은 전부 `.?AVCNM*@@`
  (Nexon Messenger 클래스: CNMVirtualFriendInfo, CNMSelfUserInfo, CNMFriendList,
  CNMNoteInfoEx, CNMReportInfo, CNMChatMessage, CNMFileEvent, CNMMyGameInfo…) —
  암호화와 무관.
- v0/v1 슬롯 상수: v0 +0x20=`0x1fca34`, +0x28=`0x8a119e` (상수 반환 패턴의 선례).

## 4. 실제 복호화 디스패처 = .vlizer VM 바이트코드 (추정+근거)

xrefs: `FUN_181272fa0`(v1 decrypt) 참조 위치 = vftable 슬롯 `0x181658ff0`,
**`0x18188bebc`/`0x18188becc`(.rdata), `0x182195060`(.vlizer)**.
`0x18188be20+` 영역 헥스덤프 = RVA 피연산자를 포함한 **VM 명령 스트림**:
`c0 2b 27 01`(=0x181272bc0 체크섬 함수), `a0 2f 27 01`(=0x181272fa0 v1 복호화),
`dc 2f 27 01`(=0x181272fdc), `44 be 88 01`/`a0 be 88 01`(자기 참조=점프) 등이
정렬 안 된 명령 인코딩으로 배열. 즉 네트워크 수신 복호화는 VM 프로그램이 v1 네이티브
루틴(체크섬/복호화 코어)을 부품으로 호출하는 래퍼 — 헤더 배치(type 바이트, 상수
`10 10` 트레일러)가 v1과 다른 이유. (VM 난독화라 완전한 정적 해석은 미완.)

## 5. obf 평문(내부 페이로드) — 미해결

- 로그인 3패킷(type 0x3d/0x42/0x51, 평문 198B): 16바이트 주기 유사반복 + 위치별 변형
  (블록 일부만 같은 패턴 → 8B 블록 ECB와 불일치).
- 하트비트(type 0x8, 198B): 앞 ~144B는 `a3 52 0d 83 db 99 b9 3a e9 62 47 c7 4f 7c 03 85`
  16바이트 단위 반복, 꼬리는 패킷마다 상이(시퀀스 추정) — 같은 key에서도 꼬리만 다름.
- XTEA-ECB 가설(고정키) 검증: 8바이트 윈도우 전수 복호화에서 반복 영역이 동일 출력을
  내나 이는 동일입력→동일출력의 자명성(순환논법)이라 확정 근거 아님.
- 16바이트 XOR 키스트림 가설: 하트비트/XTEA_E(counter) 후보로 로그인 패킷 XOR →
  토큰("NP11","nest",계정) 미발견, ASCII run 15자 수준(노이즈 범위).
- 결론: 내부층 = 미확인 암호/구조. 후보: 세션 키 기반 스트림(S2C 첫 패킷 38B가
  시드일 수 있음), XTEA 비-ECB 모드, 또는 프로토콜 자체 필드.

## 6. 산출 스크립트

- `analyze-run1.js` — packets.log → 스트림 재조립 → u16 체인 검증 → obf 통계/덤프
- `find-v1-alignment.js` — v1 tag=1 정렬 브루트포스(부정 증명)
- `scan-inner-layer.js`, `xtea-phases.js`, `extract-keystream.js` — 내부층 가설 검증
- `dump-vtables.js`, `dump-rtti-names.js` — .rdata vftable/RTTI 직접 덤프
- `split-session29.js`, `extract-session29.js` — REA 결과 파서

## 7. 다음 실험

1. 재캡처(게임시작 재클릭)로 로그인→로비까지 장기 세션 확보 — 내부층 평문 다양성 확보.
2. S2C 673KB 지점의 프레임 경계 규칙 해석 (대형 프레임/분할 여부).
3. VM 바이트코드(0x18188be20+) 디코딩 — .vlizer 명령 세트 해석으로 실전 코덱 exact 복원.
4. FUN_181272bc0 기계어(SSE) 정확 재구현 → v1 체크섬 KAT 확보.
