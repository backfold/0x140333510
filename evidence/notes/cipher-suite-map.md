# SEED cipher suite map (cshell.dll) — 로컬 정적분석 증거노트

날짜: 2026-10-18 · 방법: PE 섹션 직독(va2off) + e8/e9 rel32 콜사이트 스캔(scripts/py/find-callers.js) + cc-패딩 경계 스캔 + 수동 x64 디코드(scripts/py/dump-wrappers.js). Ghidra xrefs/resolve_containing_procedure는 provider_timeout(330s)으로 전부 실패 — 로컬 스캔이 그 대체다.

## 사실 (관측된 바이트 기반)

### 함수 맵 (호출 관계 포함, find-callers.js 출력 전문)
```
.text: VA=0x180001000 size=0x1437000
0x18018ae96: call ctor_3340d0      ← 외부 호출부 #2 (함수 시작 0x180189760, -0x1736B 지점)
0x1801aa456: call wrapper_332ee0   ← 외부 호출부 #1 (함수 시작 0x1801a9fa0, -0x4b6B 지점)
0x180332ade: call seedBlockDec     (helper_332a50 내부)
0x180332beb: call seedInit         (wrapper_332b40 내부)
0x180332c0d: call modeProc_333ff0  (wrapper_332b40 내부)
0x180332cb5: call seedBlockDec     (wrapper_332b40 내부)
0x180332d2f: call seedBlockEnc     (wrapper_332b40 내부)
0x180332de8: call seedBlockDec     (wrapper_332b40 내부)
0x180332f68: call seedInit         (wrapper_332ee0 내부)
0x180332f8e: call modeProc_333ff0  (wrapper_332ee0 내부)
0x180333034: call seedBlockDec     (wrapper_332ee0 내부)
0x1803330af: call seedBlockEnc     (wrapper_332ee0 내부)
0x180333178: call seedBlockDec     (wrapper_332ee0 내부)
0x1803332fb: call seedBlockDec     (method_333250 path A)
0x18033336a: call seedBlockEnc     (method_333250 path B)
```
- **SEED 스위트 전체에서 외부 호출부는 단 2곳** (0x18018ae96, 0x1801aa456). 나머지 13개 호출은 0x180332a50~0x180333250 클러스터 내부.
- seedInit(0x1803333f0) 직접 호출부는 두 래퍼뿐: 0x180332beb, 0x180332f68.

### ctx 구조 (0x180333250 / 0x180332a50 디스어셈블리로 확정)
```
+0x00 u32  id            (83 39 01 = cmp dword[rcx],1 → id==1이 path A)
+0x04 16B  IV / 현재 마스크 (path A block0: dst = src ^ [rcx+4])
+0x14 32u32 라운드키 (lea r8,[r14+14h] → 블록 E/D 세번째 인자)
+0x94 16B  체인 피드백 상태 (0x180332a50이 src 4dword를 xor 후 블록 D 호출)
+0xA4 u32  남은 길이 (0x180333250이 len-16 저장, 0x180332a50이 movsxd로 재독)
```

### 0x180333250 = 스트리밍 CFB 계열 암복호화 메서드
- 인자: (this=ctx, src=rdi…실제 rdx, dst=r9, len=r8d), this/src/dst/len 널·0가드.
- `id==1` **path A**: 루프@0x1803332d0 — `dst = src ^ mask; dst = BlockDec(dst) 인플레이스; mask_next = dst(방금 복호한 것)`. 라운드키 r8 로드 후 `call 0x180331bb0`(seedBlockDec).
- `id!=1` **path B**: 루프@0x180333360 — `dst = BlockEnc(src); dst ^= mask; mask_next = src(평문!)`. `call 0x180330d10`(seedBlockEnc). 평문 피드백 = CFB 암호화 표준형.
- 패딩: 버퍼 `(len/16 + 1) * 16` (0x1803332c4 `44 8d 7e 01; 41 c1 e7 04`).
- 루프 후: `movups xmm0,[마지막 mask]; movups [r14+4],xmm0` — **ctx->IV ← 마지막 마스크** (호출 간 스트리밍 상태 지속), 이어 `call 0x18137536e`(꼬리 처리), `*arg7 = padded_size-16`.

### 와이어 프로토콜과의 관계 (층 2 관측과 정합)
- 와이어 상수마스크(세션당 16B, 패킷내 i%16 반복)는 0x180333250의 체인 구조와 **不相合**: S2C 0x8e 하트비트 #16/#17은 plen=198(12블록+) 내내 `25 00…00` — 블록 1+까지 같은 마스크 → 체인 없음.
- 또한 벌크 텍스트(#22~24)의 반복 필드 `04z~~C?`가 서로 다른 위상(2,22,40)에서 동일 복호화 — 상수 마스크 재확인.
- **추론**: 와이어 코덱은 체인을 쓰지 않는 별도 경로(래퍼 0x180332b40/0x180332ee0 후보)이며, ctx->IV(+4) 16B가 세션 마스크 M_c2s/M_s2c 그 자체일 가능성이 높다(path A block0이 IV 직접 XOR). 0x180333250/0x180332a50의 CFB는 로그인·핸드셰이크 단계(#25 이후 불투명 패킷 0x34/0xbf/0x42/0x51 등)에 쓰일 것으로 추정.

### modeProc 0x180333ff0
`cdq/and 3` = len%4 → `lea rax,[r8+1]; cmovz…` 4바이트 단위 버퍼 처리 후 `call [rip]`(alloc) → 0x180333250류로 넘기는 전처리기. (정확한 역할은 디컴파일 대기)

### 0x180332b40 초입부 (수동 디코드)
`mov r8d,0BCh`(188)로 지역 버퍼 생성 → len을 16바이트 배수로 올려 alloc/memcpy/free → `mov r9,r12`(래퍼 arg2 = seedInit state16/IV 후보) → seedInit@0x180332beb. **188 = 벌크 프레임 plen 198 - 10 = LEN(208) - 20** — 고정크기 채널 프레임과 수치가 맞물림.

## 미해결 → 다음 실험
1. wrapper 0x180332b40/0x180332ee0 디컴파일(session33 진행 중) → 마스크/키 소스 확정.
2. 인클로징 함수 0x1801a9fa0/0x180189760 디컴파일(session34 후보) → 와이어 send/recv 지점 및 ctx 보관소.
3. seedInit에 넘어가는 key16 인자 값 — 세션 키 후보 = 로그인 0x3d 패킷 ~0x86 오프셋 16B blob(`c0e98d1f c0479aff c0319038…`).
4. M_c2s/M_s2c가 IV 그 자체인지 E(K,IV)인지 — key16을 알면 solve-mask.js 배터리 재실행으로 판정.

## 추가 관측 (2026-10-18 후반 — 수동 디코드 계속)

### 래퍼 인자 셋업 (seedInit 호출부 직전 바이트)
- **wrapper_332b40**: `seedInit(ctx=[rsp+40], id=0, key16=arg4(r13), state16=arg2(r12))` — `xor edx,edx`@0x180332bea.
- **wrapper_332ee0**: `seedInit(ctx=[rsp+40], id=1, key16=arg1(r15), state16=arg2(r14))` — `lea edx,[r12+1]`@0x180332f5c.
- id=0 → path B(E 기반), id=1 → path A(D 기반) = B의 역변환. **332b40=CFB 암호화, 332ee0=CFB 복호화**로 짝.
- 두 래퍼 모두 진입부에서 `cdq/and 0Fh/add/sar 4`로 ceil16 블록수 계산, `operator new`로 패딩 버퍼 확보 후 memcpy.

### wrapper_332b40 후반부 (0x180332c40~0x180332ed5) — PKCS#7 확정
- `cmp dword [rsp+40h],1` (ctx->id) 로 A/B 루프 분기 — 0x180333250 method와 동일한 id 게이트.
- 루프 A: `mov eax,[rcx](마스크) ^ src → dst`, `lea r8,[rsp+54h]`(라운드키), `call 0x180331bb0`(D) 인플레이스, 마스크=직후 출력. 미러 인덱싱 `41 8b 44 3f fc` = `[rdi+r15-4]` — 버퍼 뒤집힘(와이어 reverse) 관련.
- 루프 B(0x180332d20): `lea rdi,[r15+rbx]` … `call 0x180330d10`(E) 후 `xor [rbx],eax` 4dword — `c=E(p)^mask`.
- **언패드 꼬리**: `0f b6 5d f7 movzx ebx,byte [rbp-9]`(복호화된 마지막 블록 첫 바이트=패딩길이) → `test/1..16 범위검사(83 fb 10)` → `sub rdi,rbx`로 패딩 제거. **PKCS#7**(패딩 1..16, 정렬시 +1 풀블록 → `(len/16+1)*16`의 실체).
- 332ee0에도 동일 구조(미러 주소).

### 외부 호출부 인자 (0x1801a9fa0 내 0x1801aa456 직전)
- `wrapper_332ee0(rcx=[rbp+8](키), rdx=std::string@rbp-0x78(IV/상태), r8=std::string src, r9d=[rbp-8](len), [rsp+20]=[rbp+0x120] 256B 출력버퍼)`.
- 직전에 256B 버퍼 2개 초기화(0x100 크기 생성 호출 ×2), 호출 직후 `call 0x1801aac80`(2단 변환) — **다단 파이프라인**. IV가 std::string 세션 상태에서 옴 = 세션 키/IV는 연결 객체가 들고 있음.
- 0x180189760의 ctor_3340d0 호출부: `b9 a0 02 00 00 mov ecx,0x2A0; call operator new` 후 ctor — **ctx 크기 = 0x2A0(672B)** 객체를 힙에 만들어 `[rsi+0xC90]`에 저장 → 연결 객체의 SEED ctx 보관소 후보.

### 와이어 시퀀스 (decoded.log 기준, 로그인 시퀀스 캡처 확인)
```
#1  S2C 0x0d plen=28  90fc4958b2acba5406687df4d6536870 7deb5ee2edc15a78572e00b1  ← 서버 헬로/세션시드 후보
#2  C2S 0x3d plen=198 '8'패딩 + 0x70에 c0e98d1fc0479affc03190(11B) + 0x9d에 9152a360×2(8B)
#3  C2S 0x42 plen=198 전체 불투명(고엔트로피)
#4  C2S 0x51 plen=198 전체 불투명
#5~ C2S 0x08 하트비트(key 동일 7회 → key 교체 2회)
#14~ S2C 0xbe/0xbc 채널목록(텍스트) → 0x8e 하트비트 → 0x37/0xca/0xf7 소형(4/19/21B, 고엔트로피) → 벌크
```
- M_c2s/M_s2c 16B 패턴은 cshell.dll/suddenattack.exe 어디에도 없음(검색 0건) — 하드코딩 아님, 세션 파생 확정.
- 0x42/0x51에 대한 SEED-CFB/ECB 브루트(키·IV 후보 8×5 × fb 2 × ED 2 = 관측재료 전부) 전부 탈락 — 세션 키는 관측 바이트 밖(연결 상태)에서 유도됨. solve-login.js 참조.

## 추가 관측 (2026-10-18 session33/34 사이 — 정적 키·커넥션 객체 확정)

### 정적 초기화 썽크 → 전역 문자열 3개가 전부 .rdata 상수에서 복사됨 (사실)
- `0x18000cb90` → 글로벌 `0x1818bc670`: SSE 원본 `0x18144c3a0`, 64+1B, **표준 base64 알파벳** `A-Za-z0-9+/` (size=0x40, cap=0x4f, operator new 0x50).
- `0x18000cc00` → 글로벌 `0x1818bc6b0`: SSE 원본 `0x18145eae0`, 16B **`SDAT.NEXON.COM..`** (size=0x10, cap=0x1f, new 0x20).
- `0x18000cc50` → 글로벌 `0x1818bc690`: SSE 원본 `0x18145eac0`, 24B **`c9x6zoVPQL1y00oPpGZ6/A==`** (size=0x18, cap=0x1f, new 0x20).
- 각 썽크 끝의 `lea rcx,[0x1814252d0/340/3b0]`는 atexit 파괴자 콜백 포인터(문자열 데이터 아님 — 처음에 착각).

### 0x1801a9fa0 = 정적 키 설정/문자열 복호화기 (사실, 수동 디코드)
- `0x1801aa02c`: `lea r8,[rbp+8]`(키 출력), `mov edx,eax`(strlen), 소스=글로벌 `0x1818bc690` → `call 0x1801aa8a0` = **base64 디코더**(`cmp bl,0x3d '='` 패딩 분기, `sub bl,0x2b '+'`, 4자 그룹 `cmp r14,4`, 알파벳 strchr 0x181375398×3).
- → **key16 = b64dec("c9x6zoVPQL1y00oPpGZ6/A==") = `73dc7ace854f40bd72d34a0fa4667afc`**.
- `0x1801aa452`: `wrapper_332ee0(rcx=rbp+8 key, rdx=std::string@rbp-0x78 ← 글로벌 "SDAT.NEXON.COM..", r8=src@rbp-0x18, r9d=len, [rsp+20]=256B out@rbp+0x120)`, 직전 memset(out,0,0x100)×2 (0x18137537a).
- 호출 직후 `stage2 0x1801aac80(rcx=dec_buf, edx=retlen, r8=src, r9=rsp+0x40)` — 2단 변환 파이프라인.
- **이 정적 키로는 와이어 불투명 프레임(#3 0x42, #4 0x51, #26 0x34, #27 0xbf)이 풀리지 않음** (solve-real.js: cfbDecStd/cfbDecDbc/cfbEncB/cbcDec/ecbDec 전부 pr≈40% 노이즈). 마스크도 E/D(정적키, 후보 IV 8종) 전부 불일치 (solve-mask2.js). → 와이어 세션 키는 핸드셰이크 파생, 디스크에 없음.

### 커넥션 암호 객체 2개 (0x18018ae96 호출부 디코드, 사실)
```
mov ecx,0x2A0; call operator new(0x181371f54); call ctor_3340d0 → [rsi+0xC90]  (SEED ctx)
call 0x1803342e0(ctx, 0, 0x232, 0x100, 0x40)          ← 초기화(키 설정?) ★신규 함수
mov ecx,0x298; operator new; call 0x180b2bc40 → [rsi+0xCF0]                      (제2 객체)
call 0x180b2eaf0(obj2, 0, 8, 0x33, 0x200, 0x40, 0x200, 0x40)                     ← 제2 초기화
각각 0x180fd8210(manager, obj)로 등록
```
- `ctor_3340d0` = 순수 제로 초기화(vptr `0x1814977b8`, std::string 멤버 +0x210/+0x230, +0x2A0까지 0) — **키 설정 없음**. vtable 0x1814977b8 slot0=0x180334220(삭제 소멸자 추정), 0x1814977c0부터는 별개 클래스 vtable.
- `0x1803342e0` = 암호 프레임워크 디스패처: `mov rax,[rcx]` 가상 호출 +0xa8/+0xa0/+0x88/+0x80/+0xb8, 레지스트리 `0x1814979e8`, 꼬리 `0x180d4cf20`(XTEA 클러스터 0x180d5e9c0/0x180d5ef00 근방). 인자 (0, 0x232, 0x100, 0x40) = 알고리즘/모드/사이즈 지정 추정.
- **0x1803342e0 + 0x180d4cf20 = 와이어 키 합의 진입점 후보 (다음 디컴파일 타깃)**.

### 도구 노트 (사실)
- mcp-client의 batch_decompile 결과 문자열은 ~400,014B에서 잘림("...[truncated]") → 다중 주소 요청 시 뒤 항목 소실. **1요청 1주소 원칙**.
- batch_decompile은 `timeoutMs` 인자 거부(Unrecognized key) — 클라이언트 타임아웃은 별도 경로.
- session33 기록(항목1~4)은 결과 잘림으로 복구 불가(항목0 provider_timeout만 확인됨).

## 정정 및 확정 (2026-10-18 session34/35 — 수동 분석 + 호출부 인구조사)

### 정정: "conn+0xC90 = SEED ctx" 주장 철회
- `0x1803342e0`(0x18018aec0에서 ctor 직후 호출)은 **UI 텍스처 초기화**다: `lea rdx,["sa_interface2\menu\main\renew\ServerNameBack.dtx"]`(0x1814979e8), 0x100/0x40을 `movd+cvtdq2ps`로 **부동소수(256.0×64.0)** 로 변환해 가상 호출 — 암호 초기화가 아님.
- `0x180d4cf20`은 .text 전체에서 **5,153회** 호출되는 범용 헬퍼(문자열/에셋 계열), `0x180b2eaf0`도 47회 — 프레임워크 디스패처 아님.
- 따라서 ctor_3340d0/334180/334220(vtable 0x1814977b8, 문자열 멤버 +0x210/+0x230)이 SEED 클러스터 소속이었다는 근거는 없음(주소 인접 + cc-경계 추정이었음). "SEED ctx 0x2A0를 conn+0xC90에 보관" 추정 **무효**. 0x180189760 일대는 서버선택 화면 UI 조립일 가능성이 큼.

### 확정: 평문 .text에서의 암호 표면 (find-callers2.js 전수 스캔)
- `wrapper_332ee0`(SEED-CFB 복호) 호출부 **1개**: 0x1801aa456(설정 문자열 복호 경로) 뿐.
- `wrapper_332b40`(SEED-CFB 암호화) 호출부 **0개** — 평문 코드에서 미사용(VM 영역 전용 또는 사장).
- XTEA enc/dec(0x180d5ef00/0x180d5e9c0) 호출부 각 1개(0x180d5e11b/0x180d5e3c1 = 값 코덱 래퍼 내부).
- 체섬 0x181272bc0 호출부 2개(0x181272f51/0x181272fc7 = v1 enc/dec 내부).
- **결론: 와이어 2단 계열(불투명 프레임 0x42/0x51/0x34/0xbf/… 및 마스크)은 평문 .text 진입점이 없다** — 이전 세션의 "VM 디스패치 변종"(0x18188be20+ VM 바이트코드가 0x181272bc0/0x181272fa0 참조) 관측과 정합. 마스크·세션키는 (a) VM 코드 내부 파생 또는 (b) 핸드셰이크 암호화 프레임 안의 랜덤 교환 — 관측만으로는 결정 불가.

### 0x1801aac80 = base64 **인코더** (수동 디코드 확정)
- 3바이트→4자 비트 패킹(`shr 2 / and 3 / shl 4 / shl 2 / shr 4 / shr 6`), 알파벳 글로벌(0x1818bc670) 인덱싱 3회, 문자열 append.
- 최종 파이프라인: **`0x1801a9fa0(in) = b64encode( SEED-CFB-Dec(key=73dc7ace854f40bd72d34a0fa4667afc, IV="SDAT.NEXON.COM..", src=in) )`** — 정적 키 설정문자열 복호화 헬퍼로 완결. 와이어 무관(불투명 프레임 부호화 불일치로 실증 완료).

### session34/35 디컴파일 시도 결과
- 0x1801a9fa0: 1주소 단독 요청에도 항목 provider_timeout(콜 661.19s, 결과 102,954B = 진단 로그) — 함수가 ~0x4b6b+ 바이트 STL 중첩으로 330s 내 분석 불가. **수동 분석이 최종 소스**.
- 0x180189760: 동일 예상(진행/타임아웃).
- 소형 함수(0x1801aac80/0x1801aa8a0) 단독 요청은 성공 가능성 있음(session35).
