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
