# Snow2 identification & .pkg container validation (sessions 24–26)

Date: 2026-10-18
Scope: Lambda::SnowCipher in suddenattack.exe and the .pkg container.

## 1. Cipher identification: Nexon "Snow2" (SNOW 2.0-derived)

Evidence chain:

1. **Table comparison (byte-exact).** `scripts/extract-tables.js` extracted six
   256-entry dword tables from suddenattack.exe .rdata and compared them with the
   tables in MapleLib's `Snow2CryptoTransform.cs` (github.com/lastbattle/MapleLib,
   ported from WzComparerR2 / ahti fsbench snow2_fast.c):

   | table | VA | file offset | match |
   |---|---|---|---|
   | snow_alpha_mul | 0x1403ef1a0 | 0x3ef1a0−0x1000… (see json) | 256/256 |
   | snow_alphainv_mul | 0x1403ef5a0 | — | 256/256 |
   | snow_T0 | 0x1403ef9a0 | — | 256/256 |
   | snow_T1 | 0x1403efda0 | — | 256/256 |
   | snow_T2 | 0x1403f01a0 | — | 256/256 |
   | snow_T3 | 0x1403f05a0 | — | 256/256 |

   Output artifact: `evidence/snow_tables_from_exe.json` (`all_tables_match_maplelib: true`).
   snow_T0..T3 are the AES encryption T-tables Te0..Te3 (verified independently by
   `scripts/verify-cipher-tables.js`: 8/8 first dwords of Te0 and Te2 match an
   AES S-box-based construction).

2. **Structural match.** FUN_1402abee0 (session 24 decompile) implements:
   16-word LFSR load with key + complements (s15..s12 = key BE words,
   s11..s8 = ~key, s7..s4 = key, s3..s0 = ~key), IV XOR into s15/s12/s10/s9,
   r1=r2=0, then 2 × 16 unrolled steps = the "32 initial clockings", using
   DAT_1403ef1a0/ef5a0 (a_mul/ainv_mul) and the Te tables — identical to
   MapleLib `LoadKey`.

3. **MapleStory cross-reference.** MapleLib `WzMsFile.cs` uses the same cipher
   for .ms v2 containers ("Encrypting and decrypting (.ms v2 SnowCipher /
   v4 ChaCha20)"), with `DeriveSnowKey(fileNameWithSalt)` and a 16-byte key.
   The SA usage (key derived from path + container header string) is a
   Nexon-internal reuse of the same primitive.

Conclusion: Lambda::SnowCipher = Nexon "Snow2" stream cipher
(SNOW 2.0 with AES T-table S-box), keystream combined with data by 32-bit
addition (encryption) / subtraction (decryption).

## 2. Empirical container validation (2026-10-18)

Samples: `target/pkg_samples/global_00000.pkg` (29,696 B),
`target/pkg_samples/texturescripts_00000.pkg` (18,432 B), copied from
`H:\Program Files\Nexon\SuddenAttack\game\`.

Parser: `scripts/pkg-parse.js` (deterministic; brute-force path scan in
`scripts/pkg-scan-index.js`). Results — both files parse completely:

| | global_00000.pkg | texturescripts_00000.pkg |
|---|---|---|
| path string used | `global_00000.pkg` | `texturescripts_00000.pkg` |
| N1 (mask len) | 110 | 110 |
| N2 | 201 | 41 |
| version | v1 | v1 |
| header string | `!dlstps20djr@` | `!dlstps20djr@` |
| dataStart | 141 | 141 |
| data head [checksum, count] | [524325, 6] | [393435, 16] |
| indexStart (dataStart+N2+8) | 350 ✓ (scan hit) | 190 ✓ (predicted & hit) |
| entries parsed | 6/6 (global/models/*.ltb/.ltc) | 16/16 (texturescripts/*.tfs/.txt) |
| indexSize | 596 | 1724 |

Key confirmations:
- The header string decrypts to the same value on both files → fixed salt
  per build, path only feeds N1/N2/key derivation.
- Signed key load (MSVC char sign-extension) is required: texturescripts
  key1 contains bytes ≥ 0x80; unsigned load yields garbage, signed works.
- Subtract (decryption) is the correct combine op; keystream blocks are 16
  words, refreshed per 16 words, constructor generates the first block
  immediately.
- indexStart = dataStart + N2 + 8, where 8 = the [checksum][count] head
  consumed from the data stream. Empirically confirmed on both samples
  (texturescripts index start was *predicted* before scanning and hit).
- Index entry format (FUN_140290e00 / FUN_1402b18c0):
  `[u32 strlen][strlen×2 UTF-16LE name][6×u32][u32 n][n×16B][16B tail]`
  `(+32B if field[1] & 0x10)`. All extracted names are clean paths
  (`global/models/1x1_square.ltb`, `texturescripts/uvrotate.tfs`, …).

Entry field semantics (updated 세션36–37; 근거 병기):
- field[0] (f0): 값이 파일크기 초과 가능(예: 48030 > 29696) → 단순 바이트
  오프셋 아님. [가설] 키스트림 논스/시크 값 — FUN_14029bf30이 `[[entry+0x30]]`
  dword를 읽어 `seek(cipher, 값/4)` 호출 (손수 디스어셈블리).
- field[1] (f1): 플래그. **bit0(0x1) = zlib 압축** (7=압축, 6=저장;
  1x1_square.ltb 35781→9952 비율 0.28, .ltc 소형 파일 f4=f3+1..3로 상관 확정).
  bit4(0x10) = 인덱스 엔트리에 **40B 추가 필드** (FUN_1402b18c0: 16+16+8).
  bit5(0x20) = 스트림 생성 시 키 파생 경로 A 분기 (FUN_14029bf30).
- field[2] (f2): **데이터 영역 내 오프셋 / 1024 (1KiB 블록 인덱스)** —
  FACT. 근거: FUN_14029c810 `mov ebx,[X+8]; shl ebx,0xa; add ebx,[this+0x20]`
  = f2×1024+dataBase, 그리고 global_00000.pkg 6/6 엔트리에서
  파일 시작 블록 연속 할당이 f4 크기의 1KiB 올림과 정확히 일치
  (0→10블록 점유→다음 10, 12→2블록→14, 14→4블록→18, 18→3블록→21,
  21→7블록→끝 28) + dataBase=alignUp(indexEnd,0x400)=1024 →
  마지막 끝 29296 ≈ 파일 29696 (400B 슬랙).
- field[3] (f3): 무압축 크기 — FUN_14029c810이 `mov edx,[rdi+0xc]`로
  길이 설정 + 크기 상관(1x1_square.ltb f3=35781=f4 복원 전 크기).
- field[4] (f4): 저장(디스크) 크기 — .ltc 비압축 파일 f4=f3+1..3,
  동일 템플릿 .txt 쌍 동일 (261,264) 값으로 상관 확정.
- dataBase: alignUp(indexEnd, 0x400) — FUN_1402aa700이 Package+0xf8에
  저장 (global_00000.pkg에서 950→1024, 실측 일치).
- 16B items (n×): 청크 테이블 추정 — 래퍼 0x14029ca20 계열이
  `([+0x20]−[0x18])>>4`로 개수 산출. global 6 엔트리 모두 n=0.
- tail16: 16B — 정체 미해결 (전 조합 복호화 매트릭스에서 키로도 탈락).

## 2.5 파일 데이터 열기 경로 (세션37, 손수 디스어셈블리 + Ghidra headless)

- FUN_14029c810 (디스패처): 이름→엔트리 맵 조회 → ebx = dataBase+f2×1024,
  길이 = f3 → FUN_14028c580/14028ca10(오프셋 설정)/14028ca90(길이 설정)로
  스트림 객체 초기화 → 래퍼 구성 → FUN_14029ca20 → 스트림 생성기 3종
  (FUN_14029bf30 / FUN_14029c2a0 / FUN_14029c4c0) 분기 (플래그 비트 0x04,
  0x02, itemCount 등으로 선택).
- FUN_14029bf30 (스트림 생성기#1): 엔트리 플래그 f1&0x20 → 경로A
  (0x1402a8630+0x1402a84a0), 이름 첫 바이트 비교 → 경로B(0x1402a84a0,
  변형값=[+0x18] 역참조), 그 외 → 경로C(0x1402a83f0). 세 경로 모두
  16B 키를 [rbp+0x60]에 파생 → snowLoadKey(cipher, key, 0x80, IV=0)
  → `seek(cipher, [[entry+0x30]]/4)` → 0xc8B 노드에 cipher 클론
  (FUN_1402abc00), [node+0xc0]=워드 오프셋, 할당자 포인터 +0xc8 진행.
- 키 파생기: 0x1402a83f0 = 문자 산술 16B (`src[(i/10)*4] − 5*(i/10)` 등,
  k1/k2 파생과 동일 스타일), 0x1402a84a0 = 부동소수점(0x1402b939d) +
  RNG(0x140263e64) + 십진 자릿수 전개 혼합. — 정확한 재구현 진행 중.
- **per-file 키 실증**: k1/k2/tail16 × 배치(base 4종×정렬 3종×순서 3종)
  × skip(0/cum/f0w) × combine(sub/xor) = 648조합 전부 노이즈
  (ASCII≤0.55, `scripts/pkg-extract-test.js`) → 파일 데이터는 엔트리별
  파생 키로 암호화 [FACT, 소거법].
- zlib 청크 크기 DAT_1403ef150 = **65536 (0x10000)** 정적 값 —
  압축 파일은 64KiB 무압축 단위 청크로 저장, offset/65536 청크 인덱스로
  랜덤 액세스 (FUN_1402a6340/FUN_1402a60a0: CipherStream vtable+0x48 Read,
  FUN_14026cbd0 = inflate 스텝, 오류문 "zlib inflate() error. invalid
  package file data.", "1.2.11").
- FUN_1402abee0 (snowLoadKey) 전체 해독: 키 16B를 **부호 있는 바이트**로
  BE 워드 4개(w0..w3) 조립 → s[0..3]=w, s[4..7]=~w, s[8..11]=w,
  s[12..15]=~w (검증된 JS 구현과는 인덱스 거울 관계), 32 init 클로킹
  완전 언롤드(2회 루프×16), 마지막 [cipher+0x90]=0x10(키스트림 블록=16워드)
  설정 후 FUN_1402ad020(자기자신) 호출 = checkpoint(0) 저장.
  0x1402ac1xx–0x1402acc86의 6테이블 대규모 산술 = 이 언롤드 본체
  (테이블 6종 @0x1403ef1a0..0x1403f09a0 = snow_alpha_mul/alphainv_mul/
  T0..T3 바이트 일치 확인 — 이전 세션의 "엔트리 초기화 함수" 가설 정정).

## 3. Remaining unknowns (Q3 follow-up)

- 키 파생기 3종의 정확한 재구현 (경로C 0x1402a83f0 우선 — normal 케이스).
  완성 시 pkg 풀 추출기 작성 가능 (배치/암호화 구조는 모두 확정).
- [[entry+0x30]] dword의 원천 필드 (f0 매핑 추정, 미확정).
- PackageHeader2 (v2) variant: 샘플 없음.
- global_00000.pkg 끝 400B 슬랙 (29296 vs 29696)의 정체.

## 4. Tooling

- `scripts/extract-tables.js` — table extraction + MapleLib diff
- `scripts/verify-cipher-tables.js` — AES T-table cross-check
- `scripts/pkg-parse.js` — full deterministic container parser
- `scripts/pkg-scan-index.js` — index-region locator (brute force)
- `scripts/pkg-scan-data.js` — data-region decryptor/signature scanner
- Evidence: `evidence/session25.jsonl`, `evidence/session26.jsonl`,
  `evidence/snow_tables_from_exe.json`, `evidence/pkg_index_dump.json`,
  `evidence/maplelib_Snow2CryptoTransform.cs`, `evidence/maplelib_WzMsFile.cs`
