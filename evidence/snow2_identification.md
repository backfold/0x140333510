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

Entry field semantics (inference from both dumps, not yet proven):
- field[0]: 16-bit checksum (all values < 65536)
- field[1]: flags (6 or 7)
- field[2]: sequence index (0..count−1)
- field[3], field[4]: data-region coordinates (meaning unresolved)
- tail16: 16-byte per-entry blob (checksum/MAC or IV — unresolved)

## 3. Remaining unknowns (Q3 follow-up)

- Where per-file data physically lives and how field[3]/field[4] address it.
  The whole tail from dataStart decrypts to high-entropy noise under a
  position-0 key1 stream (`scripts/pkg-scan-data.js`: no LithTech signature
  found), consistent with per-file random access via the Snow2 checkpoint
  vector (+0xa0 history, FUN_1402ad020) rather than one linear stream.
  Next experiment: decompile the file-read path (CipherStream::Read /
  FUN_1402a95f0 callers) to map entry fields to absolute offsets.
- PackageHeader2 (v2) variant: no sample available; only the loader branch
  (seek −1, raw masked bytes as key) is documented from decompile.
- The 0x400 end-alignment formula (FUN_1402aa700 tail) could not be checked
  because neither sample's aligned end equals its file size (global: parsed
  end 946 vs file 29696) — the tail beyond the index is unaccounted for by
  the current model, presumably the per-file data area (see above).

## 4. Tooling

- `scripts/extract-tables.js` — table extraction + MapleLib diff
- `scripts/verify-cipher-tables.js` — AES T-table cross-check
- `scripts/pkg-parse.js` — full deterministic container parser
- `scripts/pkg-scan-index.js` — index-region locator (brute force)
- `scripts/pkg-scan-data.js` — data-region decryptor/signature scanner
- Evidence: `evidence/session25.jsonl`, `evidence/session26.jsonl`,
  `evidence/snow_tables_from_exe.json`, `evidence/pkg_index_dump.json`,
  `evidence/maplelib_Snow2CryptoTransform.cs`, `evidence/maplelib_WzMsFile.cs`
