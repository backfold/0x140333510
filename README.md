# SuddenAttack Client — Reverse-Engineering Analysis (REA)

> Personal analysis for study/interop. All work was done on **copies** in
> `H:\SA_Analysis\target\`; the live install at `H:\Program Files\Nexon\SuddenAttack` was
> only read from. With the owner's authorization (2026-10-18), this analysis output and the
> captured binaries are published to the analysis repo `github.com/backfold/0x140333510`.

## 1. TL;DR

- **Target**: `suddenattack.exe` (8,063,864 bytes, v26.1015.7.0283, x64 PE32+,
  SHA-256 `1a2343a24dae074dd9dba63f65cd637a8a5a7384fcd6b4f2840016b78e37e741`).
- **Themida hypothesis: CONFIRMED** (Oreans Themida 3.x-era layout): a virtual-only `.themida`
  section (rawSize 0, RWX), a high-entropy `.boot` depacker section holding the entry point,
  a decoy import table (34 DLLs × exactly 1 hint/name each), and real IAT slots zeroed on disk.
  **However**, Themida here is *not* compressing the original code: `.text`/`.rdata` are intact,
  normal-entropy, and statically analyzable — the protection is entry-point-VM + import
  elimination, so a classic "dump" step was unnecessary for static analysis (Section 5).
- **HackShield hypothesis: REFUTED.** No `HShield/` folder, and REA string search for
  `HackShield` returns zero hits in the client. The actual anti-cheat stack is
  **Easy Anti-Cheat (EOS variant)** + **Nexon NGS (BlackCat2.sys)** + **nProtect BlackCipher**
  (encrypted `.aes` modules, incl. `NGClient64.aes` imported by the client by ordinal 2).
- **Engine: LithTech-derived** (confirmed by build strings, RTTI, rez handling, and embedded
  NOLF2 mission text in `cres.dll`) with a Nexon package layer used for the encrypted `.pkg`
  game resources. Renderer is **DirectX 9** (`Direct3DCreate9Ex`, `RenderDll d3d.ren`,
  CD3D* classes). The client shell (`cshell.dll`) is MD5-verified before load.
- **`.pkg` resource layer (sessions 11–26) — CRACKED**: the loader is the Nexon-internal
  **lapacker** library statically linked into `suddenattack.exe` (`Lambda` namespace).
  `Lambda::SnowCipher` is the Nexon **Snow2** stream cipher (SNOW 2.0 with AES T-tables —
  the same primitive as MapleStory `.ms` v2; all 6 cipher tables in the exe are byte-exact
  vs MapleLib). Complete v1 container reversed **and validated with a standalone parser**
  (`scripts/pkg-parse.js`): path-derived sizes `N1 = Σchars mod 312 + 30`,
  `N2 = 3·Σchars mod 212 + 33`; masked in-file key (`byte >> 1` sar, check
  `(first>>1)^version == 3`); cycling-XOR header string (fixed salt `!dlstps20djr@`);
  two Snow2 streams with keys `key1[i] = (i + concat[i mod L]) & 0xff` /
  `key2[i] = (concat[L−(i mod L)−1]·((i mod 3)+2) + i) & 0xff` over `concat = path +
  headerString`; data region head `[checksum][count]`; index region at
  `dataStart + N2 + 8` with length-prefixed UTF-16LE filenames —
  `global_00000.pkg` (6/6 entries, `global/models/*.ltb/.ltc`) and
  `texturescripts_00000.pkg` (16/16, `*.tfs/.txt`) parse 100%. Remaining: per-file
  data-block addressing (index `field[3]/[4]`), v2 header variant unsampled.
- **Network crypto (sessions 27–28) — FOUND & DECODED** (in `cshell.dll`, §9):
  `CStreamCryptor_v1` packet obfuscation = rolling XOR with a **per-packet random
  15-bit key that ships inside the packet** + whole-block reversal + u16 checksum
  (self-describing → proxy-side decryption with zero prior knowledge), plus an
  XTEA-32 value codec with hardcoded key `"156def789023abc4"` (hex+`"SA"` wrapper),
  plus `CPHObject` header XORs. Working decryptors (Python+Node, KAT-verified) and a
  MITM capture proxy with automatic de-obfuscation logging under `scripts\py\`.
- **Live-wire MITM capture done (sessions 29–30)**: an `ngm://` protocol-handler
  shim redirects the game's server IP to a local proxy (full launcher/anticheat
  chain preserved), yielding **17.24 MB / 83,130 frames** of real 175.207.21.11:12000
  traffic. Wire framing `[u16le LEN][BODY]` chain-validated; the port-12000 codec is
  a **VM-dispatched variant** of the v1 core (per-packet TYPE byte, constant
  `0x1010` trailer, rolling-XOR key still travels in-packet — proxy decrypts
  160,192 frames). Inner payload layer **SOLVED** (sessions 31–33, §9): a
  session-scoped 16-byte XOR mask per direction
  (`M_c2s=85a3520d…7c03`, `M_s2c=f2596446…dc46`), and the cipher behind the
  suite is **KISA SEED (RFC 4269)** — SS-boxes byte-exact in `cshell.dll`
  `.rdata`, JS reimplementation KAT-clean (4/4 RFC vectors). Full-decode log
  of all 83,071 frames produced (`scripts/py/decode-all.js`).
- **cshell.dll (session 10)**: 33 MB, VLizer VM sections (`.vm_sec`/`.vlizer`) but intact
  21 MB `.text` — Ghidra recovers 74,642 procedures. Drives the EAC/EOS anti-cheat client
  session, game socket I/O (WS2_32), and `CSAGameClientShell` game logic. No plaintext
  `CMSG_*` network message names.
- OEP chain (statically identified): Themida stub (entry `0x140ab3058`) →
  `mainCRTStartup` `0x1402644b8` → `WinMain` `0x14007acf0`.
- Full evidence trail: `evidence\session1..28.jsonl` (REA MCP raw results),
  `evidence\evidence_index.tsv` (tool call → evidence_id index),
  `evidence\snow2_identification.md` (cipher/container validation),
  `evidence\network_crypto_identification.md` (wire crypto), decompiled
  functions in `decompiled\`, scripts in `scripts\`.

## 2. Target & Environment

| Item | Value | Source |
|---|---|---|
| Live install | `H:\Program Files\Nexon\SuddenAttack` | task |
| Analysis copies | `H:\SA_Analysis\target\` (exe + 12 related modules) | inventory.ps1 |
| Main client | `suddenattack.exe`, 8,063,864 bytes | `evidence\inventory.csv` |
| SHA-256 | `1a2343a24dae074dd9dba63f65cd637a8a5a7384fcd6b4f2840016b78e37e741` | Get-FileHash |
| File version | 26.1015.7.0283, Company `NEXON GT CO.,LTD.`, Product `SuddenAttack` | PE version resource |
| Link timestamp | 2026-10-13 12:19:45 UTC (21:19:45 KST) | PE COFF header |
| Format | PE32+ x64, image base `0x140000000`, 14 sections, subsystem GUI | pe-triage.js |
| Entry point (RVA) | `0xab3058` → VA `0x140ab3058` (inside `.boot`) | PE optional header |
| PDB (referenced) | `SuddenAttack.pdb`, GUID `{6c56246a-9feb-4a5e-b74a-c9543885c781}` — **not available locally** | debug directory |
| Authenticode | **Valid**; signer `CN="NEXON Games Co., Ltd.", Seoul, KR`; DigiCert timestamp 2026 | Get-AuthenticodeSignature (re-verified 2026-10-18) |

Toolchain used for analysis (all local):

- **REA** (rea-agents v6.5.0) via `npx rea-agents --mcp`, driven by the custom stdio client
  `scripts\mcp-client.js` (Ghidra provider; see Section 12).
- **Ghidra 12.1.4 PUBLIC** + Temurin JDK 21.0.12.1, installed into `H:\SA_Analysis\tools\`
  (per-invocation env: `GHIDRA_INSTALL_DIR`, `JAVA_HOME`).
- Helper scripts (Node.js, no Python on this box): `pe-triage.js`, `strings.js`, `entropy.js`,
  `inventory.ps1`, `digest.ps1`, `export-pseudo.ps1`.
- 8 REA sessions on suddenattack.exe (`evidence\session1..8.jsonl`) + 1 on machineidlib.dll
  (`session9.jsonl`), each re-importing the binary (~140 s) and
  closed with a snapshot (`evidence\sa_snapshot1..8.bin`, plus `sa_snapshot.bin` from s1).
- OS: Windows 10 Pro 19042; PowerShell 5.1; Node 24.

## 3. File Inventory

Full recursive inventories (path, size, SHA-256, type, version info, mtime):

- `evidence\inventory.csv` — 198 files in the install root and its subfolders
  (excluding the big `game\` package tree).
- `evidence\inventory_gamepkg.csv` — 516 `.pkg` files under `game\`, totaling
  29,428,845,022 bytes (~27.4 GiB). These are Nexon `Lambda` package archives
  (SnowCipher-encrypted, chunked entropy H=8.000 — measured with `entropy.js`). *(fact)*

Representative layout (roles: **fact** = direct observation; **inference** = labeled):

| Path | Size | Role |
|---|---|---|
| `suddenattack.exe` | 8,063,864 | Game client — this analysis' subject (**fact**) |
| `cshell.dll`, `cres.dll`, `ClientFX.fxd` | 33,648,304 / 671,592 / 309,608 | **Captured 2026-10-18 02:56** when the user launched the game (watcher `watch-cshell.ps1`): `cshell.dll` = game-logic client shell (VLizer VM-protected, §6.10); `cres.dll` = client resource DLL (`ClientRes.rc`, version 26.1015.7.0283); `ClientFX.fxd` = LithTech ClientFx effects module (a PE DLL renamed, `ClientFx.pdb`, references `SA_Shaders\...\modeleffect.fxc`) (**fact**) |
| `engine.rez` | 102,191 | LithTech RezMgr archive, **Sudden Attack variant** (signature `0x0a3f`, dir-info at file offset `0x16`); parsed by `scripts\rez-parse.js` → 11 files: 10 `RENDERSTYLES\*.LTB` render styles + `CONSOLE\CONSOLE_FONT.DTX` (**fact**, §6.8) |
| `ghsalncr.exe` | 4,076,904 | Launcher/patcher: strings `sa.dn.nexoncdn.co.kr`, `/sa_patch/gvi.dat`, `CheckLauncher >> Launcher Patch`, registry `Software\Nexon\SuddenAttack`, `INIT : NGM(%d) NEXON(%d)` (**fact** → role is inference from strings) |
| `NGM64.exe`, `NGMDll64.dll`, `NGMResource.dll` | ~8.9 MB | Nexon Game Manager (NGM) launcher modules (**inference** from names + NGM strings) |
| `eaclaunch.exe` | 3,975,920 | Easy Anti-Cheat launch helper (**inference** from name) |
| `EAEOS\EasyAntiCheat_EOS.exe`, `EAEOS\EasyAntiCheat_EOS.sys` | ~40 MB (.sys) | Easy Anti-Cheat, EOS (Epic Online Services) variant (**fact**: files present; pairing with `eossdk-win64-shipping.dll` 19,256,272 B) |
| `easyanticheat\` (localization, licenses, certificates) | 26 files | EAC support data (**fact**) |
| `blackcipher\blackcipher64.aes`, `blackcall64.aes`, `eTracer.aes`, `config.bc` | 56/48/2.3/1.2 MB | nProtect BlackCipher anti-cheat, AES-encrypted modules (**fact**: encrypted data blobs; vendor ID from names/NGClient import is inference) |
| `NGClient64.aes` (install root) | 12,825,088 | nProtect GameGuard-era client module, imported by suddenattack.exe as **ordinal 2** (**fact**: import entry) |
| `C:\ProgramData\Nexon\NGS\BlackCat2.sys`, `NGService.exe` | — | Nexon Game Security kernel driver + service (**fact**: files observed on the live system) |
| `libcef.dll` | 196,738,408 | Chromium Embedded Framework — Nexon Launcher/lobby UI (**inference**) |
| `vivoxsdk.dll` | 12,184,904 | Vivox voice chat SDK (**inference** from name; `vivox.log` string in client) |
| `bdcap64.dll` | 15,782,56 | Bandicam-family video capture library (**inference** from name) |
| `nexonanalytics64.dll`, `nmcogame64.dll`, `machineidlib.dll`, `nps64.dll`, `snddrv.dll`, `sacefdll.dll`, `sacefprocess.exe`, `CrashReporter.dll`, `CrashRpt64.dll`, `sashot64.dll`, `SAShot64.dll` | — | Nexon support modules (analytics, machine ID, sound, screenshots, crash reporting); copied to `target\` for later study |
| `game\digest.md5`, `_foreRevision.json` (`{"revision":1310}`) | — | Patch-manifest bookkeeping (**fact**) |
| `resources\resources.pak`, `icudtl.dat` | 7.7/10.5 MB | CEF/UI resources (**inference**) |

## 4. Protection Analysis (Themida)

### 4.1 CONFIRMED indicators

| # | Observation | Evidence |
|---|---|---|
| P1 | Section `.themida` @ VA `0x509000`, virtualSize 5,939,200, **rawSize 0** (virtual-only), flags `0xe0000060` (CODE\|IDATA\|EXEC\|READ\|WRITE) | `evidence\sa_exe_triage.json` (pe-triage.js) |
| P2 | Section `.boot` @ VA `0xab3000`, 3,323,904 raw bytes, **entropy 7.96**, holds the entry point `0x140ab3058` | pe-triage.js; REA `procedure_info` (ev_c72654d79c1d…) |
| P3 | Entry-point code is an **aPLib-style bit-decompression stub** (LZSS-style `ADD DL,DL / JNC / ADC` bit-reader loop) — the classic Themida/WL packer bootstrap | REA `procedure_assembly` at `0x140ab3058` (ev_d1fe6a116b07…) |
| P4 | **Decoy import table**: Import directory (`0x4d44a4`) lists 34 DLLs with **exactly one** hint/name each (`kernel32.dll→GetModuleHandleA`, `d3d9.dll→Direct3DCreate9Ex`, `NGClient64.aes→ord2`, `CrashRpt64.dll→MursumUT_MinimizeAllWindows`, …) — a name table Themida leaves so loaders can resolve the DLLs, while the real imports are reconstructed at runtime | pe-triage.js imports; REA `read_bytes` @ `0x1404d4000` (ev_722025fdff59…) shows the 1-name-per-DLL table verbatim |
| P5 | **Real IAT slots zeroed on disk**: REA `read_bytes` at `0x1403d5b28` and `0x1403d7838` (16 bytes each) return all-zero — these are runtime-filled import slots inside `.rdata` | ev_fdde21e648c5…, ev_cb6d03bbecf1… |
| P6 | ASCII marker string `@.themida` in the raw image; sections literally named `.themida`/`.boot` | pe-triage.js packerMarkerStrings_ascii |

Note on honesty: REA's `search_strings` for the literal `themida` returns **no hits** — the marker
lives in the raw header/marker area, not in Ghidra-defined strings. The identification rests on
P1–P6 jointly, not on a "Themida" ASCII string. *(fact)*

### 4.2 What Themida is *not* doing here (important)

- `.text` entropy **6.457** (3,132,647 bytes) and `.rdata` **6.019** — normal compiled code/data,
  not compressed/encrypted. The original program is **not packed away**.
- `.pdata` (x64 unwind data) intact, `.reloc` present, debug directory present (PDB ref).
- The unsigned high-entropy unnamed section @ VA `0x48d000` (157,184 bytes, **H=7.999**) is
  small — likely a Themida-internal data blob or crypto material, not the program body. *(inference)*
- Themida version: layout matches Themida 3.x-era "VM + import elimination" rather than full
  packing; exact version **unknown** (no version resource on Themida itself). *(inference/unknown)*

### 4.3 Authenticode & integrity

- Security directory RVA `0x7ae210`, size 10,600 == the 10,600-byte file overlay at offset
  8,053,264 (i.e., the signature is the overlay, standard Authenticode). *(fact)*
- Signature chain valid (NEXON Games / DigiCert timestamp 2026). Any byte-level tampering
  with the file breaks it — relevant because residual Themida/runtime integrity checks are
  expected (Section 8.6). *(fact + inference)*
- The client contains a `CIntegrityChecker`-style MD5 verification of `cshell.dll`/`cres.dll`
  before loading them (Section 7, FUN_1400bef00). *(fact, from pseudocode)*

### 4.4 Background hypotheses — verdicts

| Hypothesis (task background) | Verdict | Key evidence |
|---|---|---|
| Themida/WinLicense packing | **CONFIRMED** (§4.1) | P1–P6 |
| AhnLab HackShield anti-cheat | **REFUTED** | No `HShield/` dir anywhere in inventory; REA `search_strings "HackShield"` = 0 hits (ev_d267b02aa592…); no HackShield-flavored DLLs |
| LithTech engine, .rez archives | **CONFIRMED** | `LithTech build %s initialized…` @0x140304a00 (ev_01cf3f0e7bf8…), `engine.rez` @0x1403048d8 (ev_3087ca78611f…), rez-tree logic in FUN_14007a2f0, `LT_*` error strings, `LTGetILTMemory`/`SetMasterDatabase` exports @0x1404d3000 (ev_99ff1fa4735e…) |
| NGM launcher integration | **CONFIRMED** | `ghsalncr.exe` strings `INIT : NGM(%d) NEXON(%d)`, `NGM64.exe` present, `+NexonSN/+SessionID` command-line handling in WinMain |

Actual anti-cheat stack (**fact** — files present; the *interplay* is inference):

1. **Easy Anti-Cheat (EOS variant)**: `EAEOS\EasyAntiCheat_EOS.exe/.sys`, `eaclaunch.exe`,
   `easyanticheat\` support dirs, `eossdk-win64-shipping.dll`. In-client class
   `nxa::ETC_EasyAntiCheat` (RTTI @0x1403f76d8; getter FUN_14002b410 returns
   `"ETC_EasyAntiCheat"`).
2. **Nexon Game Security (NGS)**: WinMain step "Init 2 - NGS Start" → `NGSStart(%s)` error
   formatting (`0x140304838`, `0x140304848`); kernel driver `BlackCat2.sys` + `NGService.exe`
   under `C:\ProgramData\Nexon\NGS\`.
3. **nProtect BlackCipher**: `blackcipher\*.aes` encrypted modules; client imports
   `NGClient64.aes` by **ordinal 2** (import entry — REA saw the name; resolution of the
   encrypted module happens at runtime, REA cannot statically see inside it).

## 5. Unpacking Strategy & Procedure

**Finding**: because the original code is not compressed (§4.2), the on-disk image is
statically analyzable as-is. "Unpacking" in the classic dump sense is only required to obtain a
*runnable* image with a reconstructed import table. This analysis therefore proceeded
statically; no memory dump was taken (running the client was avoided — anti-cheat on the
analysis machine, and the task allowed static-only work). *(fact + decision)*

### 5.1 OEP chain (all statically identified)

| Step | VA | File offset | Evidence |
|---|---|---|---|
| Themida stub (entry) | `0x140ab3058` | 4,729,432 | PE header + REA `address_to_file_offset` (ev_048092cad1d9…) |
| `mainCRTStartup` | `0x1402644b8` | 2,505,400 | decompile (ev_82a976f0dae3…): `__security_init_cookie` → `__scrt_initialize_crt` → `FUN_14007acf0(&IMAGE_DOS_HEADER_140000000, 0, …)` |
| `WinMain` | `0x14007acf0` | 500,464 | decompile (ev_b69c573beffa…) — full client init sequence |

### 5.2 Reproducible procedure for a *dynamic* dump (documented, not executed)

To produce a runnable unpacked image (e.g., for IDA/Ghidra on a dump), on a machine where
running the client is acceptable (disposable account/VM — EAC/NGS ban risk on a live account):

1. Let Themida's stub run under a debugger with a hardware breakpoint on the IAT slot range in
   `.rdata` (e.g., the region around `0x1403d5000`–`0x1403d8000`, where slots
   `0x1403d5b28`/`0x1403d7838` were observed zeroed on disk).
2. When the runtime fills the IAT and transfers to `mainCRTStartup` (`0x1402644b8`), dump the
   process image with the reconstructed imports (e.g., Scylla).
3. Fix section table: drop the `.themida` virtual-only section, keep `.boot` for reference.
4. Verify dump OEP == `0x1402644b8` (or `0x14007acf0` if you enter after CRT init).
5. Note: the Authenticode signature (10,600-byte overlay) will no longer validate on the dump —
   that is expected and irrelevant offline.

`FUN_1400bef00`'s pseudocode contains `(*(code *)0x3d5b28)();` — Ghidra renders the
runtime-resolved IAT call targets as raw offsets (RVAs) because the slots are zero on disk;
this is a *visual* artifact of the import elimination, and corroborates P5. *(derivation)*

### 5.3 Scripts & artifacts for this phase

- `scripts\pe-triage.js` → `evidence\sa_exe_triage.json` (headers/sections/entropy/imports/TLS/overlay).
- `scripts\entropy.js` (chunked entropy; used to show `.text` ≈ 6.4–6.5 across chunks).
- REA snapshots: `evidence\sa_snapshot1..8.bin` (post-close snapshots of the Ghidra sessions).
- No memory dump exists in this workspace (static-only). *(fact)*

## 6. Static Analysis of the Client (REA / Ghidra 12.1.4)

All addresses are VAs in the on-disk image (image base `0x140000000`); every claim cites a REA
evidence_id (full index: `evidence\evidence_index.tsv`).

### 6.1 Startup / CRT

- Entry: Themida stub `0x140ab3058` (§4.1 P3).
- `mainCRTStartup` `0x1402644b8`: standard MSVC CRT init; calls `FUN_14007acf0` (WinMain) —
  decompiled in `decompiled\FUN_1402644b8_mainCRTStartup.c`.

### 6.2 WinMain — client bootstrap (`0x14007acf0`, 3,473 bytes)

Decompiled (ev_b69c573beffa…, full text `decompiled\FUN_14007acf0_WinMain.c`). Sequence
reconstructed from pseudocode + string xrefs (all string addresses are REA observations):

1. Registry/config: opens `sa_kr`, appends `\debugconfig.ini`; reads
   `LiveAssistCrashDump\Behavior\SAVELOCAL_FULLDUMP_AND_SENDSERVER_MINIDUMP`;
   starts logs `vivox.log`, `debug.log`, `errorlog\SAClient.log` (with
   `IS_CLIENTLOG_EXISTS` check), machine `GUID`.
2. Command-line parsing (`+CTool`, `+SessionID`, `+NexonSN`, `+ServerPort`) —
   launcher (NGM/ghsalncr) hands these in; `Nexon Game Log System` init
   (`GameLogManager: initialize successful.`).
3. Logs `"[CLIENT INIT] Start SuddenAttack V2.0 - %d/%02d/…"` (@0x140305330 — this xref is
   how WinMain was located; the same address holds the `s_net.cpp` build-path string, i.e.
   WinMain is the referencing function for both).
4. **Init 2 — NGS Start** (`NGSStart(%s)` on failure), **Init 4 — CrashReport Start**,
   **Init 6 — RunClientApp** — i.e., anti-cheat (NGS) is started *before* the game app runs.
5. Inside WinMain body is also the network bring-up referenced by the
   `D:\Jenkins\...\Engine\Runtime\server\src\s_net.cpp` string (@0x140313d70, xref
   `0x14007b68d` — inside WinMain's range `0x14007acf0–0x14007ba80`; ev_01c0ffe42f4c…,
   ev_51970b56ed79…).

### 6.3 Engine init / resource loading (`0x14007a2f0`)

Decompiled (ev_690e2576b386…, `decompiled\FUN_14007a2f0_engine_init.c`):

- Walks the **rez tree**: arg `world`, builds `"game\%s"` paths, default archive
  `engine.rez` (@0x1403048d8), optional `rez_dir` prefix, with overflow guard
  (`"Rez Overflow!!!!!!!"` + `MessageBox` "ERROR").
- Config plumbing: `noinput`, `workingdir`, `config`→`autoexec.cfg`, `display`→`display.cfg`,
  `+sounddll`.
- Ends with `"initialize client manager."` and, on success,
  `"LithTech build %s initialized in %.2f seconds.\n"` (@0x140304a00).

### 6.4 Renderer — DirectX 9 *(fact)*

- Import (decoy name, but the *only* renderer-named import present):
  `d3d9.dll → Direct3DCreate9Ex` (names @ `0x1404d445a`/`0x1404d4465`; ev_a60fceda28dd…,
  ev_dfb0f0ac3b9d…).
- `RenderDll d3d.ren` (@0x140309ba0, ev_89b60316b52e…) — LithTech render-DLL plug-in name.
- RTTI classes: `CD3DDrawPrim`, `CD3DRenderStyle`, `CD3DRigidMesh`, `CD3DSkelMesh`,
  `CD3DVAMesh`, `CD3DXInclude` (`evidence\rtti_classes.txt`).

### 6.5 Nexon resource layer (`Lambda` namespace, "lapacker") *(fact from strings/RTTI)*

RTTI/strings (file offsets `0x3f5e68`–`0x3f69f8` in `evidence\sa_exe_strings.txt`):
`Lambda::PackFileStream`, `Lambda::SnowCipher`, `Lambda::CipherHeaderStream<SnowCipher>`,
`Lambda::CipherStream<SnowCipher>`, `Lambda::ZlibStream`, `Lambda::PackageHeader`,
`Lambda::PackageHeader2`, `Lambda::FileSystem_CR`. Interpretation: the 516 `game\*.pkg`
files (~27.4 GiB, chunk entropy H=8.000) are SnowCipher-encrypted, zlib-compressed package
archives read through this stream stack.

Update (2026-10-18, further `sa_exe_strings.txt` mining — file offsets `0x330622`–`0x332b50`):
the package loader is a Nexon-internal library called **lapacker**, and its code is linked
**into suddenattack.exe** (not cshell.dll):

- Assert/log trace strings name the implementing functions directly:
  `Lambda::FileSystem_CR::FileSystem_CR`, `Lambda::FileSystem::FileSystem`,
  `Lambda::FileSystem::LoadPknAll` (a `.pkn` archive family also exists),
  `Lambda::PackageUri::PackageUri`, `Lambda::PackageLoader::OpenFile`,
  `Lambda::PackageHeaderLoader::LoadMaskedData`, `Lambda::PackageHeaderLoader::LoadEncryptData`,
  `Lambda::PackageHeaderLoader::LoadIndexTable`.
- Source paths in those strings: `C:\Git\lapacker\lib\FileSystemLib\FileSystem.cpp`,
  `...\PackageUri.cpp`, `...\PackageLoader.cpp`, `C:\Git\lapacker\Packing\LiveAssistCache.cpp`
  — a build tree distinct from the game code's Jenkins/SVN tree (§6.10), i.e. a prebuilt
  in-house library linked into the exe. *(fact)*
- Supporting members: `LiveAssist::LiveAssistCache::Get` (patch-on-the-fly layer),
  `/digest.md5` (integrity manifest), `"zlib inflate() error. invalid package file data."`
  (confirms zlib inside the container), and the literal default-key candidate `"1234567890"`
  near `PackageUri.cpp` strings *(hypothesis only — not verified as a key)*.
- Game-side package names (exe strings `0x30c840`–`0x30c878`):
  `game\sa_text_00000.pkg`, `game\sa_scripts_00000.pkg`, `game\sa_charactersc_00000.pkg`.
- cshell.dll strings contain **no** `SnowCipher`/`PackageHeader`/`.pkg` loader symbols —
  cshell sees resources through the exe's filesystem abstraction. *(fact from absence in
  `evidence\cshell_strings.txt`)*

Update (2026-10-18, REA sessions 12–13 — xrefs + containing-procedure resolution):
the lapacker implementation is confirmed to be a compact code region in the exe's `.text`,
and the consuming functions are now identified:

| String (VA) | Referenced from | Containing function |
|---|---|---|
| `"Lambda::PackageHeaderLoader::LoadIndexTable"` (`0x140333750`) | `0x1402a9c9d`/`0x1402a9d6e`/`0x1402a9e45`/`0x1402a9f16` | `FUN_1402a9820` (`0x1402a9820`) |
| `"Lambda::PackageHeaderLoader::LoadEncryptData"` (`0x1403336e0`) | `0x1402a969b`/`0x1402a9775` | `FUN_1402a95f0` (`0x1402a95f0`) |
| `"Lambda::PackageHeaderLoader::LoadMaskedData"` (`0x140333680`) | `0x1402aa32b` | `FUN_1402a9fc0` (`0x1402a9fc0`) |
| `"Lambda::PackageLoader::OpenFile"` (`0x1403335c0`) | `0x1402aa4e1`/`0x1402aa5a6`/`0x1402aa66b` | `FUN_1402aa3d0` (`0x1402aa3d0`) |
| `"zlib inflate() error. invalid package file data."` (`0x140333510`) | `0x1402a61a9`/`0x1402a61b7`/`0x1402a6624`/`0x1402a6632` | `FUN_1402a60a0`, `FUN_1402a6340` (zlib inflate wrappers) |
| `"game\sa_text_00000.pkg"` (`0x14030d440`) | `0x1402dd745` | `FUN_1402dd700` (game-side text-package consumer) |

*(fact — `evidence\session12.jsonl`, `evidence\session13.jsonl`; evidence IDs in
`evidence\evidence_index.tsv` rows s12/s13)*. All references cluster inside
`0x1402a6000`–`0x1402ab000`, consistent with a single linked lapacker translation-unit
group.

Update (2026-10-18, REA session 14 — `batch_decompile` of the seven functions,
`ev_71f96c14f948af4064770d364291b651a21fd9e1f37e6d963247b681a423d0e5`; pseudocode in
`decompiled\FUN_1402a*_lapacker.c`):

- **`FUN_1402aa3d0` = `Lambda::PackageLoader::OpenFile`** — opens the `.pkg` with a
  three-call memory-map sequence: open (`GENERIC_READ` `0x80000000`, share=1),
  `CreateFileMappingW` (`PAGE_READONLY` = 2), `MapViewOfFile` (`FILE_MAP_READ` = 4);
  handle/section/view stored at object +0xE0/+0xE8/+0xF0. Failure asserts reference
  `PackageLoader.cpp` lines 0x37/0x3d/0x43. The package is read as a memory-mapped
  image. *(fact from decompile)*
- **`FUN_1402a6340` = `ZlibStream` inflate driver** — manages a `z_stream` at
  object+0x20 and calls `inflateInit_(&s, "1.2.11", 0x58)`: the exe **statically links
  zlib 1.2.11** (version string passed to `inflateInit_`, sizeof(z_stream)=0x58).
  Inflate errors throw `"zlib inflate() error. invalid package file data."`
  (seen live at the error site, matching the s12 xrefs). *(fact)*
- **`FUN_1402a9820` = `PackageHeaderLoader::LoadIndexTable`** — loops
  `*(uint*)(packageHeader + 0x34)` times (per-file count in `PackageHeader` at offset
  0x34); each iteration reads a length-prefixed name string and appends a **32-byte
  (0x20) index entry** to a vector (entries copied at granularity `>> 5`). Assert
  messages cite `PackageLoader.cpp` lines 0xc2/0xc6/0xcd/0xd3. *(fact)*
- **`FUN_1402a9fc0` = `PackageHeaderLoader::LoadMaskedData`** — reads `*param_4` bytes
  one at a time; format check `(first_byte >> 1) ^ last_byte == 3`; if it passes, each
  stored byte is **un-masked by `>> 1`** before use, and a `Lambda::PackageHeader`
  object is constructed (`FUN_1402b14d0`), otherwise a `Lambda::PackageHeader2`
  (`FUN_1402b1490`) plus a seek(-1, cur). Then virtual `+0x18` loads the buffer and
  `FUN_1402b1b50` decrypts it. *(fact; object identities confirmed by vftable symbols in
  session 15 — see below)*
- **`FUN_1402a95f0` = `PackageHeaderLoader::LoadEncryptData`** — reads the encrypted
  block through stream virtuals (+0x20 read, +0x10 status) with a size assertion against
  `FUN_1402b17f0` (`PackageLoader.cpp` lines 0xae/0xb3). *(fact)*
- **`FUN_1402dd700`** — game-side error handler: logs `"PKG File open Error ( %ls : %s )"`
  and registers `game\sa_text_00000.pkg`, `game\sa_scripts_00000.pkg`,
  `game\sa_charactersc_00000.pkg` on first failure. *(fact)*

The SnowCipher key schedule itself is still open: the cipher-stream constructors
`FUN_1402b14d0` / `FUN_1402b1490` and the expander `FUN_1402b1b50` are the next
decompile targets (session 15, Q3, Section 10).

Update (2026-10-18, REA session 15 — `batch_decompile`,
`ev_43b19c3161cf2afaaffe93c9272f0587c71ebe02245b1f57f45e26482d306ad8`; pseudocode in
`decompiled\FUN_1402b*_lapacker.c`). **The `.pkg` header decryption is now reversed:**

- **`FUN_1402b14d0` = `Lambda::PackageHeader` constructor, `FUN_1402b1490` =
  `Lambda::PackageHeader2` constructor** — Ghidra resolved the vftable symbols
  (`Lambda::PackageHeader::vftable` / `Lambda::PackageHeader2::vftable`) from the RTTI
  in the binary. So the mask check in `LoadMaskedData` selects the header *version*
  (PackageHeader vs PackageHeader2), not a cipher choice. This corrects the session-14
  reading above. *(fact)*
- **`FUN_1402b1b50` = header decryptor** — the decrypted output is built 16 bits at a
  time: `out16[i] = in16[i] ^ keyBytes[i % keyLen]`, where `in16` is the encrypted
  header blob (an SSO string at header+0x10, word count at header+0x20) and
  `keyBytes` is the **in-file un-masked key vector** (`local_180` from
  `LoadMaskedData` after the `>> 1` pass). The key is therefore **per-package and
  stored inside the `.pkg` file itself** — not the `"1234567890"` candidate
  (hypothesis from §6.5 strings now considered unlikely for the header layer). *(fact
  from decompile; "which bytes are the key blob vs. the encrypted blob" is fully
  determined by `FUN_1402a9fc0` + this function)*
- **`FUN_1402b17f0` = header size/checksum accumulator** — sums the header blob as
  16-bit words (8-way unrolled) plus fields at +0xc, +0x8 (byte), +0x34; this is the
  value `LoadEncryptData` asserts against. *(fact)*
- **`FUN_1402a8600`** — trivial forwarder to `FUN_1402a82f0` (string helper). *(fact)*

Net container model (header layer, **fact**): `OpenFile` memory-maps the `.pkg` →
read masked key bytes → verify `(first>>1)^last == 3` (version select) → un-mask
(`byte >> 1`) → XOR-decrypt the header blob as 16-bit words with the cycling key →
`PackageHeader`/`PackageHeader2` fields → `LoadIndexTable` (count at +0x34, 32-byte
entries). Still open (Q3 remainder): whether the *file data* blocks use the same
cycling-XOR (the `SnowCipher` name) or a different `CipherStream<SnowCipher>` stage,
and the exact `PackageHeader` field map.

Update (2026-10-18, REA sessions 16–23 — **SnowCipher usage resolved**):

- `FUN_1402b1b50` (the 16-bit XOR) has exactly **one** caller — `LoadMaskedData` —
  so it is header-only (ev_2e4eeb6dca0e…). The file-data and index-table regions are
  decrypted by **`Lambda::SnowCipher`** stream objects (RTTI
  `.?AV?$CipherStream@VSnowCipher@Lambda@@@Lambda@@` @`0x1403f73c0`).
- **`FUN_1402aa700` = the package-open orchestrator** (vftable symbols
  `Lambda::SnowCipher::vftable` appear in its decompile, ev_be2d39257eac…). Flow:
  1. Masked-key byte count comes from the loader object
     (`FUN_14029fa20(param_1+0x20)`), not from the file header.
  2. `LoadMaskedData` → decrypted header string (the cycling-XOR result).
  3. **Key derivation** `FUN_14029f470` produces a **128-byte (0x80) key** from the
     decrypted header string; `FUN_1402abee0(cipher, key, 0x80, 0)` initializes
     SnowCipher instance #1 and `FUN_1402ace20(cipher, pos)` sets a position counter
     (`param_4 / 4`).
  4. `LoadEncryptData` reads through **SnowCipher stream #1** (CipherStream
     constructor `FUN_14029aba0`).
  5. A **second** 128-byte key is derived (`FUN_14029f6b0`) for SnowCipher instance
     #2, and `LoadIndexTable` reads through it.
  6. The consumed region is rounded up to **0x400 (1024-byte) alignment**
     (`*(param_1+0xf8)` end-offset handling).
- Remaining for a standalone parser: the SnowCipher core itself
  (`FUN_1402abee0` key schedule / `FUN_1402ace20` position set) and the two
  key-derivation functions — session 24 in flight. *(fact up to here; cipher
  internals pending)*

Update (2026-10-18, REA sessions 24–26 — **SnowCipher identified and the whole
`.pkg` container decrypted**; details in `evidence/snow2_identification.md`):

- **`Lambda::SnowCipher` = Nexon "Snow2"** — the SNOW 2.0-derived stream cipher
  also used for MapleStory `.ms` v2 containers (MapleLib/WzComparerR2
  `Snow2CryptoTransform`). Proof: all six 256-entry cipher tables in the exe's
  `.rdata` are **byte-exact** matches of the MapleLib tables
  (`scripts/extract-tables.js` → `evidence/snow_tables_from_exe.json`,
  `all_tables_match_maplelib: true`): `snow_alpha_mul`@`0x1403ef1a0`,
  `snow_alphainv_mul`@`0x1403ef5a0`, `snow_T0..T3`@`0x1403ef9a0/fda0/f01a0/f05a0`
  (snow_T0..T3 are the AES T-tables Te0..Te3 — independently regenerated by
  `scripts/verify-cipher-tables.js`). `FUN_1402abee0` implements the MapleLib
  `LoadKey` structure (key+complements into s15..s0, IV XOR into s15/s12/s10/s9,
  2×16 unrolled init clockings using a_mul/ainv_mul/Te tables). *(fact)*
- **Key-derivation formulas** (session 24 decompiles, confirmed by validation):
  path string = package file name as opened (e.g. `global_00000.pkg`);
  `concat = path + headerString` (UTF-16), `L = char count`;
  `N1 = (Σ chars) mod 312 + 30` (`FUN_14029fa20`),
  `N2 = (3·Σ chars) mod 212 + 33` (`FUN_14029f920`),
  `key1[i] = (i + concat[i mod L]) mod 256` (`FUN_14029f470`),
  `key2[i] = (concat[L−(i mod L)−1]·((i mod 3)+2) + i) mod 256` (`FUN_14029f6b0`).
  SnowCipher instances use the first **16 bytes** of each 128-byte derived key,
  IV = 0, position = byteOffset/4 (`FUN_1402ace20`; the 0x94-byte state
  snapshots appended at +0xa0 by `FUN_1402ad020` are keystream checkpoints for
  random access). *(fact)*
- **Standalone parser works** (`scripts/pkg-parse.js`). Both validation samples
  parse end-to-end — `global_00000.pkg`: header string `!dlstps20djr@`, data
  head `[checksum=524325, count=6]`, index @350 = dataStart(141)+N2(201)+8,
  6/6 entries (`global/models/*.ltb/.ltc`); `texturescripts_00000.pkg`:
  `[393435, 16]`, index @190 (predicted before scanning, then hit), 16/16
  entries (`texturescripts/*.tfs/.txt`). The header string is a **fixed salt**
  (`!dlstps20djr@` on both files); the path only feeds N1/N2/key derivation.
  *(fact)*
- **Index entry format** (`FUN_140290e00`/`FUN_1402b18c0`, session 26):
  `[u32 strlen][strlen×2 UTF-16LE name][6×u32][u32 n][n×16B][16B tail]`
  plus 32 more bytes when `field[1] & 0x10`. Field semantics (inference):
  `field[0]` 16-bit checksum, `field[1]` flags (6/7), `field[2]` sequence
  index, `field[3]/[4]` data-region coordinates, `tail16` per-entry MAC/IV.
  *(format = fact; field meanings = inference)*
- **Still open (Q3 remainder)**: where per-file data physically lives and how
  `field[3]/[4]` address it — the tail after the index decrypts to
  high-entropy noise under a position-0 key1 stream (no LithTech signature;
  `scripts/pkg-scan-data.js`), consistent with per-file random access through
  the checkpoint vector rather than one linear stream. Next experiment:
  decompile the file-read path (CipherStream::Read / callers of
  `FUN_1402a95f0`). The v2 (PackageHeader2) variant has no sample. *(unknown)*

### 6.6 Input / sound / misc

- Sound: `+sounddll` command-line (engine init), `snddrv.dll` present in install. *(fact)*
- Input: `noinput` flag in engine init; no dedicated input DLL observed. REA did not deep-dive
  the input path — **unknown** beyond this. *(fact/unknown)*
- Voice: `vivox.log` in WinMain; `vivoxsdk.dll` in install. *(fact)*
- Crash reporting: `CrashReporter.dll`, `CrashRpt64.dll` imports (decoy names);
  `LiveAssistCrashDump` registry settings. *(fact)*

### 6.7 RTTI class census

`evidence\rtti_classes.txt` — 543 classes extracted via REA string search for MSVC RTTI
name patterns (`.?AV…@@`, ev_ff081938397d…). Notable families: LithTech client
(`ILTClient*`, `CClientShell`, `CAPIHolder<VILTClient*>`), networking
(`CBaseConn`, `CUDPConn`, `CUDPDriver`, `CUDPSession`, `CMoArray<CBaseConn*>`,
`GenList<CUDPQuery>`), Nexon (`nxa::ETC_EasyAntiCheat`, `INXGSM`/`TiNXGSM`).

### 6.8 `engine.rez` archive — parsed (Q4 resolved)

The archive is a LithTech **RezMgr** container in the *Sudden Attack variant* — a layout
documented publicly in Luigi Auriemma's QuickBMS script `rezmgr.bms` (SA variant: 2-byte
signature `0x0a3f` at offset 0; directory-info triple `dummy/dirOffset/dirSize` at file
offset `0x16`; recursive listings at the end of the file with 8-byte *reversed* extension
fields — e.g. `XTD` = `.DTX`).

`scripts\rez-parse.js` implements that layout and parses the local copy completely:

```
node scripts\rez-parse.js target\engine.rez
# RezMgr SuddenAttack variant (0x0a3f), size=102191
# header@0x16: dummy=0x18ae2 info_offset=0x18efa info_size=0x35
# 11 file entries
 15a38  1727  RENDERSTYLES\RS_SPHEREENVMAP_ADD.LTB
 10643   621  RENDERSTYLES\RS_ALPHATEST_GREATER.LTB
 10169   621  RENDERSTYLES\RS_ALPHABLEND_TEXALPHA.LTB
 103d6   621  RENDERSTYLES\RS_ALPHABLEND_TFACTORALPHA.LTB
 160f7   621  RENDERSTYLES\RS_SPHEREENVMAP_MODTEXALPHA.LTB
 16364  7762  RENDERSTYLES\RS_TOON_VS.LTB
 13856  8674  RENDERSTYLES\RS_HALO_VS.LTB
 181b6  1727  RENDERSTYLES\RS_TWOTEXTURE.LTB
 18875   621  RENDERSTYLES\RS_VERTEXSPECULAR.LTB
 108b0 12198  RENDERSTYLES\RS_DOT3BUMP_DIR_VS.LTB
    c5 65700  CONSOLE\CONSOLE_FONT.DTX
```

*(fact — parser output; offsets are file offsets in engine.rez.)* The render-style names
(toon, halo, dot3-bump, sphere-env-map, vertex-specular) corroborate the DX9 fixed-function
+ vertex-shader pipeline identified in §6.4. The whole-file low entropy (H≈0.7–3.3 per
chunk) confirms the archive is **not** encrypted — unlike the `.pkg` tree (§6.5).

### 6.9 Support-module roles (Q8, largely resolved)

Triage of the copied support modules (`pe-triage.js` + `strings.js` outputs
`evidence\<module>_strings.txt`; REA session 9 for machineidlib.dll). All are clean,
unpacked PE32+ x64 with visible imports. *(facts = strings/PDB-path observations;
interpretations labeled)*

| Module | Identified role | Key evidence |
|---|---|---|
| `machineidlib.dll` | **Machine-ID library** feeding Nexon account/ban systems | REA s9: export `MIDLib_GetMachineId` (procedure @`0x18000127b`, ev_9712d52a9603…) + string `MIDLib_GetGameRoomCode` @`0x180077aed` (ev_417e83cde991…); PDB path `…\guss-mid-library-vs2019\…\MachineIdLib.pdb` @0x70280 (strings). "GameRoomCode" = PC-bang/game-room identification *(inference)* |
| `sacefdll.dll` / `sacefprocess.exe` | **CEF (Chromium) UI integration** for the client (SACefApp / SACefBrowserSingleton) | source paths `…\SA_Source\Engine\Runtime\SACefDll\*.cpp` @0x39780+, `SACefProcess.pdb`; imports `libcef.dll` |
| `eaclaunch.exe` | **Easy Anti-Cheat Bootstrapper (EOS)** | UTF-16 string `Easy Anti-Cheat Bootstrapper (EOS)` @0x3c4878, dialogs `Easy Anti-Cheat Launch Info/Launch Error/Launch Canceled`; embeds EOS SDK + SDL2 gamecontroller DB (hence the controller-mapping strings) |
| `nmcogame64.dll` | Nexon **platform/login SDK** ("NexonTalk"/NMCO) | PDB `…\NexonTalk\20210518_nmconew\PlatformSDK\x64\Release\nmcogame64.pdb` @0x5f174; RTTI `CNMLocaleInfo_TW_Nexon` |
| `nps64.dll` | Nexon **base-tech SDK** ("NpsSdk") — *not* nProtect | PDB `D:\GitLabRepos\basetech_cpp_nps\NpsSdk\Release_Win64\nps64.pdb` @0x442c4; enum string `NPS_NO_ERROR` @0x417b0 |
| `nexonanalytics64.dll` | Telemetry/analytics | name + `serialNumber`/regex machinery in strings; 8.2 MB size |
| `snddrv.dll` | **Sound driver module of the same engine build** as suddenattack.exe | PDB `D:\Jenkins\workspace\workspace\SA_QA_FINAL_BUILD\svn_source\Built\Final\bins\Client\SndDrv.pdb` @0xd3c4 — identical Jenkins/SVN build tree as `s_net.cpp` (§6.2) |
| `ghsalncr.exe` / `NGM64.exe` | Launcher + patcher (§3) | CDN/patch strings; NGM64 WinHTTP imports (`HttpOpenRequestW` etc.) |

### 6.10 `cshell.dll` — the game-logic half (Q1 captured, Q7 largely resolved)

Captured 2026-10-18 02:56 during a user-initiated game launch (watcher log
`evidence\cshell_watch.log`; SHA-256 `82F0F4E40A21EFCF9C2826B7E8AD195264CA844F7C3DF8E76D19BBDC03BC2F23`,
hash-verified against the live file). Triage (`pe-triage.js`, `strings.js` —
`evidence\cshell_strings.txt`, 58,400 strings; REA session 10):

**Protection (fact)**: x64 PE32+ DLL, 8 sections, **VLizer VM protection** — sections
`.vm_sec` (49,664 B, H=4.89) and `.vlizer` (5,920,256 B, H=6.19) + `.vlizer` marker string
@0x378. Unlike Themida on the exe, VLizer here does **not** eliminate imports (full
35-DLL import table readable) and leaves `.text` intact (21.2 MB, H=6.37, entry RVA
`0x13730b4` inside `.text`). Same situation as the exe: statically analyzable; the VM
sections protect selected functions at runtime. *(Which functions are virtualized: unknown
without runtime analysis.)*

**Build origin (fact)**: PDB path `D:\Jenkins\workspace\workspace\SA_QA_FINAL_BUILD\svn_source\Built\Final\bins\Client\Game\CShell.pdb` @0x16e3cc0 — the same Jenkins/SVN build tree as `suddenattack.exe` (`s_net.cpp`) and `snddrv.dll`/`ClientFX.fxd`.

**Runtime module graph (fact — import table)**, resolving most of Q7's interplay:

| Imported DLL | Count | Notable functions → role |
|---|---|---|
| `EOSSDK-Win64-Shipping.dll` | 30 | `EOS_AntiCheatClient_BeginSession/EndSession/AddNotifyClientIntegrityViolated/ReceiveMessageFromServer`, `EOS_Connect_Login/Logout/CopyIdToken`, `EOS_Platform_Create/Tick` → **cshell.dll drives the EAC (EOS) client session and EOS account connectivity** |
| `MachineIdLib.dll` | 2 | `MIDLib_GetMachineId`, `MIDLib_GetGameRoomCode` → machine identity is consumed by the game shell |
| `nps64.dll` | 2 | `OpenSurveyWindowA`, `GetLastErrorMsg` → in-game survey UI |
| `nmcogame64.dll` | 5 | `NMCO_SetLocaleAndRegion`, `NMCO_SetVersionFileUrlA`, `NMCO_SetPatchOption`, `NMCO_CallNMFunction` → platform/locale wiring |
| `WS2_32.dll` | 25 | `WSAConnect`, `WSASend`, `WSARecv` → **game socket I/O lives in cshell.dll** |
| `WINMM.dll` | 32 | `waveIn/waveOut/mixer` → voice capture/playback |
| `d3dx9_43.dll` | 5, `AVIFIL32.dll` (9), `MSVFW32.dll`, `IMM32.dll` (11) | shader assembly, AVI playback, IME input |

So the anti-cheat division of labor is: **suddenattack.exe starts NGS** (WinMain "Init 2 —
NGS Start"), while **cshell.dll runs the EAC/EOS anti-cheat client session** (Begin/EndSession,
integrity-violation notifications) and the actual game socket I/O. *(derivation from imports;
exact call sites pending further decompiles.)*

**REA session 10 (executed 2026-10-18, Ghidra deep-dive on the 33 MB DLL; evidence rows
s10 in `evidence_index.tsv`)**:

- **Full Ghidra layout (fact)** — image base `0x180000000`, 10 segments:
  `.text` `0x180001000`–`0x181438000` (21,196,800 B), `.rdata` 4.7 MB, `.data` 2.2 MB,
  `.pdata` 1.0 MB, `.vm_sec` 49,664 B @`0x181c14000`, `.vlizer` 5,920,256 B @`0x181c21000`,
  plus a `tdb` block at `0xff00000000` (Ghidra memory-block artifact, not file data).
  Ghidra recovered **74,642 procedures** and 32,020 defined strings from the intact
  `.text` (ev_35fb49477ec8…). Confirms the earlier triage: VLizer VM sections exist but
  the bulk of cshell is statically analyzable.
- **Client-shell classes (fact)** — `CSAGameClientShell` @`0x181502b88` (the
  Sudden-Attack-specific subclass), `CGameClientShell::OnEngineInitialized` log string
  @`0x1815e84a8`, RTTI for `CGameClientShell` plus its hook-data objects
  (`KeyDownHookDataObject`, `LButtonUpHookDataObject`,
  `Before/AfterHandleWeaponPickupHookDataObject`) @`0x18190b148`–`0x18191c2f0`
  (ev_5d2ac743f3b1…). Input and weapon-pickup events flow through LithTech shell hooks.
- **Negative findings (fact from absence)** — `CMSG_`-prefixed strings: **0 hits**
  (ev_755774f5da20…); `VLizer` as a literal: 0 hits; procedure name `ShellInit`: 0
  hits. So network message type names are **not** stored as plain `CMSG_*` literals in
  cshell.dll — they are either constructed dynamically or live in the `.pkg` script
  resources (see §6.5). The earlier "VLizer" attribution rests on the section names and
  the @0x378 marker string, not on a readable "VLizer" string in defined data.

**Game-logic strings (fact, samples)**: `[SurvivalMode] inventory PacketRecv false : %d`,
`DoorPointDoorServerActionPacketEvent%d`, `ActionPacketID%d`, and hundreds of
`sa_interface2\menu\...dtx` UI texture paths.

**cres.dll / ClientFX.fxd (fact)**: `cres.dll` = resource-only DLL (`ClientRes.rc`,
version 26.1015.7.0283, .rsrc 650 KB); `ClientFX.fxd` = LithTech ClientFx effects module —
a PE DLL with a renamed extension (`ClientFx.pdb` same build tree, references
`SA_Shaders\Characters\Effect\modeleffect.fxc`), unprotected, 12 imports.

**cres.dll embedded text (fact, engine archaeology)**: strings extracted from the captured
`cres.dll` (`evidence\cres_strings.txt`, 5,747 lines) contain large blocks of English
mission-briefing / dialogue text from the **No One Lives Forever 2** corpus — characters
"Cate Archer", "H.A.R.M.", "UNITY", "Santa", mission-objective and radio-transmission
strings (e.g. @0x2d94c, @0x115c6, @0x3c3be). This is direct evidence that the resource
module descends from the LithTech Jupiter-era codebase/text corpus that NOLF2 shipped on —
text inherited alongside the licensed engine rather than SuddenAttack-authored content.
*(fact from string presence; "inherited with the engine license" is inference.)*



## 7. Key Decompiled Functions

Full pseudocode files in `decompiled\` (each with REA evidence_id header; Ghidra-resolved
function starts differ from queried addresses where noted).

| Function (VA) | File offset | Guessed prototype | Purpose | Pseudocode summary | Evidence |
|---|---|---|---|---|---|
| `0x1402644b8` mainCRTStartup | 2,505,400 | `int mainCRTStartup(void)` | CRT entry, OEP | `__security_init_cookie`; `__scrt_initialize_crt`; calls `FUN_14007acf0` (WinMain); normal CRT teardown | ev_82a976f0dae3… |
| `0x14007acf0` WinMain | 500,464 | `int WinMain(HINSTANCE, HINSTANCE, LPSTR, int)` | Full client bootstrap | logs/registry init → parse `+CTool/+SessionID/+NexonSN/+ServerPort` → GameLogManager → NGS start → CrashReport → `RunClientApp` (engine loop) | ev_b69c573beffa… |
| `0x140078f60` | 492,896* | `void client_globals_init(void)` | Initialize client-side global managers/tables | long init of globals at `DAT_1403fe648` client object; follows WinMain's early setup | ev_af1e55a8d000… |
| `0x14007a2f0` engine init | 497,904* | `bool engine_init(CLTArg*)` | Rez trees, config, client manager init | §6.3 | ev_690e2576b386… |
| `0x1400bef00` cshell loader (queried at `0x1400bef4a`) | 779,520 | `uint cshell_load(void)` | MD5-verified load of `cshell.dll` + `cres.dll` | `FUN_1400bdc40("cshell.dll", path, 0x104, &md5)`; on hash mismatch → `LT_MISSINGSHELLDLL`/`LT_INVALIDSHELLDLL`/`LT_ERRORCOPYINGFILE` errors via `InitClientShellDE`; calls virtual `(*h+8)(h, …)` to hand the engine pointer to the shell; then loads `cres.dll` the same way | ev_22e9a94bf997… |
| `0x140131010` model/piece load (queried at `0x140131444`) | 1,246,736 | `uint model_load(obj*, db*, wchar_t*, ctx*)` | Model database / piece loading (NOT networking — corrected during analysis) | iterates models; `pModel->GetModelDB()` error paths; `FUN_1401331b0` finalize | ev_5e9fd862953c… |
| `0x14002b410` | 174,608* | `const char* etc_name(void)` | Anti-cheat identifier getter | returns `"ETC_EasyAntiCheat"` | ev_0bbd0ce3a376… |

\* offsets marked `*` computed from the VA through the section table
(`.text`: rawPointer 0x600 at RVA 0x1000 ⇒ `file offset = VA − 0x140000A00`); the formula
was validated against all four REA-observed pairs above (mainCRTStartup/WinMain/cshell/model,
each matching to the byte — ev_048092cad1d9…, ev_becfef9b3057…, ev_353d066c4604…,
ev_7e10ea09e290…, ev_8c221e0299e2…).

Additional decompiled-for-reference (not exported as files): `0x1400015e8` — a large
HRESULT→message table function (69,821 chars, ev_dd66557fb358…). Initially suspected to be
client anti-debug because it contains `"Debugger is present."` (@0x140354880); decompilation
showed it is a D3D/DirectX `D3DERR`/`DXGI` message table lookup (e.g. `0x8876024B
D3DERR_DRIVERINTERNALERROR`-style mapping), referenced from the message formatting path — **not**
an anti-debug check. *(correction, documented to keep the evidence trail honest)*

## 8. Systems Overview (fact vs inference vs unknown)

1. **Process flow (fact)**: Nexon Launcher/NGM → `ghsalncr.exe` (patch: `sa.dn.nexoncdn.co.kr`,
   `/sa_patch/…`) → `suddenattack.exe` with `+SessionID/+NexonSN/+ServerPort/+CTool` args →
   Themida stub → CRT → WinMain → NGS start → engine/rez init → cshell.dll (MD5-checked) →
   game loop.
2. **Engine (fact)**: LithTech-derived runtime (build string, rez handling, `LT_*` error
   strings, `LTGetILTMemory`/`SetMasterDatabase` exports @ `0x1404d3000`).
3. **Renderer (fact)**: DirectX 9 (`Direct3DCreate9Ex`, `d3d.ren`, CD3D* classes).
4. **Resources (fact/inference)**: `.pkg` SnowCipher+zlib packages (Lambda) as primary store;
   `engine.rez` is a standard LithTech **RezMgr archive in the documented "Sudden Attack
   variant"** (2-byte signature `0x0a3f`; directory-info triple at offset `0x16`) — parsed
   end-to-end by `scripts\rez-parse.js` (§6.8). *Correction*: the initial "obfuscated
   64-byte header" hypothesis (based on the scrambled-looking first bytes) was **refuted** —
   those bytes are the signature plus the leading `CONSOLE_FONT.DTX` payload.
5. **Client shell (fact)**: `cshell.dll`/`cres.dll` loaded with MD5 verification
   (FUN_1400bef00); shell receives engine interface via vtable call `(*obj+8)(obj, iface)`.
6. **Anti-cheat handoff (fact + inference)**: WinMain starts NGS explicitly; EAC-EOS +
   BlackCipher modules exist on disk; `nxa::ETC_EasyAntiCheat` class exists in-client.
   Exact handoff ordering/IPC **unknown** (would need runtime observation — skipped, §10).
7. **Networking (fact)**: LithTech UDP stack (`CUDPDriver`/`CUDPConn`/`CBaseConn`/`CUDPSession`
   RTTI; `s_net.cpp` build-path string xref'd from WinMain; packet-log strings;
   `CMSG_CONNECTSTAGE` message). Protocol bytes **not** reversed (no traffic capture,
   no cshell.dll). *(unknown beyond class/message names)*
8. **Residual Themida integrity checks (inference)**: expected at runtime (standard for
   Themida), but *none were statically confirmed* in `.text` — REA string searches for
   anti-debug idioms found only the D3D message-table false positive (§7). The
   `CIntegrityChecker` MD5 path is a *Nexon* check (cshell), distinct from Themida's own.
   *(inference/unknown)*
9. **TLS (fact)**: TLS directory present @ RVA `0x4d5018`, **zero callbacks** — no TLS-based
   anti-debug hook via callback array on disk.
10. **Build environment (fact)**: Jenkins CI path
    `D:\Jenkins\workspace\workspace\SA_QA_FINAL_BUILD\svn_source\Engine\Runtime\server\src\s_net.cpp`
    (@0x140313d70) — SVN-based source tree, "SA_QA_FINAL_BUILD" job, engine/server split.
    Developer names leak in error strings (`-kwangsik`).

## 9. Network / Protocol Notes

- Transport: LithTech CUDP driver (RTTI `CUDPDriver`, `CUDPConn`, `CUDPSession`,
  `CBaseConn`; `CMoArray<CBaseConn*>`/`GenList<CUDPQuery>` connection/query pools). *(fact)*
- `WS2_32.dll` ordinal import (decoy table `ord21`) — Winsock usage. *(fact)*
- WinMain parses `+ServerPort` before starting the client app; `s_net.cpp` (engine/server
  runtime source file) string is referenced from WinMain body @0x14007b68d. *(fact)*
- Message names visible in strings (e.g. `CMSG_CONNECTSTAGE`) indicate a LithTech-style
  message-ID protocol for connection staging. *(fact that the string exists; protocol
  semantics unknown)*
- **Wire crypto found and reversed in `cshell.dll`** (sessions 27–28,
  `evidence/network_crypto_identification.md`):
  - `CStreamCryptor` RTTI hierarchy — base (pure-virtual) + `v0` (pass-through:
    tag getters return 0) + `v1` (real codec). vftables 0x181658f58 / f98 / fd8.
  - **v1 packet obfuscation** (`FUN_181272e40` enc / `FUN_181272fa0` dec,
    vtable +0x08/+0x10): header `{rand8, tag8, rand8, key32(15-bit rand), rand8}`
    + payload rolling-XOR (`c[i] = key ^ p[i] ^ c[i-1]`) → whole block **reversed**
    → u16 checksum appended. **The key travels inside the packet**, so a
    capture-side proxy can decrypt with zero prior knowledge. *(fact from
    decompile; checksum fn 0x181272bc0 body + live-wire usage pending session 29)*
  - **XTEA-32 with a hardcoded key** `"156def789023abc4"` (u32s
    0x64363531/0x38376665/0x33323039/0x34636261) on an 8-byte block
    (enc `FUN_180d5ef00`, dec `FUN_180d5e9c0`), wrapped as uppercase-hex + `"SA"`
    suffix (`FUN_180d5e0e0/2e0`) — value-level obfuscation, login-flow related
    *(inference)*. Also invoked from the VM-protected `.vlizer` region
    (0x18215b904/910). *(fact)*
  - `CPHObject` header de-obfuscators: XOR_1 `[this+0x38]^[this+0x30]^[this+8]`,
    XOR_2 `[this+0x40]^[this+0x38]^[this+8]` (raw machine-code read). *(fact)*
  - Correction: the earlier "XXTEA" identification was wrong — the constant +
    unroll pattern is textbook **XTEA** on a 64-bit block.
- **Live-wire capture (sessions 29–30) — the port-12000 codec is NOT v1**:
  a full MITM capture (ngm protocol-handler shim → local proxy → real server;
  17.24 MB / 83,130 frames / 13 s, `evidence/session30_wire_capture.md`) shows
  framing `[u16le LEN][BODY]` (chain-validated across the whole C2S stream), and
  BODY = `reverse(H)||0x1010` where `H = {rand, TYPE, rand, key32, rand}` +
  the same rolling-XOR core — but `H[1]` varies per packet (message type:
  0x3d/0x42/0x51 login, 0x8 heartbeat C2S, 0x8e bulk S2C …) while v1's tag
  getter returns constant 1, and the 2-byte trailer is the constant `10 10`
  on every frame (impossible for v1's content-dependent checksum
  `FUN_181272bc0`). Alignment brute-force found no v1 block inside any frame.
  The actual decrypt dispatcher is **VM bytecode in `.rdata` 0x18188be20+**
  (instruction stream with RVA operands pointing at `0x181272bc0` checksum,
  `0x181272fa0` v1-decrypt core, self-referencing jumps) — the `.vlizer` VM
  wraps the native v1 routines with its own header/trailer layout. Rolling-XOR
  parameters (key-in-packet, prev reset per packet) were verified against
  identical-payload heartbeats. Inner payload layer: still unresolved
  (16-byte quasi-periodic structure; XTEA-ECB and simple-XOR-keystream
  hypotheses tested and not confirmed). *(fact up to the VM conclusion,
  which is inference from the bytecode's RVA operands)*
- Working Python/Node implementations + KAT: `scripts/py/sa_net_crypto.py`
  (validated via Node mirror, `scripts/py/sa-proxy.js --selftest`), and a
  capture proxy with automatic de-obfuscation logging:
  `scripts/py/sa_proxy.py` / `sa-proxy.js` (usage: `scripts/py/PROXY_USAGE.md`).
  Launch endpoint observed from a user-supplied `ngm://` URL:
  `175.207.21.11:12000` (`evidence/ngm_launch_args.md`, token redacted).
- **Inner payload layer — SOLVED (sessions 31–33)**. After the obf layer, the
  payload is `P[i] = C[i] ⊕ M_dir[i % 16]` — a **session-scoped 16-byte mask
  per direction**, absolute alignment at payload offset 0, period 16, constant
  across the whole session (proven three ways: per-position byte modes over all
  83k frames; per-tag constant padding — `mode(tag) ⊕ M ∈ {0x00,'0','H','8'}` —
  and heartbeats #16/#27 with different key32 but identical decoded payload
  structure). **`M_c2s = 85a3520d83db99b93ae96247c74f7c03`,
  `M_s2c = f2596446d34b7b6469cc4ef7ca42dc46`** (this capture). Decoded content:
  heartbeats `[0xda/0x24/0x25][zero or 0xfe fill]`; bulk 0xb6–0xe0 tags carry a
  pipe-separated text protocol (`04z~~CA|00|00|01}01}00|ut@A|…`, 230 distinct
  tags); login 0x3d has `'8'`(0x38) padding + a 16-byte blob at ~0x86
  (`c0e98d1f c0479aff c0319038…` — session-key candidate); 0x42/0x51 and the
  post-login 0x34/0xbf/0x8e frames remain opaque (second crypto stage).
  Full-session decoder: `scripts/py/decode-all.js` →
  `logs/run1/decoded.log` (83,071 frames, 75.9 MB, git-ignored).
- **The cipher is KISA SEED (RFC 4269)** — identified by table match: the four
  1 KiB tables at `0x1814967b0/0x181496bb0/0x181496fb0/0x1814973b0` in
  `cshell.dll` `.rdata` are byte-exact SS0..SS3 (Oryx CycloneCRYPTO `seed.c`
  lineage). Suite map (`evidence/notes/cipher-suite-map.md`):
  `0x180330d10` block-ENCRYPT, `0x180331bb0` block-DECRYPT,
  `0x1803333f0` **seedInit** (ctx: id@0, IV16@4, 32×u32 round keys@0x14,
  feedback state@0x94, len@0xA4), `0x180333250` **streaming CFB-family
  method** (id==1: `c=D(K,p⊕mask)`, mask←c; id≠1: `c=E(K,p)⊕mask`, mask←p —
  plaintext-feedback CFB; IV persists across calls), `0x180333ff0` mode
  pre-processor (len%4), ctors `0x180334060/0d0/180/220`. Local
  e8/e9-rel32 callsite scan (Ghidra xrefs times out on this 33 MB binary):
  the **entire SEED suite has exactly two external callers** —
  `0x1801aa456` (in `0x1801a9fa0`, → wrapper `0x180332ee0`) and
  `0x18018ae96` (in `0x180189760`, → ctor `0x1803340d0`). The two ~900-byte
  self-contained wrappers `0x180332b40`/`0x180332ee0` call seedInit directly
  and are the wire-codec candidates. The wire's constant-mask XOR does **not**
  match 0x180333250's per-block chaining (S2C heartbeat #16 shows 12+ blocks
  of constant mask), so the wrappers implement the per-packet reset path —
  key/mask source pending their decompile (session 33). Mask-derivation
  hypotheses from key32 alone (SEED/XTEA/RC4/hash battery, 800+ combos incl.
  fixed key `"156def789023abc4"`) are all eliminated — the mask is
  session-state-derived.
- **Hardcoded SEED key/IV recovered from disk** (2026-10-18, sessions 33–34
  follow-up): static-init thunks `0x18000cb90/0x18000cc00/0x18000cc50` build
  three global `std::string`s from `.rdata` constants — base64 alphabet
  (`0x18144c3a0`, standard `A-Za-z0-9+/`), **`"SDAT.NEXON.COM.."`**
  (`0x18145eae0` → global `0x1818bc6b0`, used as the wrapper's IV string), and
  **`"c9x6zoVPQL1y00oPpGZ6/A=="`** (`0x18145eac0` → global `0x1818bc690`).
  Caller `0x1801a9fa0` runs `0x1801aa8a0` (a **base64 decoder**: `cmp '='`,
  `sub '+'`, 4-char groups, `strchr` on the alphabet global) over the latter
  into `rbp+8`, then `wrapper_332ee0(key=rbp+8, IV="SDAT.NEXON.COM..", src,
  len, out256)` followed by a second-stage transform `0x1801aac80` — i.e.
  `0x1801a9fa0` is a **static-key config/string decryptor** with
  `key16 = 73dc7ace854f40bd72d34a0fa4667afc`. This key does **not** decrypt
  the wire's opaque frames (CFB×2/CBC/ECB on frames #3/#4/#26/#27: all noise)
  and the wire masks are not `E/D` of any observed 16-byte material under it —
  the wire session key remains handshake-derived (state, not bytes on disk).
- **Connection crypto objects** *(corrected 2026-10-18, see below — this was a
  UI object, not a cipher ctx)*: callsite `0x18018ae96` decode showed
  `ctor_3340d0` (zero-init, vptr `0x1814977b8`) then
  `0x1803342e0(obj, 0, 0x232, 0x100, 0x40)`. **Correction**: `0x1803342e0`
  passes `"sa_interface2\menu\main\renew\ServerNameBack.dtx"` and converts
  0x100/0x40 to *floats* (256.0×64.0) for virtual calls — it is a **UI texture
  initializer**, and `0x180d4cf20` is a 5,153-callsite generic helper, so the
  "+0xC90 SEED ctx" reading is **retracted**. A plain-.text call census
  (`find-callers2.js`) then showed the **entire crypto surface in plain code**:
  `wrapper_332ee0` 1 caller (the config path), `wrapper_332b40` **0 callers**,
  XTEA enc/dec 1 caller each (the value codec itself), checksum `0x181272bc0`
  2 callers (v1 enc/dec) — the wire's 2nd stage has **no plain-.text entry**,
  matching the earlier VM-dispatch finding (VM bytecode at `0x18188be20+`
  references `0x181272bc0`/`0x181272fa0`). Decompile attempts of the two big
  callers (`0x1801a9fa0`, `0x180189760`) hit the provider's 330 s/item limit
  even as single-address requests — hand analysis is the final source.
- **Config-path pipeline fully closed**: stage-2 `0x1801aac80` is a
  **base64 encoder** (3→4 bit packing, alphabet-global lookups), so
  `0x1801a9fa0(in) = b64encode(SEED-CFB-Dec(key=73dc7ace…, IV="SDAT.NEXON.COM..", in))`
  — a static-key string-decrypt helper, proven unrelated to the wire.

## 10. Open Questions

| # | Question | Why unresolved | Next experiment |
|---|---|---|---|
| Q1 | ~~`cshell.dll` / `cres.dll` / `ClientFX.fxd` acquisition~~ **RESOLVED** (2026-10-18 02:56) | User launched the game; the watcher captured all three files to `target\` (hash-verified vs. live: cshell.dll `82F0F4E40A21EFCF…`, cres.dll `F17689E3AF722496…`). Deep REA analysis of cshell.dll started (§6.10, session 10) | Continue sessions on cshell.dll / ClientFX.fxd as needed |
| Q2 | Runtime IAT reconstruction (real import list) | Would require running the client under a debugger (dynamic dump, §5.2) — deliberately not done on this machine to avoid anti-cheat entanglement | Disposable VM + hardware breakpoint on `.rdata` IAT region; dump with Scylla at OEP `0x1402644b8` |
| Q3 | ~~`.pkg` (SnowCipher) container format~~ **RESOLVED for v1** (2026-10-18, sessions 12–26, §6.5) | Cipher identified as Nexon **Snow2** (MapleStory `.ms` v2 primitive; 6/6 tables byte-exact vs MapleLib). Full v1 container model reversed and **validated with a standalone parser** (`scripts/pkg-parse.js`) on two real packages: masked-key region (`N1 = Σchars mod 312 + 30`) → version byte → length-obfuscated, cycling-XOR-encrypted header string (fixed salt `!dlstps20djr@`) → Snow2 data region (key1, head = `[checksum][count]`) → index region at `dataStart + N2 + 8` (key2), entries `[u32 strlen][UTF-16LE name][6×u32][n×16B][16B]`(+32B if flag&0x10). Both samples parse 100% (6/6 + 16/16 entries, clean filenames). Remaining: per-file data addressing (`field[3]/[4]`, `tail16`) — index parses but data-block layout unconfirmed; v2 header variant has no sample | Decompile the file-read path (CipherStream::Read / `FUN_1402a95f0` callers) to map index fields to absolute data offsets; obtain a v2 sample if one exists in the install |

| Q4 | ~~`engine.rez` header obfuscation~~ **RESOLVED** (see §6.8) | Initial "obfuscated header" hypothesis refuted — it is the standard RezMgr SA-variant layout, fully parseable | Done: `node scripts\rez-parse.js target\engine.rez` |
| Q5 | Exact Themida version / VM handler layout | No version resource; full VM devirtualization out of scope | Compare `.boot` stub bytes against Oreans SDK samples; or devirtualize the stub's dispatch loop |
| Q6 | PDB symbols | Referenced PDB `SuddenAttack.pdb` GUID 6c56246a-9feb-4a5e-b74a-c9543885c781 not on disk; symbol servers are public infrastructure, not used here (local-only rule) | None planned (would require network symbol lookup, outside the local-only constraint if interpreted strictly) |
| Q7 | ~~Anti-cheat interaction order/IPC at runtime~~ **largely RESOLVED statically** (§6.10) | cshell.dll's import table shows it drives the EOS/EAC anti-cheat client session + machine-ID + socket I/O, while the exe starts NGS. Exact call ordering still needs runtime/decompile follow-up. External module enumeration of the live process returns 0 modules (protection blocks handle queries — observed during the 2026-10-18 launch) | Optional: decompile the `EOS_AntiCheatClient_*` call sites in cshell.dll |
| Q8 | ~~Role confirmation for support DLLs~~ **largely RESOLVED** (see §6.9) | Roles identified via strings/PDB paths + REA session 9 (machineidlib); deep REA passes on the remaining modules not done | Optional: full `open_binary` → pseudo-code workflow per module as needed |
| Q9 | ~~TCP message crypto location~~ **RESOLVED, then refined by live capture** (sessions 27–30, §9) | Located in `cshell.dll` (not the exe): `CStreamCryptor` v1 packet obfuscation (rolling XOR + reverse + u16 cksum, **key embedded per packet**) + XTEA-32 fixed-key `"156def789023abc4"` value codec + CPHObject header XORs. Sessions 29–30 added the checksum decompile (`FUN_181272bc0` = SIMD add+xor fold), the v1 tag getter (`return 1`), and a **17 MB live MITM capture**: the port-12000 wire uses the v1 rolling-XOR core but a **VM-dispatched variant** (per-packet TYPE byte at H[1], constant `0x1010` trailer — v1's tag/checksum don't fit; dispatcher = `.rdata` VM bytecode 0x18188be20+ referencing 0x181272bc0/0x181272fa0). Inner payload layer unresolved | Recapture a longer session; decode the VM bytecode at 0x18188be20+ |
| Q10 | ~~Inner payload layer of port-12000 frames~~ **RESOLVED** (sessions 31–33, §9) | Layer 2 = session-scoped 16-byte directional XOR masks (values + proof in §9); layer 3 content now readable (pipe-text protocol, heartbeats, login structure). Cipher behind the suite = KISA SEED (RFC 4269), suite mapped, two external callers located. Remaining opaque: 0x42/0x51 + post-login 0x34/0xbf/0x8e frames (2nd stage, likely the CFB path) and the mask/session-key derivation (handshake 0xbe/0xbc + login 0x3d blob) | Decompile wrappers `0x180332b40/0x180332ee0` (session 33 in flight) and their callers `0x1801a9fa0`/`0x180189760` (session 34) |

## 11. Evidence & Limitations

### 11.1 Evidence conventions

- Every REA tool call has a SHA-256-style `evidence_id`; the complete mapping
  (session → tool → args → evidence_id) is `evidence\evidence_index.tsv`, built from
  `evidence\session1..26.jsonl` (raw JSONL of every MCP exchange, including the full raw
  results). Snapshots of each closed session: `evidence\sa_snapshot{,1..26}.bin`.
  The Snow2/cipher identification and container validation are summarized in
  `evidence\snow2_identification.md`.
- Non-REA observations (PE parsing, entropy, strings, hashes, Authenticode, rez parsing)
  come from the local scripts in `scripts\` with outputs in `evidence\`
  (`sa_exe_triage.json`, `sa_exe_strings.txt`, `ghsalncr_strings.txt`,
  `<module>_strings.txt`, `inventory*.csv`, and `rez-parse.js` console output quoted in
  §6.8). The rez layout itself is a *publicly documented* format (Auriemma's
  `rezmgr.bms` QuickBMS script); only the local parsing is ours.

### 11.2 Claim taxonomy used throughout

- **Observation/fact**: directly seen in a tool output (quoted above with address/evidence_id).
- **Derivation**: mechanically derived from observations (e.g., file offsets from VAs via the
  section table; OEP chain from decompiled call sequence).
- **Inference**: reasoned but not directly observed (labeled inline; e.g., module roles from
  names/strings, Themida version era, expected runtime integrity checks).
- **Unknown**: explicitly listed in Section 10.

### 11.3 Limitations / what REA could not see

- Themida's runtime-import reconstruction: statically invisible (slots zeroed on disk);
  documented as P5 rather than guessed. The **real** import list (beyond the 34 decoy names)
  is unknown without a dynamic dump.
- Inside `blackcipher\*.aes` / `NGClient64.aes`: encrypted blobs — REA cannot see their
  contents statically. Stated plainly, not speculated.
- `cshell.dll` (the game-logic half of the client) was never on disk during analysis
  (Q1) — this README covers the engine half only.
- No execution of the game client took place on this machine during analysis (Phase 5 runtime
  cross-checks skipped): launching would run EAC/NGS/BlackCipher on the user's machine with
  ban risk for the account, and the task allowed static-only completion. The cshell watcher
  (`scripts\watch-cshell.ps1`) was left running as the low-impact capture path.
- Windows PowerShell 5.1 + Node-only toolchain: no Python; all helpers reimplemented in
  Node/PS. Results cross-checked between REA/Ghidra and the independent scripts.

## 12. Reproduction Steps

Environment: Windows x64, Node 22.19+/24.11+, PowerShell 5.1+, ~10 GB free disk.

1. **Workspace layout**
   ```
   H:\SA_Analysis\
     target\          copies under analysis (never touch the live install)
     evidence\        all tool outputs, REA session JSONL, snapshots
     scripts\         inventory.ps1, pe-triage.js, strings.js, entropy.js,
                      mcp-client.js, cmds-session1..8.json, digest.ps1,
                      export-pseudo.ps1, watch-cshell.ps1
     tools\           ghidra_12.1.4_PUBLIC\, jdk-21.0.12.1+1\
     decompiled\      exported pseudocode (one .c per key function)
   ```
2. **Copy the targets** (PowerShell):
   `Copy-Item 'H:\Program Files\Nexon\SuddenAttack\suddenattack.exe' 'H:\SA_Analysis\target\'`
   (plus the other modules listed in Section 3).
3. **Install analysis toolchain** (once): Ghidra 12.1.4 zip + Temurin JDK 21 into
   `tools\`. Set per-shell:
   ```powershell
   $env:GHIDRA_INSTALL_DIR='H:\SA_Analysis\tools\ghidra_12.1.4_PUBLIC'
   $env:JAVA_HOME='H:\SA_Analysis\tools\jdk-21.0.12.1+1'
   $env:Path="$env:JAVA_HOME\bin;$env:Path"
   ```
4. **Inventory & static triage**:
   ```powershell
   powershell -File scripts\inventory.ps1 -Root 'H:\Program Files\Nexon\SuddenAttack' -Out evidence\inventory.csv
   node scripts\pe-triage.js target\suddenattack.exe > evidence\sa_exe_triage.json
   node scripts\strings.js  target\suddenattack.exe > evidence\sa_exe_strings.txt
   node scripts\entropy.js  target\suddenattack.exe
   ```
5. **REA bridge verification** (trivial inspection first, per task):
   `node scripts\mcp-client.js scripts\cmds-session1.json` — session 1 opens the binary,
   reads the export table, and runs the string searches quoted in Sections 4/6/8
   (commands in `scripts\cmds-session1.json`; output `evidence\session1.jsonl`).
   Digest: `powershell -File scripts\digest.ps1 -Session 1 -Out evidence\session1.digest.txt`.
6. **Full analysis sessions**: `scripts\cmds-session2..8.json` similarly (each re-imports
   into a fresh Ghidra instance, ~140 s; each closes with a snapshot). Session 9
   (`cmds-session9.json`) runs the same workflow on `machineidlib.dll` (§6.9). Key calls are
   indexed in `evidence\evidence_index.tsv` — use it to re-locate any claim in this README.
7. **Export pseudocode**:
   `powershell -File scripts\export-pseudo.ps1` → regenerates `decompiled\*.c` from the
   session JSONL (address map in the script header comments).
8. **Rez archive & support modules** (§6.8/§6.9):
   ```powershell
   node scripts\rez-parse.js target\engine.rez
   foreach ($m in 'machineidlib','nexonanalytics64','nmcogame64','nps64','sacefdll','snddrv','eaclaunch') {
     $ext = if (Test-Path "target\$m.exe") { 'exe' } else { 'dll' }
     node scripts\strings.js "target\$m.$ext" | Out-File "evidence\${m}_strings.txt" -Encoding utf8
   }
   ```
9. **cshell capture** *(executed 2026-10-18 02:56)*:
   `powershell -File scripts\watch-cshell.ps1` — polls the live install for
   `cshell.dll`/`cres.dll`/`ClientFX.fxd` and copies them to `target\` with a log at
   `evidence\cshell_watch.log`. All three files were captured while the user played and
   hash-verified against the live copies.
10. **cshell.dll deep session (10) & exe lapacker session (11)**: because cshell.dll is
    33 MB, Ghidra's import exceeds the REA bridge's default startup deadline (330 s →
    `provider_timeout`). Raise it first, then run:
    ```powershell
    $env:REA_GHIDRA_STARTUP_TIMEOUT_MS='3600000'
    node scripts\mcp-client.js scripts\cmds-session10.json   # cshell.dll (§6.10)
    node scripts\mcp-client.js scripts\cmds-session11.json   # exe, lapacker strings (§6.5)
    ```
    (sessions 1–9 do not need the env var; the exe's ~140 s import fits the default).
11. **lapacker xrefs & decompiles (sessions 12–15)** (same env var as step 10):
    ```powershell
    $env:REA_GHIDRA_STARTUP_TIMEOUT_MS='3600000'
    node scripts\mcp-client.js scripts\cmds-session12.json   # exe, xrefs to lapacker strings (§6.5)
    node scripts\mcp-client.js scripts\cmds-session13.json   # exe, resolve containing procedures (§6.5)
    node scripts\mcp-client.js scripts\cmds-session14.json   # exe, batch_decompile of the 7 lapacker functions (§6.5)
    node scripts\mcp-client.js scripts\cmds-session15.json   # exe, cipher-stream constructors (§6.5)
    ```
    Sessions 12–15 restore the previous session's snapshot (`sa_snapshot11/12/13/14.bin`)
    instead of re-analyzing from scratch.
12. **SnowCipher sessions (16–26)** (same env var; snapshots chain
    `sa_snapshot15/…/25.bin`): decompiles of the Snow2 key schedule
    (`FUN_1402abee0`), position setter, key derivations (`FUN_14029f470/f6b0/
    f920/fa20`), orchestrator (`FUN_1402aa700`), and index readers
    (`FUN_140290e00`/`FUN_1402b18c0`, session 26):
    ```powershell
    $env:REA_GHIDRA_STARTUP_TIMEOUT_MS='3600000'
    node scripts\mcp-client.js scripts\cmds-session26.json   # index readers (§6.5)
    ```
13. **Cipher-table extraction & container parsing** (no Ghidra needed):
    ```powershell
    node scripts\extract-tables.js        # 6 Snow2 tables vs MapleLib → evidence/snow_tables_from_exe.json
    node scripts\verify-cipher-tables.js  # AES Te0/Te2 cross-check of snow_T0..T3
    Copy-Item 'H:\Program Files\Nexon\SuddenAttack\game\global_00000.pkg' target\pkg_samples\
    Copy-Item 'H:\Program Files\Nexon\SuddenAttack\game\texturescripts_00000.pkg' target\pkg_samples\
    node scripts\pkg-parse.js target\pkg_samples\global_00000.pkg
    node scripts\pkg-parse.js target\pkg_samples\texturescripts_00000.pkg
    ```
    Expected: both files report header string `!dlstps20djr@`, a plausible
    `[checksum][count]` data head, and 6/6 + 16/16 index entries with clean
    filenames (`evidence\pkg_index_dump.json`).
14. **Network-crypto sessions (27–28)** (cshell.dll, same env var as step 10; snapshots
    chain `cshell_snapshot27/28.bin`): local triage first —
    `node scripts\crypto-constants-scan.js target\cshell.dll`,
    `node scripts\rtti-locate.js target\cshell.dll`, `node scripts\pdata-funcs.js …`,
    `node scripts\callers-scan.js …` — then `node scripts\mcp-client.js
    scripts\cmds-session28.json` decompiles the XTEA pair, wrappers, and
    CStreamCryptor v1 enc/dec. Deliverables: `evidence\network_crypto_identification.md`,
    `scripts\py\sa_net_crypto.py`.
15. **Capture proxy** (self-contained, no Ghidra):
    ```powershell
    node scripts\py\sa-proxy.js --selftest                                  # pipeline + crypto KAT
    node scripts\py\sa-proxy.js --listen 127.0.0.1:12000 --upstream 175.207.21.11:12000
    powershell -File scripts\py\launch-via-proxy.ps1   # ngm:// URL (clipboard) → passarg IP 교체 실행
    ```
    Logs land in `H:\SA_Analysis\logs\<session>\` (raw streams, events.jsonl,
    packets.log with automatic v1 de-obfuscation, strings.log). `logs/` is
    git-ignored (may contain account data). Usage details: `scripts\py\PROXY_USAGE.md`.
16. **Verify the deliverable chain**: every claim in Sections 4–9 cites either an
   `ev_…` evidence_id (resolvable in `evidence_index.tsv` → session JSONL → raw result) or
   a named script output file. To audit, open `evidence\session<N>.jsonl`, find the
   `evidence_id`, and compare the `raw_result` against the README statement.

---

*Analysis performed 2026-10-17/18 by Claude Code using the REA (reverse-engineer-anything)
skill workflow. This analysis and the game binaries were published with the owner's
authorization at github.com/backfold/0x140333510 (see repo); SessionID/NexonSN and other
personal identifiers are excluded from all published artifacts.*
