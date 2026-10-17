## evidence_id

ev_493e90c2079edf5b5b4b026777a9bcf7749988313c3758e859764bb6d5a7c0d0

## subject.name

suddenattack.exe

## subject.digest

| Key    | Value                                                            |
|--------|------------------------------------------------------------------|
| sha256 | 1a2343a24dae074dd9dba63f65cd637a8a5a7384fcd6b4f2840016b78e37e741 |

## subject.local_path

H:\SA_Analysis\target\suddenattack.exe

## subject.format

pe

## subject.architecture

x86_64

## provider

| Key     | Value                               |
|---------|-------------------------------------|
| id      | rea-workflow                        |
| name    | REA composed investigation workflow |
| version | 1                                   |

## analysis_profile.provider

| Key     | Value                               |
|---------|-------------------------------------|
| id      | rea-workflow                        |
| name    | REA composed investigation workflow |
| version | 1                                   |

## analysis_profile.parameters.upstream_analysis_profile.provider

| Key     | Value  |
|---------|--------|
| id      | ghidra |
| name    | Ghidra |
| version | 12.1.4 |

## analysis_profile.parameters.upstream_analysis_profile.parameters.target_kind

executable

## analysis_profile.parameters.upstream_analysis_profile.parameters.target_format

pe

## analysis_profile.parameters.upstream_analysis_profile.parameters.executable_role

application

## analysis_profile.parameters.upstream_analysis_profile.parameters.managed

false

## analysis_profile.parameters.upstream_analysis_profile.parameters.native_aot_metadata

| Key                  | Value                       |
|----------------------|-----------------------------|
| contract_revision    | rtr-9.1-x64-pe-read-only-v3 |
| source_bytes         | 134217728                   |
| work_units           | 67108864                    |
| working_memory_bytes | 67108864                    |
| report_bytes         | 4194304                     |

## analysis_profile.parameters.upstream_analysis_profile.parameters.architecture

x86_64

## analysis_profile.parameters.upstream_analysis_profile.parameters.available_architectures

x86_64

## analysis_profile.parameters.upstream_analysis_profile.parameters.import_mode

ephemeral-source-immutable

## analysis_profile.parameters.upstream_analysis_profile.parameters.pdb_observations

program-info-v1

## analysis_profile.parameters.upstream_analysis_profile.parameters.annotation_policy

atomic-function-entry-metadata-v1

## analysis_profile.parameters.upstream_analysis_profile.parameters.load_image_observations

source-mappings-entry-context-v2

## analysis_profile.parameters.upstream_analysis_profile.parameters.function_body_evidence

complete-inclusive-ranges-v1

## analysis_profile.parameters.upstream_analysis_profile.parameters.function_references

complete-body-and-entry-reference-manager-v2

## analysis_profile.parameters.upstream_analysis_profile.parameters.call_relationship_coverage

function-body-call-coverage-v5

## analysis_profile.parameters.upstream_analysis_profile.parameters.function_dossier_coverage

observed-facets-and-call-relationships-v1

## analysis_profile.parameters.upstream_analysis_profile.parameters.string_inventory_evidence

defined-data-coverage-v1

## analysis_profile.parameters.upstream_analysis_profile.parameters.location_resolution

explicit-address-exact-entry-symbol-first-v3

## analysis_profile.parameters.upstream_analysis_profile.parameters.procedure_file_offset_resolution

address-first-unique-target-source-mapping-v2

## analysis_profile.parameters.upstream_analysis_profile.parameters.instruction_flow_evidence

decoded-return-pcode-v1

## analysis_profile.parameters.upstream_analysis_profile.parameters.instruction_references

exact-address-incoming-v1

## analysis_profile.parameters.upstream_analysis_profile.parameters.function_boundary_observations

ghidra-function-boundary-limitations-v3

## analysis_profile.parameters.upstream_analysis_profile.parameters.no_return_repair

disabled-windows-p0

## analysis_profile.parameters.upstream_analysis_profile.parameters.process_launch

official-headless-script-v1

## analysis_profile.parameters.upstream_analysis_profile.parameters.jump_table_evidence

typed-case-default-blocks-v1

## analysis_profile.parameters.upstream_analysis_profile.parameters.decompiler_jump_loads

true

## analysis_profile.parameters.upstream_analysis_profile.parameters.loader

auto-from-header

## analysis_profile.parameters.upstream_analysis_profile.parameters.language_id

auto-from-header

## analysis_profile.parameters.upstream_analysis_profile.parameters.compiler_spec_id

auto-default

## analysis_profile.parameters.upstream_analysis_profile.parameters.analyzer_preset

ghidra-default

## analysis_profile.parameters.upstream_analysis_profile.digest

ab1af6a0e002de5d4940f7e3d2cfd844cfe45f918fcd3678b343002640413374

## analysis_profile.parameters.workflow_revision

3

## analysis_profile.digest

90871c3407d76084c1e460aa06850f52468e7c5b1852c7bc407b8e03c0cf3eb6

## predicate_type

rea.analysis

## operation

binary_overview

## parameters

| Key | Value |
|-----|-------|


## raw_result

null

## normalized_result.document

target-1a2343a24dae.exe

## normalized_result.image_base

0x140000000

## normalized_result.segments

| name      | start        | end          | length  | image_base  | address_space |
|-----------|--------------|--------------|---------|-------------|---------------|
| Headers   | 0x140000000  | 0x140000600  | 1536    | 0x140000000 | ram           |
| .text     | 0x140001000  | 0x1402fde00  | 3132928 | 0x140000000 | ram           |
| .rdata    | 0x1402fe000  | 0x1403d9000  | 897024  | 0x140000000 | ram           |
| .data     | 0x1403d9000  | 0x14046014c  | 553292  | 0x140000000 | ram           |
| .pdata    | 0x140461000  | 0x14048c600  | 177664  | 0x140000000 | ram           |
| SECTION.4 | 0x14048d000  | 0x1404cb060  | 254048  | 0x140000000 | ram           |
| .reloc    | 0x1404cc000  | 0x1404d1e00  | 24064   | 0x140000000 | ram           |
| .debug    | 0x1404d2000  | 0x1404d3000  | 4096    | 0x140000000 | ram           |
| .edata    | 0x1404d3000  | 0x1404d4000  | 4096    | 0x140000000 | ram           |
| .idata    | 0x1404d4000  | 0x1404d5000  | 4096    | 0x140000000 | ram           |
| .tls      | 0x1404d5000  | 0x1404d6000  | 4096    | 0x140000000 | ram           |
| .rsrc     | 0x1404d6000  | 0x140509000  | 208896  | 0x140000000 | ram           |
| .themida  | 0x140509000  | 0x140ab3000  | 5939200 | 0x140000000 | ram           |
| .boot     | 0x140ab3000  | 0x140dde800  | 3323904 | 0x140000000 | ram           |
| .reloc    | 0x140ddf000  | 0x140de0000  | 4096    | 0x140000000 | ram           |
| tdb       | 0xff00000000 | 0xff00001850 | 6224    | 0x140000000 | ram           |

## normalized_result.segment_count

16

## normalized_result.procedure_count

12346

## normalized_result.string_count

8220

## confidence

derived

## authority

shipped-artifact

## environment

null

## limitations

Derived by an REA composed workflow.,A headless Ghidra session contains exactly one imported Program, unlike Hopper's multi-document GUI session.,Cancelling an active Ghidra request terminates its ephemeral database and discards session annotations. The selected target remains open; the next provider query imports the original artifact again.,Charset is reported, while a non-missing terminator cannot distinguish a present terminator from a fixed or Pascal layout.,Default-space addresses use lowercase 0x-prefixed hexadecimal; other address spaces use <percent-encoded-space>:0x<hex>.,External functions and local thunks are distinct; procedure metadata identifies both and preserves a thunk target when Ghidra resolves one.,Memory-block end addresses are exclusive; permissions come from Ghidra MemoryBlock flags rather than inference from section names.,Only Ghidra-defined string Data is observed; packed or undefined string bytes may be absent. Completeness applies to that inventory, and an empty search does not establish that text is absent from the artifact. If an address is known, use read_bytes and xrefs to inspect bytes and references.,The Windows bridge uses authenticated IPv4 loopback because Node path-based IPC does not expose Java AF_UNIX sockets; the endpoint file contains no bearer token.,The imported Program and temporary project are ephemeral and deleted on close. Annotation operations edit session database metadata; original executable bytes are never written.,The session serves operations only after Ghidra reports default auto-analysis complete; incomplete analysis does not expose partial results.,The target references PDB SuddenAttack.pdb (GUID 6c56246a-9feb-4a5e-b74a-c9543885c781, age (hex) 1, signature unknown, version RSDS); Ghidra reports load state unknown. Original names and types may be missing; an empty name search does not prove a procedure is absent. Use list_procedures and address-based analysis to inspect recovered functions. REA does not admit a caller-selected PDB companion.,Windows Ghidra P0 accepts native x86 and x86-64 PE applications and DLLs, and explicitly selected raw 6502 images; managed, hostile, sensitive, and mutable-path targets are unsupported.,Windows sessions require the matching packaged Windows x64 native addon, local NTFS targets and runtimes, and Windows 10 or later. Native handles enforce path admission, private DACLs, and Job Object ownership automatically.

## relationship_coverage

null

## locations



## evidence_links

