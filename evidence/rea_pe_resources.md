## evidence_id

ev_cd2718e88e8ef5a9b0f0c0df23f175fe9f24c9dcae16f918712f09886297e8b4

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

null

## provider

| Key     | Value                  |
|---------|------------------------|
| id      | rea-pe-resources       |
| name    | REA PE resource parser |
| version | 1                      |

## analysis_profile

null

## predicate_type

rea.analysis

## operation

inspect_pe_resources

## parameters

| Key            | Value                                  |
|----------------|----------------------------------------|
| path           | H:\SA_Analysis\target\suddenattack.exe |
| max_file_bytes | 67108864                               |
| max_entries    | 16384                                  |

## raw_result

null

## normalized_result.artifact

| Key    | Value                                                            |
|--------|------------------------------------------------------------------|
| path   | H:\SA_Analysis\target\suddenattack.exe                           |
| sha256 | 1a2343a24dae074dd9dba63f65cd637a8a5a7384fcd6b4f2840016b78e37e741 |
| bytes  | 8063864                                                          |

## normalized_result.format

pe32-plus

## normalized_result.machine

34404

## normalized_result.directory.rva

5070848

## normalized_result.directory.location

| Key    | Value   |
|--------|---------|
| offset | 4520448 |
| bytes  | 208440  |

## normalized_result.directory.data_directory_location

| Key    | Value |
|--------|-------|
| offset | 504   |
| bytes  | 8     |

## normalized_result.directories

| location        | characteristics | timestamp | major_version | minor_version | named_entries | id_entries |
|-----------------|-----------------|-----------|---------------|---------------|---------------|------------|
| [object Object] | 0               | 0         | 0             | 0             | 0             | 4          |
| [object Object] | 0               | 0         | 0             | 0             | 0             | 6          |
| [object Object] | 0               | 0         | 0             | 0             | 0             | 1          |
| [object Object] | 0               | 0         | 0             | 0             | 0             | 1          |
| [object Object] | 0               | 0         | 0             | 0             | 0             | 1          |
| [object Object] | 0               | 0         | 0             | 0             | 0             | 1          |
| [object Object] | 0               | 0         | 0             | 0             | 0             | 1          |
| [object Object] | 0               | 0         | 0             | 0             | 0             | 1          |
| [object Object] | 0               | 0         | 0             | 0             | 0             | 1          |
| [object Object] | 0               | 0         | 0             | 0             | 0             | 1          |
| [object Object] | 0               | 0         | 0             | 0             | 0             | 1          |
| [object Object] | 0               | 0         | 0             | 0             | 0             | 1          |
| [object Object] | 0               | 0         | 0             | 0             | 0             | 1          |
| [object Object] | 0               | 0         | 0             | 0             | 0             | 1          |

## normalized_result.resources

| index | type            | name            | language        | entry_locations                                 | data_entry_location | code_page | reserved | payload         |
|-------|-----------------|-----------------|-----------------|-------------------------------------------------|---------------------|-----------|----------|-----------------|
| 0     | [object Object] | [object Object] | [object Object] | [object Object],[object Object],[object Object] | [object Object]     | 0         | 0        | [object Object] |
| 1     | [object Object] | [object Object] | [object Object] | [object Object],[object Object],[object Object] | [object Object]     | 0         | 0        | [object Object] |
| 2     | [object Object] | [object Object] | [object Object] | [object Object],[object Object],[object Object] | [object Object]     | 0         | 0        | [object Object] |
| 3     | [object Object] | [object Object] | [object Object] | [object Object],[object Object],[object Object] | [object Object]     | 0         | 0        | [object Object] |
| 4     | [object Object] | [object Object] | [object Object] | [object Object],[object Object],[object Object] | [object Object]     | 0         | 0        | [object Object] |
| 5     | [object Object] | [object Object] | [object Object] | [object Object],[object Object],[object Object] | [object Object]     | 0         | 0        | [object Object] |
| 6     | [object Object] | [object Object] | [object Object] | [object Object],[object Object],[object Object] | [object Object]     | 0         | 0        | [object Object] |
| 7     | [object Object] | [object Object] | [object Object] | [object Object],[object Object],[object Object] | [object Object]     | 0         | 0        | [object Object] |
| 8     | [object Object] | [object Object] | [object Object] | [object Object],[object Object],[object Object] | [object Object]     | 0         | 0        | [object Object] |

## normalized_result.icon_groups

| resource_index | images                                                                                          |
|----------------|-------------------------------------------------------------------------------------------------|
| 7              | [object Object],[object Object],[object Object],[object Object],[object Object],[object Object] |

## normalized_result.coverage

| Key              | Value    |
|------------------|----------|
| status           | complete |
| examined_entries | 22       |
| resources        | 9        |

## normalized_result.limitations

Static PE32/PE32+ type/name/language resource inventory; payloads other than RT_GROUP_ICON remain opaque.,Icon candidates are resource-table relationships. Language fallback, image decoding and actual shell/window loading are not observed.,Exact shared byte ranges are retained; non-identical overlapping resource structures or payloads are rejected.

## confidence

observed

## authority

shipped-artifact

## environment

null

## limitations

Static PE32/PE32+ type/name/language resource inventory; payloads other than RT_GROUP_ICON remain opaque.,Icon candidates are resource-table relationships. Language fallback, image decoding and actual shell/window loading are not observed.,Exact shared byte ranges are retained; non-identical overlapping resource structures or payloads are rejected.

## relationship_coverage

null

## locations

| kind          | path                                   |
|---------------|----------------------------------------|
| artifact-path | H:\SA_Analysis\target\suddenattack.exe |

## evidence_links

