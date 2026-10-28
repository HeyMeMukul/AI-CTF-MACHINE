---
name: imported-dwarf-expert
description: Recover types, structs, enums, line tables, and variable locations from DWARF instead of guessing in a decompiler.
category: rev
phase: analyze
source: https://github.com/trailofbits/skills/tree/main/plugins/dwarf-expert/skills/dwarf-expert
license: CC-BY-SA-4.0
ctf_domains: [rev]
status: imported
---

# DWARF debug-info reconstruction (imported)

> Adapted for CTF use from [Trail of Bits](https://github.com/trailofbits/skills/tree/main/plugins/dwarf-expert/skills/dwarf-expert). License: `CC-BY-SA-4.0`.
> Technique-only; no flags or target-specific data. Authorized CTF use only.

Execution policy: follow `skills/_shared/SKILL_CONTRACT.md`.

## When to use

A rev target ships debug info or a split debug file; you need exact struct layouts or source-line mapping.

## Signals

- .debug_info present
- stripped but split debug file
- unknown struct layout
- need line/address mapping

## Preconditions

- ELF/Mach-O with DWARF or a matching debug file

## CTF workflow

1. `readelf --debug-dump=info` and `readelf --debug-dump=decodedline` (or `dwarfdump`) to map addresses to source lines.
2. Reconstruct structs/enums from `DW_TAG_structure_type`/`DW_TAG_member` and `DW_AT_data_member_location`.
3. Use `gdb` `ptype`, `info line *ADDR`, and `pahole` to confirm layouts and padding.
4. Feed the recovered types back into Ghidra/rizin before writing an exploit or parser.

## Falsifier

No `.debug_*` sections and no matching debug file; DWARF cannot help.

## Pitfalls

- optimized-out variables
- DWARF version mismatch
- split debug links
- compiler-generated types

## Source and license

- Source: https://github.com/trailofbits/skills/tree/main/plugins/dwarf-expert/skills/dwarf-expert
- Author/team: Trail of Bits
- License: `CC-BY-SA-4.0`
- Imported: 2026-10-20; adapted summary, not a verbatim copy.
