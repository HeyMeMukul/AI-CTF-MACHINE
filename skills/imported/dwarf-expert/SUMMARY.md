# DWARF debug-info reconstruction

Recover types, structs, enums, line tables, and variable locations from DWARF instead of guessing in a decompiler.

- Use when: A rev target ships debug info or a split debug file; you need exact struct layouts or source-line mapping.
- Domains: rev
- Source: https://github.com/trailofbits/skills/tree/main/plugins/dwarf-expert/skills/dwarf-expert
- Status: imported, source-verified (no CTF fixture yet)
