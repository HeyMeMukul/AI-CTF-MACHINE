# chaining-flagpath SUMMARY (Lead only)
1. Inventory primitives from ALL profiles → CHAIN-INVENTORY.md
   (leak / write / auth-gap + confidence + location).
2. Verify evidence for each (drop claim-only).
3. Kill impossible chains:
   - ASLR + no leak → no direct-ret
   - Full RELRO → no GOT-overwrite (needs FSOP path)
   - rate-limited oracle → needs ≤10-query path
4. Construct forward (primitive→unlock?) + backward (flag→prereqs?).
5. Score realism×reach×compounding — ship if ≥50.
6. ONE path per task: FLAGPATH-NNN.hypothesis.md
   with per-step proofs for validators.
7. Hold LOWs as gadgets, never lone reports.
