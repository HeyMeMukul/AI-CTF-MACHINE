# Recipes — verified, executable technique cards

A recipe is retrieved by the solver only when `"verified": true`. Each one must
have:

- `id`, `domain`, `title`
- `signals` — what the artifact/service looks like when this applies
- `preconditions` — the facts that must be true first
- `steps` — the ordered, executable approach
- `falsifier` — the observation that rules it out
- `pitfalls` — the common failure modes
- `sources` — at least one real reference
- `fixtures` — the eval task(s) that exercise it
- `verified_by`, `last_verified`, `verified: true`

If a recipe cannot be tied to a fixture and a source, leave `verified: false`.
The engine ignores it, and that is the point: a reading list is not a solver.

Audit with:

```bash
python3 -m engine knowledge --query "base64" --domain misc
python3 -m engine doctor
```

The old `knowledge/writeups_mined/*_manifest.md` rows are **quarantined** by
`knowledge/writeups_mined/POLICY.json`; they are not loaded unless
`--include-unverified` is passed. The sampled technique labels were wrong (see
`docs/FRAMEWORK_REVIEW.md`, F5), so they must not be treated as truth.
