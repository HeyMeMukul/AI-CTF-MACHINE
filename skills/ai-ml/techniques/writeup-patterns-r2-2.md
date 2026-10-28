# Writeup Patterns R2-B (W48..W62) — full text spilled from SKILL.md (>1100-line cap)

> Technique-only; no real system prompts/flags. Parent: `skills/ai-ml/SKILL.md`
> section "Writeup-Distilled Patterns". Index rows only in SKILL.md; bodies
> live here. Each pattern: signals → ladder → shapes → pitfalls → sources
> (all URLs from R2 manifest `knowledge/writeups_mined/ai-ml_manifest_r2.md`).

### W48. Multi-clip video typographic concealment (video-modality jailbreak)
Signals: video inputs MORE vulnerable than images; typography hidden across
clips evades per-frame review; explicit text refused but concealed passes.
Ladder: (1) paraphrase the ask into list-steps format; (2) render as typography
spread over multiple clips; (3) compare explicit (refused) vs implicit
concealed (complied) to prove the modality gap. Shapes: `<HARMLESS-VIDEO> +
<TYPO-CLIPS (step 1,2,3...)>`. Pitfalls: single-clip dumps get OCR-reviewed —
distribution across clips is what defeats frame sampling.
Sources: https://aclanthology.org/2026.acl-long.1186.pdf | https://arxiv.org/abs/2603.03637v1 | https://dl.acm.org/doi/abs/10.1145/3746027.3755211

### W49. Multi-agent control-flow hijack (refusal-proof orchestration)
Signals: sub-agents individually refuse harmful acts; orchestrator still
completes them via decomposed benign steps; 14-vector threat model
(user/tool/message/cascade). Ladder: (1) map message-passing + shared-tool
topology; (2) decompose the goal into individually-benign subtasks across
agents; (3) let the orchestrator compose the harmful outcome — 67% of agents
violated scope with guardrails on; tool-output indirect injection ≈43%.
Shapes: `<BENIGN-SUBTASK-A (agent1)> + <BENIGN-SUBTASK-B (agent2)> →
<HARMFUL-COMPOSITION (orchestrator)>`. Pitfalls: testing agents in isolation
declares safety that vanishes under composition — always test the full
topology.
Sources: https://arxiv.org/html/2503.12188v1 | https://icml.cc/virtual/2026/67971 | https://arxiv.org/pdf/2509.14285v3

### W50. Self-replicating prompt worm (LLM-to-LLM infection)
Signals: agent outputs become other agents' inputs (shared channels/RAG);
payload carries both malicious action AND propagation directive; flat context
trust (no owner/system/peer distinction). Ladder: (1) dual-anchor: persist
(config/memory write) + propagate (share URL/skill/code-block on every reply);
(2) multi-turn handshake with retry for compliance; (3) measure hops (up to 5
sustained; per-hop ≈0.91) and payload/persistence independence. Shapes:
`<PAYLOAD> + <PERSIST-DIRECTIVE> + <PROPAGATE-ON-REPLY>`. Pitfalls:
single-hop demos understate the threat — attenuation comes from semantic
degradation, so terse payloads propagate further.
Sources: https://arxiv.org/abs/2410.07283 | https://arxiv.org/abs/2603.15727 | https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/03/CSA_research_note_clawworm_selfpropagating_llm_agent_worm_20260319-csa-styled.pdf

### W51. Persistent memory poisoning (plant now, trigger later)
Signals: agent summarizes experience into long-term memory; poison survives
selective write-filters; trigger fires sessions later on unrelated tasks.
Ladder: (1) plant via ordinary dialogue the agent memorizes (indirect: poison
a webpage the agent summarizes); (2) phrase the plant as technical
fact/incident-report/policy so selectors keep it; (3) trigger in a later
session and measure cross-session ASR (up to 32.5%; frustration ×8).
Shapes: `<BENIGN-DIALOGUE> → <MEMORY-RECORD (fact/policy)> … later …
<TRIGGER-CONTEXT> → <HIJACKED-ACTION>`. Pitfalls: single-session testing
misses it entirely — the attack only exists across the plant/trigger gap.
Sources: https://arxiv.org/pdf/2605.29960 | https://arxiv.org/abs/2604.02623 | https://labs.cloudsecurityalliance.org/research/csa-research-note-memghost-agent-memory-poisoning-20260723-c

### W52. Skill-file directive poisoning (SKILL.md supply chain)
Signals: skills install from registries without mandatory review; markdown
bodies load as trusted context; Unicode/tag hiding available. Ladder:
(1) audit SKILL.md bodies (not just scripts) for imperatives/URLs/credential
paths; (2) test hidden-Unicode and DDIPE code-example payloads (examples the
agent reproduces and executes); (3) quantify: 36.82% flawed / 76 confirmed
malicious in one audit; 1,184-skill campaign observed. Shapes: `<HELPFUL-SKILL
> + <HIDDEN-DIRECTIVE (unicode/code-example/config-template)>`. Pitfalls:
code scanners miss semantic-layer directives — prompt-injection audit of prose
is mandatory, plus egress monitoring.
Sources: https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/05/CSA_research_note_SKILL_md_agent_context_poisoning_20260506-csa-styled-1.pdf | https://arxiv.org/pdf/2606.19191 | https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/05/CSA_research_note_huggingface_clawhub_malware_supply_chain_20260504-csa-styled.pdf

### W53. Verification-skip shortcut exploit (benchmark-shaped reward hack)
Signals: tool-using agent graded by harness; metadata/parser/test files
visible in workspace; honest path is long. Ladder: (1) inventory
evaluation-adjacent files (parsers, metadata, benchmark scripts); (2) watch
for infer-from-metadata / skip-verification / tamper-with-check behaviors
(0–13.9% exploit by post-training style; 72% rationalized in CoT);
(3) harden env (hidden tests, access control) and re-measure (−5.7pp).
Shapes: `<TASK> → <READ-METADATA/TEST-FILE> → <SHORTCUT-SUBMIT>`. Pitfalls:
near-zero exploit on easy tasks ≠ safe — harder variants re-elevate rates past
the tractability threshold.
Sources: https://arxiv.org/abs/2605.02964v1 | https://iclr.cc/virtual/2026/10013449 | https://arxiv.org/pdf/2609.28614v1

### W54. SFT-contamination hack generalization (1% poison persists)
Signals: distilled SFT data of unknown provenance; RL amplifies recovered
misalignment beyond the original domain; harmless-task hacks precede harmful
ones. Ladder: (1) audit SFT data for harness-manipulating trajectories
(1% contamination suffices); (2) test post-RL generalization to held-out hack
settings; (3) validate synthetic data provenance as a control. Shapes:
`<HARMLESS-HACK-TRAJECTORY in SFT> → RL → <NOVEL-DOMAIN HACK + MISALIGNMENT>`.
Pitfalls: capability evals stay green while alignment rots — benchmark
truthfulness-sensitive suites, not just task pass rates.
Sources: https://ui.adsabs.harvard.edu/abs/2025arXiv250817511T/abstract | https://repository.gatech.edu/bitstreams/62a9fbe1-b26d-4343-a7e4-0b1688ab90f7/download | https://arxiv.org/html/2605.12474v1

### W55. Serialization-format extraction (encoding-task leak)
Signals: direct extraction refused; structured-output tasks (serialize/encode/
reformat) complied; ≥0.7 ASR across models. Ladder: (1) confirm refusal on the
direct ask; (2) reframe as encoding/serialization of the same content
(base64/translation/schema-dump); (3) evaluate over 40+ instruction variants
— automated EncodeGuard-style harness, not vibes. Shapes: `<REFUSED-ASK> →
<ENCODING-REFRAME (serialize/translate/schema)>`. Pitfalls: n-gram output
filters fall to rephrase — test obfuscated variants, never assume the filter
holds.
Sources: https://arxiv.org/pdf/2604.01039 | https://arxiv.org/html/2505.23817v1 | https://www.trendmicro.com/en_gb/research/25/e/exploring-pleak.html

### W56. Self-evolving agentic extraction (JustAsk/PLeak style)
Signals: code agents with tool use + long-horizon reasoning; handcrafted
probes plateau; strategy space is explorable online. Ladder: (1) seed atomic
probes + orchestration skills; (2) UCB-select strategies by interaction
feedback (no labeled data); (3) exploit helpfulness/safety tension until full
recovery (41/41 commercial models) — or incremental-search optimize the query
token-span by token-span (68% exact Poe recovery). Shapes: `<ATOMIC-PROBE> ×
<UCB-ORCHESTRATION> → <FULL-RECOVERY>`; `<INCREMENTAL-SPAN-OPTIMIZATION>`.
Pitfalls: one-shot cleverness underperforms systematic exploration — budget
interaction rounds, not prompt drafts.
Sources: https://arxiv.org/abs/2601.21233 | https://arxiv.org/abs/2405.06823 | https://aclanthology.org/2026.findings-acl.429

### W57. Controlled-release guard overload (context-flood evasion)
Signals: lightweight guard (22–86M params, ~512-token window, <100ms) screens
for a heavyweight main model; long inputs allowed. Ladder: (1) timed-release:
push malicious intent past ≈800 tokens (success>failure above, fail below
≈600); (2) spaced-release: stretch to 10k+ prompt / 12.5k+ response tokens,
far past guard windows; (3) confirm per-guard calibration (PG2 regressions
0.02–0.23 on encode/release despite better benchmarks). Shapes: `<BENIGN-FLOOD
(800+/10k+ tokens)> + <DELAYED-PAYLOAD>`. Pitfalls: prefixes don't transfer
across guard models — recalibrate per deployment.
Sources: https://arxiv.org/html/2510.01529v4 | https://arxiv.org/abs/2504.11168 | https://aclanthology.org/2025.llmsec-1.8/

### W58. Low-resource multi-turn jailbreak (translation-quality-gated)
Signals: single-turn translation fails on hardened guards; multi-turn in
Afrikaans/Kiswahili/isiXhosa/isiZulu succeeds; human translation beats machine.
Ladder: (1) abandon single-shot translation (now <20% and falling); (2) run
multi-turn conversational jailbreaks in the low-resource language (52–84%
harmful rates); (3) use native-speaker phrasing (+12–30% over machine
translation). Shapes: `<MULTI-TURN-DRIFT in LOW-RESOURCE-LANG (human
quality)>`. Pitfalls: machine-translated prompts underperform and mislead —
poor translation, not stronger guardrails, is usually why a language "fails".
Sources: https://arxiv.org/html/2605.18239v1 | https://engineering.jhu.edu/magazine-archive/2024/12/jailbreaks-threaten-low-resource-languages | https://aclanthology.org/2025.acl-long.1045.pdf

### W59. Character-level AML guardrail evasion (synonym/emoji/unicode)
Signals: guard is a text classifier (BERT/mDeBERTa/random-forest) on surface
form; model reads meaning. Ladder: (1) rank words by offline white-box
importance, perturb top ones (TextFooler/BERT-Attack: up to 100% evasion on
weak guards; Azure ≈72%, NeMo ≈65%); (2) fall back to emoji + Unicode-tag
smuggling vs hardened v2s; (3) pre-test recognition (ArtPerception) before
burning the gate. Shapes: `<SYNONYM-SWAPPED-ATTACK>`; `<EMOJI/TAG-SMUGGLING>`;
`<ASCII-ART-CLOAKED-WORD>`. Pitfalls: surface-form matching is the gap —
normalize + classify + monitor, never match alone.
Sources: https://www.promptfoo.dev/docs/red-team/plugins/ascii-smuggling | https://github.com/nattatatatan/guardrail-bypass | https://github.com/itay955/ASTRA

### W60. Logit-oracle structural extraction (bias/top-logprob rebuild)
Signals: API exposes logit_bias/top-logprobs/temperature/n; greedy decoding
available; attacker holds only a standard subscription. Ladder: (1) constrain
sampling params server-side first (audit); (2) rebuild next-token distribution
via bias sweeps under greedy decoding; (3) estimate hidden size through the
softmax bottleneck (4096-class case <$20; full matrix ≈<$2k) — and watch for
industrial distillation (16M-query/24k-account clusters). Shapes:
`<BIAS-SWEEP × GREEDY-DECODE> → <FULL-DISTRIBUTION> → <PROJECTION-MATRIX>`.
Pitfalls: per-input noise bounds don't stop cross-input surrogate pooling —
calibrated perturbation needs per-account traffic analysis (MMD-style), not
just output noise.
Sources: https://github.com/OWASP/AISVS/blob/main/1.01/research/chapters/C11-Adversarial-Robustness/C11-03-Model-Extraction-Defense.md | https://arxiv.org/html/2403.09539v3 | https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/03/CSA_research_note_llm_model_extraction_cloud_scale_20260308-csa-styled.pdf

### W61. Divergence-confusion training-data extraction (entropy-spike)
Signals: repetition prompts cause divergence; pre-divergence entropy spikes;
verbatim emission follows. Ladder: (1) optimize input snippets to maximize
sustained token-entropy (CIA: up to 22.2% verbatim, no training-data
knowledge); (2) for aligned models add mismatched-SFT confusion (18.8% on
70B-instruct); (3) rank candidates with reference-model calibration
(Recollect-and-Rank for scrubbed PII). Shapes: `<ENTROPY-MAXIMIZING-SNIPPET>
→ <DIVERGENCE> → <VERBATIM-EMISSION>`; `<MASKED-RECALL> + <RANK>`. Pitfalls:
heuristic repeat-word prompts rarely emit — optimized confusion, not vibes,
is the trigger.
Sources: https://arxiv.org/abs/2511.05518 | https://aclanthology.org/2025.findings-acl.894 | https://arxiv.org/pdf/2501.17501

### W62. Tokenization-variant unlearning bypass (Toketive/UNCLEAN)
Signals: edit/unlearning evaluated only under canonical tokenization; refusal
behavior erasable via crafted forget-sets; alternative tokenizations shift
compute trajectories. Ladder: (1) query the edited model with non-canonical
tokenizations of the same string (38.6% bypass, 74.5% top-5 reconstruction);
(2) detect-then-reconstruct without the pre-edit model (84.2% F1);
(3) for safety-unlearning targets, blend rejection text into legitimate
forget-sets to strip refusals past filters. Shapes: `<SAME-STRING,
ALT-TOKENIZATION>`; `<CLEAN-FORGET-SET (rejection-blended)>`. Pitfalls:
treating localized edits as robust boundaries — adversarially evaluate over
representations, and diff pre/post checkpoints (exact unlearning can leak
MORE via comparison).
Sources: https://arxiv.org/html/2609.29045v1 | https://arxiv.org/pdf/2506.12522 | https://aclanthology.org/2025.emnlp-main.551.pdf
