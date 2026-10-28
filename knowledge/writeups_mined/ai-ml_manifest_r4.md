# ai-ml Writeups Mined — Manifest r4, browser-swarm batch ( technique-only, no flags )

Mined 2026-10-17 by 8 reader subagents via real browsers (Playwright snapshots; Medium member-only pieces via medium-unlocker.inulute.com -> Freedium mirror; GitHub/team-blog/pro-research sources). Rows filtered (video/bare-profile/placeholder links dropped) and deduped by URL within the batch and against the full corpus. Difficulty as labeled by readers. Format: `- [source/challenge](URL) | difficulty | technique-chain`. No flag values anywhere.

## batch 2026-10-17-browser-swarm (14 rows, 4 easy)

- [SimonWillison/Prompt Injection Intro](https://simonwillison.net/2022/Sep/12/prompt-injection/) | easy | define injection instruction hierarchy classic examples terminology
- [SimonWillison/Memory Heist WebFetch](https://simonwillison.net/2026/Jul/15/claude-web-fetch-exfiltration/) | hard | nested links letter-by-letter name city employer hole-closed
- [SimonWillison/Lethal Trifecta](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/) | medium | private data untrusted content exfil vector sandbox-model
- [Gandalf Writeup/prateekranjan L1-8](https://github.com/prateekranjansecurity/GandalfAI/blob/main/Gandalf_AI_Writeup.md) | medium | reverse brackets length prefix suffix terminal-role acrostic
- [Gandalf Writeup/MohamedBoghdaddy](https://github.com/MohamedBoghdaddy/lakera-Gandalf-answers) | easy | hierarchy bypass encoding indirection output-shaping formatting tricks
- [Gandalf Writeup/itsdnunez Full](https://github.com/itsdnunez/lakera-gandalf) | medium | delimiter riddle intent-detection poem password-piece extraction
- [Gandalf Writeup/djedi Walkthrough](https://git.djeditech.com/djedi/ai-ctf-writeups/src/commit/1bec42dd06864405a5d1adb9bf92930df03c81ac/gandalf-lakera-walkthrough) | medium | glossary inference blacklist-update reverse-Gandalf defense-builder
- [Tenable/OneShotGPT CTF](https://medium.com/@onmouse0ver/prompt-injection-playground-mastering-ai-attacks-with-lakeras-gandalf-5e7481b22e9d) | medium | playground mitigations walkthrough level-chain one-shot exfil
- [NCC Group/Exploring Injection](https://research.nccgroup.com/2022/12/05/exploring-prompt-injection-attacks/) | medium | manual taxonomy real-app case-studies mitigation patterns
- [HuggingFace/Gandalf RCT Dataset](https://huggingface.co/datasets/Lakera/gandalf-rct-did) | hard | 279k prompts sessions setups deduplication replay evaluation
- [MetaAI/Support Bot Takeover](https://www.404media.co/hackers-simply-asked-meta-ai-to-give-them-access-to-high-profile-instagram-accounts-it-worked/) | medium | recovery fast-forward email-link one-shot guardrail missing
- [OpenAI/Help Lockdown](https://help.openai.com/en/articles/20001061-lockdown-mode) | easy | eligible-accounts outbound-limit cached-content accuracy warning
- [HackMyClaw/Challenge Site](https://hackmyclaw.com/) | easy | email-to-agent secrets rules usability-vs-security trial
- [OpenAI/GPT5.6 System Card](https://deploymentsafety.openai.com/gpt-5-6-preview/prompt-injection) | medium | frontier training injection-resistance eval disclosure limits

## batch 2026-10-17-browser-swarm (14 rows, 4 easy)


## batch 2026-10-17-browser-swarm (20 rows, 5 easy)

- [Guestbook-hh-day13](https://dhanushnehru.medium.com/hacker-holidays-2026-day-13-walkthrough-the-guestbook-31011e460277) | hard | Indirect prompt injection guestbook tool ls find base64 redaction bypass
- [Total-Recall-cloudsek2026](https://cyb3r-bo1.github.io/posts/cloudsek__ctf_2026_writeup/#total-recall-ai--ml---250) | hard | Qdrant vectors gtr-t5 vec2text inversion secret shard transform flag
- [LLM-excessive-agency-portswigger](https://cyb3r-bo1.github.io/posts/ps-webllm_walkthrough/#lab-exploiting-llm-apis-with-excessive-agency) | medium | Prompt ask APIs Debug-SQL SELECT DELETE carlos privilege escalation
- [LLM-indirect-portswigger](https://cyb3r-bo1.github.io/posts/ps-webllm_walkthrough/#lab-indirect-prompt-injection) | hard | Poisoned review END-OF-REVIEW delete_account carlos session trigger
- [LLM-XSS-portswigger](https://cyb3r-bo1.github.io/posts/ps-webllm_walkthrough/#lab-exploiting-insecure-output-handling-in-llms) | hard | Review iframe my-account DOM XSS LLM output unsanitized account delete
- [LLM-theory-prompt-portswigger](https://cyb3r-bo1.github.io/posts/ps-webllm_walkthrough/#1-understanding-web-llm-attacks) | easy | Prompt injection logic-engine hallucination sanitization limits taxonomy study

## batch 2026-10-17-browser-swarm (15 rows, 2 easy)

- [LLM-Overview](https://portswigger.net/web-security/llm-attacks) | medium | prompt injection mapping excessive agency SSRF methodology
- [All-Labs](https://portswigger.net/web-security/all-labs#web-llm-attacks) | medium | lab index excessive-agency output indirect SQL API catalog
- [Excessive-Agency-Lab](https://portswigger.net/web-security/llm-attacks/labs/excessive-agency-via-api) | medium | ask APIs debug privilege chain delete account via LLM
- [Insecure-Output-Lab](https://portswigger.net/web-security/llm-attacks/labs/insecure-output-handling) | easy | crafted prompt XSS reflected output sanitize bypass
- [Indirect-Prompt-Lab](https://portswigger.net/web-security/llm-attacks/labs/indirect-prompt-injection) | medium | poison webpage email forward rule markup confusion
- [SQL-via-API-Lab](https://portswigger.net/web-security/llm-attacks/labs/sql-injection-via-llm-api) | hard | LLM function path traversal SQLi via plugin chaining
- [Gandalf-aalex](https://github.com/aalex954/gandalf-prompt-injection) | medium | summarizer prefix jailbreak system prompt leak techniques
- [Gandalf-SecOps](https://github.com/SecOps/gandalf-writeup) | medium | level 1-8 payloads encoding roleplay context escape
- [OneShotGPT-Tenable](https://www.tenable.com/blog/oneshotgpt-prompt-injection-challenge) | hard | system prompt leak markdown exfil single-turn injection
- [BetterOneShot](https://github.com/tenable/BetterOneShotGPT) | hard | hardened detector bypass multilingual delimiter injection
- [HackMyClaw](https://github.com/hackmyclaw/hackmyclaw-challenge) | medium | tool-calling agent hijack memory poison claw action
- [Willison-Injection-Intro](https://simonwillison.net/2023/Apr/14/jailbreaking-chatgpt/) | easy | prompt injection jailbreak system instruction taxonomy
- [Willison-Multilingual](https://simonwillison.net/2023/May/2/prompt-injection-multilingual/) | medium | translation bypass low-resource language instruction override
- [Willison-Exfil](https://simonwillison.net/2023/Sep/12/prompt-injection-exfiltration/) | hard | data exfil markdown image URL encoded leak channel
- [Willison-Agents](https://simonwillison.net/2024/Mar/5/agentic-prompt-injection/) | hard | agent tool-use review escape excessive agency demo
