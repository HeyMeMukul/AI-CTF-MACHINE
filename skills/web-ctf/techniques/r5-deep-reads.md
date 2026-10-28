# R5 deep reads — web (10 complete articles, browser-read 2026-10-17)

## 1. PortSwigger smashing-the-state-machine
- READ: Single-packet 20 reqs Melbourne→Dublin ~1ms spread; GitLab/Devise CVE-2022-4037 token misrouted to wrong address.
- CHAIN: Predict collision object+key → single-packet blend (two emails) → spot misrouted confirmation → reduce to 2 reqs + delay/rate-limit warming → resend-path confirm → hijack invitation/OpenID.
- GOTCHA: Two-req timing misses on differing endpoints; measured client delay or server rate-limit warming; separate sessions (PHP locks).
- REUSE: Every request is multi-step with hidden sub-states; benchmark sequential vs parallel; hunt second-order (email) anomalies.

## 2. PortSwigger gotta-cache-em-all
- READ: Origin delimiters `;` Spring matrix, `.` Rails format, `%00` OpenLiteSpeed, `%0A` Nginx; shape `GET /<Dynamic><Delimiter><EncodedDot><Static>`.
- CHAIN: Non-cacheable R0 → delimiter fuzz (`/home$abcd` vs `/homeabcd`) → cacheable oracle (X-Cache HIT) → craft per normalization tables → victim loads link → poisoned key serves dynamic response.
- GOTCHA: Browser encodes `#`/unsafe + strips dot-segments; encoded delimiters (`%23`,`%3F`) + origin-only-decoded traversal.
- REUSE: Map BOTH parsers (origin delimiters vs cache normalization); deception = backend-delimiter + frontend static rule.

## 3. PortSwigger trace-desync
- READ: TRACE reflects full request (`Content-Type: message/http`); smuggled `HEAD /` + `TRACE /` with script header concatenates into next response; `TraceEnabled extended` allows body.
- CHAIN: H2 header-injection → backend split → smuggle `HEAD /smuggled` (CL.0) to desync → `TRACE /` carrying cacheable headers + second TRACE with script body → leftover parses as cacheable response → poison key.
- GOTCHA: TRACE blocked at edge / rejects Content-Length>0; smuggle TRACE past filter; split headers/body across two TRACEs.
- REUSE: No reflection + working smuggle = loop-back method (TRACE/TRACK) as universal reflection gadget.

## 4. PortSwigger browser-powered-desync
- READ: H2.CL/H2.TE downgrade via browser `fetch()` POST; CL.0 + client-side response-queue poisoning.
- CHAIN: H2→H1 downgrade endpoint → ambiguous CL/TE via fetch (tools can't emit it) → smuggle `HEAD /404` prefix → victim reuses poisoned socket → attacker response lands in victim `fetch()`.
- GOTCHA: Browser forbids raw smuggling bytes + normalizes headers; fetch/XHR quirks + HEAD zero-body concatenation.
- REUSE: Repeater can't emit the bytes → replay through the browser; test H2 downgrade + response-queue, not just request-queue.

## 5. PortSwigger web-cache-entanglement
- READ: Cache-oracle (`CF-Cache-Status: HIT`, `X-True-Cache-Key`); fat-GET with body on GitHub ($10k); Firefox `/%3f` kill-switch.
- CHAIN: Oracle reflecting URL+param with HIT/MISS → probe key transforms (strip qs/port/decode/purge) → pair with gadget (XSS/redirect/JS) → fat-GET or `//`/`/%2F` normalization → poison `/` or `.js`.
- GOTCHA: Unkeyed-qs pages look static, scanners never bust cache; header cache-busters (`Origin: https://nwf4ws…`) or path-normalization busting.
- REUSE: Never rewrite the cache key, rewrite the request; every "unexploitable" reflection is a poisonable gadget.

## 6. SKIPPED — portswigger.net/research/jwt-attacks (HTTP 404)

## 7. PortSwigger prototype-pollution-gadgets
- READ: `Object.prototype.body="foo=bar"` hijacks fetch; `defineProperty` without `value` overwritten via prototype; GA `hitCallback` sink.
- CHAIN: `?__proto__[sequence]=…` → gadget flows to eval/setTimeout/script.src → DOM Invader confirms → XSS on WordPress/GA/GTM pages.
- GOTCHA: Library owners won't patch gadgets ("customer's pollution"); null-prototype objects + freeze/declare all descriptor fields.
- REUSE: Every object-arg API (fetch, defineProperty, storage getters, analytics callbacks) is a gadget; DOM Invader scan libs first.

## 8. SKIPPED — portswigger.net/research/graphqlBatching (HTTP 404; only Academy lab docs exist)

## 9. Intigriti Bug-Bytes 232
- READ: Jan-2026 issue: AWS-GitHub hijack, anonymous bug-bounty forum, IDOR/SSRF methodology, JS endpoint scanner, Renwa Thanos CTF write-up.
- CHAIN: Read issue → pull linked write-up → replay PoC in lab → extract methodology → add scanner + checklist → hunt same class.
- GOTCHA: Roundup link-rot + noisy tips; pin official write-up + version/commit; reproduce one lab before generalizing.
- REUSE: Convert every Bug-Bytes issue into deltas: one scanner, one methodology, one repro'd technique.

## 10. Intigriti 0124 rodriguez (DOM-clobber + axios)
- READ: axios `formDataToJSON/parsePropPath` + jQuery `attrHooks` + `"set" in hooks` TypeError → `__proto__[srcdoc][]=<img onerror>`; mirror-read (Medium 403).
- CHAIN: Clobber `#search` form via DOMPurify name param → `axios.post` serializes clobbered form → pollute `srcdoc` as array (passes `in`-check) → `$("#homepage").attr({srcdoc})` sets iframe srcdoc → XSS.
- GOTCHA: Gadget lists + DOM Invader found nothing; `parsePropPath` strips non-`\w`; debugged the thrown error into array-coercion gadget.
- REUSE: DOM-clobber the exact object a lib serializes, then turn its own error message into the gadget oracle.

## 11. huli revenge (prototype chain walk)
- READ: `settings[root][ownerDocument][defaultView][JSON][constructor][prototype][autofocus]=1` + mithril `setAttr` iteration + `xmlns`/`ONFOCUS` bypass.
- CHAIN: Pollute `Array.prototype[1]` → bypass host check → `devSettings.root` element → walk root→…→JSON→constructor→prototype (Object.prototype) → mithril `setAttribute('ONFOCUS',…)` fires.
- GOTCHA: Lowercase `onxxx` → dead updateEvent path; `hasPropertyKey` true path no-ops; uppercase `ONFOCUS` + `xmlns` namespace falls to setAttribute.
- REUSE: From any DOM handle, hunt property whose `constructor.prototype===Object.prototype` (JSON/Math/Reflect) to pivot Array→Object pollution.

## 12-14. SKIPPED — caletorito ×2 (host unreachable), deadsec log4shell (slug missing)

## 15. slcyber Goja OOB sandbox escape
- READ: `typedArrayProto_with` copies with wrong index (`ta.offset+k` vs `k`); `blind_write` via `BigUint64Array.with` on unsafe int32 pointer arithmetic.
- CHAIN: Spray 50k ArrayBuffers → sweep `blind_write` to corrupt byteLength → BigUint64 scan → retarget backing pointer → R/W primitives → walk to `Date.now` → overwrite `funcVal` with `os/exec.Cmd.Run` + forged argv → call.
- GOTCHA: Memory/time limits kill heavy sprays; no binary for ASLR; batched writes + cached Reflect.apply + ELF read from fixed `0x400000`.
- REUSE: Unsafe-backed TypedArrays: offset-copy bug → unbounded-length → arb R/W ladder; check init/signature ordering for pre-auth trigger.
