# mobile Writeups Mined — Manifest r4, browser-swarm batch ( technique-only, no flags )

Mined 2026-10-17 by 8 reader subagents via real browsers (Playwright snapshots; Medium member-only pieces via medium-unlocker.inulute.com -> Freedium mirror; GitHub/team-blog/pro-research sources). Rows filtered (video/bare-profile/placeholder links dropped) and deduped by URL within the batch and against the full corpus. Difficulty as labeled by readers. Format: `- [source/challenge](URL) | difficulty | technique-chain`. No flag values anywhere.

## batch 2026-10-17-browser-swarm (19 rows, 8 easy)

- [Droid-Warden INE first static dynamic](https://infosecwriteups.com/droid-warden-ctf-by-ine-how-i-finished-first-under-pressure-6caad8b21155) | medium | adb pull base.apk, jadx static, frida API SQLi auth bypass
- [Morty New Tool intermediate](https://infosecwriteups.com/mortys-new-tool-android-application-based-ctf-challenge-walkthrough-6058e080598e) | medium | member gate via Freedium, jadx frida APK challenge walkthrough
- [2025 Mobile pentest MobSF guide](https://infosecwriteups.com/2025-mobile-app-pentesting-guide-tools-techniques-real-world-examples-0465bd33e1db) | easy | MobSF setup, jadx apktool decompile, Burp HTTPS intercept
- [PwnSec CuteFrida no-run reverse](https://medium.com/@fara7/pwnsec-cutefrida-writeup-113e4288efeb) | easy | online decompiler structure, Java decrypt script offline, no emulation
- [HTB Arno Unity il2cpp frida](https://medium.com/@devrajlokhande1610/arno-htb-mobile-challenge-walkthrough-19b98ce87e64) | medium | jadx APK lib arm64, adb install frida il2cpp dump keys
- [CyberGym Lab1 jadx-gui](https://medium.com/@prathunan777/reverse-engineering-android-apps-ctf-challenge-baa3a9cbe7d5) | easy | apktool unzip APK, jadx-gui decompile database challenge
- [Hacker101 level13 WebView intent](https://medium.com/@GhoulKingR/intentional-exercise-hacker-101-ctf-writeup-19b98ce87e64) | medium | Android Studio profile APK, smali WebView intent hash analysis
- [MHL Strings intent frida](https://medium.com/%40mehmetfarisacar/mobile-hacking-lab-strings-71cddbf466f5) | easy | jadx manifest intent, apktool smali if-nez, uber signer rebuild
- [AndroPseudoProtect token service](https://medium.com/@TionoX/andropseudoprotect-exploiting-aae9396e1bba) | medium | jadx Intent receiver service, frida token extract exploit app
- [Beetlebug strings.xml hardcode](https://medium.com/@m0t07ha/beetlebug-ctf-embedded-secret-strings-write-up-8ad4856ccc7b) | easy | jadx strings.xml arsc, EmbeddedSecret activity variable review
- [Bypass Canadian activity frida](https://medium.com/@adhaamsayed3/mobile-application-pentest-bypass-the-main-restricted-activity-b9d4420b7ff9) | medium | jadx manifest APK, frida boolean flip, Nox adb jarsigner
- [Frida Labs 0x1 get_random](https://medium.com/@ahmed-alnajjar/frida-labs-challenge-0x1-bypassing-a-random-check-with-frida-ee74e0e5e172) | easy | adb install jadx MainActivity, frida hook return zero deterministic
- [MHL Strings Mahmoud KLOW AES](https://medium.com/@0xAwali/mobile-hacking-lab-android-challenges-3e7bbf3c05ab) | medium | adb install strings, jadx sharedprefs native, frida KLOW deep link
- [MHL Strings Ismail journey](https://medium.com/@ismail.djamhur/mobile-hacking-lab-strings-writeup-3843a7b5e55d) | easy | jadx workflow reverse, static code intent analysis journey
- [Frida practical auth pinning root](https://medium.com/@tandelpruthvi/mobile-pentesting-with-frida-a-practical-guide-0cadd8bcf730) | medium | frida objection Burp, login pinning root hook labs
- [Secure Notes AES PIN frida](https://medium.com/@afandertr/secure-notes-mobile-hacking-lab-write-up-a6b94557948c) | medium | jadx decryptSecret AES CBC, assets properties PIN frida brute
- [Damn Bank objection anti-frida](https://medium.com/h7w/mobile-pen-testing-part-4-dynamic-analysis-of-the-damm-vulnerable-bank-app-0b29bf8a74c0) | medium | objection patch gadget, jadx FridaCheckJNI bypass script
- [MHL Strings Anas deep link](https://anas0x1.medium.com/write-up-strings-mobile-hacking-lab-b16dc5be72eb) | medium | apktool manifest deep link, Frida sharedprefs memory scan AES
- [Android tools frida-server setup](https://medium.com/%40vivian.kfrost/android-penetration-testing-the-tools-d25970107d92) | easy | adb push frida-server chmod, frida-ps objection jadx workflow

## batch 2026-10-17-browser-swarm (25 rows, 12 easy)

- [APKey](https://medium.com/@0xk3r0/hackthebox-apkey-mobile-challenge-6e3cf564c2d) | easy | APK JADX smali hardcoded key
- [APKrypt](https://csbygb.gitbook.io/pentips/writeups/htbtracks/htb-intro-to-android-exploitation-track) | easy | APK decompile key recovery dex
- [Cat](https://danishzia.medium.com/hack-the-box-cat-challenge-write-up-914e0876f68d) | easy | Android backup ab extract flag
- [SAW](https://github.com/Hackplayers/hackthebox-writeups/blob/master/challenges/mobile/htb-mobile-saw-writeup.pdf) | easy | smali patch logic bypass rebuild
- [Manager](https://medium.com/@xprotagonist_/manager-hackthebox-intro-to-android-exploitation-track-by-xprotagonist-7e1ac22fd79a) | medium | password manager intent export flaw
- [Cryptohorrific](https://medium.com/@sanketkumkar77/cryptohorrific-hack-the-box-challenge-writeup-857caf1def0f) | medium | mobile crypto hardcoded AES decrypt

## batch 2026-10-17-browser-swarm (28 rows, 13 easy)

- [APK-rev-wolv2025-extra](https://medium.com/@zzzmilky/wolvctf-2025-writeups-497b68e8ad2e#mobile) | medium | Beginner APK jadx manifest strings flag logic decompile
- [Mobile-OSINT-swimmer2026-truckvideo](https://cyb3r-bo1.github.io/posts/swimmer-osint-ctf-2026_writeup/#truck-mobile) | easy | Vertical video metadata Maps plus-code truck brand read mobile capture
- [Android-debug-hh2026-beacon](https://medium.com/@antor.csecu/tryhackme-packed-light-walkthrough-hacker-holidays-2026-day-4-complete-write-up-eec41e9ced25#mobile-beacon) | medium | User-Agent ByteLotusClient cookie exfil mobile traffic decode pattern

## batch 2026-10-17-browser-swarm (16 rows, 6 easy)

- [Frida-Labs](https://github.com/DERE-ad2001/Frida-Labs) | easy | frida hook Java native bypass root ssl pinning labs
- [OWASP-MSTG-Crackmes](https://github.com/OWASP/owasp-mstg/tree/master/Crackmes) | medium | jadx frida string crypto root anti-tamper walkthroughs
- [UnCrackable-L1](https://github.com/OWASP/owasp-mstg/tree/master/Crackmes/Android/Level_01) | easy | jadx root check frida hook exit string reveal
- [UnCrackable-L2](https://github.com/OWASP/owasp-mstg/tree/master/Crackmes/Android/Level_02) | medium | native barrier frida hook strstr debugger check bypass
- [HTB-APKey](https://app.hackthebox.com/challenges/APKey) | easy | apktool jadx hardcoded API key string resource extraction
- [HTB-APKrypt](https://app.hackthebox.com/challenges/APKrypt) | medium | dex decrypt AES asset config-editor dynamic frida dump
- [HTB-Saw](https://app.hackthebox.com/challenges/Saw) | medium | intent deeplink exported activity path traversal bypass
- [HTB-Pinned](https://app.hackthebox.com/challenges/Pinned) | medium | ssl pinning bypass frida objection network intercept
- [HTB-Manager](https://app.hackthebox.com/challenges/Manager) | medium | content-provider SQL injection smali patch auth bypass
- [HTB-Anchored](https://app.hackthebox.com/challenges/Anchored) | hard | deep-link WebView XSS intent scheme token theft
- [HTB-Cryptohorrific](https://app.hackthebox.com/challenges/Cryptohorrific) | hard | native lib crypto static AES key reverse JNI
- [MHL-Strings](https://mobilehackinglab.com/labs/strings) | easy | strings apk secret endpoint config extraction static
- [MHL-ConfigEditor](https://mobilehackinglab.com/labs/config-editor) | easy | shared_prefs XML edit premium flag unlock
- [MHL-SecureNotes](https://mobilehackinglab.com/labs/secure-notes) | medium | sqlite AES biometric bypass note decrypt frida
- [NahamCon-Kitty](https://app.hackthebox.com/challenges/Kitty) | easy | apk stego image exfil strings zsteg asset
- [NahamCon-Beetlebug](https://app.hackthebox.com/challenges/Beetlebug) | medium | BLE GATT service characteristic flag notify read
