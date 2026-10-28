# hardware Writeups Mined — Manifest r4, browser-swarm batch ( technique-only, no flags )

Mined 2026-10-17 by 8 reader subagents via real browsers (Playwright snapshots; Medium member-only pieces via medium-unlocker.inulute.com -> Freedium mirror; GitHub/team-blog/pro-research sources). Rows filtered (video/bare-profile/placeholder links dropped) and deduped by URL within the batch and against the full corpus. Difficulty as labeled by readers. Format: `- [source/challenge](URL) | difficulty | technique-chain`. No flag values anywhere.

## batch 2026-10-17-browser-swarm (20 rows, 7 easy)

- [HardwareAllTheThings/Home](https://swisskyrepo.github.io/HardwareAllTheThings/) | easy | wiki payloads bypasses community methodology index
- [HardwareAllTheThings/Firmware Extraction](https://swisskyrepo.github.io/HardwareAllTheThings/firmware/) | easy | binwalk scan extract squashfs firmwalker grep secrets
- [HardwareAllTheThings/UART](https://swisskyrepo.github.io/HardwareAllTheThings/uart/) | medium | identify TX-RX-GND baud brute minicom root shell
- [HardwareAllTheThings/JTAG SWD](https://swisskyrepo.github.io/HardwareAllTheThings/jtag/) | hard | OpenOCD pinout boundary-scan dump flash bypass
- [HardwareAllTheThings/SPI Flash](https://swisskyrepo.github.io/HardwareAllTheThings/spi/) | medium | CH341A clip flashrom double-read hash-verify carve
- [HardwareAllTheThings/I2C SPI Decode](https://swisskyrepo.github.io/HardwareAllTheThings/protocols/) | medium | logic-analyzer sigrok PulseView protocol decoder
- [Hackaday/RP2350 UART Bootloader](https://hackaday.com/2025/05/11/exploring-the-rp2350s-uart-bootloader) | medium | RAM-loader RS485 remote-update boot-time security risk
- [Binwalk/Firmware Analysis Docs](https://binwalk.app/) | easy | scan extract recurse entropy measure review structure
- [ReFirmLabs Binwalk Classic](https://github.com/ReFirmLabs/binwalk) | easy | signature scan dd carve unsquashfs jefferson
- [whatdahack/Hardware IoT Guide](https://whatdahack.com/resources/hardware) | easy | binwalk firmwalker Ghidra minicom MQTT JTAG workflow
- [RedFoxSec/Getting Started Hardware](https://www.redfoxsec.com/blog/getting-started-with-hardware-hacking) | easy | flashrom Ghidra OpenOCD minicom sigrok credential grep
- [Espilon Learn/Binwalk Wiki](https://learn.espilon.net/learn/wiki/software/binwalk) | easy | bootloader kernel squashfs overlay entropy triage carving
- [Hackaday.io/Firmware Reversing Intro](https://cdn.hackaday.io/files/1750817490665504/Asmita_HackadayRemoticon2020.pdf) | medium | static dynamic bare-metal encrypted workaround non-encrypted diff
- [TokyoWesterns/BLE Replay](https://swisskyrepo.github.io/HardwareAllTheThings/ble/) | medium | GATT sniff replay OTA update key extraction
- [HCSC 2024/CAN Bus Hack](https://swisskyrepo.github.io/HardwareAllTheThings/can/) | hard | SocketCAN candump replay ECU frame injection
- [Riscure/Glitch Intro](https://swisskyrepo.github.io/HardwareAllTheThings/glitching/) | hard | voltage clock crowbar timing trigger shell bypass
- [ChipWhisperer/Side Channel](https://swisskyrepo.github.io/HardwareAllTheThings/side-channel/) | hard | power trace CPA AES key recovery trigger alignment
- [Proxmark3/RFID Clone](https://swisskyrepo.github.io/HardwareAllTheThings/rfid/) | medium | LF HF sniff clone Mifare nested attack
- [BusyBox/Router Shell Escape](https://hackaday.com/tag/uart) | medium | limited shell symlink escape telnetd httpd exploit
- [OpenOCD/SWD Dump](https://swisskyrepo.github.io/HardwareAllTheThings/arm/) | hard | ST-Link GDB dump flash unlock debug-access

## batch 2026-10-17-browser-swarm (20 rows, 7 easy)


## batch 2026-10-17-browser-swarm (23 rows, 8 easy)

- [qsort-weapon-zichmp2026](https://medium.com/@amrkhaledv2171516/zichmp-ctf-2026-cyber-champions-2026-abbfe3f13fc6#qsort) | medium | qsort comparator side-effect XOR buffer sort decrypt reverse engineer
- [SIMD-bit-zichmp2026](https://medium.com/@amrkhaledv2171516/zichmp-ctf-2026-cyber-champions-2026-abbfe3f13fc6#simd) | hard | ROL nibble swap SIMD bit manipulation reverse transforms undo chain
- [USB-ducky-jordan2023](https://0xs1rx58.medium.com/jordan-cyber-warriors-ctf-a64015aba315#usb) | easy | Rubber-Ducky powershell DownloadFile Start-Process URL exe flag combine

## batch 2026-10-17-browser-swarm (15 rows, 6 easy)

- [Firmware-Tag](https://hackaday.com/tag/firmware/) | easy | ESP32 CYD BIOS grill router firmware roundup index
- [Braino-CYD](https://hackaday.com/2026/10/16/braino-takes-the-cheap-yellow-display-to-school/) | easy | web-flash GPL educational firmware Cheap-Yellow-Display games
- [ESP-Vim](https://hackaday.com/2026/10/01/the-whole-computer-is-vim/) | medium | ESP32-S3 firmware boots Vim filesystem micropython PSRAM
- [Grill-Firmware](https://hackaday.com/2026/08/18/reverse-engineered-grill-controller-gets-open-firmware/) | medium | dump espflash UART thermistor CS1621 open rewrite OTA
- [ESP32-C6-BIOS](https://hackaday.com/2026/06/23/a-bios-for-your-esp32-c6/) | medium | bootloader syscall dynamic RAM executables network load
- [Nanoleaf-ESP32](https://hackaday.com/2026/09/22/esp32-replacement-for-lighting-display-controller/) | easy | published firmware port single-wire bus panel control
- [Amprobe-NAND](https://hackaday.com/2026/08/31/fixing-an-expensive-amprobe-cable-tracer-with-mystery-fault/) | hard | UART bootlog TSOP48 dump bitflip bootloader reflash Linux
- [Reverse-Tag](https://hackaday.com/tag/reverse-engineering/) | medium | router IoT teardown UART JTAG SPI flash guides
- [UART-Guide](https://hackaday.com/2016/08/03/what-is-uart/) | easy | baud identification logic analyzer serial console shell
- [Espilon-Binwalk](https://wiki.espilon.xyz/iot/binwalk) | easy | binwalk entropy squashfs extraction firmware unpack
- [Espilon-UART](https://wiki.espilon.xyz/iot/uart) | easy | pinout baudrate shell U-Boot baud identification console
- [Espilon-SPI](https://wiki.espilon.xyz/iot/spi) | medium | flashrom SOIC clip dump verify extraction
- [Espilon-JTAG](https://wiki.espilon.xyz/iot/jtag) | hard | JTAGenum OpenOCD boundary scan firmware debug shell
- [RedFoxSec-HW](https://redfoxsec.com/blog/hardware-hacking-guide/) | medium | UART JTAG SPI I2C methodology tools binwalk exploitation
- [Doom-Sonoff](https://hackaday.com/2026/10/16/running-doom-sort-of-on-a-sonoff-smart-switch/) | hard | constrained flash port framebuffervspace optimization hack
