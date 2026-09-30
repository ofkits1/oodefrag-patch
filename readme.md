
# O&O Defrag Patch

A lightweight DLL that removes license restrictions from O&O Defrag.

## What It Does

- Bypasses license verification checks in ClientLib and SharedLib DLLs
- Removes trial and registration restrictions
- Exe stays untouched — patches applied in-memory at runtime

## How It Works

The DLL masquerades as `version.dll` and sits alongside `OODefrag.exe`. On launch it:

1. Forwards all `version.dll` API calls to the real system DLL
2. Verifies the host EXE via hash before applying patches
3. Locates loaded license DLLs via PEB walking
4. Patches `OOSoftware.License.ClientLib.dll` and `OOSoftware.License.SharedLib.dll` to force registered state

## Installation

1. Drop `version.dll` (compiled from this source) in the install folder
2. Run `OODefrag.exe` — that's it

## Notes

- Built for **O&O Defrag x64** only. Other builds may not work.
- Patches both the host EXE and loaded license DLLs directly.
- AV may flag the DLL — false positives are common with in-memory patching tools.
- For educational purposes only.

## Disclaimer

This project is for **educational and research purposes only**. Use at your own risk. The author is not responsible for any misuse or damage.

---

Cracked by **github.com/ofkits1**
