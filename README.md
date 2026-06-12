# 🛠️ hacksudo Otool Pro Scanner

[![Python 3.x](https://img.shields.io/badge/Python-3.x-blue.svg)](https://www.python.org/)
[![macOS](https://img.shields.io/badge/OS-macOS-lightgrey.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**hacksudo Otool Pro** is an advanced static analysis and reverse engineering wrapper for Apple's `otool` binary. Designed for iOS and macOS penetration testers, it automates the discovery of insecure compiler flags, vulnerable C-functions (like `strcpy`, `system`), and deprecated frameworks across complex `.app` bundles.

## 🚀 Features

* **Recursive Bundle Scanning:** Automatically hunts down and scans all compiled Mach-O binaries, `.dylib` files, and `.framework` files inside an `.app` payload.
* **Memory Address Extraction:** Isolates the exact hex memory addresses (e.g., `0x100084ab0`) where insecure functions are imported, giving you precise locations for further analysis in tools like Hopper or Ghidra.
* **Dark-Mode HTML Reporting:** Generates a comprehensive, highly readable HTML report categorized by severity and file path.
* **Scrolling Terminal UI:** Features a custom animated verbose logging engine to keep your terminal clean while processing massive frameworks.
* **Vulnerability Mapping:**
  * **CRITICAL:** Buffer overflows (`gets`, `strcpy`) and OS Command Injection (`system`).
  * **HIGH:** Weak cryptography (`MD5`) and deprecated web views (`UIWebView`).
  * **SECURE FLAGS:** Validates `PIE`, `stack_chk` (Canaries), and ARC (`objc_release`).

## 📋 Prerequisites

* **macOS / Linux** (macOS highly recommended for native `otool` support).
* **Python 3.6+**
* **Xcode Command Line Tools:** Must be installed to use `otool` and `file` commands.
  ```bash
  xcode-select --install
