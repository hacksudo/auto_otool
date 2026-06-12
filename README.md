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
## ⚙️ Installation
Clone the repository to your local machine:
```bash
git clone [https://github.com/hacksudo/hacksudo-otool-pro.git](https://github.com/hacksudo/hacksudo-otool-pro.git)
cd hacksudo-otool-pro
```
No external Python dependencies are required. The tool relies entirely on standard libraries (os, subprocess, re).

## 💻 Usage
Ensure the target .ipa file has been unzipped into a Payload directory first
```bash
# Run the scanner
python3 auto_otool.py
```

### Interactive Prompts:

Package Path: Enter the full absolute path to the .app directory.
```bash
(Example: /Users/hacksudo/Projects/UnzippedApp/Payload/TargetApp.app)
```
The scanner will recursively map the directory, execute the required otool commands, print live findings to the terminal, and generate hacksudo_pro_report_TargetApp.app.html in your current working directory.

### ⚠️ Disclaimer
This tool is designed for educational purposes, security research, and authorized penetration testing only. Do not use this tool against applications you do not own or do not have explicit permission to test. The author (hacksudo) is not responsible for any misuse or damage caused by this program.

### 📄 License
This project is licensed under the MIT License - see the LICENSE file for details.

Developed by hacksudo
Here is the complete setup for your GitHub repository. Since this is an advanced security tool, the `README.md` is formatted to look highly professional, highlighting its capabilities for reverse engineers and iOS/macOS penetration testers.

### 1. Local Repository Setup Instructions

Open your terminal and run these commands to initialize the git repository and prepare it for GitHub:

```bash
# Create the project folder
mkdir hacksudo-otool-pro
cd hacksudo-otool-pro

# Initialize git
git init

# Create the necessary files (you will paste the code into these)
touch hacksudo_otool_pro.py
touch README.md
touch LICENSE

# Add the files to staging
git add .

# Make your first commit
git commit -m "Initial commit: Added hacksudo Otool Pro scanner and README"

# Change branch to main
git branch -M main

```

*(After creating your repository on GitHub.com, copy the remote URL they provide and run `git remote add origin <URL>` followed by `git push -u origin main`.)*

---

### 2. `README.md` Content

Copy and paste the following Markdown exactly as it is into your `README.md` file.

```markdown
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

```

## ⚙️ Installation

Clone the repository to your local machine:

```bash
git clone [https://github.com/hacksudo/hacksudo-otool-pro.git](https://github.com/hacksudo/hacksudo-otool-pro.git)
cd hacksudo-otool-pro

```

No external Python dependencies are required. The tool relies entirely on standard libraries (`os`, `subprocess`, `re`).

## 💻 Usage

Ensure the target `.ipa` file has been unzipped into a Payload directory first.

```bash
# Run the scanner
python3 hacksudo_otool_pro.py

```

**Interactive Prompts:**

1. **Package Path:** Enter the full absolute path to the `.app` directory.
*(Example: `/Users/hacksudo/Projects/UnzippedApp/Payload/TargetApp.app`)*

The scanner will recursively map the directory, execute the required `otool` commands, print live findings to the terminal, and generate `hacksudo_pro_report_TargetApp.app.html` in your current working directory.

## ⚠️ Disclaimer

This tool is designed for educational purposes, security research, and authorized penetration testing only. Do not use this tool against applications you do not own or do not have explicit permission to test. The author (`hacksudo`) is not responsible for any misuse or damage caused by this program.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](https://www.google.com/search?q=LICENSE) file for details.

---

*Developed by **hacksudo***

```

---

### 3. `LICENSE` Content (Optional but Recommended)

It is highly recommended to include an Open Source license. Paste this into the `LICENSE` file:

```text
MIT License

Copyright (c) 2026 Vishal Waghmare (hacksudo)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

```
