import os
import subprocess
import re
import time
from datetime import datetime
from collections import deque

# --- ANSI Colors ---
RESET = "\033[0m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    clear_screen()
    print(f"{CYAN}")
    print("   ██╗  ██╗ █████╗  ██████╗██╗  ██╗███████╗██╗   ██╗██████╗  ██████╗ ")
    print("   ██║  ██║██╔══██╗██╔════╝██║ ██╔╝██╔════╝██║   ██║██╔══██╗██╔═══██╗")
    print("   ███████║███████║██║     █████╔╝ ███████╗██║   ██║██║  ██║██║   ██║")
    print("   ██╔══██║██╔══██║██║     ██╔═██╗ ╚════██║██║   ██║██║  ██║██║   ██║")
    print("   ██║  ██║██║  ██║╚██████╗██║  ██╗███████║╚██████╔╝██████╔╝╚██████╔╝")
    print("   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝  ╚═════╝ ")
    print("            ULTIMATE STATIC ANALYSIS & THREAT INTEL ENGINE           ")
    print(f"{RESET}")
    print(f"{GREEN}                     --- Created by hacksudo ---{RESET}\n")

# --- Threat Intelligence Database ---
CHECKS = [
    {
        "flag": "-Iv", "search": "_strcpy", "name": "Buffer Overflow Risk (strcpy)", "severity": "CRITICAL",
        "observation": "The binary imports '_strcpy', an unsafe C function that copies strings without checking the destination buffer size.",
        "impact": "An attacker can supply input larger than the buffer, overwriting adjacent memory. This leads to application crashes (DoS) or Remote Code Execution (RCE) by hijacking the execution flow.",
        "cve_tool": "Tools: GDB, LLDB, Radare2, Metasploit (pattern_create/offset). Ref: CWE-120 (Classic Buffer Overflow).",
        "recommendation": "Replace '_strcpy' with bounds-checking alternatives like 'strlcpy', 'strncpy_s', or native Swift String handling."
    },
    {
        "flag": "-Iv", "search": "_system", "name": "OS Command Injection (system)", "severity": "CRITICAL",
        "observation": "The binary imports the '_system' function, allowing it to pass strings directly to the host operating system shell.",
        "impact": "If user-controlled input reaches this function un-sanitized, an attacker can execute arbitrary OS commands with the privileges of the application.",
        "cve_tool": "Tools: Commix, Burp Suite (if tied to network input). Ref: CWE-78 (OS Command Injection).",
        "recommendation": "Avoid calling OS commands directly. Use native APIs (e.g., Foundation, NSTask/Process) with strict argument separation."
    },
    {
        "flag": "-Iv", "search": "_CC_MD5", "name": "Weak Cryptography (MD5)", "severity": "HIGH",
        "observation": "The binary references MD5 hashing algorithms via the CommonCrypto library.",
        "impact": "MD5 is highly vulnerable to collision attacks. Attackers can generate two different files/inputs that produce the same hash, breaking integrity checks or forging signatures.",
        "cve_tool": "Tools: Hashcat, John the Ripper. Ref: CWE-327 (Use of Broken Cryptographic Algorithm).",
        "recommendation": "Migrate to SHA-256 or SHA-3 via 'CC_SHA256'. Do not use MD5 for passwords, tokens, or file integrity."
    },
    {
        "flag": "-Iv", "search": "_random", "name": "Insecure Randomness (random)", "severity": "LOW",
        "observation": "The application imports a predictable Pseudo-Random Number Generator (PRNG).",
        "impact": "If used for security mechanisms (tokens, cryptography, session IDs), an attacker can guess the 'random' values by determining the seed.",
        "cve_tool": "Tools: Custom Python scripting to predict PRNG output based on system time (seed). Ref: CWE-330.",
        "recommendation": "Use Cryptographically Secure PRNGs (CSPRNG) like 'SecRandomCopyBytes' or 'arc4random()'."
    },
    {
        "flag": "-oV", "search": "UIWebView", "name": "Deprecated/Insecure WebView (UIWebView)", "severity": "HIGH",
        "observation": "The binary links against the deprecated 'UIWebView' component.",
        "impact": "UIWebView lacks modern security isolation (out-of-process rendering) and cannot effectively restrict JavaScript execution, increasing the risk of Cross-Site Scripting (XSS) and bridging vulnerabilities.",
        "cve_tool": "Tools: Frida, Objection (to hook webview calls). Ref: Apple Deprecation Notices, XSS vectors.",
        "recommendation": "Replace all instances of 'UIWebView' with 'WKWebView', and ensure 'javaScriptEnabled' is disabled unless strictly necessary."
    }
]

def get_color(severity):
    colors = {"CRITICAL": RED, "HIGH": RED, "MEDIUM": YELLOW, "LOW": CYAN, "INFO": BLUE, "SECURE_FLAG": GREEN}
    return colors.get(severity, RESET)

def find_macho_binaries(app_dir):
    macho_files = []
    for root, _, files in os.walk(app_dir):
        for file in files:
            full_path = os.path.join(root, file)
            if file.endswith(('.png', '.jpg', '.nib', '.plist', '.strings', '.css', '.js')):
                continue
            try:
                result = subprocess.run(['file', full_path], capture_output=True, text=True)
                if "Mach-O" in result.stdout:
                    macho_files.append(full_path)
            except Exception:
                pass
    return macho_files

def extract_address_from_line(line):
    match = re.search(r'(0x[0-9a-fA-F]+)', line)
    return match.group(1) if match else "Global/Header"

def generate_html_report(results, app_dir):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    app_name = os.path.basename(app_dir.rstrip('/'))
    report_name = f"hacksudo_threat_report_{app_name}.html"
    
    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>hacksudo Threat Intel Report</title>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, sans-serif; background-color: #0b0f19; color: #e2e8f0; margin: 0; padding: 20px; }}
            h1 {{ color: #00e5ff; text-align: center; text-transform: uppercase; letter-spacing: 2px; }}
            .header {{ text-align: center; margin-bottom: 40px; color: #94a3b8; font-size: 1.1em; border-bottom: 1px solid #1e293b; padding-bottom: 20px; }}
            .card {{ background-color: #1e293b; border-radius: 8px; margin-bottom: 25px; padding: 20px; box-shadow: 0 4px 15px rgba(0,0,0,0.5); border-left: 5px solid #334155; }}
            .card.CRITICAL {{ border-left-color: #ff4d4d; }}
            .card.HIGH {{ border-left-color: #ff751a; }}
            .card.LOW {{ border-left-color: #2dd4bf; }}
            h2 {{ margin-top: 0; display: flex; justify-content: space-between; align-items: center; }}
            .sev-badge {{ padding: 5px 12px; border-radius: 4px; font-size: 0.8em; color: #000; font-weight: bold; }}
            .sev-CRITICAL {{ background-color: #ff4d4d; }}
            .sev-HIGH {{ background-color: #ff751a; }}
            .sev-LOW {{ background-color: #2dd4bf; }}
            .section-title {{ color: #38bdf8; font-size: 0.9em; text-transform: uppercase; margin: 15px 0 5px 0; font-weight: bold; }}
            .text-content {{ color: #cbd5e1; font-size: 0.95em; line-height: 1.5; margin: 0; }}
            .cmd-box {{ background-color: #0f172a; padding: 10px; border-radius: 4px; font-family: monospace; font-size: 0.85em; color: #f59e0b; margin-top: 10px; }}
            .snippet-box {{ background-color: #000; padding: 10px; border-radius: 4px; font-family: monospace; font-size: 0.85em; color: #a3e635; margin-top: 5px; white-space: pre-wrap; }}
        </style>
    </head>
    <body>
        <h1>Static Analysis & Threat Intel</h1>
        <div class="header">
            <p><strong>Target Bundle:</strong> {app_dir}</p>
            <p><strong>Scan Date:</strong> {timestamp}</p>
        </div>
    """
    
    for res in results:
        for item in res['findings']:
            html += f"""
        <div class="card {res['severity']}">
            <h2>
                <span style="color: #f8fafc;">{res['name']}</span>
                <span class="sev-badge sev-{res['severity']}">{res['severity']}</span>
            </h2>
            
            <p class="section-title">Target File & Location</p>
            <p class="text-content"><strong>File:</strong> {item['file']} <br><strong>Address:</strong> <span style="font-family: monospace; color: #f472b6;">{item['address']}</span></p>

            <p class="section-title">Observation</p>
            <p class="text-content">{res['observation']}</p>

            <p class="section-title">Exploitation & Impact</p>
            <p class="text-content">{res['impact']}</p>

            <p class="section-title">Tools & CVE Reference</p>
            <p class="text-content">{res['cve_tool']}</p>

            <p class="section-title">Recommendation</p>
            <p class="text-content">{res['recommendation']}</p>

            <p class="section-title">Cross-Check Verification Command</p>
            <div class="cmd-box">{item['verify_cmd']}</div>

            <p class="section-title">Raw Binary Memory Snippet</p>
            <div class="snippet-box">{item['snippet']}</div>
        </div>
            """
            
    html += """
    </body>
    </html>
    """
    with open(report_name, "w", encoding="utf-8") as f:
        f.write(html)
    return report_name

def main():
    print_banner()
    app_dir = input(f"{MAGENTA}[?] Enter full package path (e.g., /path/to/Payload/MyApp.app): {RESET}").strip()
    
    if not os.path.exists(app_dir):
        print(f"\n{RED}[!] Error: Path not found at {app_dir}{RESET}")
        return

    print(f"\n{CYAN}[*] Scanning bundle for Mach-O binaries...{RESET}")
    binaries = find_macho_binaries(app_dir)
    
    if not binaries:
        print(f"{RED}[!] No compiled Mach-O binaries found.{RESET}")
        return
        
    print(f"{GREEN}[+] Found {len(binaries)} files/frameworks to analyze.{RESET}\n")
    time.sleep(1)

    report_results = []
    log_buffer = deque(maxlen=8)
    
    print("-" * 90)
    print(f"{MAGENTA}--- HACKSUDO VERBOSE OTOOL ENGINE ---{RESET}")
    
    for check in CHECKS:
        flag = check['flag']
        search_term = check['search']
        findings_for_this_check = []
        
        for binary in binaries:
            cmd = f"otool {flag} '{os.path.basename(binary)}'"
            log_buffer.append(f"[Exec] {cmd}")
            
            print("\033[F" * len(log_buffer), end="")
            for log_line in log_buffer:
                print(f"{CYAN}{log_line[:88].ljust(88)}{RESET}")
            
            # Control the speed of the output so it is readable
            time.sleep(0.08)

            try:
                process = subprocess.run(['otool'] + flag.split() + [binary], capture_output=True, text=True)
                lines = process.stdout.split('\n')
                
                pattern = r"\b" + re.escape(search_term) + r"\b" if search_term.startswith("_") else re.escape(search_term)
                grep_flag = "-w" if search_term.startswith("_") else ""

                for line in lines:
                    if re.search(pattern, line):
                        addr = extract_address_from_line(line)
                        verify_cmd = f"otool {flag} '{binary}' | grep {grep_flag} '{search_term}'"
                        
                        findings_for_this_check.append({
                            "file": os.path.basename(binary),
                            "address": addr,
                            "snippet": line.strip(),
                            "verify_cmd": verify_cmd
                        })
            except Exception:
                pass

        if findings_for_this_check:
            color = get_color(check['severity'])
            print(f"\n{color}╔═════════════════════════════════════════════════════════════════════════════════════════")
            print(f"║ [!] VULNERABILITY DETECTED: {check['name']} | Severity: {check['severity']}")
            print(f"╠═════════════════════════════════════════════════════════════════════════════════════════{RESET}")
            preview = findings_for_this_check[0]
            print(f"{color}║ [+] Target File : {preview['file']} (Address: {preview['address']})")
            print(f"║ [+] Observation : {check['observation']}")
            print(f"║ [+] Impact      : {check['impact']}")
            print(f"║ [+] Threat Intel: {check['cve_tool']}")
            print(f"║ [+] CMD Verify  : {preview['verify_cmd']}{RESET}")
            print(f"{color}╚═════════════════════════════════════════════════════════════════════════════════════════{RESET}\n")
            
            for _ in range(3): log_buffer.append("") 
            
            report_results.append({
                "name": check['name'],
                "severity": check['severity'],
                "observation": check['observation'],
                "impact": check['impact'],
                "cve_tool": check['cve_tool'],
                "recommendation": check['recommendation'],
                "findings": findings_for_this_check
            })

    print("-" * 90)
    print(f"\n{GREEN}[*] Hacksudo Threat Engine Analysis complete!{RESET}")
    
    if report_results:
        report_file = generate_html_report(report_results, app_dir)
        print(f"{GREEN}[*] Comprehensive Threat Report generated: {os.path.abspath(report_file)}{RESET}")

if __name__ == "__main__":
    main()
