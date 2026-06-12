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
    print("        ██████╗ ████████╗ ██████╗  ██████╗ ██╗                       ")
    print("       ██╔═══██╗╚══██╔══╝██╔═══██╗██╔═══██╗██║                       ")
    print("       ██║   ██║   ██║   ██║   ██║██║   ██║██║                       ")
    print("       ██║   ██║   ██║   ██║   ██║██║   ██║██║                       ")
    print("       ╚██████╔╝   ██║   ╚██████╔╝╚██████╔╝███████╗                  ")
    print("        ╚═════╝    ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝                  ")
    print(f"{RESET}")
    print(f"{GREEN}                 --- ADVANCED SECURITY SCANNER ---{RESET}\n")

# --- Advanced Vulnerability Ruleset ---
CHECKS = [
    # Insecure APIs (-Iv)
    {"flag": "-Iv", "search": "_random", "name": "Insecure Randomness (random)", "severity": "LOW"},
    {"flag": "-Iv", "search": "_CC_MD5", "name": "Weak Cryptography (MD5)", "severity": "HIGH"},
    {"flag": "-Iv", "search": "_CC_SHA1", "name": "Weak Cryptography (SHA1)", "severity": "MEDIUM"},
    {"flag": "-Iv", "search": "_malloc", "name": "Memory Allocation (malloc)", "severity": "INFO"},
    {"flag": "-Iv", "search": "_gets", "name": "Buffer Overflow Risk (gets)", "severity": "CRITICAL"},
    {"flag": "-Iv", "search": "_strcpy", "name": "Buffer Overflow Risk (strcpy)", "severity": "CRITICAL"},
    {"flag": "-Iv", "search": "_system", "name": "OS Command Injection (system)", "severity": "CRITICAL"},
    
    # Header & Security Flags (-hv, -Iv)
    {"flag": "-hv", "search": "PIE", "name": "PIE (Position Independent Executable)", "severity": "SECURE_FLAG"},
    {"flag": "-Iv", "search": "stack_chk", "name": "Stack Canaries", "severity": "SECURE_FLAG"},
    {"flag": "-Iv", "search": "objc_release", "name": "ARC Enabled", "severity": "SECURE_FLAG"},
    
    # Frameworks & WebViews (-L, -oV)
    {"flag": "-L", "search": "LocalAuthentication.framework", "name": "Biometric Auth Framework", "severity": "INFO"},
    {"flag": "-oV", "search": "UIWebView", "name": "Deprecated WebView (UIWebView)", "severity": "HIGH"},
    {"flag": "-oV", "search": "WKWebView", "name": "Secure WebView (WKWebView)", "severity": "SECURE_FLAG"},
    
    # Advanced Load Commands (-l)
    {"flag": "-l", "search": "LC_ENCRYPT", "name": "Binary Encryption Status", "severity": "INFO"},
    {"flag": "-l", "search": "LC_RPATH", "name": "Runpath Search Path (Check for @executable_path)", "severity": "MEDIUM"},
    
    # Architecture (-fh)
    {"flag": "-fh", "search": "architecture", "name": "Binary Architecture Info", "severity": "INFO"}
]

def get_color(severity):
    colors = {"CRITICAL": RED, "HIGH": RED, "MEDIUM": YELLOW, "LOW": CYAN, "INFO": BLUE, "SECURE_FLAG": GREEN}
    return colors.get(severity, RESET)

def find_macho_binaries(app_dir):
    """Recursively finds all Mach-O binaries in the .app bundle (executables, dylibs, frameworks)."""
    macho_files = []
    for root, dirs, files in os.walk(app_dir):
        for file in files:
            full_path = os.path.join(root, file)
            # Skip obvious non-binaries
            if file.endswith(('.png', '.jpg', '.nib', '.plist', '.strings', '.css', '.js', '.html')):
                continue
            try:
                # Use 'file' command to check if it's a Mach-O binary
                result = subprocess.run(['file', full_path], capture_output=True, text=True)
                if "Mach-O" in result.stdout:
                    macho_files.append(full_path)
            except Exception:
                pass
    return macho_files

def extract_address_from_line(line, search_term):
    """Attempts to extract the hex memory address (line number equivalent) from otool output."""
    # Match standard otool indirect symbol format: 0x0000000100084ab0  0x... _strcpy
    match = re.search(r'(0x[0-9a-fA-F]+)', line)
    if match:
        return match.group(1)
    return "Global/Header"

def generate_html_report(results, app_dir):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    app_name = os.path.basename(app_dir.rstrip('/'))
    report_name = f"hacksudo_pro_report_{app_name}.html"
    
    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>hacksudo Pro - Binary Analysis</title>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, sans-serif; background-color: #0b0f19; color: #e2e8f0; margin: 0; padding: 20px; }}
            h1 {{ color: #00e5ff; text-align: center; text-transform: uppercase; letter-spacing: 2px; }}
            .header {{ text-align: center; margin-bottom: 30px; color: #94a3b8; font-size: 1.1em; }}
            table {{ width: 100%; border-collapse: collapse; background-color: #1e293b; box-shadow: 0 4px 15px rgba(0,0,0,0.5); font-size: 0.95em; }}
            th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #334155; vertical-align: top; }}
            th {{ background-color: #0f172a; color: #38bdf8; text-transform: uppercase; font-weight: bold; }}
            tr:hover {{ background-color: #334155; }}
            .CRITICAL {{ color: #ff4d4d; font-weight: bold; }}
            .HIGH {{ color: #ff751a; font-weight: bold; }}
            .MEDIUM {{ color: #eab308; font-weight: bold; }}
            .LOW {{ color: #2dd4bf; }}
            .INFO {{ color: #60a5fa; }}
            .SECURE_FLAG {{ color: #4ade80; font-weight: bold; }}
            .address {{ color: #f472b6; font-family: monospace; }}
            .file-path {{ color: #cbd5e1; font-size: 0.85em; word-break: break-all; }}
            .snippet-box {{ background-color: #0b0f19; padding: 10px; border-radius: 5px; font-family: monospace; font-size: 0.85em; color: #a3e635; white-space: pre-wrap; margin-top: 5px; }}
        </style>
    </head>
    <body>
        <h1>hacksudo Advanced Static Analysis</h1>
        <div class="header">
            <p><strong>Target Bundle:</strong> {app_dir}</p>
            <p><strong>Scan Date:</strong> {timestamp}</p>
        </div>
        <table>
            <thead>
                <tr>
                    <th style="width: 20%;">Vulnerability / Finding</th>
                    <th style="width: 10%;">Severity</th>
                    <th style="width: 25%;">File (Binary/Framework)</th>
                    <th style="width: 45%;">Location (Address) & Snippet</th>
                </tr>
            </thead>
            <tbody>
    """
    
    for res in results:
        for item in res['findings']:
            html += f"""
                <tr>
                    <td><strong>{res['name']}</strong></td>
                    <td class="{res['severity']}">{res['severity']}</td>
                    <td class="file-path">{item['file']}</td>
                    <td>
                        <span class="address">Address: {item['address']}</span>
                        <div class="snippet-box">{item['snippet']}</div>
                    </td>
                </tr>
            """
            
    html += """
            </tbody>
        </table>
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
        print(f"{RED}[!] No compiled Mach-O binaries found in this directory.{RESET}")
        return
        
    print(f"{GREEN}[+] Found {len(binaries)} executable files/frameworks to analyze.{RESET}\n")
    time.sleep(1)

    report_results = []
    
    # 10-line scrolling log buffer
    log_buffer = deque(maxlen=10)
    
    print("-" * 80)
    print(f"{MAGENTA}--- HACKSUDO VERBOSE OTOOL ENGINE ---{RESET}")
    
    for check in CHECKS:
        flag = check['flag']
        search_term = check['search']
        findings_for_this_check = []
        
        for binary in binaries:
            cmd = f"otool {flag} '{binary}'"
            log_buffer.append(f"[Exec] {cmd}")
            
            # Print the scrolling buffer
            print("\033[F" * len(log_buffer), end="") # Move cursor up
            for log_line in log_buffer:
                print(f"{CYAN}{log_line[:78].ljust(78)}{RESET}")

            try:
                process = subprocess.run(['otool'] + flag.split() + [binary], capture_output=True, text=True)
                lines = process.stdout.split('\n')
                
                # Regex for precise function matching if it starts with _
                if search_term.startswith("_"):
                    pattern = r"\b" + re.escape(search_term) + r"\b"
                else:
                    pattern = re.escape(search_term)

                for line in lines:
                    if re.search(pattern, line):
                        addr = extract_address_from_line(line, search_term)
                        findings_for_this_check.append({
                            "file": os.path.basename(binary),
                            "address": addr,
                            "snippet": line.strip()
                        })
            except Exception:
                pass

        if findings_for_this_check:
            color = get_color(check['severity'])
            print(f"\n{color}[!] IDENTIFIED: {check['name']} | Severity: {check['severity']} | Count: {len(findings_for_this_check)}{RESET}")
            # Show a quick preview in terminal
            preview = findings_for_this_check[0]
            print(f"{color}    ↳ File: {preview['file']} | Addr: {preview['address']}{RESET}")
            print(f"{color}    ↳ Snip: {preview['snippet']}{RESET}")
            if len(findings_for_this_check) > 1:
                print(f"{color}    ↳ (+ {len(findings_for_this_check) - 1} more instances logged to HTML){RESET}\n")
            
            # Pad the log buffer so the UI doesn't break
            for _ in range(3): log_buffer.append("") 
            
            report_results.append({
                "name": check['name'],
                "severity": check['severity'],
                "findings": findings_for_this_check
            })

    print("-" * 80)
    print(f"\n{GREEN}[*] Hacksudo Pro Analysis complete!{RESET}")
    
    if report_results:
        report_file = generate_html_report(report_results, app_dir)
        print(f"{GREEN}[*] Ultimate HTML Report generated: {os.path.abspath(report_file)}{RESET}")

if __name__ == "__main__":
    main()
