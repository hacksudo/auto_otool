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

CHECKS = [
    {"flag": "-Iv", "search": "_random", "name": "Insecure Randomness (random)", "severity": "LOW"},
    {"flag": "-Iv", "search": "_srand", "name": "Insecure Randomness (srand)", "severity": "LOW"},
    {"flag": "-Iv", "search": "_rand", "name": "Insecure Randomness (rand)", "severity": "LOW"},
    {"flag": "-Iv", "search": "_CC_MD5", "name": "Weak Cryptography (MD5)", "severity": "HIGH"},
    {"flag": "-Iv", "search": "_CC_SHA1", "name": "Weak Cryptography (SHA1)", "severity": "MEDIUM"},
    {"flag": "-Iv", "search": "_malloc", "name": "Memory Allocation (malloc)", "severity": "INFO"},
    {"flag": "-Iv", "search": "_gets", "name": "Buffer Overflow Risk (gets)", "severity": "CRITICAL"},
    {"flag": "-Iv", "search": "_memcpy", "name": "Memory Manipulation (memcpy)", "severity": "INFO"},
    {"flag": "-Iv", "search": "_strncpy", "name": "String Manipulation (strncpy)", "severity": "LOW"},
    {"flag": "-Iv", "search": "_strcpy", "name": "Buffer Overflow Risk (strcpy)", "severity": "CRITICAL"},
    {"flag": "-Iv", "search": "_strlen", "name": "String Manipulation (strlen)", "severity": "INFO"},
    {"flag": "-Iv", "search": "_vsnprintf", "name": "String Manipulation (vsnprintf)", "severity": "LOW"},
    {"flag": "-Iv", "search": "_sscanf", "name": "String Manipulation (sscanf)", "severity": "LOW"},
    {"flag": "-Iv", "search": "_strtok", "name": "String Manipulation (strtok)", "severity": "LOW"},
    {"flag": "-Iv", "search": "_alloca", "name": "Stack Memory Allocation (alloca)", "severity": "LOW"},
    {"flag": "-Iv", "search": "_sprintf", "name": "Format String Risk (sprintf)", "severity": "HIGH"},
    {"flag": "-Iv", "search": "_printf", "name": "Format String Risk (printf)", "severity": "MEDIUM"},
    {"flag": "-Iv", "search": "_vsprintf", "name": "Format String Risk (vsprintf)", "severity": "HIGH"},
    {"flag": "-Iv", "search": "_system", "name": "OS Command Injection (system)", "severity": "CRITICAL"},
    {"flag": "-hv", "search": "PIE", "name": "PIE (Position Independent Executable)", "severity": "SECURE_FLAG"},
    {"flag": "-Iv", "search": "stack_chk", "name": "Stack Canaries", "severity": "SECURE_FLAG"},
    {"flag": "-Iv", "search": "objc_release", "name": "ARC Enabled", "severity": "SECURE_FLAG"},
    {"flag": "-arch all -Vl", "search": "LC_ENCRYPT", "name": "Binary Encryption Status", "severity": "INFO"},
    {"flag": "-L", "search": "LocalAuthentication.framework", "name": "Biometric Auth Framework", "severity": "INFO"},
    {"flag": "-oV", "search": "UIWebView", "name": "Deprecated WebView (UIWebView)", "severity": "HIGH"}
]

def get_color(severity):
    colors = {"CRITICAL": RED, "HIGH": RED, "MEDIUM": YELLOW, "LOW": CYAN, "INFO": BLUE, "SECURE_FLAG": GREEN}
    return colors.get(severity, RESET)

def find_macho_binaries(app_dir):
    macho_files = []
    for root, _, files in os.walk(app_dir):
        for file in files:
            full_path = os.path.join(root, file)
            if file.endswith(('.png', '.jpg', '.nib', '.plist', '.strings', '.css', '.js', '.html')):
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
            .address {{ color: #f472b6; font-family: monospace; font-weight: bold; }}
            .file-path {{ color: #cbd5e1; font-size: 0.85em; word-break: break-all; }}
            .cmd-box {{ background-color: #111827; padding: 6px; border-radius: 4px; font-family: monospace; font-size: 0.85em; color: #f59e0b; border-left: 3px solid #f59e0b; margin-bottom: 8px; white-space: pre-wrap; }}
            .snippet-box {{ background-color: #0b0f19; padding: 8px; border-radius: 4px; font-family: monospace; font-size: 0.85em; color: #a3e635; white-space: pre-wrap; }}
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
                    <th style="width: 20%;">File Object</th>
                    <th style="width: 50%;">Cross-Check Command & Binary Snippet</th>
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
                        <div class="cmd-box"># Cross-Check Verification Command:\n{item['verify_cmd']}</div>
                        <span class="address">Location Address: {item['address']}</span>
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
        print(f"{RED}[!] No compiled Mach-O binaries found.{RESET}")
        return
        
    print(f"{GREEN}[+] Found {len(binaries)} files/frameworks to analyze.{RESET}\n")
    time.sleep(0.5)

    report_results = []
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
            
            print("\033[F" * len(log_buffer), end="")
            for log_line in log_buffer:
                print(f"{CYAN}{log_line[:78].ljust(78)}{RESET}")

            try:
                process = subprocess.run(['otool'] + flag.split() + [binary], capture_output=True, text=True)
                lines = process.stdout.split('\n')
                
                pattern = r"\b" + re.escape(search_term) + r"\b" if search_term.startswith("_") else re.escape(search_term)
                grep_flag = "-w" if search_term.startswith("_") else ""

                for line in lines:
                    if re.search(pattern, line):
                        addr = extract_address_from_line(line)
                        # Build the exact command the user can paste to verify manually
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
            print(f"\n{color}[!] IDENTIFIED: {check['name']} | Severity: {check['severity']} | Count: {len(findings_for_this_check)}{RESET}")
            preview = findings_for_this_check[0]
            print(f"{color}    ↳ File: {preview['file']} | Addr: {preview['address']}{RESET}")
            print(f"{YELLOW}    ↳ Cross-Check Command: {preview['verify_cmd']}{RESET}")
            print(f"{color}    ↳ Snip: {preview['snippet']}{RESET}")
            if len(findings_for_this_check) > 1:
                print(f"{color}    ↳ (+ {len(findings_for_this_check) - 1} more instances logged to HTML){RESET}\n")
            
            for _ in range(4): log_buffer.append("") 
            
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
