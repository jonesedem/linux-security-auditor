import subprocess
import os
import re
from collections import Counter
from datetime import datetime

REPORT_FILE = "security_audit_report.txt"
AUTH_LOG = "test_auth.log"  # Change to "/var/log/auth.log" on a live production server
FAILED_THRESHOLD = 5

def run_command(cmd):
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout.strip()

def check_ssh_root_login():
    ssh_config = "/etc/ssh/sshd_config"
    if not os.path.exists(ssh_config):
        return "[INFO] SSH config not found."
    with open(ssh_config, "r") as f:
        for line in f:
            if line.strip().startswith("PermitRootLogin"):
                if "no" in line.lower():
                    return "[PASS] SSH Root Login is disabled."
                else:
                    return "[FAIL] SSH Root Login is enabled! Set 'PermitRootLogin no'."
    return "[WARN] PermitRootLogin not explicitly set in sshd_config (defaults to prohibit-password)."

def check_firewall():
    status = run_command("ufw status")
    if "Status: active" in status:
        return "[PASS] UFW Firewall is active."
    return "[FAIL] UFW Firewall is INACTIVE. Run 'sudo ufw enable'."

def check_unattended_upgrades():
    status = run_command("dpkg -l | grep unattended-upgrades")
    if status:
        return "[PASS] Automatic security updates (unattended-upgrades) installed."
    return "[WARN] unattended-upgrades not installed."

def detect_ssh_bruteforce():
    if not os.path.exists(AUTH_LOG):
        return f"[INFO] Log file {AUTH_LOG} not found."

    pattern = re.compile(r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)")
    failed_ips = []

    try:
        with open(AUTH_LOG, "r", encoding="utf-8", errors="ignore") as log_file:
            for line in log_file:
                match = pattern.search(line)
                if match:
                    failed_ips.append(match.group(1))
    except PermissionError:
        return "[ERROR] Permission denied reading log file. Run with 'sudo'."

    ip_counts = Counter(failed_ips)
    alerts = []

    for ip, count in ip_counts.items():
        if count >= FAILED_THRESHOLD:
            alerts.append(f"[ALERT] Brute-force suspected from IP {ip} ({count} failed attempts)")

    if alerts:
        return "\n".join(alerts)
    return "[PASS] No SSH brute-force activity detected above threshold."

def main():
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    findings = [
        f"=== Linux Security Audit Report ({timestamp}) ===",
        check_ssh_root_login(),
        check_firewall(),
        check_unattended_upgrades(),
        detect_ssh_bruteforce()
    ]

    report_output = "\n".join(findings)
    print(report_output)

    with open(REPORT_FILE, "w") as f:
        f.write(report_output + "\n")
    print(f"\n[+] Report saved to {REPORT_FILE}")

if __name__ == "__main__":
    main()
