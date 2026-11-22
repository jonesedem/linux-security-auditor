# Linux Server Security Auditor & Brute-Force Detector

A lightweight, zero-dependency Python security automation tool designed to audit critical Linux server configurations and detect SSH brute-force attack patterns from system authentication logs.

## Features
* **Configuration Hardening Audit:** Verifies `/etc/ssh/sshd_config` (`PermitRootLogin`), UFW firewall status, and `unattended-upgrades` patch automation.
* **SSH Brute-Force Detection:** Parses system authentication logs using regular expressions (`re`) to flag IPv4 addresses exceeding failed login thresholds.
* **Automated Reporting:** Outputs structured pass/warn/fail/alert telemetry and saves timestamped audit logs (`security_audit_report.txt`).

## Usage
```bash
git clone https://github.com<jonesedem>/linux-security-auditor.git
cd linux-security-auditor
sudo python3 auditor.py
```
