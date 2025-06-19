# System Security

## 📋 Table of Contents
- [Operating System Security](#operating-system-security)
- [Windows Security](#windows-security)
- [Linux Security](#linux-security)
- [macOS Security](#macos-security)
- [Endpoint Protection](#endpoint-protection)
- [System Hardening](#system-hardening)
- [Practical Laboratories](#practical-laboratories)

---

## 🖥️ Operating System Security

### 📋 Basic Concepts

#### **1. Security Models**
```
┌─────────────────────────────────────────────────────────┐
│                    Security Models                      │
├─────────────────────────────────────────────────────────┤
│ • Discretionary Access Control (DAC)                   │
│ • Mandatory Access Control (MAC)                       │
│ • Role-Based Access Control (RBAC)                     │
│ • Attribute-Based Access Control (ABAC)                │
└─────────────────────────────────────────────────────────┘
```

#### **2. Privilege Escalation**
- **Horizontal Privilege Escalation**: Access to different user account at same level
- **Vertical Privilege Escalation**: Access to higher privilege level
- **Local Privilege Escalation**: Privilege escalation on local system
- **Remote Privilege Escalation**: Remote privilege escalation

---

## 🪟 Windows Security

### **1. Windows Security Architecture**

#### **Security Subsystem Components**
```powershell
# Windows security components
Get-Service | Where-Object {$_.Name -like "*sec*" -or $_.Name -like "*auth*"}

# Local Security Authority (LSA) information
Get-WmiObject -Class Win32_LogicalDisk | Select-Object DeviceID, FileSystem

# Security Identifier (SID) information
whoami /user
whoami /groups
whoami /priv
```

#### **Access Control Lists (ACL)**
```powershell
# View file/folder permissions
Get-Acl "C:\Windows\System32" | Format-List

# Check registry permissions
Get-Acl "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" | Format-List

# Check service permissions
Get-Service "Spooler" | Get-Acl

# Change permissions (administrator required)
$acl = Get-Acl "C:\temp\test.txt"
$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Users","Read","Allow")
$acl.SetAccessRule($accessRule)
$acl | Set-Acl "C:\temp\test.txt"
```

### **2. Windows Defender and Security Features**

#### **Windows Defender Configuration**
```powershell
# Windows Defender status
Get-MpComputerStatus

# Real-time protection status
Get-MpPreference | Select-Object DisableRealtimeMonitoring

# Scan history
Get-MpThreatDetection

# Exclusion list
Get-MpPreference | Select-Object ExclusionPath, ExclusionProcess

# Start manual scan
Start-MpScan -ScanType QuickScan
Start-MpScan -ScanType FullScan

# Update signatures
Update-MpSignature
```

#### **BitLocker Disk Encryption**
```powershell
# Check BitLocker status
Get-BitLockerVolume

# Enable BitLocker
Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes256 -UsedSpaceOnly

# Create recovery key
Add-BitLockerKeyProtector -MountPoint "C:" -RecoveryPasswordProtector

# TPM status
Get-Tpm
```

### **3. Windows Event Logging**

#### **Security Event Analysis**
```powershell
# Analyze security logs
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} -MaxEvents 10

# Failed login attempts
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} -MaxEvents 10

# Privilege escalation events
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4672} -MaxEvents 10

# Process creation events
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} -MaxEvents 10

# Logon type analysis
$events = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624}
$events | ForEach-Object {
    $xml = [xml]$_.ToXml()
    $logonType = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'LogonType'} | Select-Object -ExpandProperty '#text'
    Write-Host "Logon Type: $logonType - Time: $($_.TimeCreated)"
}
```

#### **Advanced Threat Protection (ATP)**
```powershell
# Windows ATP sensor status
Get-Service -Name "Sense"

# ATP configuration
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection"

# Sysmon installation and configuration
# Sysmon64.exe -accepteula -i sysmonconfig.xml

# Analyze Sysmon logs
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10
```

### **4. Windows Hardening**

#### **Group Policy Security Settings**
```powershell
# Export Local Security Policy
secedit /export /cfg C:\temp\security_policy.inf

# Check password policy
net accounts

# User rights assignment
whoami /priv

# Audit policy
auditpol /get /category:*

# Security options
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LimitBlankPasswordUse"
```

#### **Registry Security Hardening**
```powershell
# UAC settings
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA"

# Remote Desktop security
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections"

# SMB security
Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol, EnableSMB2Protocol

# PowerShell execution policy
Get-ExecutionPolicy -List

# Disable Windows Script Host
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -Value 0
```

---

## 🐧 Linux Security

### **1. Linux Security Architecture**

#### **User and Group Management**
```bash
#!/bin/bash
# Linux user and group management

# User information
id
whoami
groups

# System users
cat /etc/passwd | grep -E ":(0|1000):"

# Sudo privileged users
sudo -l
cat /etc/sudoers

# Last login information
last
lastlog

# Active users
w
who

# Failed login attempts
sudo grep "Failed password" /var/log/auth.log | tail -10
```

#### **File Permissions and ACL**
```bash
# Basic file permissions
ls -la /etc/passwd
ls -la /etc/shadow
ls -la /etc/sudoers

# Find SUID/SGID files
find / -type f \( -perm -4000 -o -perm -2000 \) -exec ls -la {} \; 2>/dev/null

# World-writable files
find / -type f -perm -002 -exec ls -la {} \; 2>/dev/null

# Extended ACL usage
# Install ACL package: sudo apt-get install acl
getfacl /path/to/file
setfacl -m u:username:rwx /path/to/file
setfacl -m g:groupname:rx /path/to/file

# SELinux context (RHEL/CentOS)
ls -Z /etc/passwd
getenforce
sestatus
```

### **2. Linux System Hardening**

#### **Kernel Security Parameters**
```bash
# /etc/sysctl.conf security settings
cat << 'EOF' | sudo tee -a /etc/sysctl.conf
# IP Spoofing protection
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.rp_filter = 1

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Ignore send redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Disable source packet routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Log Martians
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Ignore ICMP ping requests
net.ipv4.icmp_echo_ignore_all = 1

# Ignore Directed pings
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Disable IPv6 if not needed
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1

# Enable ExecShield
kernel.exec-shield = 1
kernel.randomize_va_space = 2
EOF

# Apply settings
sudo sysctl -p
```

#### **SSH Hardening**
```bash
# /etc/ssh/sshd_config security settings
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

cat << 'EOF' | sudo tee /etc/ssh/sshd_config
# SSH Hardening Configuration
Port 2222
Protocol 2

# Authentication
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey

# Disable empty passwords
PermitEmptyPasswords no

# Disable X11 forwarding
X11Forwarding no

# Disable agent forwarding
AllowAgentForwarding no

# Disable TCP forwarding
AllowTcpForwarding no

# Disable tunnel
PermitTunnel no

# Login grace time
LoginGraceTime 30

# Max auth tries
MaxAuthTries 3

# Max sessions
MaxSessions 2

# Client alive interval
ClientAliveInterval 300
ClientAliveCountMax 2

# Allowed users/groups
AllowUsers admin
AllowGroups ssh-users

# Banner
Banner /etc/ssh/banner

# Logging
SyslogFacility AUTH
LogLevel VERBOSE

# Ciphers and algorithms
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
EOF

# Restart SSH service
sudo systemctl restart sshd

# Create SSH key
ssh-keygen -t ed25519 -b 4096 -f ~/.ssh/id_ed25519 -N ""

# Copy public key to remote server
ssh-copy-id -i ~/.ssh/id_ed25519.pub user@remote-server
```

### **3. Linux Monitoring and Logging**

#### **System Monitoring**
```bash
#!/bin/bash
# Linux system monitoring script

# Process monitoring
ps aux --sort=-%cpu | head -10
ps aux --sort=-%mem | head -10

# Network connections
netstat -tulpn
ss -tulpn

# Open files
lsof -i
lsof +D /var/log

# System calls monitoring
# strace -p PID

# File system monitoring
df -h
du -sh /var/log/*

# Login monitoring
who
w
last | head -10

# Failed login attempts
sudo grep "Failed password" /var/log/auth.log | tail -10
sudo grep "Invalid user" /var/log/auth.log | tail -10

# Sudo usage
sudo grep "sudo:" /var/log/auth.log | tail -10

# System resource usage
top -b -n 1 | head -20
free -h
uptime
```

#### **Log Analysis**
```bash
# Important log files
tail -f /var/log/syslog
tail -f /var/log/auth.log
tail -f /var/log/kern.log
tail -f /var/log/messages  # RHEL/CentOS

# Journalctl usage (systemd)
journalctl -f
journalctl -u ssh.service
journalctl --since "2024-01-01" --until "2024-01-02"
journalctl -p err

# Log rotation control
cat /etc/logrotate.conf
ls -la /etc/logrotate.d/

# Rsyslog configuration
cat /etc/rsyslog.conf
sudo systemctl status rsyslog
```

### **4. Linux Security Tools**

#### **Intrusion Detection**
```bash
# AIDE (Advanced Intrusion Detection Environment) installation
sudo apt-get install aide

# Create AIDE database
sudo aideinit
sudo cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# System check
sudo aide --check

# Tripwire alternative - OSSEC installation
wget https://github.com/ossec/ossec-hids/archive/3.7.0.tar.gz
tar -xzf 3.7.0.tar.gz
cd ossec-hids-3.7.0
sudo ./install.sh
```

#### **Rootkit Detection**
```bash
# rkhunter installation and usage
sudo apt-get install rkhunter
sudo rkhunter --update
sudo rkhunter --check

# chkrootkit installation and usage
sudo apt-get install chkrootkit
sudo chkrootkit

# Malware detection - ClamAV
sudo apt-get install clamav clamav-daemon
sudo freshclam
sudo clamscan -r /home
```

---

## 🍎 macOS Security

### **1. macOS Security Features**

#### **System Integrity Protection (SIP)**
```bash
# Check SIP status
csrutil status

# Gatekeeper status
spctl --status

# XProtect (built-in antivirus) information
system_profiler SPInstallHistoryDataType | grep -i xprotect

# Firewall status
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate

# FileVault status
fdesetup status
```

#### **Code Signing and Notarization**
```bash
# Application signature check
codesign -dv --verbose=4 /Applications/Safari.app

# Notarization check
spctl -a -vv /Applications/SomeApp.app

# Quarantine attribute check
xattr -l /path/to/downloaded/file

# Remove quarantine
xattr -d com.apple.quarantine /path/to/file
```

### **2. macOS Monitoring**

#### **System Logs**
```bash
# Console log monitoring
log stream --predicate 'process == "sshd"'
log show --predicate 'eventMessage contains "error"' --last 1h

# Security events
log show --predicate 'subsystem == "com.apple.securityd"' --last 1h

# Network events
log show --predicate 'process == "networkd"' --last 1h

# Authentication events
log show --predicate 'category == "auth"' --last 1h
```

---

## 🛡️ Endpoint Protection

### **1. Antivirus/Anti-malware Solutions**

#### **Enterprise Endpoint Protection**
```python
# Python script for endpoint security monitoring
import psutil
import hashlib
import os
import json
from datetime import datetime

class EndpointMonitor:
    def __init__(self):
        self.suspicious_processes = [
            'nc.exe', 'netcat.exe', 'ncat.exe',
            'powershell.exe', 'cmd.exe', 'wscript.exe',
            'cscript.exe', 'mshta.exe', 'rundll32.exe'
        ]
        self.suspicious_network_ports = [4444, 5555, 6666, 8080, 9999]
    
    def monitor_processes(self):
        """Monitor suspicious processes"""
        suspicious_found = []
        
        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'create_time']):
            try:
                proc_name = proc.info['name'].lower()
                
                # Check suspicious process names
                if any(susp in proc_name for susp in self.suspicious_processes):
                    suspicious_found.append({
                        'pid': proc.info['pid'],
                        'name': proc.info['name'],
                        'cmdline': ' '.join(proc.info['cmdline']) if proc.info['cmdline'] else '',
                        'create_time': datetime.fromtimestamp(proc.info['create_time']).isoformat(),
                        'risk_level': 'HIGH'
                    })
                
                # Unusual parent-child relationships
                if proc_name == 'powershell.exe':
                    try:
                        parent = proc.parent()
                        if parent and parent.name().lower() in ['winword.exe', 'excel.exe', 'outlook.exe']:
                            suspicious_found.append({
                                'pid': proc.info['pid'],
                                'name': proc.info['name'],
                                'parent': parent.name(),
                                'risk_level': 'CRITICAL',
                                'reason': 'Office application spawning PowerShell'
                            })
                    except psutil.NoSuchProcess:
                        pass
                        
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        return suspicious_found
    
    def monitor_network_connections(self):
        """Monitor suspicious network connections"""
        suspicious_connections = []
        
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == psutil.CONN_ESTABLISHED:
                # Check suspicious ports
                if conn.laddr.port in self.suspicious_network_ports or \
                   (conn.raddr and conn.raddr.port in self.suspicious_network_ports):
                    
                    try:
                        proc = psutil.Process(conn.pid)
                        suspicious_connections.append({
                            'pid': conn.pid,
                            'process': proc.name(),
                            'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}",
                            'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else 'N/A',
                            'status': conn.status,
                            'risk_level': 'HIGH'
                        })
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
        
        return suspicious_connections
    
    def file_integrity_check(self, file_paths):
        """File integrity check"""
        integrity_results = []
        
        for file_path in file_paths:
            if os.path.exists(file_path):
                with open(file_path, 'rb') as f:
                    file_hash = hashlib.sha256(f.read()).hexdigest()
                
                integrity_results.append({
                    'file_path': file_path,
                    'hash': file_hash,
                    'timestamp': datetime.now().isoformat(),
                    'size': os.path.getsize(file_path)
                })
        
        return integrity_results
    
    def generate_report(self):
        """Generate security report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'hostname': os.environ.get('COMPUTERNAME', 'Unknown'),
            'suspicious_processes': self.monitor_processes(),
            'suspicious_connections': self.monitor_network_connections(),
            'system_info': {
                'cpu_percent': psutil.cpu_percent(),
                'memory_percent': psutil.virtual_memory().percent,
                'disk_usage': psutil.disk_usage('/').percent,
                'boot_time': datetime.fromtimestamp(psutil.boot_time()).isoformat()
            }
        }
        
        return report

# Usage
if __name__ == "__main__":
    monitor = EndpointMonitor()
    report = monitor.generate_report()
    
    # Save report in JSON format
    with open(f"endpoint_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json", 'w') as f:
        json.dump(report, f, indent=2)
    
    # Print critical situations to screen
    if report['suspicious_processes']:
        print("🚨 SUSPICIOUS PROCESSES DETECTED:")
        for proc in report['suspicious_processes']:
            print(f"  - {proc['name']} (PID: {proc['pid']}) - Risk: {proc['risk_level']}")
    
    if report['suspicious_connections']:
        print("🚨 SUSPICIOUS NETWORK CONNECTIONS:")
        for conn in report['suspicious_connections']:
            print(f"  - {conn['process']} -> {conn['remote_addr']} - Risk: {conn['risk_level']}")
```

### **2. Host-based Intrusion Detection (HIDS)**

#### **OSSEC Configuration**
```xml
<!-- /var/ossec/etc/ossec.conf -->
<ossec_config>
  <global>
    <email_notification>yes</email_notification>
    <email_to>admin@company.com</email_to>
    <smtp_server>localhost</smtp_server>
    <email_from>ossec@company.com</email_from>
  </global>

  <rules>
    <include>rules_config.xml</include>
    <include>pam_rules.xml</include>
    <include>sshd_rules.xml</include>
    <include>telnetd_rules.xml</include>
    <include>syslog_rules.xml</include>
    <include>arpwatch_rules.xml</include>
    <include>symantec-av_rules.xml</include>
    <include>symantec-ws_rules.xml</include>
    <include>pix_rules.xml</include>
    <include>named_rules.xml</include>
    <include>smbd_rules.xml</include>
    <include>vsftpd_rules.xml</include>
    <include>pure-ftpd_rules.xml</include>
    <include>proftpd_rules.xml</include>
    <include>ms_ftpd_rules.xml</include>
    <include>ftpd_rules.xml</include>
    <include>hordeimp_rules.xml</include>
    <include>roundcube_rules.xml</include>
    <include>wordpress_rules.xml</include>
    <include>cimserver_rules.xml</include>
    <include>vpopmail_rules.xml</include>
    <include>vmpop3d_rules.xml</include>
    <include>courier_rules.xml</include>
    <include>web_rules.xml</include>
    <include>web_appsec_rules.xml</include>
    <include>apache_rules.xml</include>
    <include>nginx_rules.xml</include>
    <include>php_rules.xml</include>
    <include>mysql_rules.xml</include>
    <include>postgresql_rules.xml</include>
    <include>ids_rules.xml</include>
    <include>squid_rules.xml</include>
    <include>firewall_rules.xml</include>
    <include>cisco-ios_rules.xml</include>
    <include>netscreenfw_rules.xml</include>
    <include>sonicwall_rules.xml</include>
    <include>postfix_rules.xml</include>
    <include>sendmail_rules.xml</include>
    <include>imapd_rules.xml</include>
    <include>mailscanner_rules.xml</include>
    <include>dovecot_rules.xml</include>
    <include>ms-exchange_rules.xml</include>
    <include>racoon_rules.xml</include>
    <include>vpn_concentrator_rules.xml</include>
    <include>spamd_rules.xml</include>
    <include>msauth_rules.xml</include>
    <include>mcafee_av_rules.xml</include>
    <include>trend-osce_rules.xml</include>
    <include>ms-se_rules.xml</include>
    <include>zeus_rules.xml</include>
    <include>solaris_bsm_rules.xml</include>
    <include>vmware_rules.xml</include>
    <include>ms_dhcp_rules.xml</include>
    <include>asterisk_rules.xml</include>
    <include>ossec_rules.xml</include>
    <include>attack_rules.xml</include>
    <include>local_rules.xml</include>
  </rules>

  <syscheck>
    <!-- Frequency that syscheck is executed -- default every 22 hours -->
    <frequency>79200</frequency>
    
    <!-- Directories to check  (perform all possible verifications) -->
    <directories check_all="yes">/etc,/usr/bin,/usr/sbin</directories>
    <directories check_all="yes">/bin,/sbin,/boot</directories>
    
    <!-- Files/directories to ignore -->
    <ignore>/etc/mtab</ignore>
    <ignore>/etc/hosts.deny</ignore>
    <ignore>/etc/mail/statistics</ignore>
    <ignore>/etc/random-seed</ignore>
    <ignore>/etc/random.seed</ignore>
    <ignore>/etc/adjtime</ignore>
    <ignore>/etc/httpd/logs</ignore>
    <ignore>/etc/utmpx</ignore>
    <ignore>/etc/wtmpx</ignore>
    <ignore>/etc/cups/certs</ignore>
    <ignore>/etc/dumpdates</ignore>
    <ignore>/etc/svc/volatile</ignore>
  </syscheck>

  <rootcheck>
    <rootkit_files>/var/ossec/etc/shared/rootkit_files.txt</rootkit_files>
    <rootkit_trojans>/var/ossec/etc/shared/rootkit_trojans.txt</rootkit_trojans>
    <system_audit>/var/ossec/etc/shared/system_audit_rcl.txt</system_audit>
    <system_audit>/var/ossec/etc/shared/cis_debian_linux_rcl.txt</system_audit>
    <system_audit>/var/ossec/etc/shared/cis_rhel_linux_rcl.txt</system_audit>
    <system_audit>/var/ossec/etc/shared/cis_rhel5_linux_rcl.txt</system_audit>
  </rootcheck>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/messages</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/authlog</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/secure</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/xferlog</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/maillog</location>
  </localfile>

  <localfile>
    <log_format>apache</log_format>
    <location>/var/log/httpd/error_log</location>
  </localfile>

  <localfile>
    <log_format>apache</log_format>
    <location>/var/log/httpd/access_log</location>
  </localfile>

  <localfile>
    <log_format>apache</log_format>
    <location>/var/log/apache2/error.log</location>
  </localfile>

  <localfile>
    <log_format>apache</log_format>
    <location>/var/log/apache2/access.log</location>
  </localfile>
</ossec_config>
```

---

## 🔒 System Hardening

### **1. General Hardening Principles**

#### **Defense in Depth Strategy**
```
┌─────────────────────────────────────────────────────────┐
│                  Defense in Depth                      │
├─────────────────────────────────────────────────────────┤
│ 1. Physical Security                                    │
│ 2. Network Security (Firewalls, IDS/IPS)              │
│ 3. Host Security (OS Hardening, Antivirus)            │
│ 4. Application Security (Input Validation, WAF)        │
│ 5. Data Security (Encryption, Access Control)          │
│ 6. User Education and Awareness                        │
└─────────────────────────────────────────────────────────┘
```

### **2. Automated Hardening Scripts**

#### **Linux Hardening Script**
```bash
#!/bin/bash
# Linux System Hardening Script

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   error "This script must be run as root"
fi

# Backup important files
backup_files() {
    log "Creating backups..."
    
    BACKUP_DIR="/root/hardening_backup_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$BACKUP_DIR"
    
    # Backup critical configuration files
    cp /etc/ssh/sshd_config "$BACKUP_DIR/"
    cp /etc/sysctl.conf "$BACKUP_DIR/"
    cp /etc/login.defs "$BACKUP_DIR/"
    cp /etc/pam.d/common-password "$BACKUP_DIR/" 2>/dev/null || true
    cp /etc/security/limits.conf "$BACKUP_DIR/"
    
    log "Backups created in $BACKUP_DIR"
}

# Update system
update_system() {
    log "Updating system packages..."
    
    if command -v apt-get &> /dev/null; then
        apt-get update && apt-get upgrade -y
        apt-get autoremove -y
    elif command -v yum &> /dev/null; then
        yum update -y
    elif command -v dnf &> /dev/null; then
        dnf update -y
    else
        warn "Package manager not recognized"
    fi
}

# Configure automatic updates
setup_automatic_updates() {
    log "Setting up automatic security updates..."
    
    if command -v apt-get &> /dev/null; then
        apt-get install -y unattended-upgrades
        
        cat << 'EOF' > /etc/apt/apt.conf.d/50unattended-upgrades
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};

Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF
        
        systemctl enable unattended-upgrades
        systemctl start unattended-upgrades
    fi
}

# Disable unnecessary services
disable_services() {
    log "Disabling unnecessary services..."
    
    SERVICES_TO_DISABLE=(
        "telnet"
        "rsh"
        "rlogin"
        "vsftpd"
        "httpd"
        "nginx"
        "apache2"
        "sendmail"
        "postfix"
        "dovecot"
        "cups"
        "avahi-daemon"
        "bluetooth"
    )
    
    for service in "${SERVICES_TO_DISABLE[@]}"; do
        if systemctl is-enabled "$service" &>/dev/null; then
            systemctl disable "$service"
            systemctl stop "$service"
            info "Disabled service: $service"
        fi
    done
}

# Configure firewall
setup_firewall() {
    log "Configuring firewall..."
    
    if command -v ufw &> /dev/null; then
        # UFW (Ubuntu)
        ufw --force reset
        ufw default deny incoming
        ufw default allow outgoing
        ufw allow ssh
        ufw --force enable
        
    elif command -v firewall-cmd &> /dev/null; then
        # FirewallD (RHEL/CentOS)
        systemctl enable firewalld
        systemctl start firewalld
        firewall-cmd --set-default-zone=drop
        firewall-cmd --zone=drop --add-service=ssh --permanent
        firewall-cmd --reload
        
    else
        # iptables fallback
        iptables -F
        iptables -P INPUT DROP
        iptables -P FORWARD DROP
        iptables -P OUTPUT ACCEPT
        iptables -A INPUT -i lo -j ACCEPT
        iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
        iptables -A INPUT -p tcp --dport 22 -j ACCEPT
        
        # Save iptables rules
        if command -v iptables-save &> /dev/null; then
            iptables-save > /etc/iptables/rules.v4
        fi
    fi
}

# Harden SSH configuration
harden_ssh() {
    log "Hardening SSH configuration..."
    
    cat << 'EOF' > /etc/ssh/sshd_config
# SSH Hardening Configuration
Port 2222
Protocol 2

# Authentication
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey

# Disable empty passwords
PermitEmptyPasswords no

# Disable X11 forwarding
X11Forwarding no

# Disable agent forwarding
AllowAgentForwarding no

# Disable TCP forwarding
AllowTcpForwarding no

# Disable tunnel
PermitTunnel no

# Login grace time
LoginGraceTime 30

# Max auth tries
MaxAuthTries 3

# Max sessions
MaxSessions 2

# Client alive interval
ClientAliveInterval 300
ClientAliveCountMax 2

# Logging
SyslogFacility AUTH
LogLevel VERBOSE

# Ciphers and algorithms
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
EOF
    
    # Test SSH configuration
    if sshd -t; then
        systemctl restart sshd
        log "SSH configuration updated successfully"
    else
        error "SSH configuration test failed"
    fi
}

# Configure kernel parameters
harden_kernel() {
    log "Hardening kernel parameters..."
    
    cat << 'EOF' >> /etc/sysctl.conf

# Security hardening parameters
# IP Spoofing protection
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.rp_filter = 1

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Ignore send redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Disable source packet routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Log Martians
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Ignore ICMP ping requests
net.ipv4.icmp_echo_ignore_all = 1

# Ignore Directed pings
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Enable ExecShield
kernel.exec-shield = 1
kernel.randomize_va_space = 2

# Controls the System Request debugging functionality of the kernel
kernel.sysrq = 0

# Controls whether core dumps will append the PID to the core filename
kernel.core_uses_pid = 1

# Restrict access to kernel logs
kernel.dmesg_restrict = 1

# Restrict access to kernel pointers
kernel.kptr_restrict = 2
EOF
    
    sysctl -p
}

# Set password policies
set_password_policy() {
    log "Setting password policies..."
    
    # Install libpam-pwquality if available
    if command -v apt-get &> /dev/null; then
        apt-get install -y libpam-pwquality
    elif command -v yum &> /dev/null; then
        yum install -y libpwquality
    fi
    
    # Configure password quality
    cat << 'EOF' > /etc/security/pwquality.conf
# Password quality configuration
minlen = 12
minclass = 3
maxrepeat = 2
maxclassrepeat = 2
lcredit = -1
ucredit = -1
dcredit = -1
ocredit = -1
difok = 8
reject_username
enforce_for_root
EOF
    
    # Configure login.defs
    sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' /etc/login.defs
    sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 1/' /etc/login.defs
    sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE 7/' /etc/login.defs
    sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN 12/' /etc/login.defs
}

# Configure file permissions
set_file_permissions() {
    log "Setting secure file permissions..."
    
    # Secure important files
    chmod 600 /etc/ssh/sshd_config
    chmod 600 /etc/shadow
    chmod 600 /etc/gshadow
    chmod 644 /etc/passwd
    chmod 644 /etc/group
    
    # Remove world-writable permissions from system directories
    find /etc -type f -perm -002 -exec chmod o-w {} \;
    find /usr -type f -perm -002 -exec chmod o-w {} \;
    find /var -type f -perm -002 -exec chmod o-w {} \;
    
    # Set sticky bit on /tmp
    chmod 1777 /tmp
    chmod 1777 /var/tmp
}

# Install and configure fail2ban
setup_fail2ban() {
    log "Installing and configuring fail2ban..."
    
    if command -v apt-get &> /dev/null; then
        apt-get install -y fail2ban
    elif command -v yum &> /dev/null; then
        yum install -y epel-release
        yum install -y fail2ban
    fi
    
    cat << 'EOF' > /etc/fail2ban/jail.local
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
backend = systemd

[sshd]
enabled = true
port = 2222
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600

[apache-auth]
enabled = false

[apache-badbots]
enabled = false

[apache-noscript]
enabled = false

[apache-overflows]
enabled = false
EOF
    
    systemctl enable fail2ban
    systemctl start fail2ban
}

# Configure audit logging
setup_auditd() {
    log "Setting up audit logging..."
    
    if command -v apt-get &> /dev/null; then
        apt-get install -y auditd audispd-plugins
    elif command -v yum &> /dev/null; then
        yum install -y audit
    fi
    
    cat << 'EOF' > /etc/audit/rules.d/hardening.rules
# Audit rules for security monitoring

# Monitor authentication events
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k identity

# Monitor system configuration changes
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /etc/sysctl.conf -p wa -k sysctl

# Monitor privilege escalation
-a always,exit -F arch=b64 -S setuid -S setgid -S setreuid -S setregid -k privilege_escalation
-a always,exit -F arch=b32 -S setuid -S setgid -S setreuid -S setregid -k privilege_escalation

# Monitor file access
-a always,exit -F arch=b64 -S open -S openat -S creat -S truncate -S ftruncate -F exit=-EACCES -k file_access
-a always,exit -F arch=b64 -S open -S openat -S creat -S truncate -S ftruncate -F exit=-EPERM -k file_access

# Monitor network connections
-a always,exit -F arch=b64 -S socket -S connect -S accept -S bind -S listen -k network

# Make the configuration immutable
-e 2
EOF
    
    systemctl enable auditd
    systemctl start auditd
}

# Main execution
main() {
    log "Starting Linux system hardening..."
    
    backup_files
    update_system
    setup_automatic_updates
    disable_services
    setup_firewall
    harden_ssh
    harden_kernel
    set_password_policy
    set_file_permissions
    setup_fail2ban
    setup_auditd
    
    log "System hardening completed successfully!"
    warn "Please reboot the system to ensure all changes take effect."
    warn "SSH port has been changed to 2222. Update your firewall rules accordingly."
}

# Run main function
main "$@"
```

---

## 🧪 Practical Laboratories

### **Lab 1: Windows Security Assessment**
```powershell
# Windows security assessment script

# System information
Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion, TotalPhysicalMemory

# User account analysis
Get-LocalUser | Where-Object {$_.Enabled -eq $true}
Get-LocalGroupMember -Group "Administrators"

# Service analysis
Get-Service | Where-Object {$_.Status -eq "Running" -and $_.StartType -eq "Automatic"}

# Network connections
Get-NetTCPConnection | Where-Object {$_.State -eq "Listen"}

# Security logs
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} -MaxEvents 10

# Installed software
Get-WmiObject -Class Win32_Product | Select-Object Name, Version

# Firewall status
Get-NetFirewallProfile

# Windows Defender status
Get-MpComputerStatus
```

### **Lab 2: Linux Security Audit**
```bash
#!/bin/bash
# Linux security audit script

echo "=== Linux Security Audit ==="
echo "Date: $(date)"
echo "Hostname: $(hostname)"
echo "Kernel: $(uname -r)"
echo

# User accounts
echo "=== User Accounts ==="
cat /etc/passwd | grep -E ":(0|1000):"
echo

# Sudo privileged users
echo "=== Sudo Users ==="
grep -E "^%sudo|^%wheel" /etc/group
echo

# SUID/SGID files
echo "=== SUID/SGID Files ==="
find / -type f \( -perm -4000 -o -perm -2000 \) -exec ls -la {} \; 2>/dev/null | head -10
echo

# Open ports
echo "=== Open Ports ==="
netstat -tulpn | grep LISTEN
echo

# Running services
echo "=== Running Services ==="
systemctl list-units --type=service --state=running | head -10
echo

# Recent login information
echo "=== Recent Logins ==="
last | head -10
echo

# Failed login attempts
echo "=== Failed Login Attempts ==="
grep "Failed password" /var/log/auth.log 2>/dev/null | tail -5
echo

# Disk usage
echo "=== Disk Usage ==="
df -h
echo

# System load
echo "=== System Load ==="
uptime
free -h
echo
```

### **Lab 3: Vulnerability Assessment**
```python
# Python vulnerability scanner
import socket
import subprocess
import sys
import threading
from datetime import datetime

class VulnerabilityScanner:
    def __init__(self, target):
        self.target = target
        self.open_ports = []
        self.vulnerabilities = []
    
    def port_scan(self, port):
        """Port scanning function"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target, port))
            if result == 0:
                self.open_ports.append(port)
                print(f"Port {port}: Open")
            sock.close()
        except socket.gaierror:
            pass
    
    def scan_common_ports(self):
        """Scan common ports"""
        common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080]
        
        print(f"Scanning {self.target} for open ports...")
        threads = []
        
        for port in common_ports:
            thread = threading.Thread(target=self.port_scan, args=(port,))
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()
    
    def check_ssh_vulnerabilities(self):
        """Check SSH vulnerabilities"""
        if 22 in self.open_ports:
            print("\nChecking SSH vulnerabilities...")
            
            # SSH banner grabbing
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((self.target, 22))
                banner = sock.recv(1024).decode().strip()
                print(f"SSH Banner: {banner}")
                
                # Check for known vulnerable versions
                vulnerable_versions = ['OpenSSH_7.4', 'OpenSSH_6.6', 'OpenSSH_5.3']
                for vuln_version in vulnerable_versions:
                    if vuln_version in banner:
                        self.vulnerabilities.append(f"Vulnerable SSH version detected: {banner}")
                
                sock.close()
            except Exception as e:
                print(f"SSH check failed: {e}")
    
    def check_web_vulnerabilities(self):
        """Check web vulnerabilities"""
        web_ports = [80, 443, 8080]
        
        for port in web_ports:
            if port in self.open_ports:
                print(f"\nChecking web vulnerabilities on port {port}...")
                
                try:
                    import requests
                    
                    protocol = 'https' if port == 443 else 'http'
                    url = f"{protocol}://{self.target}:{port}"
                    
                    response = requests.get(url, timeout=5, verify=False)
                    
                    # Check server header
                    server = response.headers.get('Server', '')
                    if server:
                        print(f"Web Server: {server}")
                        
                        # Check for known vulnerable servers
                        if 'Apache/2.2' in server or 'nginx/1.0' in server:
                            self.vulnerabilities.append(f"Potentially vulnerable web server: {server}")
                    
                    # Check for common security headers
                    security_headers = [
                        'X-Frame-Options',
                        'X-XSS-Protection',
                        'X-Content-Type-Options',
                        'Strict-Transport-Security'
                    ]
                    
                    missing_headers = []
                    for header in security_headers:
                        if header not in response.headers:
                            missing_headers.append(header)
                    
                    if missing_headers:
                        self.vulnerabilities.append(f"Missing security headers: {', '.join(missing_headers)}")
                
                except ImportError:
                    print("requests module not available for web scanning")
                except Exception as e:
                    print(f"Web check failed: {e}")
    
    def generate_report(self):
        """Generate report"""
        print("\n" + "="*50)
        print("VULNERABILITY ASSESSMENT REPORT")
        print("="*50)
        print(f"Target: {self.target}")
        print(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Open Ports: {', '.join(map(str, self.open_ports)) if self.open_ports else 'None'}")
        
        if self.vulnerabilities:
            print("\nVULNERABILITIES FOUND:")
            for i, vuln in enumerate(self.vulnerabilities, 1):
                print(f"{i}. {vuln}")
        else:
            print("\nNo obvious vulnerabilities detected.")
        
        print("\nRECOMMENDATIONS:")
        print("1. Keep all software updated")
        print("2. Use strong passwords and enable 2FA")
        print("3. Close unnecessary ports")
        print("4. Implement proper firewall rules")
        print("5. Regular security audits")
    
    def run_scan(self):
        """Run full scan"""
        self.scan_common_ports()
        self.check_ssh_vulnerabilities()
        self.check_web_vulnerabilities()
        self.generate_report()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 vuln_scanner.py <target_ip>")
        sys.exit(1)
    
    target = sys.argv[1]
    scanner = VulnerabilityScanner(target)
    scanner.run_scan()
```

### **Lab 4: Incident Response Simulation**
```bash
#!/bin/bash
# Incident response simulation script

echo "=== INCIDENT RESPONSE SIMULATION ==="
echo "Simulating a security incident..."

# Create suspicious files
mkdir -p /tmp/incident_sim
echo "This is a suspicious file" > /tmp/incident_sim/malware.txt
echo "#!/bin/bash\necho 'Backdoor activated'" > /tmp/incident_sim/backdoor.sh
chmod +x /tmp/incident_sim/backdoor.sh

# Simulate network connections
nc -l 4444 &
NC_PID=$!

echo "Incident artifacts created. Starting investigation..."

# Evidence collection
echo "1. Collecting system information..."
date > /tmp/incident_report.txt
hostname >> /tmp/incident_report.txt
uname -a >> /tmp/incident_report.txt

echo "2. Collecting process information..."
ps aux >> /tmp/incident_report.txt

echo "3. Collecting network information..."
netstat -tulpn >> /tmp/incident_report.txt

echo "4. Collecting file system information..."
find /tmp/incident_sim -type f -exec ls -la {} \; >> /tmp/incident_report.txt

echo "5. Collecting log information..."
tail -50 /var/log/syslog >> /tmp/incident_report.txt 2>/dev/null

# Cleanup
kill $NC_PID 2>/dev/null
rm -rf /tmp/incident_sim

echo "Incident response simulation completed."
echo "Report saved to /tmp/incident_report.txt"
```

---

## 📚 Additional Resources

### **Books**
- "Windows Internals" - Mark Russinovich
- "Linux Security Cookbook" - Daniel J. Barrett
- "Hacking: The Art of Exploitation" - Jon Erickson
- "The Practice of Network Security Monitoring" - Richard Bejtlich
- "Applied Cryptography" - Bruce Schneier

### **Online Resources**
- NIST Cybersecurity Framework
- CIS Controls (Center for Internet Security)
- OWASP Security Guidelines
- SANS Institute Resources
- CVE Database (Common Vulnerabilities and Exposures)

### **Tools and Platforms**
- **Vulnerability Scanners**: Nessus, OpenVAS, Qualys
- **Network Security**: Wireshark, Nmap, Metasploit
- **System Monitoring**: Nagios, Zabbix, PRTG
- **Log Analysis**: ELK Stack, Splunk, Graylog
- **Penetration Testing**: Kali Linux, Parrot OS

---

## 🎯 Level 1 Completion Criteria

### **Theoretical Knowledge**
- [ ] Understanding of operating system security models
- [ ] Knowledge of Windows, Linux, and macOS security features
- [ ] Familiarity with access control mechanisms
- [ ] Understanding of system hardening principles

### **Practical Skills**
- [ ] Ability to configure basic security settings on different OS
- [ ] Experience with system monitoring and log analysis
- [ ] Knowledge of firewall configuration
- [ ] Basic incident response procedures

### **Tool Usage**
- [ ] Proficiency with command-line security tools
- [ ] Experience with vulnerability scanners
- [ ] Familiarity with system hardening scripts
- [ ] Basic penetration testing skills

### **Project Suggestion**
**"Multi-Platform Security Assessment"**

Create a comprehensive security assessment project that includes:

1. **Environment Setup**
   - Set up virtual machines with Windows, Linux, and macOS
   - Configure basic network infrastructure
   - Install monitoring and security tools

2. **Security Assessment**
   - Perform vulnerability scans on all systems
   - Analyze security configurations
   - Document findings and recommendations

3. **Hardening Implementation**
   - Apply security hardening measures
   - Configure monitoring and logging
   - Implement access controls

4. **Incident Response**
   - Simulate security incidents
   - Practice evidence collection
   - Create incident response documentation

5. **Documentation**
   - Create detailed security policies
   - Document procedures and configurations
   - Prepare executive summary report

**Deliverables:**
- Security assessment report
- Hardening implementation guide
- Incident response playbook
- Executive presentation

---

## 📝 Notes

- Always test security configurations in a lab environment first
- Keep security tools and signatures updated
- Document all changes and configurations
- Regular security assessments are essential
- Stay informed about latest security threats and vulnerabilities

---

**Next Level:** [Network Security](../level-2/network-security.md)

**Previous Level:** [Introduction to Cybersecurity](../level-0/introduction.md)