#!/usr/bin/env python3
"""
Endpoint Security Monitor
Author: ibrahimsql
Description: Endpoint güvenlik izleme ve şüpheli aktivite tespit sistemi
"""

import psutil
import hashlib
import os
import json
from datetime import datetime
import logging
import time
import threading
from typing import List, Dict, Optional

class EndpointMonitor:
    def __init__(self):
        self.suspicious_processes = [
            'nc.exe', 'netcat.exe', 'ncat.exe',
            'powershell.exe', 'cmd.exe', 'wscript.exe',
            'cscript.exe', 'mshta.exe', 'rundll32.exe'
        ]
        self.suspicious_network_ports = [4444, 5555, 6666, 8080, 9999]
        self.logger = self._setup_logging()
        self.baseline_hashes = {}
        self.monitoring = False
        
    def _setup_logging(self) -> logging.Logger:
        """Logging sistemini kur"""
        logger = logging.getLogger('EndpointMonitor')
        logger.setLevel(logging.INFO)
        
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
        # File handler
        file_handler = logging.FileHandler('endpoint_monitor.log')
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        
        return logger
    
    def monitor_processes(self) -> List[Dict]:
        """Şüpheli process'leri izle"""
        suspicious_found = []
        
        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'create_time', 'ppid']):
            try:
                proc_name = proc.info['name'].lower()
                
                # Şüpheli process isimleri kontrol et
                if any(susp in proc_name for susp in self.suspicious_processes):
                    suspicious_found.append({
                        'pid': proc.info['pid'],
                        'name': proc.info['name'],
                        'cmdline': ' '.join(proc.info['cmdline']) if proc.info['cmdline'] else '',
                        'create_time': datetime.fromtimestamp(proc.info['create_time']).isoformat(),
                        'ppid': proc.info['ppid'],
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
                
                # Process injection detection
                if self._detect_process_injection(proc):
                    suspicious_found.append({
                        'pid': proc.info['pid'],
                        'name': proc.info['name'],
                        'risk_level': 'CRITICAL',
                        'reason': 'Possible process injection detected'
                    })
                        
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        return suspicious_found
    
    def _detect_process_injection(self, proc) -> bool:
        """Process injection tespiti"""
        try:
            # Memory usage anomalies
            memory_info = proc.memory_info()
            if memory_info.rss > 500 * 1024 * 1024:  # 500MB'dan fazla
                return True
            
            # Unusual memory regions
            memory_maps = proc.memory_maps()
            for mmap in memory_maps:
                if 'rwx' in mmap.perms:  # Read-Write-Execute permissions
                    return True
                    
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        
        return False
    
    def monitor_network_connections(self) -> List[Dict]:
        """Şüpheli ağ bağlantılarını izle"""
        suspicious_connections = []
        
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == psutil.CONN_ESTABLISHED:
                # Şüpheli portları kontrol et
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
                
                # Outbound connections to suspicious IPs
                if conn.raddr and self._is_suspicious_ip(conn.raddr.ip):
                    try:
                        proc = psutil.Process(conn.pid)
                        suspicious_connections.append({
                            'pid': conn.pid,
                            'process': proc.name(),
                            'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}",
                            'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}",
                            'status': conn.status,
                            'risk_level': 'CRITICAL',
                            'reason': 'Connection to suspicious IP'
                        })
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
        
        return suspicious_connections
    
    def _is_suspicious_ip(self, ip: str) -> bool:
        """Şüpheli IP kontrolü"""
        # Known malicious IP ranges (örnek)
        suspicious_ranges = [
            '10.0.0.0/8',    # Private networks (context dependent)
            '172.16.0.0/12', # Private networks
            '192.168.0.0/16' # Private networks
        ]
        
        # Tor exit nodes, known C2 servers, etc. burada kontrol edilebilir
        known_malicious_ips = [
            '198.51.100.1',  # Example malicious IP
            '203.0.113.1'    # Example malicious IP
        ]
        
        return ip in known_malicious_ips
    
    def file_integrity_check(self, file_paths: List[str]) -> List[Dict]:
        """Dosya bütünlüğü kontrolü"""
        integrity_results = []
        
        for file_path in file_paths:
            if os.path.exists(file_path):
                try:
                    with open(file_path, 'rb') as f:
                        file_hash = hashlib.sha256(f.read()).hexdigest()
                    
                    file_stat = os.stat(file_path)
                    
                    result = {
                        'file_path': file_path,
                        'hash': file_hash,
                        'timestamp': datetime.now().isoformat(),
                        'size': file_stat.st_size,
                        'modified_time': datetime.fromtimestamp(file_stat.st_mtime).isoformat(),
                        'permissions': oct(file_stat.st_mode)[-3:]
                    }
                    
                    # Baseline ile karşılaştır
                    if file_path in self.baseline_hashes:
                        if self.baseline_hashes[file_path] != file_hash:
                            result['status'] = 'MODIFIED'
                            result['risk_level'] = 'MEDIUM'
                        else:
                            result['status'] = 'UNCHANGED'
                    else:
                        result['status'] = 'NEW_FILE'
                        self.baseline_hashes[file_path] = file_hash
                    
                    integrity_results.append(result)
                    
                except (IOError, OSError) as e:
                    integrity_results.append({
                        'file_path': file_path,
                        'error': str(e),
                        'status': 'ERROR'
                    })
        
        return integrity_results
    
    def monitor_registry_changes(self) -> List[Dict]:
        """Windows Registry değişikliklerini izle (Windows için)"""
        registry_changes = []
        
        # Bu fonksiyon Windows'ta winreg modülü ile implement edilebilir
        # Şu an için simulated data
        
        suspicious_registry_keys = [
            r'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
            r'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
            r'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
        ]
        
        # Registry monitoring simülasyonu
        registry_changes.append({
            'key': r'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
            'value_name': 'WindowsUpdate',
            'value_data': r'C:\temp\malware.exe',
            'action': 'CREATED',
            'timestamp': datetime.now().isoformat(),
            'risk_level': 'HIGH'
        })
        
        return registry_changes
    
    def detect_privilege_escalation(self) -> List[Dict]:
        """Privilege escalation tespiti"""
        escalation_attempts = []
        
        for proc in psutil.process_iter(['pid', 'name', 'username']):
            try:
                # SYSTEM veya root olarak çalışan şüpheli process'ler
                if proc.info['username'] in ['SYSTEM', 'root', 'NT AUTHORITY\\SYSTEM']:
                    proc_name = proc.info['name'].lower()
                    if proc_name in ['cmd.exe', 'powershell.exe', 'bash', 'sh']:
                        escalation_attempts.append({
                            'pid': proc.info['pid'],
                            'name': proc.info['name'],
                            'username': proc.info['username'],
                            'risk_level': 'HIGH',
                            'reason': 'Shell running with elevated privileges'
                        })
                        
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        return escalation_attempts
    
    def generate_report(self) -> Dict:
        """Kapsamlı güvenlik raporu oluştur"""
        self.logger.info("Generating security report...")
        
        # Critical system files to monitor
        critical_files = [
            '/etc/passwd',
            '/etc/shadow',
            '/etc/hosts',
            'C:\\Windows\\System32\\drivers\\etc\\hosts',
            'C:\\Windows\\System32\\config\\SAM'
        ]
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'hostname': os.environ.get('COMPUTERNAME', os.uname().nodename),
            'platform': os.name,
            'suspicious_processes': self.monitor_processes(),
            'suspicious_connections': self.monitor_network_connections(),
            'file_integrity': self.file_integrity_check(critical_files),
            'registry_changes': self.monitor_registry_changes(),
            'privilege_escalation': self.detect_privilege_escalation(),
            'system_info': {
                'cpu_percent': psutil.cpu_percent(interval=1),
                'memory_percent': psutil.virtual_memory().percent,
                'disk_usage': psutil.disk_usage('/').percent if os.name != 'nt' else psutil.disk_usage('C:\\').percent,
                'boot_time': datetime.fromtimestamp(psutil.boot_time()).isoformat(),
                'uptime_hours': (time.time() - psutil.boot_time()) / 3600
            },
            'network_stats': {
                'connections_count': len(psutil.net_connections()),
                'bytes_sent': psutil.net_io_counters().bytes_sent,
                'bytes_recv': psutil.net_io_counters().bytes_recv
            }
        }
        
        # Risk assessment
        report['risk_assessment'] = self._calculate_risk_score(report)
        
        return report
    
    def _calculate_risk_score(self, report: Dict) -> Dict:
        """Risk skoru hesapla"""
        risk_score = 0
        risk_factors = []
        
        # Suspicious processes
        critical_procs = len([p for p in report['suspicious_processes'] if p.get('risk_level') == 'CRITICAL'])
        high_procs = len([p for p in report['suspicious_processes'] if p.get('risk_level') == 'HIGH'])
        
        risk_score += critical_procs * 10 + high_procs * 5
        if critical_procs > 0:
            risk_factors.append(f"{critical_procs} critical suspicious processes")
        
        # Network connections
        critical_conns = len([c for c in report['suspicious_connections'] if c.get('risk_level') == 'CRITICAL'])
        high_conns = len([c for c in report['suspicious_connections'] if c.get('risk_level') == 'HIGH'])
        
        risk_score += critical_conns * 8 + high_conns * 4
        if critical_conns > 0:
            risk_factors.append(f"{critical_conns} critical network connections")
        
        # File integrity
        modified_files = len([f for f in report['file_integrity'] if f.get('status') == 'MODIFIED'])
        risk_score += modified_files * 3
        if modified_files > 0:
            risk_factors.append(f"{modified_files} critical files modified")
        
        # Privilege escalation
        escalations = len(report['privilege_escalation'])
        risk_score += escalations * 15
        if escalations > 0:
            risk_factors.append(f"{escalations} privilege escalation attempts")
        
        # Risk level determination
        if risk_score >= 50:
            risk_level = 'CRITICAL'
        elif risk_score >= 25:
            risk_level = 'HIGH'
        elif risk_score >= 10:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'
        
        return {
            'score': risk_score,
            'level': risk_level,
            'factors': risk_factors,
            'recommendation': self._get_recommendation(risk_level)
        }
    
    def _get_recommendation(self, risk_level: str) -> str:
        """Risk seviyesine göre öneri"""
        recommendations = {
            'CRITICAL': 'Immediate action required! Isolate system and investigate.',
            'HIGH': 'Urgent investigation needed. Monitor closely.',
            'MEDIUM': 'Schedule investigation. Increase monitoring.',
            'LOW': 'Continue normal monitoring. Review periodically.'
        }
        return recommendations.get(risk_level, 'Unknown risk level')
    
    def start_continuous_monitoring(self, interval: int = 60):
        """Sürekli izleme başlat"""
        self.monitoring = True
        self.logger.info(f"Starting continuous monitoring with {interval}s interval")
        
        def monitor_loop():
            while self.monitoring:
                try:
                    report = self.generate_report()
                    
                    # High risk durumlarında alert
                    if report['risk_assessment']['level'] in ['HIGH', 'CRITICAL']:
                        self.logger.warning(f"HIGH RISK DETECTED: {report['risk_assessment']['level']}")
                        self._send_alert(report)
                    
                    # Raporu kaydet
                    filename = f"endpoint_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                    with open(filename, 'w') as f:
                        json.dump(report, f, indent=2)
                    
                    time.sleep(interval)
                    
                except Exception as e:
                    self.logger.error(f"Monitoring error: {e}")
                    time.sleep(interval)
        
        monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        monitor_thread.start()
    
    def stop_monitoring(self):
        """İzlemeyi durdur"""
        self.monitoring = False
        self.logger.info("Monitoring stopped")
    
    def _send_alert(self, report: Dict):
        """Alert gönder"""
        # Email, Slack, SIEM integration burada yapılabilir
        alert_message = f"""
🚨 SECURITY ALERT 🚨

Host: {report['hostname']}
Risk Level: {report['risk_assessment']['level']}
Risk Score: {report['risk_assessment']['score']}

Risk Factors:
{chr(10).join('- ' + factor for factor in report['risk_assessment']['factors'])}

Recommendation: {report['risk_assessment']['recommendation']}

Timestamp: {report['timestamp']}
        """
        
        self.logger.critical(alert_message)
        
        # Alert dosyasına kaydet
        with open('security_alerts.log', 'a') as f:
            f.write(f"{datetime.now().isoformat()} - {alert_message}\n\n")

# Kullanım örneği
if __name__ == "__main__":
    monitor = EndpointMonitor()
    
    # Tek seferlik rapor
    report = monitor.generate_report()
    
    # Raporu JSON formatında kaydet
    with open(f"endpoint_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json", 'w') as f:
        json.dump(report, f, indent=2)
    
    # Kritik durumları ekrana yazdır
    print(f"\n🔍 ENDPOINT SECURITY REPORT - {report['hostname']}")
    print(f"📊 Risk Level: {report['risk_assessment']['level']} (Score: {report['risk_assessment']['score']})")
    print(f"💡 Recommendation: {report['risk_assessment']['recommendation']}")
    
    if report['suspicious_processes']:
        print("\n🚨 SUSPICIOUS PROCESSES DETECTED:")
        for proc in report['suspicious_processes']:
            print(f"  - {proc['name']} (PID: {proc['pid']}) - Risk: {proc['risk_level']}")
    
    if report['suspicious_connections']:
        print("\n🚨 SUSPICIOUS NETWORK CONNECTIONS:")
        for conn in report['suspicious_connections']:
            print(f"  - {conn['process']} -> {conn['remote_addr']} - Risk: {conn['risk_level']}")
    
    if report['file_integrity']:
        modified_files = [f for f in report['file_integrity'] if f.get('status') == 'MODIFIED']
        if modified_files:
            print("\n🚨 MODIFIED CRITICAL FILES:")
            for file_info in modified_files:
                print(f"  - {file_info['file_path']} - {file_info['status']}")
    
    # Sürekli izleme başlat (isteğe bağlı)
    # monitor.start_continuous_monitoring(interval=30)
    
    print("\n✅ Endpoint monitoring completed!")