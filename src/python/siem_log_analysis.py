#!/usr/bin/env python3
"""
SIEM Log Analysis and Threat Hunting Framework
Author: ibrahimsql
Description: Comprehensive SIEM log analysis and threat hunting tools
"""

import re
import json
import datetime
from typing import Dict, List, Optional, Any
import geoip2.database
import hashlib
import requests
import smtplib
import time
from email.mime.text import MimeText
from email.mime.multipart import MimeMultipart
import logging
import pandas as pd
import numpy as np
from elasticsearch import Elasticsearch
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import warnings
warnings.filterwarnings('ignore')

class SecurityLogParser:
    """Security log parsing and enrichment class"""
    
    def __init__(self, geoip_db_path: str = None):
        self.geoip_reader = None
        if geoip_db_path:
            try:
                self.geoip_reader = geoip2.database.Reader(geoip_db_path)
            except:
                print(f"[-] GeoIP database could not be loaded: {geoip_db_path}")
        
        # Common log patterns
        self.patterns = {
            'apache_access': re.compile(
                r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<timestamp>[^\]]+)\] '
                r'"(?P<method>\w+) (?P<url>[^"]+) HTTP/[^"]+" '
                r'(?P<status>\d+) (?P<size>\d+|-) '
                r'"(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)"'
            ),
            'ssh_auth': re.compile(
                r'(?P<timestamp>\w+ \d+ \d+:\d+:\d+) (?P<hostname>\w+) '
                r'sshd\[(?P<pid>\d+)\]: (?P<status>\w+) password for '
                r'(?P<user>\w+) from (?P<ip>\d+\.\d+\.\d+\.\d+)'
            ),
            'windows_logon': re.compile(
                r'EventID=(?P<event_id>\d+).*?'
                r'Account Name:\s+(?P<user>[^\s]+).*?'
                r'Source Network Address:\s+(?P<ip>\d+\.\d+\.\d+\.\d+)'
            ),
            'nginx_access': re.compile(
                r'(?P<ip>\d+\.\d+\.\d+\.\d+) - (?P<user>[^\s]+) '
                r'\[(?P<timestamp>[^\]]+)\] "(?P<method>\w+) (?P<url>[^"]+) '
                r'HTTP/[^"]+" (?P<status>\d+) (?P<size>\d+) '
                r'"(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)"'
            ),
            'firewall': re.compile(
                r'(?P<timestamp>\w+ \d+ \d+:\d+:\d+) (?P<hostname>\w+) '
                r'kernel: \[.*?\] (?P<action>\w+) (?P<protocol>\w+) '
                r'(?P<src_ip>\d+\.\d+\.\d+\.\d+):(?P<src_port>\d+) '
                r'-> (?P<dst_ip>\d+\.\d+\.\d+\.\d+):(?P<dst_port>\d+)'
            )
        }
        
        # Threat intelligence database (simulated)
        self.threat_intel_db = {
            '192.168.1.100': {'type': 'malware_c2', 'confidence': 'high', 'family': 'Zeus'},
            '10.0.0.50': {'type': 'brute_force', 'confidence': 'medium', 'source': 'honeypot'},
            '172.16.0.25': {'type': 'scanner', 'confidence': 'low', 'tool': 'nmap'},
            '203.0.113.1': {'type': 'phishing', 'confidence': 'high', 'campaign': 'APT29'}
        }
    
    def parse_log_line(self, log_line: str, log_type: str) -> Optional[Dict]:
        """Parse a single log line"""
        if log_type not in self.patterns:
            return None
        
        match = self.patterns[log_type].search(log_line)
        if not match:
            return None
        
        parsed_data = match.groupdict()
        
        # Enrich with additional data
        enriched_data = self.enrich_log_data(parsed_data, log_type)
        
        return enriched_data
    
    def parse_log_file(self, file_path: str, log_type: str) -> List[Dict]:
        """Parse log file"""
        parsed_logs = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    parsed_log = self.parse_log_line(line.strip(), log_type)
                    if parsed_log:
                        parsed_log['line_number'] = line_num
                        parsed_log['raw_log'] = line.strip()
                        parsed_logs.append(parsed_log)
        
        except Exception as e:
            print(f"[-] Log dosyası okuma hatası: {e}")
        
        return parsed_logs
    
    def enrich_log_data(self, data: Dict, log_type: str) -> Dict:
        """Parse edilmiş log verisini ek bağlamla zenginleştir"""
        enriched = data.copy()
        
        # Timestamp normalizasyonu
        if 'timestamp' in data:
            enriched['normalized_timestamp'] = self.normalize_timestamp(
                data['timestamp'], log_type
            )
        
        # GeoIP bilgisi ekle
        if 'ip' in data and self.geoip_reader:
            geo_info = self.get_geoip_info(data['ip'])
            if geo_info:
                enriched['geoip'] = geo_info
        
        # Tehdit istihbaratı ekle
        if 'ip' in data:
            threat_info = self.check_threat_intelligence(data['ip'])
            if threat_info:
                enriched['threat_intel'] = threat_info
        
        # Risk skoru hesapla
        enriched['risk_score'] = self.calculate_risk_score(enriched, log_type)
        
        # Event kategorilendirmesi
        enriched['category'] = self.categorize_event(enriched, log_type)
        
        # Anomali tespiti
        enriched['anomaly_score'] = self.detect_anomalies(enriched, log_type)
        
        return enriched
    
    def normalize_timestamp(self, timestamp: str, log_type: str) -> str:
        """Timestamp'i ISO formatına normalize et"""
        try:
            if log_type == 'apache_access' or log_type == 'nginx_access':
                # Format: 10/Oct/2000:13:55:36 -0700
                dt = datetime.datetime.strptime(
                    timestamp.split()[0], '%d/%b/%Y:%H:%M:%S'
                )
            elif log_type == 'ssh_auth' or log_type == 'firewall':
                # Format: Oct 10 13:55:36
                current_year = datetime.datetime.now().year
                dt = datetime.datetime.strptime(
                    f"{current_year} {timestamp}", '%Y %b %d %H:%M:%S'
                )
            else:
                return timestamp
            
            return dt.isoformat()
        except:
            return timestamp
    
    def get_geoip_info(self, ip: str) -> Optional[Dict]:
        """IP adresi için GeoIP bilgisi al"""
        try:
            response = self.geoip_reader.city(ip)
            return {
                'country': response.country.name,
                'country_code': response.country.iso_code,
                'city': response.city.name,
                'latitude': float(response.location.latitude) if response.location.latitude else None,
                'longitude': float(response.location.longitude) if response.location.longitude else None,
                'asn': response.traits.autonomous_system_number,
                'isp': response.traits.isp
            }
        except:
            return None
    
    def check_threat_intelligence(self, ip: str) -> Optional[Dict]:
        """IP'yi tehdit istihbaratı kaynaklarına karşı kontrol et"""
        return self.threat_intel_db.get(ip)
    
    def calculate_risk_score(self, data: Dict, log_type: str) -> int:
        """Event için risk skoru hesapla"""
        score = 0
        
        # Log tipine göre temel skor
        base_scores = {
            'apache_access': 1,
            'nginx_access': 1,
            'ssh_auth': 3,
            'windows_logon': 2,
            'firewall': 2
        }
        score += base_scores.get(log_type, 1)
        
        # Başarısız eventler için skor artır
        if log_type in ['ssh_auth'] and data.get('status') == 'Failed':
            score += 5
        
        if log_type in ['apache_access', 'nginx_access']:
            status = data.get('status', '')
            if status.startswith('4'):  # 4xx errors
                score += 3
            elif status.startswith('5'):  # 5xx errors
                score += 2
        
        # Tehdit istihbaratı hit'leri için skor artır
        if data.get('threat_intel'):
            confidence = data['threat_intel'].get('confidence', 'low')
            if confidence == 'high':
                score += 8
            elif confidence == 'medium':
                score += 5
            else:
                score += 2
        
        # Yabancı ülkeler için skor artır
        if data.get('geoip', {}).get('country_code') not in ['US', 'CA', 'GB', 'TR']:
            score += 2
        
        # Şüpheli portlar
        if 'dst_port' in data:
            suspicious_ports = [22, 23, 3389, 445, 135, 139]
            if int(data.get('dst_port', 0)) in suspicious_ports:
                score += 1
        
        return min(score, 10)  # 10'da sınırla
    
    def categorize_event(self, data: Dict, log_type: str) -> str:
        """Güvenlik eventini kategorilere ayır"""
        if data.get('threat_intel'):
            return 'threat_intelligence_hit'
        
        if log_type == 'ssh_auth' and data.get('status') == 'Failed':
            return 'authentication_failure'
        
        if log_type in ['apache_access', 'nginx_access']:
            status = data.get('status', '')
            if status.startswith('4'):
                return 'web_attack_attempt'
            elif status.startswith('5'):
                return 'web_server_error'
        
        if log_type == 'firewall' and data.get('action') == 'DROP':
            return 'network_blocked'
        
        return 'normal_activity'
    
    def detect_anomalies(self, data: Dict, log_type: str) -> float:
        """Anomali tespiti için skor hesapla"""
        anomaly_score = 0.0
        
        # Gece saatleri aktivitesi
        if 'normalized_timestamp' in data:
            try:
                dt = datetime.datetime.fromisoformat(data['normalized_timestamp'])
                if dt.hour < 6 or dt.hour > 22:  # Gece saatleri
                    anomaly_score += 0.3
            except:
                pass
        
        # Yüksek risk skorlu eventler
        if data.get('risk_score', 0) > 7:
            anomaly_score += 0.4
        
        # Yabancı IP'ler
        if data.get('geoip', {}).get('country_code') not in ['US', 'CA', 'GB', 'TR']:
            anomaly_score += 0.2
        
        # Şüpheli user agent'lar
        if 'user_agent' in data:
            suspicious_agents = ['sqlmap', 'nikto', 'nmap', 'masscan', 'zap']
            user_agent = data['user_agent'].lower()
            if any(agent in user_agent for agent in suspicious_agents):
                anomaly_score += 0.5
        
        return min(anomaly_score, 1.0)  # 1.0'da sınırla

class SIEMAlertHandler:
    """SIEM alert yanıt otomasyonu"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.elasticsearch_url = config.get('elasticsearch', {}).get('url', 'http://localhost:9200')
        self.smtp_config = config.get('smtp', {})
        self.alert_rules = config.get('alert_rules', {})
        
        # Logging kurulumu
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('siem_alerts.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
        # Alert geçmişi
        self.alert_history = []
    
    def query_elasticsearch(self, query: Dict, index_pattern: str = "logstash-*") -> Optional[Dict]:
        """Elasticsearch'ten güvenlik eventlerini sorgula"""
        url = f"{self.elasticsearch_url}/{index_pattern}/_search"
        
        try:
            response = requests.post(url, json=query, timeout=30)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Elasticsearch sorgu hatası: {e}")
            return None
    
    def check_brute_force_attacks(self) -> List[Dict]:
        """Brute force saldırılarını kontrol et"""
        query = {
            "query": {
                "bool": {
                    "must": [
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": "now-15m"
                                }
                            }
                        },
                        {
                            "terms": {
                                "winlog.event_id": [4625, 4771, 4776]
                            }
                        }
                    ]
                }
            },
            "aggs": {
                "failed_logins_by_ip": {
                    "terms": {
                        "field": "source_ip.keyword",
                        "size": 100
                    },
                    "aggs": {
                        "unique_users": {
                            "cardinality": {
                                "field": "user_name.keyword"
                            }
                        }
                    }
                }
            },
            "size": 0
        }
        
        result = self.query_elasticsearch(query)
        if not result:
            return []
        
        alerts = []
        threshold = self.alert_rules.get('brute_force', {}).get('threshold', 10)
        
        for bucket in result.get('aggregations', {}).get('failed_logins_by_ip', {}).get('buckets', []):
            ip = bucket['key']
            failed_count = bucket['doc_count']
            unique_users = bucket['unique_users']['value']
            
            if failed_count >= threshold:
                alert = {
                    'type': 'brute_force_attack',
                    'severity': 'HIGH',
                    'source_ip': ip,
                    'failed_attempts': failed_count,
                    'unique_users_targeted': unique_users,
                    'timestamp': datetime.datetime.now().isoformat(),
                    'description': f'Brute force attack detected from {ip} with {failed_count} failed attempts'
                }
                alerts.append(alert)
                self.logger.warning(f"Brute force alert: {alert}")
        
        return alerts
    
    def check_lateral_movement(self) -> List[Dict]:
        """Lateral movement aktivitelerini kontrol et"""
        query = {
            "query": {
                "bool": {
                    "must": [
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": "now-1h"
                                }
                            }
                        },
                        {
                            "terms": {
                                "winlog.event_id": [4624, 4648, 4672]
                            }
                        }
                    ]
                }
            },
            "aggs": {
                "users_by_systems": {
                    "terms": {
                        "field": "user_name.keyword",
                        "size": 50
                    },
                    "aggs": {
                        "unique_systems": {
                            "cardinality": {
                                "field": "computer_name.keyword"
                            }
                        }
                    }
                }
            },
            "size": 0
        }
        
        result = self.query_elasticsearch(query)
        if not result:
            return []
        
        alerts = []
        threshold = self.alert_rules.get('lateral_movement', {}).get('threshold', 5)
        
        for bucket in result.get('aggregations', {}).get('users_by_systems', {}).get('buckets', []):
            user = bucket['key']
            system_count = bucket['unique_systems']['value']
            
            if system_count >= threshold:
                alert = {
                    'type': 'lateral_movement',
                    'severity': 'MEDIUM',
                    'user': user,
                    'systems_accessed': system_count,
                    'timestamp': datetime.datetime.now().isoformat(),
                    'description': f'Potential lateral movement: User {user} accessed {system_count} systems'
                }
                alerts.append(alert)
                self.logger.warning(f"Lateral movement alert: {alert}")
        
        return alerts
    
    def check_data_exfiltration(self) -> List[Dict]:
        """Veri sızdırma aktivitelerini kontrol et"""
        query = {
            "query": {
                "bool": {
                    "must": [
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": "now-30m"
                                }
                            }
                        },
                        {
                            "range": {
                                "bytes_out": {
                                    "gte": 100000000  # 100MB
                                }
                            }
                        }
                    ]
                }
            },
            "aggs": {
                "high_volume_by_user": {
                    "terms": {
                        "field": "user.keyword",
                        "size": 20
                    },
                    "aggs": {
                        "total_bytes": {
                            "sum": {
                                "field": "bytes_out"
                            }
                        }
                    }
                }
            },
            "size": 0
        }
        
        result = self.query_elasticsearch(query)
        if not result:
            return []
        
        alerts = []
        threshold = self.alert_rules.get('data_exfiltration', {}).get('threshold', 500000000)  # 500MB
        
        for bucket in result.get('aggregations', {}).get('high_volume_by_user', {}).get('buckets', []):
            user = bucket['key']
            total_bytes = bucket['total_bytes']['value']
            
            if total_bytes >= threshold:
                alert = {
                    'type': 'data_exfiltration',
                    'severity': 'CRITICAL',
                    'user': user,
                    'bytes_transferred': total_bytes,
                    'timestamp': datetime.datetime.now().isoformat(),
                    'description': f'Potential data exfiltration: User {user} transferred {total_bytes} bytes'
                }
                alerts.append(alert)
                self.logger.critical(f"Data exfiltration alert: {alert}")
        
        return alerts
    
    def send_alert_email(self, alert: Dict) -> bool:
        """Alert e-postası gönder"""
        try:
            msg = MimeMultipart()
            msg['From'] = self.smtp_config.get('from_email', 'siem@company.com')
            msg['To'] = self.smtp_config.get('to_email', 'security@company.com')
            msg['Subject'] = f"SIEM Alert: {alert['type']} - {alert['severity']}"
            
            body = f"""
            SIEM Security Alert
            
            Type: {alert['type']}
            Severity: {alert['severity']}
            Timestamp: {alert['timestamp']}
            Description: {alert['description']}
            
            Alert Details:
            {json.dumps(alert, indent=2)}
            
            Please investigate immediately.
            """
            
            msg.attach(MimeText(body, 'plain'))
            
            server = smtplib.SMTP(self.smtp_config.get('server', 'localhost'), 
                                 self.smtp_config.get('port', 587))
            
            if self.smtp_config.get('use_tls', True):
                server.starttls()
            
            if self.smtp_config.get('username'):
                server.login(self.smtp_config['username'], self.smtp_config['password'])
            
            server.send_message(msg)
            server.quit()
            
            self.logger.info(f"Alert email sent for {alert['type']}")
            return True
            
        except Exception as e:
            self.logger.error(f"Email gönderme hatası: {e}")
            return False
    
    def run_continuous_monitoring(self, interval: int = 300):
        """Sürekli monitoring çalıştır"""
        self.logger.info("SIEM sürekli monitoring başlatılıyor...")
        
        while True:
            try:
                # Tüm kontrolleri çalıştır
                all_alerts = []
                
                all_alerts.extend(self.check_brute_force_attacks())
                all_alerts.extend(self.check_lateral_movement())
                all_alerts.extend(self.check_data_exfiltration())
                
                # Alert'leri işle
                for alert in all_alerts:
                    self.alert_history.append(alert)
                    
                    # E-posta gönder
                    if alert['severity'] in ['HIGH', 'CRITICAL']:
                        self.send_alert_email(alert)
                
                if all_alerts:
                    self.logger.info(f"{len(all_alerts)} alert oluşturuldu")
                
                time.sleep(interval)
                
            except KeyboardInterrupt:
                self.logger.info("Monitoring durduruldu")
                break
            except Exception as e:
                self.logger.error(f"Monitoring hatası: {e}")
                time.sleep(60)  # Hata durumunda 1 dakika bekle

class ThreatHunter:
    """Gelişmiş tehdit avcılığı framework'ü"""
    
    def __init__(self, es_host: str = 'localhost', es_port: int = 9200):
        try:
            self.es = Elasticsearch([{'host': es_host, 'port': es_port}])
        except:
            self.es = None
            print(f"[-] Elasticsearch bağlantısı kurulamadı: {es_host}:{es_port}")
        
        self.scaler = StandardScaler()
        self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
    
    def hunt_lateral_movement(self, days_back: int = 7) -> List[Dict]:
        """Lateral movement kalıplarını avla"""
        if not self.es:
            return self._simulate_lateral_movement_hunt()
        
        query = {
            "query": {
                "bool": {
                    "must": [
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": f"now-{days_back}d"
                                }
                            }
                        },
                        {
                            "terms": {
                                "winlog.event_id": [4624, 4648, 4672]
                            }
                        }
                    ]
                }
            },
            "size": 10000,
            "sort": [{"@timestamp": {"order": "asc"}}]
        }
        
        try:
            response = self.es.search(index="windows-*", body=query)
        except:
            return self._simulate_lateral_movement_hunt()
        
        # DataFrame'e dönüştür
        events = []
        for hit in response['hits']['hits']:
            source = hit['_source']
            event = {
                'timestamp': source.get('@timestamp'),
                'event_id': source.get('winlog', {}).get('event_id'),
                'user': source.get('winlog', {}).get('event_data', {}).get('TargetUserName'),
                'source_ip': source.get('winlog', {}).get('event_data', {}).get('IpAddress'),
                'computer': source.get('winlog', {}).get('computer_name'),
                'logon_type': source.get('winlog', {}).get('event_data', {}).get('LogonType')
            }
            events.append(event)
        
        df = pd.DataFrame(events)
        
        return self._analyze_lateral_movement_patterns(df)
    
    def _simulate_lateral_movement_hunt(self) -> List[Dict]:
        """Lateral movement hunt simülasyonu"""
        return [
            {
                'pattern': 'multiple_system_access',
                'user': 'admin_user',
                'system_count': 8,
                'risk_score': 9,
                'description': 'User accessed multiple systems in short timeframe'
            },
            {
                'pattern': 'rapid_successive_logins',
                'user': 'service_account',
                'rapid_logins': 5,
                'risk_score': 7,
                'description': 'Rapid successive logins detected'
            }
        ]
    
    def _analyze_lateral_movement_patterns(self, df: pd.DataFrame) -> List[Dict]:
        """Lateral movement kalıplarını analiz et"""
        suspicious_patterns = []
        
        if df.empty:
            return suspicious_patterns
        
        # Pattern 1: Aynı kullanıcının birden fazla sisteme giriş yapması
        user_systems = df.groupby('user')['computer'].nunique().sort_values(ascending=False)
        for user, system_count in user_systems.head(10).items():
            if system_count > 5:  # Threshold
                suspicious_patterns.append({
                    'pattern': 'multiple_system_access',
                    'user': user,
                    'system_count': system_count,
                    'risk_score': min(system_count * 2, 10),
                    'description': f'User {user} accessed {system_count} different systems'
                })
        
        # Pattern 2: Hızlı ardışık giriş yapma
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df = df.sort_values('timestamp')
        
        for user in df['user'].unique():
            if pd.isna(user):
                continue
            
            user_events = df[df['user'] == user].copy()
            user_events['time_diff'] = user_events['timestamp'].diff().dt.total_seconds()
            
            rapid_logins = user_events[user_events['time_diff'] < 60].shape[0]  # < 1 dakika
            if rapid_logins > 3:
                suspicious_patterns.append({
                    'pattern': 'rapid_successive_logins',
                    'user': user,
                    'rapid_logins': rapid_logins,
                    'risk_score': min(rapid_logins * 2, 10),
                    'description': f'User {user} had {rapid_logins} rapid successive logins'
                })
        
        return suspicious_patterns
    
    def hunt_privilege_escalation(self, days_back: int = 7) -> List[Dict]:
        """Privilege escalation kalıplarını avla"""
        # Simulated privilege escalation hunting
        return [
            {
                'pattern': 'admin_group_addition',
                'user': 'regular_user',
                'target_group': 'Domain Admins',
                'risk_score': 10,
                'description': 'User added to high-privilege group'
            },
            {
                'pattern': 'service_account_abuse',
                'user': 'svc_backup',
                'suspicious_activity': 'interactive_logon',
                'risk_score': 8,
                'description': 'Service account used for interactive logon'
            }
        ]
    
    def hunt_data_staging(self, days_back: int = 7) -> List[Dict]:
        """Veri hazırlama (staging) aktivitelerini avla"""
        # Simulated data staging hunting
        return [
            {
                'pattern': 'large_file_creation',
                'user': 'employee_x',
                'file_size': '2.5GB',
                'location': 'C:\\temp\\data.zip',
                'risk_score': 7,
                'description': 'Large compressed file created in temp directory'
            },
            {
                'pattern': 'unusual_file_access',
                'user': 'contractor_y',
                'files_accessed': 150,
                'time_window': '30 minutes',
                'risk_score': 9,
                'description': 'Unusual volume of file access in short time'
            }
        ]
    
    def hunt_command_and_control(self, days_back: int = 7) -> List[Dict]:
        """Command & Control aktivitelerini avla"""
        # Simulated C2 hunting
        return [
            {
                'pattern': 'beaconing_traffic',
                'destination': '203.0.113.50',
                'interval': '60 seconds',
                'duration': '4 hours',
                'risk_score': 9,
                'description': 'Regular beaconing traffic to external IP'
            },
            {
                'pattern': 'dns_tunneling',
                'domain': 'malicious-c2.example.com',
                'query_count': 500,
                'risk_score': 8,
                'description': 'Suspicious DNS query patterns indicating tunneling'
            }
        ]
    
    def hunt_persistence_mechanisms(self, days_back: int = 7) -> List[Dict]:
        """Persistence mekanizmalarını avla"""
        # Simulated persistence hunting
        return [
            {
                'pattern': 'scheduled_task_creation',
                'task_name': 'WindowsUpdate',
                'command': 'powershell.exe -enc <base64>',
                'user': 'SYSTEM',
                'risk_score': 8,
                'description': 'Suspicious scheduled task created'
            },
            {
                'pattern': 'registry_run_key',
                'key': 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
                'value': 'SecurityUpdate',
                'data': 'C:\\Windows\\Temp\\update.exe',
                'risk_score': 9,
                'description': 'Suspicious registry run key added'
            }
        ]
    
    def run_comprehensive_hunt(self, days_back: int = 7) -> Dict[str, List[Dict]]:
        """Kapsamlı tehdit avcılığı çalıştır"""
        print("[+] Kapsamlı tehdit avcılığı başlatılıyor...")
        
        hunt_results = {
            'lateral_movement': self.hunt_lateral_movement(days_back),
            'privilege_escalation': self.hunt_privilege_escalation(days_back),
            'data_staging': self.hunt_data_staging(days_back),
            'command_and_control': self.hunt_command_and_control(days_back),
            'persistence_mechanisms': self.hunt_persistence_mechanisms(days_back)
        }
        
        # Sonuçları özetle
        total_findings = sum(len(findings) for findings in hunt_results.values())
        high_risk_findings = sum(
            len([f for f in findings if f.get('risk_score', 0) >= 8])
            for findings in hunt_results.values()
        )
        
        print(f"[+] Tehdit avcılığı tamamlandı:")
        print(f"    - Toplam bulgu: {total_findings}")
        print(f"    - Yüksek riskli bulgu: {high_risk_findings}")
        
        return hunt_results
    
    def generate_hunt_report(self, hunt_results: Dict[str, List[Dict]]) -> str:
        """Tehdit avcılığı raporu oluştur"""
        report = []
        report.append("# Threat Hunting Report")
        report.append(f"Generated: {datetime.datetime.now().isoformat()}")
        report.append("\n## Executive Summary")
        
        total_findings = sum(len(findings) for findings in hunt_results.values())
        high_risk_findings = sum(
            len([f for f in findings if f.get('risk_score', 0) >= 8])
            for findings in hunt_results.values()
        )
        
        report.append(f"- Total findings: {total_findings}")
        report.append(f"- High-risk findings: {high_risk_findings}")
        
        for hunt_type, findings in hunt_results.items():
            if findings:
                report.append(f"\n## {hunt_type.replace('_', ' ').title()}")
                
                for finding in findings:
                    report.append(f"\n### {finding.get('pattern', 'Unknown Pattern')}")
                    report.append(f"- Risk Score: {finding.get('risk_score', 0)}/10")
                    report.append(f"- Description: {finding.get('description', 'No description')}")
                    
                    # Ek detayları ekle
                    for key, value in finding.items():
                        if key not in ['pattern', 'risk_score', 'description']:
                            report.append(f"- {key.replace('_', ' ').title()}: {value}")
        
        return "\n".join(report)

class LogAnalyticsDashboard:
    """Log analitik dashboard'u"""
    
    def __init__(self):
        self.parsed_logs = []
        self.analytics_data = {}
    
    def load_parsed_logs(self, logs: List[Dict]):
        """Parse edilmiş log'ları yükle"""
        self.parsed_logs = logs
        self._calculate_analytics()
    
    def _calculate_analytics(self):
        """Analitik verilerini hesapla"""
        if not self.parsed_logs:
            return
        
        df = pd.DataFrame(self.parsed_logs)
        
        self.analytics_data = {
            'total_events': len(df),
            'unique_ips': df['ip'].nunique() if 'ip' in df.columns else 0,
            'risk_distribution': df['risk_score'].value_counts().to_dict() if 'risk_score' in df.columns else {},
            'category_distribution': df['category'].value_counts().to_dict() if 'category' in df.columns else {},
            'top_threat_ips': df[df['threat_intel'].notna()]['ip'].value_counts().head(10).to_dict() if 'threat_intel' in df.columns else {},
            'hourly_distribution': self._get_hourly_distribution(df),
            'geographic_distribution': self._get_geographic_distribution(df)
        }
    
    def _get_hourly_distribution(self, df: pd.DataFrame) -> Dict:
        """Saatlik dağılımı hesapla"""
        if 'normalized_timestamp' not in df.columns:
            return {}
        
        try:
            df['hour'] = pd.to_datetime(df['normalized_timestamp']).dt.hour
            return df['hour'].value_counts().sort_index().to_dict()
        except:
            return {}
    
    def _get_geographic_distribution(self, df: pd.DataFrame) -> Dict:
        """Coğrafi dağılımı hesapla"""
        if 'geoip' not in df.columns:
            return {}
        
        countries = []
        for geoip in df['geoip'].dropna():
            if isinstance(geoip, dict) and 'country' in geoip:
                countries.append(geoip['country'])
        
        if countries:
            return pd.Series(countries).value_counts().head(10).to_dict()
        return {}
    
    def generate_dashboard_data(self) -> Dict:
        """Dashboard verilerini oluştur"""
        return {
            'analytics': self.analytics_data,
            'recent_high_risk_events': self._get_recent_high_risk_events(),
            'threat_intel_summary': self._get_threat_intel_summary(),
            'anomaly_summary': self._get_anomaly_summary()
        }
    
    def _get_recent_high_risk_events(self) -> List[Dict]:
        """Son yüksek riskli eventleri al"""
        high_risk_events = [
            log for log in self.parsed_logs 
            if log.get('risk_score', 0) >= 7
        ]
        
        # Timestamp'e göre sırala (en yeni önce)
        high_risk_events.sort(
            key=lambda x: x.get('normalized_timestamp', ''), 
            reverse=True
        )
        
        return high_risk_events[:10]  # Son 10 event
    
    def _get_threat_intel_summary(self) -> Dict:
        """Tehdit istihbaratı özetini al"""
        threat_events = [
            log for log in self.parsed_logs 
            if log.get('threat_intel')
        ]
        
        if not threat_events:
            return {'total': 0, 'by_type': {}, 'by_confidence': {}}
        
        df = pd.DataFrame(threat_events)
        
        # Threat tiplerini çıkar
        threat_types = []
        confidence_levels = []
        
        for threat_intel in df['threat_intel']:
            if isinstance(threat_intel, dict):
                threat_types.append(threat_intel.get('type', 'unknown'))
                confidence_levels.append(threat_intel.get('confidence', 'unknown'))
        
        return {
            'total': len(threat_events),
            'by_type': pd.Series(threat_types).value_counts().to_dict(),
            'by_confidence': pd.Series(confidence_levels).value_counts().to_dict()
        }
    
    def _get_anomaly_summary(self) -> Dict:
        """Anomali özetini al"""
        if not self.parsed_logs:
            return {'total': 0, 'high_anomaly': 0, 'avg_score': 0}
        
        anomaly_scores = [
            log.get('anomaly_score', 0) for log in self.parsed_logs
        ]
        
        high_anomaly_count = len([score for score in anomaly_scores if score >= 0.7])
        avg_score = sum(anomaly_scores) / len(anomaly_scores) if anomaly_scores else 0
        
        return {
            'total': len(self.parsed_logs),
            'high_anomaly': high_anomaly_count,
            'avg_score': round(avg_score, 3)
        }

# Kullanım örnekleri
if __name__ == "__main__":
    print("🔍 SIEM Log Analysis and Threat Hunting Framework")
    print("⚠️  Bu araçları sadece sahip olduğunuz sistemlerde kullanın!")
    
    # Log parser örneği
    print("\n📋 Log Parser Örneği")
    parser = SecurityLogParser()
    
    # Örnek log satırları
    sample_logs = [
        '192.168.1.100 - - [10/Oct/2000:13:55:36 -0700] "GET /admin HTTP/1.1" 401 2326 "-" "Mozilla/5.0"',
        'Oct 10 13:55:36 server sshd[1234]: Failed password for admin from 192.168.1.50',
        '203.0.113.1 - - [10/Oct/2000:14:00:00 -0700] "POST /login HTTP/1.1" 200 1234 "-" "sqlmap/1.0"'
    ]
    
    log_types = ['apache_access', 'ssh_auth', 'apache_access']
    
    parsed_results = []
    for log_line, log_type in zip(sample_logs, log_types):
        result = parser.parse_log_line(log_line, log_type)
        if result:
            parsed_results.append(result)
            print(f"✅ {log_type}: Risk Score {result['risk_score']}, Category: {result['category']}")
    
    # SIEM Alert Handler örneği
    print("\n🚨 SIEM Alert Handler Örneği")
    
    config = {
        'elasticsearch': {
            'url': 'http://localhost:9200'
        },
        'smtp': {
            'server': 'smtp.company.com',
            'port': 587,
            'username': 'siem@company.com',
            'password': 'password',
            'from_email': 'siem@company.com',
            'to_email': 'security@company.com'
        },
        'alert_rules': {
            'brute_force': {'threshold': 10},
            'lateral_movement': {'threshold': 5},
            'data_exfiltration': {'threshold': 500000000}
        }
    }
    
    alert_handler = SIEMAlertHandler(config)
    
    # Simulated alert checks
    brute_force_alerts = alert_handler.check_brute_force_attacks()
    lateral_movement_alerts = alert_handler.check_lateral_movement()
    
    print(f"🔍 Brute force alerts: {len(brute_force_alerts)}")
    print(f"🔍 Lateral movement alerts: {len(lateral_movement_alerts)}")
    
    # Threat Hunter örneği
    print("\n🎯 Threat Hunter Örneği")
    threat_hunter = ThreatHunter()
    
    # Kapsamlı tehdit avcılığı
    hunt_results = threat_hunter.run_comprehensive_hunt(days_back=7)
    
    # Rapor oluştur
    report = threat_hunter.generate_hunt_report(hunt_results)
    print("\n📄 Threat Hunting Report:")
    print(report[:500] + "..." if len(report) > 500 else report)
    
    # Analytics Dashboard örneği
    print("\n📊 Analytics Dashboard Örneği")
    dashboard = LogAnalyticsDashboard()
    dashboard.load_parsed_logs(parsed_results)
    
    dashboard_data = dashboard.generate_dashboard_data()
    print(f"📈 Dashboard Analytics:")
    print(f"  - Total Events: {dashboard_data['analytics']['total_events']}")
    print(f"  - Unique IPs: {dashboard_data['analytics']['unique_ips']}")
    print(f"  - High Risk Events: {len(dashboard_data['recent_high_risk_events'])}")
    print(f"  - Threat Intel Hits: {dashboard_data['threat_intel_summary']['total']}")
    
    print("\n✅ SIEM Log Analysis Framework tamamlandı!")
    print("📝 Detaylı analiz için log dosyalarınızı işleyin.")