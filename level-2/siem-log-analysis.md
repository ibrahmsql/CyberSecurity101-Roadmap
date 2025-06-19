# 🔍 SIEM ve Log Analizi

## 1. Executive Summary

### Konunun Özeti ve Önemi
SIEM (Security Information and Event Management) sistemleri, modern siber güvenlik operasyonlarının kalbidir. Bu sistemler, organizasyonların güvenlik olaylarını gerçek zamanlı olarak tespit etmesini, analiz etmesini ve müdahale etmesini sağlar. Log analizi ise, sistem ve ağ aktivitelerinin kayıtlarını inceleyerek güvenlik tehditlerini ve anormallikleri belirleme sürecidir.

### Öğrenme hedefleri
- SIEM sistemlerinin mimarisi ve işleyişini anlama
- Log kaynaklarını tanımlama ve yönetme
- Güvenlik olaylarını tespit etme ve analiz etme
- SIEM kuralları yazma ve optimize etme
- Threat hunting teknikleri geliştirme
- SOC (Security Operations Center) operasyonlarını yönetme

### Gerçek Dünya Uygulaması
- Enterprise güvenlik operasyonları
- Compliance gereksinimleri (SOX, HIPAA, PCI DSS)
- Incident response süreçleri
- Threat intelligence entegrasyonu
- Forensic analiz desteği

## 2. Theoretical Foundation

### Kavramsal Açıklama

#### SIEM Nedir?
SIEM, güvenlik bilgilerini ve olaylarını merkezi bir platformda toplayan, analiz eden ve raporlayan bir güvenlik çözümüdür. İki ana bileşenden oluşur:

1. **SIM (Security Information Management)**: Uzun vadeli log depolama ve analiz
2. **SEM (Security Event Management)**: Gerçek zamanlı olay izleme ve uyarı

#### Temel Bileşenler
```
SIEM Architecture:
├── Data Collection Layer
│   ├── Log Collectors
│   ├── Network Sensors
│   └── Endpoint Agents
├── Data Processing Layer
│   ├── Normalization Engine
│   ├── Correlation Engine
│   └── Analytics Engine
├── Storage Layer
│   ├── Hot Storage (Recent data)
│   ├── Warm Storage (Medium-term)
│   └── Cold Storage (Long-term archive)
└── Presentation Layer
    ├── Dashboards
    ├── Reports
    └── Alert Management
```

### Tarihsel Context

#### SIEM Gelişim Süreci
- **1990'lar**: İlk log management sistemleri
- **2000'ler**: SIM ve SEM teknolojilerinin birleşimi
- **2010'lar**: Big Data ve machine learning entegrasyonu
- **2020'ler**: Cloud-native SIEM ve SOAR entegrasyonu

### Current State of the Art

#### Modern SIEM Özellikleri
- **User and Entity Behavior Analytics (UEBA)**: Anormal davranış tespiti
- **Security Orchestration and Response (SOAR)**: Otomatik müdahale
- **Threat Intelligence Integration**: Harici tehdit verisi entegrasyonu
- **Cloud-Native Architecture**: Scalable ve esnek altyapı
- **AI/ML-Powered Analytics**: Gelişmiş analitik yetenekler

## 3. Technical Deep Dive

### SIEM Mimarisi ve Bileşenler

#### Data Collection Methods
```
Log Collection Types:
├── Agent-based Collection
│   ├── Endpoint agents
│   ├── Application agents
│   └── Database agents
├── Agentless Collection
│   ├── Syslog
│   ├── SNMP
│   └── WMI/API calls
├── Network-based Collection
│   ├── Network taps
│   ├── Span ports
│   └── Flow data (NetFlow, sFlow)
└── Cloud-based Collection
    ├── API integrations
    ├── Cloud logs
    └── Container logs
```

#### Log Sources ve Event Types
```
Common Log Sources:
├── Operating Systems
│   ├── Windows Event Logs
│   ├── Linux Syslog
│   └── macOS System Logs
├── Network Infrastructure
│   ├── Firewall logs
│   ├── Router/Switch logs
│   ├── IDS/IPS logs
│   └── DNS logs
├── Applications
│   ├── Web server logs
│   ├── Database logs
│   ├── Email server logs
│   └── Custom application logs
├── Security Tools
│   ├── Antivirus logs
│   ├── DLP logs
│   ├── Vulnerability scanner logs
│   └── Authentication system logs
└── Cloud Services
    ├── AWS CloudTrail
    ├── Azure Activity Logs
    ├── Google Cloud Audit Logs
    └── Office 365 logs
```

### Log Normalization ve Parsing

#### Common Event Format (CEF)
```
CEF Format:
CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|[Extension]

Example:
CEF:0|Microsoft|Windows|6.1|4624|An account was successfully logged on|Low|src=192.168.1.100 suser=john.doe dst=192.168.1.50 duser=admin
```

#### LEEF (Log Event Extended Format)
```
LEEF Format:
LEEF:Version|Vendor|Product|Version|EventID|Delimiter|[Extension]

Example:
LEEF:2.0|Microsoft|Windows|6.1|4624|^|src=192.168.1.100^suser=john.doe^dst=192.168.1.50^duser=admin
```

### Correlation Rules ve Use Cases

#### Rule Types
```
SIEM Rule Categories:
├── Threshold Rules
│   ├── Failed login attempts
│   ├── High data transfer
│   └── Excessive privilege usage
├── Statistical Rules
│   ├── Baseline deviation
│   ├── Anomaly detection
│   └── Trend analysis
├── Pattern Rules
│   ├── Attack signatures
│   ├── Sequence detection
│   └── Behavioral patterns
└── Enrichment Rules
    ├── Threat intelligence
    ├── Asset information
    └── User context
```

## 4. Hands-on Laboratory

### Lab Environment Setup

#### ELK Stack Installation
```bash
#!/bin/bash
# ELK Stack (Elasticsearch, Logstash, Kibana) Installation

# Install Java (prerequisite)
sudo apt update
sudo apt install openjdk-11-jdk -y

# Add Elastic repository
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-7.x.list

# Install Elasticsearch
sudo apt update
sudo apt install elasticsearch -y

# Configure Elasticsearch
sudo tee /etc/elasticsearch/elasticsearch.yml > /dev/null <<EOF
cluster.name: security-lab
node.name: node-1
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch
network.host: localhost
http.port: 9200
discovery.type: single-node
EOF

# Start and enable Elasticsearch
sudo systemctl daemon-reload
sudo systemctl enable elasticsearch
sudo systemctl start elasticsearch

# Install Logstash
sudo apt install logstash -y

# Install Kibana
sudo apt install kibana -y

# Configure Kibana
sudo tee /etc/kibana/kibana.yml > /dev/null <<EOF
server.port: 5601
server.host: "localhost"
elasticsearch.hosts: ["http://localhost:9200"]
EOF

# Start services
sudo systemctl enable kibana
sudo systemctl start kibana
sudo systemctl enable logstash

echo "[+] ELK Stack installation completed"
echo "[+] Kibana available at: http://localhost:5601"
echo "[+] Elasticsearch available at: http://localhost:9200"
```

#### Splunk Installation (Alternative)
```bash
#!/bin/bash
# Splunk Enterprise Installation

# Download Splunk
wget -O splunk-8.2.0-e053ef3c985f-Linux-x86_64.tgz "https://download.splunk.com/products/splunk/releases/8.2.0/linux/splunk-8.2.0-e053ef3c985f-Linux-x86_64.tgz"

# Extract and install
sudo tar xvzf splunk-8.2.0-e053ef3c985f-Linux-x86_64.tgz -C /opt
sudo chown -R splunk:splunk /opt/splunk

# Start Splunk
sudo -u splunk /opt/splunk/bin/splunk start --accept-license

# Enable boot start
sudo /opt/splunk/bin/splunk enable boot-start -user splunk

echo "[+] Splunk installation completed"
echo "[+] Web interface available at: http://localhost:8000"
echo "[+] Default credentials: admin/changeme"
```

### Practical Exercises

#### Exercise 1: Log Collection Configuration

##### Logstash Configuration for Windows Event Logs
```ruby
# /etc/logstash/conf.d/windows-events.conf
input {
  beats {
    port => 5044
  }
}

filter {
  if [agent][type] == "winlogbeat" {
    # Parse Windows Event Log
    if [winlog][event_id] == 4624 {
      mutate {
        add_tag => [ "successful_logon" ]
      }
    }
    
    if [winlog][event_id] == 4625 {
      mutate {
        add_tag => [ "failed_logon" ]
      }
    }
    
    if [winlog][event_id] == 4648 {
      mutate {
        add_tag => [ "explicit_logon" ]
      }
    }
    
    # Extract user information
    if [winlog][event_data][TargetUserName] {
      mutate {
        add_field => { "user_name" => "%{[winlog][event_data][TargetUserName]}" }
      }
    }
    
    # Extract source IP
    if [winlog][event_data][IpAddress] {
      mutate {
        add_field => { "source_ip" => "%{[winlog][event_data][IpAddress]}" }
      }
    }
    
    # GeoIP enrichment
    if [source_ip] and [source_ip] != "-" and [source_ip] != "127.0.0.1" {
      geoip {
        source => "source_ip"
        target => "geoip"
      }
    }
  }
}

output {
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "windows-events-%{+YYYY.MM.dd}"
  }
  
  stdout {
    codec => rubydebug
  }
}
```

##### Winlogbeat Configuration
```yaml
# winlogbeat.yml
winlogbeat.event_logs:
  - name: Application
    ignore_older: 72h
  - name: System
    ignore_older: 72h
  - name: Security
    ignore_older: 72h
    event_id: 4624, 4625, 4648, 4656, 4672, 4720, 4728, 4732, 4756
  - name: Microsoft-Windows-Sysmon/Operational
    ignore_older: 72h

output.logstash:
  hosts: ["logstash-server:5044"]

processors:
  - add_host_metadata:
      when.not.contains.tags: forwarded
  - add_docker_metadata: ~
  - add_kubernetes_metadata: ~

logging.level: info
logging.to_files: true
logging.files:
  path: C:\ProgramData\winlogbeat\Logs
  name: winlogbeat
  keepfiles: 7
  permissions: 0644
```

#### Exercise 2: SIEM Rule Development

##### Splunk Search Queries
```spl
# Brute Force Attack Detection
index=windows EventCode=4625
| bucket _time span=5m
| stats count by _time, src_ip, user
| where count > 10
| eval severity="high"
| table _time, src_ip, user, count, severity

# Privilege Escalation Detection
index=windows EventCode=4672
| search PrivilegeList="*SeDebugPrivilege*" OR PrivilegeList="*SeTcbPrivilege*"
| eval severity="critical"
| table _time, user, Computer, PrivilegeList, severity

# Lateral Movement Detection
index=windows EventCode=4648
| search TargetServerName!="localhost" AND TargetServerName!="-"
| stats count by src_user, TargetServerName, TargetUserName
| where count > 5
| eval severity="medium"
| table src_user, TargetServerName, TargetUserName, count, severity

# Data Exfiltration Detection
index=network
| search bytes_out > 100000000
| bucket _time span=1h
| stats sum(bytes_out) as total_bytes by _time, src_ip, dest_ip
| where total_bytes > 1000000000
| eval severity="high"
| table _time, src_ip, dest_ip, total_bytes, severity
```

##### Elasticsearch/Kibana Queries
```json
{
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
          "term": {
            "winlog.event_id": 4625
          }
        }
      ]
    }
  },
  "aggs": {
    "failed_logins_by_ip": {
      "terms": {
        "field": "source_ip.keyword",
        "size": 10
      },
      "aggs": {
        "login_attempts": {
          "value_count": {
            "field": "winlog.event_id"
          }
        }
      }
    }
  }
}
```

#### Exercise 3: Custom Log Parser Development

```python
#!/usr/bin/env python3
# Custom Log Parser for Security Events

import re
import json
import datetime
from typing import Dict, List, Optional
import geoip2.database
import hashlib

class SecurityLogParser:
    def __init__(self, geoip_db_path: str = None):
        self.geoip_reader = None
        if geoip_db_path:
            self.geoip_reader = geoip2.database.Reader(geoip_db_path)
        
        # Common log patterns
        self.patterns = {
            'apache_access': re.compile(
                r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<timestamp>[^\]]+)\] '
                r'"(?P<method>\w+) (?P<url>[^"]+) HTTP/[^"]+" '
                r'(?P<status>\d+) (?P<size>\d+|-) '
                r'"(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)"
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
            )
        }
    
    def parse_log_line(self, log_line: str, log_type: str) -> Optional[Dict]:
        """Parse a single log line based on type"""
        if log_type not in self.patterns:
            return None
        
        match = self.patterns[log_type].search(log_line)
        if not match:
            return None
        
        parsed_data = match.groupdict()
        
        # Enrich with additional data
        enriched_data = self.enrich_log_data(parsed_data, log_type)
        
        return enriched_data
    
    def enrich_log_data(self, data: Dict, log_type: str) -> Dict:
        """Enrich parsed log data with additional context"""
        enriched = data.copy()
        
        # Add timestamp normalization
        if 'timestamp' in data:
            enriched['normalized_timestamp'] = self.normalize_timestamp(
                data['timestamp'], log_type
            )
        
        # Add GeoIP information
        if 'ip' in data and self.geoip_reader:
            geo_info = self.get_geoip_info(data['ip'])
            if geo_info:
                enriched['geoip'] = geo_info
        
        # Add threat intelligence
        if 'ip' in data:
            threat_info = self.check_threat_intelligence(data['ip'])
            if threat_info:
                enriched['threat_intel'] = threat_info
        
        # Add risk scoring
        enriched['risk_score'] = self.calculate_risk_score(enriched, log_type)
        
        # Add event categorization
        enriched['category'] = self.categorize_event(enriched, log_type)
        
        return enriched
    
    def normalize_timestamp(self, timestamp: str, log_type: str) -> str:
        """Normalize timestamp to ISO format"""
        try:
            if log_type == 'apache_access':
                # Format: 10/Oct/2000:13:55:36 -0700
                dt = datetime.datetime.strptime(
                    timestamp.split()[0], '%d/%b/%Y:%H:%M:%S'
                )
            elif log_type == 'ssh_auth':
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
        """Get GeoIP information for IP address"""
        try:
            response = self.geoip_reader.city(ip)
            return {
                'country': response.country.name,
                'country_code': response.country.iso_code,
                'city': response.city.name,
                'latitude': float(response.location.latitude),
                'longitude': float(response.location.longitude),
                'asn': response.traits.autonomous_system_number,
                'isp': response.traits.isp
            }
        except:
            return None
    
    def check_threat_intelligence(self, ip: str) -> Optional[Dict]:
        """Check IP against threat intelligence sources"""
        # Simulated threat intelligence check
        # In real implementation, this would query actual TI sources
        
        known_bad_ips = {
            '192.168.1.100': {'type': 'malware_c2', 'confidence': 'high'},
            '10.0.0.50': {'type': 'brute_force', 'confidence': 'medium'}
        }
        
        return known_bad_ips.get(ip)
    
    def calculate_risk_score(self, data: Dict, log_type: str) -> int:
        """Calculate risk score for the event"""
        score = 0
        
        # Base score by log type
        base_scores = {
            'apache_access': 1,
            'ssh_auth': 3,
            'windows_logon': 2
        }
        score += base_scores.get(log_type, 1)
        
        # Increase score for failed events
        if log_type == 'ssh_auth' and data.get('status') == 'Failed':
            score += 5
        
        if log_type == 'apache_access' and data.get('status', '').startswith('4'):
            score += 3
        
        # Increase score for threat intelligence hits
        if data.get('threat_intel'):
            confidence = data['threat_intel'].get('confidence', 'low')
            if confidence == 'high':
                score += 8
            elif confidence == 'medium':
                score += 5
            else:
                score += 2
        
        # Increase score for foreign countries
        if data.get('geoip', {}).get('country_code') not in ['US', 'CA', 'GB']:
            score += 2
        
        return min(score, 10)  # Cap at 10
    
    def categorize_event(self, data: Dict, log_type: str) -> str:
        """Categorize the security event"""
        if data.get('threat_intel'):
            return 'threat_intelligence_hit'
        
        if log_type == 'ssh_auth':
            if data.get('status') == 'Failed':
                return 'authentication_failure'
            else:
                return 'authentication_success'
        
        if log_type == 'apache_access':
            status = data.get('status', '')
            if status.startswith('4'):
                return 'web_client_error'
            elif status.startswith('5'):
                return 'web_server_error'
            else:
                return 'web_access'
        
        if log_type == 'windows_logon':
            event_id = data.get('event_id')
            if event_id == '4624':
                return 'windows_logon_success'
            elif event_id == '4625':
                return 'windows_logon_failure'
        
        return 'unknown'
    
    def process_log_file(self, file_path: str, log_type: str) -> List[Dict]:
        """Process entire log file"""
        results = []
        
        with open(file_path, 'r') as f:
            for line_num, line in enumerate(f, 1):
                parsed = self.parse_log_line(line.strip(), log_type)
                if parsed:
                    parsed['line_number'] = line_num
                    parsed['raw_log'] = line.strip()
                    results.append(parsed)
        
        return results
    
    def generate_summary_report(self, parsed_logs: List[Dict]) -> Dict:
        """Generate summary report from parsed logs"""
        summary = {
            'total_events': len(parsed_logs),
            'categories': {},
            'risk_distribution': {},
            'top_ips': {},
            'top_users': {},
            'timeline': {}
        }
        
        for log in parsed_logs:
            # Category distribution
            category = log.get('category', 'unknown')
            summary['categories'][category] = summary['categories'].get(category, 0) + 1
            
            # Risk score distribution
            risk_score = log.get('risk_score', 0)
            risk_level = 'low' if risk_score < 4 else 'medium' if risk_score < 7 else 'high'
            summary['risk_distribution'][risk_level] = summary['risk_distribution'].get(risk_level, 0) + 1
            
            # Top IPs
            ip = log.get('ip')
            if ip:
                summary['top_ips'][ip] = summary['top_ips'].get(ip, 0) + 1
            
            # Top users
            user = log.get('user')
            if user:
                summary['top_users'][user] = summary['top_users'].get(user, 0) + 1
        
        # Sort top lists
        summary['top_ips'] = dict(sorted(summary['top_ips'].items(), key=lambda x: x[1], reverse=True)[:10])
        summary['top_users'] = dict(sorted(summary['top_users'].items(), key=lambda x: x[1], reverse=True)[:10])
        
        return summary

# Usage example
if __name__ == "__main__":
    parser = SecurityLogParser()
    
    # Example log lines
    sample_logs = [
        ('192.168.1.100 - - [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.0" 200 2326 "-" "Mozilla/4.08"', 'apache_access'),
        ('Oct 10 13:55:36 server sshd[1234]: Failed password for admin from 192.168.1.200', 'ssh_auth'),
        ('EventID=4625 Account Name: john.doe Source Network Address: 10.0.0.50', 'windows_logon')
    ]
    
    parsed_results = []
    for log_line, log_type in sample_logs:
        result = parser.parse_log_line(log_line, log_type)
        if result:
            parsed_results.append(result)
            print(json.dumps(result, indent=2))
    
    # Generate summary
    summary = parser.generate_summary_report(parsed_results)
    print("\nSummary Report:")
    print(json.dumps(summary, indent=2))
```

### Troubleshooting Guide

#### Common SIEM Issues

1. **High Memory Usage**
```bash
# Check Elasticsearch heap usage
curl -X GET "localhost:9200/_cat/nodes?v&h=name,heap.percent,heap.current,heap.max,ram.percent,ram.current,ram.max"

# Optimize Elasticsearch settings
echo "ES_JAVA_OPTS=\"-Xms4g -Xmx4g\"" >> /etc/default/elasticsearch

# Clear old indices
curl -X DELETE "localhost:9200/logstash-*" -H 'Content-Type: application/json' -d'
{
  "query": {
    "range": {
      "@timestamp": {
        "lt": "now-30d"
      }
    }
  }
}'
```

2. **Log Ingestion Problems**
```bash
# Check Logstash pipeline status
sudo /usr/share/logstash/bin/logstash --path.settings /etc/logstash --config.test_and_exit

# Monitor log ingestion rate
watch -n 5 'curl -s "localhost:9200/_cat/indices?v" | grep logstash'

# Check for parsing errors
tail -f /var/log/logstash/logstash-plain.log | grep ERROR
```

3. **Performance Optimization**
```bash
# Optimize Elasticsearch for logging
cat > /etc/elasticsearch/elasticsearch.yml << EOF
# Increase bulk queue size
thread_pool.bulk.queue_size: 1000

# Optimize for write-heavy workloads
index.refresh_interval: 30s
index.number_of_replicas: 0

# Increase buffer sizes
indices.memory.index_buffer_size: 20%
EOF

# Restart Elasticsearch
sudo systemctl restart elasticsearch
```

## 5. Code Examples

### SIEM Automation Scripts

#### Automated Alert Response
```python
#!/usr/bin/env python3
# SIEM Alert Response Automation

import requests
import json
import smtplib
import time
from email.mime.text import MimeText
from email.mime.multipart import MimeMultipart
from datetime import datetime, timedelta
import logging

class SIEMAlertHandler:
    def __init__(self, config):
        self.config = config
        self.elasticsearch_url = config['elasticsearch']['url']
        self.smtp_config = config['smtp']
        self.alert_rules = config['alert_rules']
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('siem_alerts.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def query_elasticsearch(self, query, index_pattern="logstash-*"):
        """Query Elasticsearch for security events"""
        url = f"{self.elasticsearch_url}/{index_pattern}/_search"
        
        try:
            response = requests.post(url, json=query, timeout=30)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Elasticsearch query failed: {e}")
            return None
    
    def check_brute_force_attacks(self):
        """Check for brute force attacks"""
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
        threshold = self.alert_rules['brute_force']['threshold']
        
        for bucket in result['aggregations']['failed_logins_by_ip']['buckets']:
            if bucket['doc_count'] >= threshold:
                alert = {
                    'type': 'brute_force_attack',
                    'severity': 'high',
                    'source_ip': bucket['key'],
                    'failed_attempts': bucket['doc_count'],
                    'unique_users': bucket['unique_users']['value'],
                    'timestamp': datetime.now().isoformat(),
                    'description': f"Brute force attack detected from {bucket['key']} with {bucket['doc_count']} failed login attempts"
                }
                alerts.append(alert)
        
        return alerts
    
    def check_privilege_escalation(self):
        """Check for privilege escalation attempts"""
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
                            "term": {
                                "winlog.event_id": 4672
                            }
                        },
                        {
                            "wildcard": {
                                "winlog.event_data.PrivilegeList": "*SeDebugPrivilege*"
                            }
                        }
                    ]
                }
            },
            "sort": [
                {
                    "@timestamp": {
                        "order": "desc"
                    }
                }
            ],
            "size": 50
        }
        
        result = self.query_elasticsearch(query)
        if not result or not result['hits']['hits']:
            return []
        
        alerts = []
        for hit in result['hits']['hits']:
            source = hit['_source']
            alert = {
                'type': 'privilege_escalation',
                'severity': 'critical',
                'user': source.get('winlog', {}).get('event_data', {}).get('SubjectUserName'),
                'computer': source.get('winlog', {}).get('computer_name'),
                'privileges': source.get('winlog', {}).get('event_data', {}).get('PrivilegeList'),
                'timestamp': source.get('@timestamp'),
                'description': f"Privilege escalation detected: User {source.get('winlog', {}).get('event_data', {}).get('SubjectUserName')} obtained debug privileges"
            }
            alerts.append(alert)
        
        return alerts
    
    def check_data_exfiltration(self):
        """Check for potential data exfiltration"""
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
                "data_transfer_by_user": {
                    "terms": {
                        "field": "user.keyword",
                        "size": 50
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
        threshold = self.alert_rules['data_exfiltration']['threshold']
        
        for bucket in result['aggregations']['data_transfer_by_user']['buckets']:
            if bucket['total_bytes']['value'] >= threshold:
                alert = {
                    'type': 'data_exfiltration',
                    'severity': 'high',
                    'user': bucket['key'],
                    'bytes_transferred': bucket['total_bytes']['value'],
                    'timestamp': datetime.now().isoformat(),
                    'description': f"Potential data exfiltration: User {bucket['key']} transferred {bucket['total_bytes']['value']:,} bytes"
                }
                alerts.append(alert)
        
        return alerts
    
    def send_alert_email(self, alert):
        """Send alert via email"""
        try:
            msg = MimeMultipart()
            msg['From'] = self.smtp_config['from']
            msg['To'] = ', '.join(self.smtp_config['to'])
            msg['Subject'] = f"SIEM Alert: {alert['type'].upper()} - {alert['severity'].upper()}"
            
            body = f"""
            Security Alert Detected
            
            Type: {alert['type']}
            Severity: {alert['severity']}
            Timestamp: {alert['timestamp']}
            Description: {alert['description']}
            
            Details:
            {json.dumps(alert, indent=2)}
            
            Please investigate immediately.
            """
            
            msg.attach(MimeText(body, 'plain'))
            
            server = smtplib.SMTP(self.smtp_config['server'], self.smtp_config['port'])
            if self.smtp_config.get('use_tls'):
                server.starttls()
            if self.smtp_config.get('username'):
                server.login(self.smtp_config['username'], self.smtp_config['password'])
            
            server.send_message(msg)
            server.quit()
            
            self.logger.info(f"Alert email sent for {alert['type']}")
            
        except Exception as e:
            self.logger.error(f"Failed to send alert email: {e}")
    
    def block_ip_address(self, ip_address):
        """Block IP address using firewall"""
        try:
            # Example using iptables (Linux)
            import subprocess
            
            cmd = f"iptables -A INPUT -s {ip_address} -j DROP"
            result = subprocess.run(cmd.split(), capture_output=True, text=True)
            
            if result.returncode == 0:
                self.logger.info(f"Successfully blocked IP address: {ip_address}")
                return True
            else:
                self.logger.error(f"Failed to block IP address {ip_address}: {result.stderr}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error blocking IP address {ip_address}: {e}")
            return False
    
    def disable_user_account(self, username):
        """Disable user account"""
        try:
            # Example using Active Directory (Windows)
            import subprocess
            
            cmd = f"net user {username} /active:no"
            result = subprocess.run(cmd.split(), capture_output=True, text=True, shell=True)
            
            if result.returncode == 0:
                self.logger.info(f"Successfully disabled user account: {username}")
                return True
            else:
                self.logger.error(f"Failed to disable user account {username}: {result.stderr}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error disabling user account {username}: {e}")
            return False
    
    def process_alerts(self):
        """Main alert processing function"""
        self.logger.info("Starting SIEM alert processing")
        
        # Check for different types of attacks
        all_alerts = []
        
        # Brute force attacks
        brute_force_alerts = self.check_brute_force_attacks()
        all_alerts.extend(brute_force_alerts)
        
        # Privilege escalation
        privesc_alerts = self.check_privilege_escalation()
        all_alerts.extend(privesc_alerts)
        
        # Data exfiltration
        exfil_alerts = self.check_data_exfiltration()
        all_alerts.extend(exfil_alerts)
        
        # Process each alert
        for alert in all_alerts:
            self.logger.info(f"Processing alert: {alert['type']} - {alert['severity']}")
            
            # Send email notification
            self.send_alert_email(alert)
            
            # Automated response based on alert type and severity
            if alert['type'] == 'brute_force_attack' and alert['severity'] == 'high':
                if self.config['automated_response']['block_ips']:
                    self.block_ip_address(alert['source_ip'])
            
            elif alert['type'] == 'privilege_escalation' and alert['severity'] == 'critical':
                if self.config['automated_response']['disable_users']:
                    self.disable_user_account(alert['user'])
            
            # Log alert to file
            with open('siem_alerts.json', 'a') as f:
                f.write(json.dumps(alert) + '\n')
        
        self.logger.info(f"Processed {len(all_alerts)} alerts")
        return all_alerts
    
    def run_continuous_monitoring(self, interval=300):
        """Run continuous monitoring"""
        self.logger.info(f"Starting continuous monitoring with {interval}s interval")
        
        while True:
            try:
                self.process_alerts()
                time.sleep(interval)
            except KeyboardInterrupt:
                self.logger.info("Monitoring stopped by user")
                break
            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}")
                time.sleep(60)  # Wait 1 minute before retrying

# Configuration example
config = {
    'elasticsearch': {
        'url': 'http://localhost:9200'
    },
    'smtp': {
        'server': 'smtp.company.com',
        'port': 587,
        'use_tls': True,
        'username': 'siem-alerts@company.com',
        'password': 'password',
        'from': 'siem-alerts@company.com',
        'to': ['security-team@company.com']
    },
    'alert_rules': {
        'brute_force': {
            'threshold': 10  # Failed login attempts
        },
        'data_exfiltration': {
            'threshold': 1000000000  # 1GB
        }
    },
    'automated_response': {
        'block_ips': True,
        'disable_users': False  # Requires manual approval
    }
}

if __name__ == "__main__":
    handler = SIEMAlertHandler(config)
    
    # Run one-time check
    alerts = handler.process_alerts()
    print(f"Found {len(alerts)} alerts")
    
    # Or run continuous monitoring
    # handler.run_continuous_monitoring(interval=300)
```

### Threat Hunting Queries

#### Advanced Threat Hunting with Python
```python
#!/usr/bin/env python3
# Advanced Threat Hunting Framework

import pandas as pd
import numpy as np
from elasticsearch import Elasticsearch
from datetime import datetime, timedelta
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import warnings
warnings.filterwarnings('ignore')

class ThreatHunter:
    def __init__(self, es_host='localhost', es_port=9200):
        self.es = Elasticsearch([{'host': es_host, 'port': es_port}])
        self.scaler = StandardScaler()
    
    def hunt_lateral_movement(self, days_back=7):
        """Hunt for lateral movement patterns"""
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
        
        response = self.es.search(index="windows-*", body=query)
        
        # Convert to DataFrame
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
        
        # Analyze patterns
        suspicious_patterns = []
        
        # Pattern 1: Same user logging into multiple systems
        user_systems = df.groupby('user')['computer'].nunique().sort_values(ascending=False)
        for user, system_count in user_systems.head(10).items():
            if system_count > 5:  # Threshold
                suspicious_patterns.append({
                    'pattern': 'multiple_system_access',
                    'user': user,
                    'system_count': system_count,
                    'risk_score': min(system_count * 2, 10)
                })
        
        # Pattern 2: Rapid successive logins
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df = df.sort_values('timestamp')
        
        for user in df['user'].unique():
            if pd.isna(user):
                continue
            
            user_events = df[df['user'] == user].copy()
            user_events['time_diff'] = user_events['timestamp'].diff().dt.total_seconds()
            
            rapid_logins = user_events[user_events['time_diff'] < 60].shape[0]  # < 1 minute
            if rapid_logins > 3:
                suspicious_patterns.append({
                    'pattern': 'rapid_successive_logins',
                    'user': user,
                    'rapid_login_count': rapid_logins,
                    'risk_score': min(rapid_logins, 10)
                })
        
        return suspicious_patterns
    
    def hunt_privilege_escalation(self, days_back=7):
        """Hunt for privilege escalation patterns"""
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
                                "winlog.event_id": [4672, 4673, 4674, 4720, 4728, 4732]
                            }
                        }
                    ]
                }
            },
            "size": 10000
        }
        
        response = self.es.search(index="windows-*", body=query)
        
        events = []
        for hit in response['hits']['hits']:
            source = hit['_source']
            event = {
                'timestamp': source.get('@timestamp'),
                'event_id': source.get('winlog', {}).get('event_id'),
                'user': source.get('winlog', {}).get('event_data', {}).get('SubjectUserName'),
                'target_user': source.get('winlog', {}).get('event_data', {}).get('TargetUserName'),
                'privileges': source.get('winlog', {}).get('event_data', {}).get('PrivilegeList'),
                'computer': source.get('winlog', {}).get('computer_name')
            }
            events.append(event)
        
        df = pd.DataFrame(events)
        
        suspicious_patterns = []
        
        # Pattern 1: Unusual privilege assignments
        dangerous_privileges = ['SeDebugPrivilege', 'SeTcbPrivilege', 'SeBackupPrivilege']
        
        for privilege in dangerous_privileges:
            privilege_events = df[df['privileges'].str.contains(privilege, na=False)]
            if not privilege_events.empty:
                for _, event in privilege_events.iterrows():
                    suspicious_patterns.append({
                        'pattern': 'dangerous_privilege_assignment',
                        'user': event['user'],
                        'privilege': privilege,
                        'computer': event['computer'],
                        'timestamp': event['timestamp'],
                        'risk_score': 9
                    })
        
        # Pattern 2: Account creation followed by privilege assignment
        account_creations = df[df['event_id'] == 4720]
        privilege_assignments = df[df['event_id'].isin([4728, 4732])]
        
        for _, creation in account_creations.iterrows():
            created_user = creation['target_user']
            creation_time = pd.to_datetime(creation['timestamp'])
            
            # Look for privilege assignments within 1 hour
            recent_privileges = privilege_assignments[
                (privilege_assignments['target_user'] == created_user) &
                (pd.to_datetime(privilege_assignments['timestamp']) > creation_time) &
                (pd.to_datetime(privilege_assignments['timestamp']) < creation_time + timedelta(hours=1))
            ]
            
            if not recent_privileges.empty:
                suspicious_patterns.append({
                    'pattern': 'rapid_privilege_escalation',
                    'created_user': created_user,
                    'creator': creation['user'],
                    'privilege_count': len(recent_privileges),
                    'risk_score': 8
                })
        
        return suspicious_patterns
    
    def hunt_data_exfiltration(self, days_back=7):
        """Hunt for data exfiltration patterns"""
        # Query for file access events
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
                                "winlog.event_id": [4656, 4658, 4663]
                            }
                        }
                    ]
                }
            },
            "size": 10000
        }
        
        response = self.es.search(index="windows-*", body=query)
        
        events = []
        for hit in response['hits']['hits']:
            source = hit['_source']
            event = {
                'timestamp': source.get('@timestamp'),
                'event_id': source.get('winlog', {}).get('event_id'),
                'user': source.get('winlog', {}).get('event_data', {}).get('SubjectUserName'),
                'object_name': source.get('winlog', {}).get('event_data', {}).get('ObjectName'),
                'access_mask': source.get('winlog', {}).get('event_data', {}).get('AccessMask'),
                'computer': source.get('winlog', {}).get('computer_name')
            }
            events.append(event)
        
        df = pd.DataFrame(events)
        
        suspicious_patterns = []
        
        # Pattern 1: Unusual file access patterns
        sensitive_extensions = ['.doc', '.docx', '.pdf', '.xls', '.xlsx', '.ppt', '.pptx', '.txt']
        
        for user in df['user'].unique():
            if pd.isna(user):
                continue
            
            user_events = df[df['user'] == user]
            
            # Count sensitive file accesses
            sensitive_accesses = 0
            for ext in sensitive_extensions:
                sensitive_accesses += user_events['object_name'].str.contains(ext, na=False).sum()
            
            if sensitive_accesses > 50:  # Threshold
                suspicious_patterns.append({
                    'pattern': 'excessive_file_access',
                    'user': user,
                    'file_access_count': sensitive_accesses,
                    'risk_score': min(sensitive_accesses // 10, 10)
                })
        
        # Pattern 2: After-hours file access
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df['hour'] = df['timestamp'].dt.hour
        
        after_hours_events = df[(df['hour'] < 6) | (df['hour'] > 22)]
        
        for user in after_hours_events['user'].unique():
            if pd.isna(user):
                continue
            
            user_after_hours = after_hours_events[after_hours_events['user'] == user]
            
            if len(user_after_hours) > 10:  # Threshold
                suspicious_patterns.append({
                    'pattern': 'after_hours_file_access',
                    'user': user,
                    'after_hours_count': len(user_after_hours),
                    'risk_score': min(len(user_after_hours) // 5, 10)
                })
        
        return suspicious_patterns
    
    def behavioral_analysis(self, days_back=30):
        """Perform behavioral analysis using machine learning"""
        # Query for user login events
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
                            "term": {
                                "winlog.event_id": 4624
                            }
                        }
                    ]
                }
            },
            "size": 10000
        }
        
        response = self.es.search(index="windows-*", body=query)
        
        events = []
        for hit in response['hits']['hits']:
            source = hit['_source']
            timestamp = pd.to_datetime(source.get('@timestamp'))
            
            event = {
                'user': source.get('winlog', {}).get('event_data', {}).get('TargetUserName'),
                'hour': timestamp.hour,
                'day_of_week': timestamp.dayofweek,
                'computer': source.get('winlog', {}).get('computer_name'),
                'source_ip': source.get('winlog', {}).get('event_data', {}).get('IpAddress'),
                'logon_type': source.get('winlog', {}).get('event_data', {}).get('LogonType')
            }
            events.append(event)
        
        df = pd.DataFrame(events)
        
        # Feature engineering
        user_features = []
        for user in df['user'].unique():
            if pd.isna(user):
                continue
            
            user_data = df[df['user'] == user]
            
            features = {
                'user': user,
                'avg_hour': user_data['hour'].mean(),
                'hour_std': user_data['hour'].std(),
                'unique_computers': user_data['computer'].nunique(),
                'unique_ips': user_data['source_ip'].nunique(),
                'weekend_logins': user_data[user_data['day_of_week'].isin([5, 6])].shape[0],
                'total_logins': len(user_data)
            }
            user_features.append(features)
        
        features_df = pd.DataFrame(user_features)
        features_df = features_df.fillna(0)
        
        # Prepare features for ML
        feature_columns = ['avg_hour', 'hour_std', 'unique_computers', 'unique_ips', 'weekend_logins', 'total_logins']
        X = features_df[feature_columns]
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        # Apply Isolation Forest for anomaly detection
        iso_forest = IsolationForest(contamination=0.1, random_state=42)
        anomaly_labels = iso_forest.fit_predict(X_scaled)
        
        # Identify anomalous users
        features_df['anomaly'] = anomaly_labels
        anomalous_users = features_df[features_df['anomaly'] == -1]
        
        suspicious_patterns = []
        for _, user_data in anomalous_users.iterrows():
            suspicious_patterns.append({
                'pattern': 'behavioral_anomaly',
                'user': user_data['user'],
                'anomaly_score': iso_forest.decision_function(X_scaled)[features_df['user'] == user_data['user']][0],
                'features': user_data[feature_columns].to_dict(),
                'risk_score': 7
            })
        
        return suspicious_patterns
    
    def generate_hunt_report(self, output_file='threat_hunt_report.html'):
        """Generate comprehensive threat hunting report"""
        print("[+] Starting threat hunting analysis...")
        
        # Collect all hunting results
        lateral_movement = self.hunt_lateral_movement()
        privilege_escalation = self.hunt_privilege_escalation()
        data_exfiltration = self.hunt_data_exfiltration()
        behavioral_anomalies = self.behavioral_analysis()
        
        # Generate HTML report
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Threat Hunting Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background-color: #2c3e50; color: white; padding: 20px; }}
                .section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; }}
                .high-risk {{ background-color: #ffebee; border-left: 5px solid #f44336; }}
                .medium-risk {{ background-color: #fff3e0; border-left: 5px solid #ff9800; }}
                .low-risk {{ background-color: #e8f5e8; border-left: 5px solid #4caf50; }}
                table {{ width: 100%; border-collapse: collapse; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Threat Hunting Report</h1>
                <p>Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
            
            <div class="section">
                <h2>Executive Summary</h2>
                <p>Total suspicious patterns detected: {len(lateral_movement) + len(privilege_escalation) + len(data_exfiltration) + len(behavioral_anomalies)}</p>
                <ul>
                    <li>Lateral Movement Patterns: {len(lateral_movement)}</li>
                    <li>Privilege Escalation Patterns: {len(privilege_escalation)}</li>
                    <li>Data Exfiltration Patterns: {len(data_exfiltration)}</li>
                    <li>Behavioral Anomalies: {len(behavioral_anomalies)}</li>
                </ul>
            </div>
        """
        
        # Add detailed findings
        for category, findings in [
            ('Lateral Movement', lateral_movement),
            ('Privilege Escalation', privilege_escalation),
            ('Data Exfiltration', data_exfiltration),
            ('Behavioral Anomalies', behavioral_anomalies)
        ]:
            if findings:
                html_content += f"""
                <div class="section">
                    <h2>{category}</h2>
                    <table>
                        <tr><th>Pattern</th><th>Details</th><th>Risk Score</th></tr>
                """
                
                for finding in findings:
                    risk_class = 'high-risk' if finding['risk_score'] >= 7 else 'medium-risk' if finding['risk_score'] >= 4 else 'low-risk'
                    html_content += f"""
                        <tr class="{risk_class}">
                            <td>{finding['pattern']}</td>
                            <td>{str(finding)}</td>
                            <td>{finding['risk_score']}</td>
                        </tr>
                    """
                
                html_content += "</table></div>"
        
        html_content += """
        </body>
        </html>
        """
        
        # Save report
        with open(output_file, 'w') as f:
            f.write(html_content)
        
        print(f"[+] Threat hunting report saved to: {output_file}")
        return {
            'lateral_movement': lateral_movement,
            'privilege_escalation': privilege_escalation,
            'data_exfiltration': data_exfiltration,
            'behavioral_anomalies': behavioral_anomalies
        }

# Usage example
if __name__ == "__main__":
    hunter = ThreatHunter()
    
    # Run threat hunting
    results = hunter.generate_hunt_report()
    
    # Print summary
    total_findings = sum(len(findings) for findings in results.values())
    print(f"\n[+] Threat hunting completed. Found {total_findings} suspicious patterns.")
```

## 6. Tools and Technologies

### Recommended SIEM Platforms

#### Enterprise Solutions
```
Commercial SIEM Platforms:
├── Splunk Enterprise
│   ├── Pros: Powerful search, extensive apps, mature platform
│   ├── Cons: Expensive licensing, complex deployment
│   └── Best for: Large enterprises, complex environments
├── IBM QRadar
│   ├── Pros: Strong correlation engine, threat intelligence
│   ├── Cons: Steep learning curve, resource intensive
│   └── Best for: Compliance-focused organizations
├── ArcSight (Micro Focus)
│   ├── Pros: Real-time correlation, scalable architecture
│   ├── Cons: Complex configuration, high maintenance
│   └── Best for: Large-scale deployments
└── LogRhythm
    ├── Pros: Integrated SOAR, user-friendly interface
    ├── Cons: Limited customization, vendor lock-in
    └── Best for: Mid-size organizations
```

#### Open Source Solutions
```
Open Source SIEM Options:
├── ELK Stack (Elasticsearch, Logstash, Kibana)
│   ├── Pros: Free, flexible, large community
│   ├── Cons: Requires expertise, no built-in correlation
│   └── Components: Data storage, processing, visualization
├── OSSIM (AlienVault)
│   ├── Pros: Integrated security tools, correlation engine
│   ├── Cons: Limited scalability, basic reporting
│   └── Features: Asset discovery, vulnerability assessment
├── Wazuh
│   ├── Pros: Host-based detection, compliance reporting
│   ├── Cons: Limited network monitoring, basic UI
│   └── Strengths: File integrity, rootkit detection
└── Security Onion
    ├── Pros: Complete security monitoring platform
    ├── Cons: Resource intensive, complex setup
    └── Includes: Suricata, Zeek, Elasticsearch, Kibana
```

### Installation Guides

#### Wazuh Installation
```bash
#!/bin/bash
# Wazuh Manager Installation (Ubuntu/Debian)

# Install dependencies
sudo apt update
sudo apt install curl apt-transport-https lsb-release gnupg2 -y

# Add Wazuh repository
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo apt-key add -
echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list

# Install Wazuh manager
sudo apt update
sudo apt install wazuh-manager -y

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable wazuh-manager
sudo systemctl start wazuh-manager

# Install Wazuh API
sudo apt install nodejs npm -y
sudo apt install wazuh-api -y

# Configure API
sudo systemctl enable wazuh-api
sudo systemctl start wazuh-api

# Install Filebeat for log forwarding
curl -L -O https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-7.14.0-amd64.deb
sudo dpkg -i filebeat-7.14.0-amd64.deb

# Configure Filebeat for Wazuh
sudo tee /etc/filebeat/filebeat.yml > /dev/null <<EOF
filebeat.modules:
- module: wazuh
  alerts:
    enabled: true
  archives:
    enabled: false

setup.template.json.enabled: true
setup.template.json.path: '/etc/filebeat/wazuh-template.json'
setup.template.json.name: 'wazuh'
setup.ilm.enabled: false

output.elasticsearch:
  hosts: ['localhost:9200']
  index: 'wazuh-alerts-3.x-%{+yyyy.MM.dd}'
EOF

# Start Filebeat
sudo systemctl enable filebeat
sudo systemctl start filebeat

echo "[+] Wazuh installation completed"
echo "[+] Manager status: $(sudo systemctl is-active wazuh-manager)"
echo "[+] API status: $(sudo systemctl is-active wazuh-api)"
```

#### Security Onion Installation
```bash
#!/bin/bash
# Security Onion Installation

# Download Security Onion ISO
wget https://github.com/Security-Onion-Solutions/securityonion/releases/download/v2.3.90/securityonion-2.3.90.iso

# Create bootable USB or VM
# Boot from ISO and follow installation wizard

# Post-installation configuration
sudo so-setup

# Configure network interfaces
sudo so-interface

# Start services
sudo so-start

# Access web interface
echo "[+] Security Onion web interface: https://$(hostname -I | awk '{print $1}')"
echo "[+] Default credentials: admin/admin (change immediately)"
```

### Configuration Best Practices

#### SIEM Tuning Guidelines
```yaml
# SIEM Configuration Best Practices

Data Retention:
  hot_storage: 30_days      # Fast access for recent data
  warm_storage: 90_days     # Medium access for investigations
  cold_storage: 7_years     # Long-term compliance storage

Alert Tuning:
  false_positive_threshold: 5%
  alert_fatigue_prevention: true
  severity_levels:
    - critical: immediate_response
    - high: 1_hour_response
    - medium: 4_hour_response
    - low: 24_hour_response

Performance:
  indexing_rate: 50000_eps  # Events per second
  search_timeout: 300_seconds
  concurrent_searches: 10
  memory_allocation: 70%    # Of available system memory

Security:
  encryption_at_rest: true
  encryption_in_transit: true
  role_based_access: true
  audit_logging: enabled
```

#### Integration Examples

##### SOAR Integration
```python
#!/usr/bin/env python3
# SIEM-SOAR Integration Example

import requests
import json
from datetime import datetime

class SOARIntegration:
    def __init__(self, soar_url, api_key):
        self.soar_url = soar_url
        self.api_key = api_key
        self.headers = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json'
        }
    
    def create_incident(self, alert_data):
        """Create incident in SOAR platform"""
        incident_data = {
            'title': f"SIEM Alert: {alert_data['type']}",
            'description': alert_data['description'],
            'severity': alert_data['severity'],
            'source': 'SIEM',
            'artifacts': [
                {
                    'type': 'ip',
                    'value': alert_data.get('source_ip', 'N/A')
                },
                {
                    'type': 'user',
                    'value': alert_data.get('user', 'N/A')
                }
            ],
            'custom_fields': {
                'siem_rule_id': alert_data.get('rule_id'),
                'event_count': alert_data.get('event_count'),
                'first_seen': alert_data.get('first_seen'),
                'last_seen': alert_data.get('last_seen')
            }
        }
        
        response = requests.post(
            f"{self.soar_url}/api/incidents",
            headers=self.headers,
            json=incident_data
        )
        
        if response.status_code == 201:
            incident_id = response.json()['id']
            print(f"[+] Created incident {incident_id} in SOAR")
            return incident_id
        else:
            print(f"[-] Failed to create incident: {response.text}")
            return None
    
    def trigger_playbook(self, incident_id, playbook_name):
        """Trigger automated playbook"""
        playbook_data = {
            'incident_id': incident_id,
            'playbook': playbook_name,
            'parameters': {}
        }
        
        response = requests.post(
            f"{self.soar_url}/api/playbooks/execute",
            headers=self.headers,
            json=playbook_data
        )
        
        if response.status_code == 200:
            execution_id = response.json()['execution_id']
            print(f"[+] Started playbook execution {execution_id}")
            return execution_id
        else:
            print(f"[-] Failed to start playbook: {response.text}")
            return None

# Usage example
soar = SOARIntegration('https://soar.company.com', 'api_key_here')

# Example alert from SIEM
alert = {
    'type': 'brute_force_attack',
    'severity': 'high',
    'description': 'Multiple failed login attempts detected',
    'source_ip': '192.168.1.100',
    'user': 'admin',
    'rule_id': 'BF001',
    'event_count': 25,
    'first_seen': '2024-01-15T10:00:00Z',
    'last_seen': '2024-01-15T10:15:00Z'
}

# Create incident and trigger response
incident_id = soar.create_incident(alert)
if incident_id:
    soar.trigger_playbook(incident_id, 'brute_force_response')
```

## 7. Real-world Case Studies

### Case Study 1: Advanced Persistent Threat (APT) Detection

#### Scenario
A multinational corporation's SIEM detected unusual network traffic patterns that led to the discovery of a sophisticated APT campaign.

#### Timeline
```
Day 1: Initial Compromise
├── 09:15 - Spear phishing email received
├── 09:23 - User clicks malicious link
├── 09:24 - Initial payload downloaded
└── 09:25 - Backdoor established

Day 2-7: Reconnaissance
├── Network scanning activities
├── Credential harvesting
├── Lateral movement attempts
└── Data discovery

Day 8: Detection
├── 14:30 - SIEM correlation rule triggered
├── 14:35 - SOC analyst investigation begins
├── 15:00 - Incident escalated to Tier 2
└── 16:00 - APT activity confirmed

Day 9-10: Response
├── Containment measures implemented
├── Forensic analysis conducted
├── Threat actor expelled
└── Systems hardened
```

#### SIEM Detection Logic
```spl
# Splunk query that detected the APT
index=windows EventCode=4624 OR EventCode=4648 OR EventCode=4672
| eval user=coalesce(TargetUserName, SubjectUserName)
| bucket _time span=1h
| stats dc(Computer) as unique_systems, 
        dc(IpAddress) as unique_ips,
        count as total_events by _time, user
| where unique_systems > 5 AND unique_ips > 3
| eval risk_score=case(
    unique_systems > 10 AND unique_ips > 5, "high",
    unique_systems > 7 AND unique_ips > 3, "medium",
    1=1, "low"
)
| where risk_score="high"
```

#### Lessons Learned
1. **Early Detection**: Behavioral analytics identified anomalous login patterns
2. **Correlation Power**: Multiple data sources provided complete attack timeline
3. **Response Speed**: Automated alerting reduced detection time from days to hours
4. **Threat Intelligence**: IOC matching helped identify known APT group

### Case Study 2: Insider Threat Detection

#### Scenario
A financial services company used SIEM to detect an employee attempting to steal customer data.

#### Detection Methodology
```python
# Insider threat detection algorithm
def detect_insider_threat(user_activities):
    risk_indicators = {
        'after_hours_access': 0,
        'unusual_data_access': 0,
        'privilege_escalation': 0,
        'external_communication': 0,
        'data_download_volume': 0
    }
    
    # Analyze user behavior patterns
    for activity in user_activities:
        # After-hours access
        if activity['hour'] < 6 or activity['hour'] > 22:
            risk_indicators['after_hours_access'] += 1
        
        # Unusual data access
        if activity['data_classification'] == 'confidential':
            risk_indicators['unusual_data_access'] += 1
        
        # Large data downloads
        if activity['bytes_downloaded'] > 100000000:  # 100MB
            risk_indicators['data_download_volume'] += 1
    
    # Calculate risk score
    total_risk = sum(risk_indicators.values())
    
    if total_risk > 10:
        return 'high_risk'
    elif total_risk > 5:
        return 'medium_risk'
    else:
        return 'low_risk'
```

#### Key Indicators
- Unusual file access patterns (400% increase)
- After-hours database queries (15 instances)
- Large data exports (2.3GB over 3 days)
- USB device usage (policy violation)
- Email to personal account (data exfiltration attempt)

### Case Study 3: Ransomware Detection and Response

#### Scenario
A healthcare organization's SIEM detected and helped contain a ransomware attack within 45 minutes.

#### Detection Signatures
```yaml
# Ransomware detection rules
ransomware_indicators:
  file_operations:
    - rapid_file_encryption: 
        threshold: 100_files_per_minute
        file_extensions: [.encrypted, .locked, .crypto]
    - mass_file_deletion:
        threshold: 50_deletions_per_minute
    - shadow_copy_deletion:
        command: vssadmin delete shadows
  
  network_behavior:
    - tor_communication: true
    - bitcoin_addresses: regex_pattern
    - c2_communication: suspicious_domains
  
  system_changes:
    - registry_modifications: encryption_keys
    - service_modifications: backup_services
    - wallpaper_changes: ransom_note
```

#### Response Timeline
```
13:15 - Initial infection (email attachment)
13:18 - File encryption begins
13:20 - SIEM alert triggered (mass file operations)
13:22 - SOC analyst notified
13:25 - Network isolation initiated
13:30 - Incident commander engaged
13:45 - Affected systems contained
14:00 - Recovery process begins
```

## 8. Assessment and Validation

### Knowledge Check Questions

#### Beginner Level
1. What does SIEM stand for and what are its main components?
2. Explain the difference between SIM and SEM.
3. What are the common log sources in a SIEM environment?
4. Describe the log normalization process.
5. What is the purpose of correlation rules?

#### Intermediate Level
1. Design a correlation rule to detect brute force attacks.
2. Explain the difference between signature-based and behavior-based detection.
3. How would you tune SIEM rules to reduce false positives?
4. Describe the process of threat hunting using SIEM data.
5. What are the key performance metrics for a SIEM system?

#### Advanced Level
1. Design a machine learning model for anomaly detection in SIEM data.
2. Explain how to implement User and Entity Behavior Analytics (UEBA).
3. Describe the integration between SIEM and SOAR platforms.
4. How would you architect a SIEM solution for a multi-cloud environment?
5. Explain the challenges and solutions for SIEM in containerized environments.

### Practical Assignments

#### Assignment 1: SIEM Deployment
**Objective**: Deploy and configure a complete SIEM solution

**Tasks**:
1. Install ELK Stack or Splunk in a lab environment
2. Configure log collection from multiple sources
3. Create custom parsing rules for application logs
4. Implement basic correlation rules
5. Design dashboards for security monitoring

**Deliverables**:
- Installation documentation
- Configuration files
- Custom parsing rules
- Correlation rule definitions
- Dashboard screenshots

#### Assignment 2: Threat Hunting Exercise
**Objective**: Conduct threat hunting using SIEM data

**Tasks**:
1. Analyze provided log data for suspicious activities
2. Develop hunting hypotheses
3. Create search queries to validate hypotheses
4. Document findings and recommendations
5. Present results to stakeholders

**Deliverables**:
- Threat hunting methodology
- Search queries and results
- Analysis report
- Presentation slides

### Performance Metrics

#### SIEM Effectiveness Metrics
```python
# SIEM Performance Calculator
class SIEMMetrics:
    def __init__(self):
        self.metrics = {}
    
    def calculate_detection_rate(self, true_positives, false_negatives):
        """Calculate detection rate (sensitivity)"""
        return true_positives / (true_positives + false_negatives)
    
    def calculate_false_positive_rate(self, false_positives, true_negatives):
        """Calculate false positive rate"""
        return false_positives / (false_positives + true_negatives)
    
    def calculate_precision(self, true_positives, false_positives):
        """Calculate precision (positive predictive value)"""
        return true_positives / (true_positives + false_positives)
    
    def calculate_f1_score(self, precision, recall):
        """Calculate F1 score"""
        return 2 * (precision * recall) / (precision + recall)
    
    def calculate_mttr(self, incident_times):
        """Calculate Mean Time to Response"""
        return sum(incident_times) / len(incident_times)
    
    def calculate_mttd(self, detection_times):
        """Calculate Mean Time to Detection"""
        return sum(detection_times) / len(detection_times)

# Example usage
metrics = SIEMMetrics()

# Sample data
true_positives = 85
false_positives = 15
false_negatives = 5
true_negatives = 895

# Calculate metrics
detection_rate = metrics.calculate_detection_rate(true_positives, false_negatives)
fpr = metrics.calculate_false_positive_rate(false_positives, true_negatives)
precision = metrics.calculate_precision(true_positives, false_positives)
f1_score = metrics.calculate_f1_score(precision, detection_rate)

print(f"Detection Rate: {detection_rate:.2%}")
print(f"False Positive Rate: {fpr:.2%}")
print(f"Precision: {precision:.2%}")
print(f"F1 Score: {f1_score:.2f}")
```

## 9. Advanced Topics

### AI/ML in SIEM

#### Machine Learning Applications
```python
# ML-Enhanced SIEM Analytics
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report

class MLSIEMAnalytics:
    def __init__(self):
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.label_encoders = {}
    
    def prepare_features(self, log_data):
        """Prepare features for ML model"""
        features = pd.DataFrame()
        
        # Time-based features
        log_data['timestamp'] = pd.to_datetime(log_data['timestamp'])
        features['hour'] = log_data['timestamp'].dt.hour
        features['day_of_week'] = log_data['timestamp'].dt.dayofweek
        features['is_weekend'] = (log_data['timestamp'].dt.dayofweek >= 5).astype(int)
        
        # Categorical features
        categorical_columns = ['event_type', 'source_ip', 'user', 'computer']
        for col in categorical_columns:
            if col in log_data.columns:
                if col not in self.label_encoders:
                    self.label_encoders[col] = LabelEncoder()
                    features[f'{col}_encoded'] = self.label_encoders[col].fit_transform(log_data[col].fillna('unknown'))
                else:
                    features[f'{col}_encoded'] = self.label_encoders[col].transform(log_data[col].fillna('unknown'))
        
        # Numerical features
        numerical_columns = ['bytes_transferred', 'duration', 'port']
        for col in numerical_columns:
            if col in log_data.columns:
                features[col] = log_data[col].fillna(0)
        
        # Behavioral features
        features['login_frequency'] = log_data.groupby('user')['timestamp'].transform('count')
        features['unique_ips_per_user'] = log_data.groupby('user')['source_ip'].transform('nunique')
        
        return features
    
    def train_model(self, training_data, labels):
        """Train the ML model"""
        features = self.prepare_features(training_data)
        X_train, X_test, y_train, y_test = train_test_split(features, labels, test_size=0.2, random_state=42)
        
        self.model.fit(X_train, y_train)
        
        # Evaluate model
        y_pred = self.model.predict(X_test)
        print(classification_report(y_test, y_pred))
        
        return self.model
    
    def predict_anomalies(self, new_data):
        """Predict anomalies in new data"""
        features = self.prepare_features(new_data)
        predictions = self.model.predict(features)
        probabilities = self.model.predict_proba(features)
        
        return predictions, probabilities
```

### Cloud SIEM Architecture

#### Multi-Cloud SIEM Design
```yaml
# Cloud SIEM Architecture
cloud_siem_architecture:
  data_ingestion:
    aws:
      - cloudtrail_logs
      - vpc_flow_logs
      - guardduty_findings
      - config_changes
    azure:
      - activity_logs
      - security_center_alerts
      - network_security_groups
      - key_vault_logs
    gcp:
      - cloud_audit_logs
      - vpc_flow_logs
      - security_command_center
      - cloud_dns_logs
  
  processing_layer:
    stream_processing:
      - apache_kafka
      - aws_kinesis
      - azure_event_hubs
    batch_processing:
      - apache_spark
      - aws_emr
      - azure_databricks
  
  storage_layer:
    hot_storage:
      - elasticsearch
      - aws_opensearch
      - azure_sentinel
    cold_storage:
      - aws_s3
      - azure_blob_storage
      - gcp_cloud_storage
  
  analytics_layer:
    correlation_engine:
      - custom_rules
      - ml_models
      - threat_intelligence
    visualization:
      - kibana
      - grafana
      - custom_dashboards
```

### Container Security Monitoring

#### Kubernetes SIEM Integration
```yaml
# Kubernetes Security Monitoring
apiVersion: v1
kind: ConfigMap
metadata:
  name: siem-config
data:
  fluent-bit.conf: |
    [SERVICE]
        Flush         1
        Log_Level     info
        Daemon        off
        Parsers_File  parsers.conf
    
    [INPUT]
        Name              tail
        Path              /var/log/containers/*.log
        Parser            docker
        Tag               kube.*
        Refresh_Interval  5
        Mem_Buf_Limit     50MB
        Skip_Long_Lines   On
    
    [INPUT]
        Name              systemd
        Tag               host.*
        Systemd_Filter    _SYSTEMD_UNIT=kubelet.service
        Read_From_Tail    On
    
    [FILTER]
        Name                kubernetes
        Match               kube.*
        Kube_URL            https://kubernetes.default.svc:443
        Kube_CA_File        /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
        Kube_Token_File     /var/run/secrets/kubernetes.io/serviceaccount/token
        Merge_Log           On
        K8S-Logging.Parser  On
        K8S-Logging.Exclude Off
    
    [OUTPUT]
        Name  es
        Match *
        Host  elasticsearch.logging.svc.cluster.local
        Port  9200
        Index kubernetes_logs
        Type  _doc
```

## 10. Resources and References

### Official Documentation
- [Splunk Documentation](https://docs.splunk.com/)
- [Elastic Stack Documentation](https://www.elastic.co/guide/)
- [Wazuh Documentation](https://documentation.wazuh.com/)
- [IBM QRadar Documentation](https://www.ibm.com/docs/en/qradar-siem)

### Industry Standards
- **NIST Cybersecurity Framework**: Guidelines for SIEM implementation
- **ISO 27001**: Information security management standards
- **SANS SIEM Guidelines**: Best practices for SIEM deployment
- **MITRE ATT&CK Framework**: Threat detection and response

### Research Papers
1. "A Survey of SIEM Technology" - IEEE Security & Privacy
2. "Machine Learning for Cybersecurity" - ACM Computing Surveys
3. "Behavioral Analytics in Cybersecurity" - Journal of Cybersecurity
4. "Cloud SIEM Architecture Patterns" - IEEE Cloud Computing

### Community Resources
- **Splunk Community**: forums.splunk.com
- **Elastic Community**: discuss.elastic.co
- **SANS Community**: community.sans.org
- **Reddit r/cybersecurity**: Active SIEM discussions

### Training and Certification
- **Splunk Certified Power User**
- **Elastic Certified Engineer**
- **SANS SEC511: Continuous Monitoring and Security Operations**
- **GCIH: GIAC Certified Incident Handler**

### Books
1. "Security Information and Event Management (SIEM) Implementation" - David Miller
2. "The Practice of Network Security Monitoring" - Richard Bejtlich
3. "Applied Security Visualization" - Raffael Marty
4. "Threat Hunting with Elastic Stack" - Andrew Pease

---

**Level 2 Tamamlama Kriterleri:**

✅ **SIEM Temellerini Anlama**
- SIEM mimarisi ve bileşenleri
- Log kaynaklarını tanımlama
- Normalizasyon ve parsing süreçleri

✅ **Pratik Uygulama**
- ELK Stack kurulumu ve konfigürasyonu
- Wazuh deployment
- Custom log parser geliştirme

✅ **Correlation ve Analytics**
- Güvenlik kuralları yazma
- Threat hunting teknikleri
- Behavioral analytics

✅ **Gerçek Dünya Senaryoları**
- APT detection case study
- Insider threat detection
- Ransomware response

✅ **İleri Konular**
- Machine learning entegrasyonu
- Cloud SIEM architecture
- Container security monitoring

Bu modül tamamlandığında, öğrenciler enterprise düzeyde SIEM operasyonlarını yönetebilir ve gelişmiş threat hunting aktiviteleri gerçekleştirebilir duruma gelecektir.