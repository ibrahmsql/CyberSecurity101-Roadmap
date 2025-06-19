# 🔍 Dijital Adli Tıp (Digital Forensics)

## 📋 İçindekiler
- [Giriş ve Önem](#giriş-ve-önem)
- [Öğrenme Hedefleri](#öğrenme-hedefleri)
- [Gerçek Dünya Uygulamaları](#gerçek-dünya-uygulamaları)
- [Teorik Temeller](#teorik-temeller)
- [Teknik Detaylar](#teknik-detaylar)
- [Uygulamalı Laboratuvar](#uygulamalı-laboratuvar)
- [Pratik Egzersizler](#pratik-egzersizler)
- [Önerilen Araçlar](#önerilen-araçlar)
- [Yapılandırma En İyi Uygulamaları](#yapılandırma-en-iyi-uygulamaları)
- [Gerçek Dünya Vaka Çalışmaları](#gerçek-dünya-vaka-çalışmaları)
- [Bilgi Kontrol Soruları](#bilgi-kontrol-soruları)
- [Pratik Ödevler](#pratik-ödevler)
- [Performans Metrikleri](#performans-metrikleri)
- [Yapay Zeka ve Makine Öğrenimi](#yapay-zeka-ve-makine-öğrenimi)
- [Kuantum Dirençli Forensics](#kuantum-dirençli-forensics)
- [Kaynaklar ve Referanslar](#kaynaklar-ve-referanslar)

## 🎯 Giriş ve Önem

Dijital adli tıp, dijital cihazlardan kanıt toplama, analiz etme ve sunum yapma bilim dalıdır. Modern siber güvenlik operasyonlarının kritik bir bileşeni olarak, güvenlik olaylarının araştırılması, yasal süreçlerin desteklenmesi ve organizasyonel güvenlik duruşunun güçlendirilmesinde hayati rol oynar.

### 🌟 Neden Önemli?

- **Yasal Gereklilik**: Siber suçların soruşturulması
- **Olay Müdahalesi**: Güvenlik ihlallerinin analizi
- **Uyumluluk**: Düzenleyici gereksinimlerin karşılanması
- **Risk Yönetimi**: Gelecekteki tehditlerin önlenmesi
- **Kanıt Toplama**: Hukuki süreçlerde kullanılabilir delil elde etme

## 🎯 Öğrenme Hedefleri

### 📚 Teorik Bilgi
- **Forensic Metodoloji**: NIST, RFC 3227 standartları
- **Kanıt Zinciri**: Chain of custody prosedürleri
- **Dosya Sistemleri**: NTFS, EXT4, APFS analizi
- **Network Forensics**: Trafik analizi ve log inceleme
- **Memory Forensics**: RAM analizi teknikleri
- **Mobile Forensics**: iOS/Android cihaz analizi

### 🛠️ Pratik Beceriler
- **Disk Imaging**: Bit-level kopyalama
- **File Recovery**: Silinmiş dosya kurtarma
- **Timeline Analysis**: Olay zaman çizelgesi oluşturma
- **Artifact Analysis**: Sistem artifact'larının incelenmesi
- **Report Writing**: Teknik rapor hazırlama
- **Expert Testimony**: Uzman tanıklık becerileri

### 🔧 Teknik Yetkinlikler
- **Autopsy/Sleuth Kit**: Open source forensic suite
- **Volatility**: Memory analysis framework
- **Wireshark**: Network protocol analyzer
- **FTK/EnCase**: Commercial forensic tools
- **YARA**: Pattern matching for forensics
- **Python Scripting**: Custom forensic tools

## 🌍 Gerçek Dünya Uygulamaları

### 🏢 Kurumsal Güvenlik
- **Insider Threat Investigation**: İçeriden tehdit analizi
- **Data Breach Response**: Veri ihlali müdahalesi
- **Intellectual Property Theft**: Fikri mülkiyet hırsızlığı
- **Employee Misconduct**: Çalışan suistimali

### 🚔 Kolluk Kuvvetleri
- **Cybercrime Investigation**: Siber suç soruşturması
- **Child Exploitation**: Çocuk istismarı vakaları
- **Financial Fraud**: Mali dolandırıcılık
- **Terrorism Cases**: Terör vakaları

### ⚖️ Hukuki Süreçler
- **Civil Litigation**: Hukuki davalar
- **Divorce Proceedings**: Boşanma davaları
- **Employment Disputes**: İş uyuşmazlıkları
- **Insurance Claims**: Sigorta talepleri

## 📖 Teorik Temeller

### 🔬 Forensic Bilim İlkeleri

#### Locard's Exchange Principle
"Her temas bir iz bırakır" - Dijital ortamda da geçerli

```python
# Digital Evidence Principles
class DigitalEvidencePrinciples:
    def __init__(self):
        self.principles = {
            'authenticity': 'Kanıtın orijinalliği',
            'reliability': 'Kanıtın güvenilirliği', 
            'completeness': 'Kanıtın tamlığı',
            'admissibility': 'Kanıtın kabul edilebilirliği'
        }
    
    def validate_evidence(self, evidence):
        """Kanıt doğrulama süreci"""
        validation_results = {}
        
        # Hash doğrulama
        validation_results['hash_verified'] = self.verify_hash(evidence)
        
        # Zaman damgası kontrolü
        validation_results['timestamp_valid'] = self.verify_timestamp(evidence)
        
        # Chain of custody kontrolü
        validation_results['custody_intact'] = self.verify_custody_chain(evidence)
        
        return validation_results
    
    def verify_hash(self, evidence):
        """Hash değeri doğrulama"""
        import hashlib
        
        # Orijinal hash ile karşılaştır
        current_hash = hashlib.sha256(evidence['data']).hexdigest()
        return current_hash == evidence['original_hash']
    
    def verify_timestamp(self, evidence):
        """Zaman damgası doğrulama"""
        from datetime import datetime
        
        # Zaman damgası tutarlılık kontrolü
        creation_time = evidence.get('creation_time')
        acquisition_time = evidence.get('acquisition_time')
        
        if creation_time and acquisition_time:
            return creation_time <= acquisition_time
        return False
    
    def verify_custody_chain(self, evidence):
        """Kanıt zinciri doğrulama"""
        custody_chain = evidence.get('custody_chain', [])
        
        # Her transfer için gerekli bilgilerin varlığını kontrol et
        required_fields = ['handler', 'timestamp', 'action', 'signature']
        
        for transfer in custody_chain:
            if not all(field in transfer for field in required_fields):
                return False
        
        return True
```

### 📁 Dosya Sistemi Forensics

#### NTFS Forensic Analysis

```python
# NTFS Forensic Analyzer
import struct
import datetime
from collections import namedtuple

class NTFSForensicAnalyzer:
    def __init__(self, image_path):
        self.image_path = image_path
        self.boot_sector = None
        self.mft_entries = []
        
    def parse_boot_sector(self):
        """NTFS boot sector analizi"""
        with open(self.image_path, 'rb') as f:
            boot_data = f.read(512)
        
        # NTFS boot sector structure
        boot_format = '<3s8sHBHBHHLLLLLLLLHHLLLLLL'
        boot_fields = [
            'jmp_instruction', 'oem_id', 'bytes_per_sector',
            'sectors_per_cluster', 'reserved_sectors', 'fat_count',
            'root_entries', 'total_sectors_16', 'media_descriptor',
            'fat_size_16', 'sectors_per_track', 'head_count',
            'hidden_sectors', 'total_sectors_32', 'unused1',
            'unused2', 'total_sectors', 'mft_cluster', 'mft_mirror_cluster',
            'clusters_per_file_record', 'clusters_per_index_buffer',
            'volume_serial', 'unused3'
        ]
        
        BootSector = namedtuple('BootSector', boot_fields)
        self.boot_sector = BootSector._make(struct.unpack(boot_format, boot_data[:88]))
        
        return self.boot_sector
    
    def parse_mft_entry(self, entry_data):
        """MFT entry analizi"""
        if len(entry_data) < 48:
            return None
        
        # MFT entry header
        signature = entry_data[:4]
        if signature != b'FILE':
            return None
        
        # Parse MFT entry fields
        mft_entry = {
            'signature': signature,
            'update_sequence_offset': struct.unpack('<H', entry_data[4:6])[0],
            'update_sequence_size': struct.unpack('<H', entry_data[6:8])[0],
            'logfile_sequence_number': struct.unpack('<Q', entry_data[8:16])[0],
            'sequence_number': struct.unpack('<H', entry_data[16:18])[0],
            'hard_link_count': struct.unpack('<H', entry_data[18:20])[0],
            'first_attribute_offset': struct.unpack('<H', entry_data[20:22])[0],
            'flags': struct.unpack('<H', entry_data[22:24])[0],
            'used_size': struct.unpack('<L', entry_data[24:28])[0],
            'allocated_size': struct.unpack('<L', entry_data[28:32])[0]
        }
        
        # Parse attributes
        mft_entry['attributes'] = self.parse_attributes(entry_data, mft_entry['first_attribute_offset'])
        
        return mft_entry
    
    def parse_attributes(self, entry_data, offset):
        """MFT attribute analizi"""
        attributes = []
        current_offset = offset
        
        while current_offset < len(entry_data) - 4:
            attr_type = struct.unpack('<L', entry_data[current_offset:current_offset+4])[0]
            
            if attr_type == 0xFFFFFFFF:  # End marker
                break
            
            attr_length = struct.unpack('<L', entry_data[current_offset+4:current_offset+8])[0]
            
            if attr_length == 0 or current_offset + attr_length > len(entry_data):
                break
            
            attribute = {
                'type': attr_type,
                'length': attr_length,
                'non_resident': bool(entry_data[current_offset+8]),
                'name_length': entry_data[current_offset+9],
                'name_offset': struct.unpack('<H', entry_data[current_offset+10:current_offset+12])[0]
            }
            
            # Parse specific attribute types
            if attr_type == 0x10:  # $STANDARD_INFORMATION
                attribute.update(self.parse_standard_info(entry_data[current_offset:current_offset+attr_length]))
            elif attr_type == 0x30:  # $FILE_NAME
                attribute.update(self.parse_filename(entry_data[current_offset:current_offset+attr_length]))
            
            attributes.append(attribute)
            current_offset += attr_length
        
        return attributes
    
    def parse_standard_info(self, attr_data):
        """$STANDARD_INFORMATION attribute analizi"""
        if len(attr_data) < 72:
            return {}
        
        # Windows FILETIME to Unix timestamp conversion
        def filetime_to_unix(filetime):
            return (filetime - 116444736000000000) / 10000000
        
        created = struct.unpack('<Q', attr_data[24:32])[0]
        modified = struct.unpack('<Q', attr_data[32:40])[0]
        mft_modified = struct.unpack('<Q', attr_data[40:48])[0]
        accessed = struct.unpack('<Q', attr_data[48:56])[0]
        
        return {
            'created_time': datetime.datetime.fromtimestamp(filetime_to_unix(created)),
            'modified_time': datetime.datetime.fromtimestamp(filetime_to_unix(modified)),
            'mft_modified_time': datetime.datetime.fromtimestamp(filetime_to_unix(mft_modified)),
            'accessed_time': datetime.datetime.fromtimestamp(filetime_to_unix(accessed)),
            'file_attributes': struct.unpack('<L', attr_data[56:60])[0]
        }
    
    def parse_filename(self, attr_data):
        """$FILE_NAME attribute analizi"""
        if len(attr_data) < 66:
            return {}
        
        filename_length = attr_data[64]
        namespace = attr_data[65]
        
        if len(attr_data) < 66 + filename_length * 2:
            return {}
        
        filename = attr_data[66:66 + filename_length * 2].decode('utf-16le', errors='ignore')
        
        return {
            'filename': filename,
            'namespace': namespace,
            'parent_directory': struct.unpack('<Q', attr_data[16:24])[0]
        }
    
    def extract_deleted_files(self):
        """Silinmiş dosyaları tespit et"""
        deleted_files = []
        
        for entry in self.mft_entries:
            if entry and entry.get('flags', 0) & 0x01 == 0:  # Not in use
                for attr in entry.get('attributes', []):
                    if attr.get('type') == 0x30 and 'filename' in attr:  # $FILE_NAME
                        deleted_files.append({
                            'filename': attr['filename'],
                            'mft_entry': entry,
                            'recovery_possible': self.assess_recovery_possibility(entry)
                        })
        
        return deleted_files
    
    def assess_recovery_possibility(self, mft_entry):
        """Dosya kurtarma olasılığını değerlendir"""
        # Simplified assessment
        if mft_entry.get('flags', 0) & 0x01 == 0:  # File deleted
            # Check if data runs are still intact
            for attr in mft_entry.get('attributes', []):
                if attr.get('type') == 0x80:  # $DATA
                    return not attr.get('non_resident', False)  # Resident data easier to recover
        return False
    
    def generate_timeline(self):
        """Dosya sistemi timeline oluştur"""
        timeline_events = []
        
        for entry in self.mft_entries:
            if not entry:
                continue
            
            filename = "Unknown"
            timestamps = {}
            
            for attr in entry.get('attributes', []):
                if attr.get('type') == 0x30 and 'filename' in attr:
                    filename = attr['filename']
                elif attr.get('type') == 0x10:  # $STANDARD_INFORMATION
                    timestamps = {
                        'created': attr.get('created_time'),
                        'modified': attr.get('modified_time'),
                        'accessed': attr.get('accessed_time'),
                        'mft_modified': attr.get('mft_modified_time')
                    }
            
            for event_type, timestamp in timestamps.items():
                if timestamp:
                    timeline_events.append({
                        'timestamp': timestamp,
                        'event_type': event_type,
                        'filename': filename,
                        'mft_entry_id': entry.get('sequence_number')
                    })
        
        # Sort by timestamp
        timeline_events.sort(key=lambda x: x['timestamp'])
        return timeline_events

# Usage example
if __name__ == "__main__":
    analyzer = NTFSForensicAnalyzer("/path/to/disk/image.dd")
    boot_sector = analyzer.parse_boot_sector()
    print(f"NTFS Volume Serial: {boot_sector.volume_serial}")
    
    # deleted_files = analyzer.extract_deleted_files()
    # timeline = analyzer.generate_timeline()
```

### 🧠 Memory Forensics

#### Volatility Framework Integration

```python
# Advanced Memory Forensics Analyzer
import subprocess
import json
import re
from datetime import datetime

class MemoryForensicsAnalyzer:
    def __init__(self, memory_dump_path):
        self.memory_dump = memory_dump_path
        self.profile = None
        self.analysis_results = {}
        
    def detect_profile(self):
        """Memory dump profil tespiti"""
        cmd = f"volatility -f {self.memory_dump} imageinfo"
        
        try:
            result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=300)
            output = result.stdout
            
            # Extract suggested profiles
            profile_match = re.search(r'Suggested Profile\(s\) : (.+)', output)
            if profile_match:
                profiles = profile_match.group(1).split(', ')
                self.profile = profiles[0].strip()
                return self.profile
        except Exception as e:
            print(f"Profile detection failed: {e}")
        
        return None
    
    def analyze_processes(self):
        """Process analizi"""
        if not self.profile:
            self.detect_profile()
        
        cmd = f"volatility -f {self.memory_dump} --profile={self.profile} pslist"
        
        try:
            result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=300)
            processes = self.parse_pslist_output(result.stdout)
            
            # Detect suspicious processes
            suspicious_processes = self.detect_suspicious_processes(processes)
            
            self.analysis_results['processes'] = {
                'total_count': len(processes),
                'suspicious_count': len(suspicious_processes),
                'processes': processes,
                'suspicious': suspicious_processes
            }
            
            return self.analysis_results['processes']
        
        except Exception as e:
            print(f"Process analysis failed: {e}")
            return None
    
    def parse_pslist_output(self, output):
        """pslist çıktısını parse et"""
        processes = []
        lines = output.split('\n')
        
        for line in lines[2:]:  # Skip header lines
            if line.strip():
                parts = line.split()
                if len(parts) >= 6:
                    process = {
                        'name': parts[0],
                        'pid': int(parts[1]),
                        'ppid': int(parts[2]),
                        'threads': int(parts[3]),
                        'handles': int(parts[4]),
                        'start_time': ' '.join(parts[5:7]) if len(parts) >= 7 else 'Unknown'
                    }
                    processes.append(process)
        
        return processes
    
    def detect_suspicious_processes(self, processes):
        """Şüpheli process tespiti"""
        suspicious = []
        
        # Suspicious process names
        suspicious_names = [
            'cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe',
            'mshta.exe', 'rundll32.exe', 'regsvr32.exe', 'certutil.exe'
        ]
        
        # Suspicious patterns
        for process in processes:
            suspicion_score = 0
            reasons = []
            
            # Check process name
            if process['name'].lower() in [name.lower() for name in suspicious_names]:
                suspicion_score += 3
                reasons.append(f"Suspicious process name: {process['name']}")
            
            # Check for processes with no parent (PPID 0 but not system processes)
            if process['ppid'] == 0 and process['pid'] not in [0, 4]:
                suspicion_score += 2
                reasons.append("Orphaned process")
            
            # Check for unusual thread/handle counts
            if process['threads'] > 100:
                suspicion_score += 1
                reasons.append(f"High thread count: {process['threads']}")
            
            if process['handles'] > 1000:
                suspicion_score += 1
                reasons.append(f"High handle count: {process['handles']}")
            
            if suspicion_score >= 2:
                process['suspicion_score'] = suspicion_score
                process['suspicion_reasons'] = reasons
                suspicious.append(process)
        
        return suspicious
    
    def analyze_network_connections(self):
        """Network bağlantı analizi"""
        cmd = f"volatility -f {self.memory_dump} --profile={self.profile} netscan"
        
        try:
            result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=300)
            connections = self.parse_netscan_output(result.stdout)
            
            # Analyze for suspicious connections
            suspicious_connections = self.detect_suspicious_connections(connections)
            
            self.analysis_results['network'] = {
                'total_connections': len(connections),
                'suspicious_count': len(suspicious_connections),
                'connections': connections,
                'suspicious': suspicious_connections
            }
            
            return self.analysis_results['network']
        
        except Exception as e:
            print(f"Network analysis failed: {e}")
            return None
    
    def parse_netscan_output(self, output):
        """netscan çıktısını parse et"""
        connections = []
        lines = output.split('\n')
        
        for line in lines[2:]:  # Skip header
            if line.strip() and 'TCP' in line or 'UDP' in line:
                parts = line.split()
                if len(parts) >= 5:
                    connection = {
                        'protocol': parts[1],
                        'local_address': parts[2],
                        'foreign_address': parts[3],
                        'state': parts[4] if len(parts) > 4 else 'Unknown',
                        'pid': parts[5] if len(parts) > 5 else 'Unknown',
                        'process': parts[6] if len(parts) > 6 else 'Unknown'
                    }
                    connections.append(connection)
        
        return connections
    
    def detect_suspicious_connections(self, connections):
        """Şüpheli network bağlantıları tespit et"""
        suspicious = []
        
        # Suspicious ports and IPs
        suspicious_ports = [4444, 5555, 6666, 8080, 9999]
        private_ip_ranges = [
            '10.', '172.16.', '172.17.', '172.18.', '172.19.',
            '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
            '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
            '172.30.', '172.31.', '192.168.'
        ]
        
        for conn in connections:
            suspicion_score = 0
            reasons = []
            
            # Check for suspicious ports
            try:
                local_port = int(conn['local_address'].split(':')[-1])
                foreign_port = int(conn['foreign_address'].split(':')[-1])
                
                if local_port in suspicious_ports or foreign_port in suspicious_ports:
                    suspicion_score += 2
                    reasons.append(f"Suspicious port usage: {local_port}/{foreign_port}")
            except:
                pass
            
            # Check for external connections from suspicious processes
            foreign_ip = conn['foreign_address'].split(':')[0]
            if not any(foreign_ip.startswith(private) for private in private_ip_ranges):
                if conn['process'].lower() in ['cmd.exe', 'powershell.exe', 'rundll32.exe']:
                    suspicion_score += 3
                    reasons.append(f"External connection from suspicious process: {conn['process']}")
            
            # Check for established connections to unknown processes
            if conn['state'] == 'ESTABLISHED' and conn['process'] == 'Unknown':
                suspicion_score += 1
                reasons.append("Established connection to unknown process")
            
            if suspicion_score >= 2:
                conn['suspicion_score'] = suspicion_score
                conn['suspicion_reasons'] = reasons
                suspicious.append(conn)
        
        return suspicious
    
    def extract_registry_artifacts(self):
        """Registry artifact çıkarma"""
        artifacts = {}
        
        # Extract common registry keys
        registry_commands = {
            'run_keys': 'printkey -K "Microsoft\\Windows\\CurrentVersion\\Run"',
            'runonce_keys': 'printkey -K "Microsoft\\Windows\\CurrentVersion\\RunOnce"',
            'services': 'printkey -K "ControlSet001\\Services"',
            'installed_programs': 'printkey -K "Microsoft\\Windows\\CurrentVersion\\Uninstall"'
        }
        
        for key_name, reg_command in registry_commands.items():
            cmd = f"volatility -f {self.memory_dump} --profile={self.profile} {reg_command}"
            
            try:
                result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=300)
                artifacts[key_name] = self.parse_registry_output(result.stdout)
            except Exception as e:
                print(f"Registry extraction failed for {key_name}: {e}")
                artifacts[key_name] = []
        
        self.analysis_results['registry'] = artifacts
        return artifacts
    
    def parse_registry_output(self, output):
        """Registry çıktısını parse et"""
        entries = []
        lines = output.split('\n')
        
        current_entry = {}
        for line in lines:
            line = line.strip()
            if line.startswith('REG_'):
                if current_entry:
                    entries.append(current_entry)
                    current_entry = {}
                
                parts = line.split(':', 1)
                if len(parts) == 2:
                    current_entry['type'] = parts[0].strip()
                    current_entry['value'] = parts[1].strip()
            elif line and not line.startswith('---'):
                if 'name' not in current_entry:
                    current_entry['name'] = line
        
        if current_entry:
            entries.append(current_entry)
        
        return entries
    
    def generate_comprehensive_report(self):
        """Kapsamlı analiz raporu oluştur"""
        report = {
            'analysis_timestamp': datetime.now().isoformat(),
            'memory_dump': self.memory_dump,
            'profile': self.profile,
            'summary': {},
            'findings': self.analysis_results
        }
        
        # Generate summary
        summary = {
            'total_processes': len(self.analysis_results.get('processes', {}).get('processes', [])),
            'suspicious_processes': len(self.analysis_results.get('processes', {}).get('suspicious', [])),
            'total_connections': len(self.analysis_results.get('network', {}).get('connections', [])),
            'suspicious_connections': len(self.analysis_results.get('network', {}).get('suspicious', [])),
            'registry_artifacts': sum(len(artifacts) for artifacts in self.analysis_results.get('registry', {}).values())
        }
        
        # Calculate risk score
        risk_score = 0
        if summary['suspicious_processes'] > 0:
            risk_score += summary['suspicious_processes'] * 10
        if summary['suspicious_connections'] > 0:
            risk_score += summary['suspicious_connections'] * 5
        
        summary['risk_score'] = min(risk_score, 100)  # Cap at 100
        summary['risk_level'] = self.calculate_risk_level(summary['risk_score'])
        
        report['summary'] = summary
        return report
    
    def calculate_risk_level(self, score):
        """Risk seviyesi hesapla"""
        if score >= 70:
            return 'HIGH'
        elif score >= 40:
            return 'MEDIUM'
        elif score >= 20:
            return 'LOW'
        else:
            return 'MINIMAL'
    
    def export_report(self, output_file):
        """Raporu dosyaya aktar"""
        report = self.generate_comprehensive_report()
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        print(f"Analysis report exported to: {output_file}")
        return output_file

# Usage example
if __name__ == "__main__":
    analyzer = MemoryForensicsAnalyzer("/path/to/memory.dmp")
    
    # Perform analysis
    analyzer.detect_profile()
    analyzer.analyze_processes()
    analyzer.analyze_network_connections()
    analyzer.extract_registry_artifacts()
    
    # Generate and export report
    analyzer.export_report("memory_analysis_report.json")
```

### 🌐 Network Forensics

#### Packet Analysis Framework

```python
# Network Forensics Analyzer
import pyshark
import ipaddress
import json
from collections import defaultdict, Counter
from datetime import datetime
import geoip2.database
import hashlib

class NetworkForensicsAnalyzer:
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.packets = []
        self.connections = defaultdict(list)
        self.protocols = Counter()
        self.suspicious_activities = []
        
    def load_packets(self, packet_limit=None):
        """PCAP dosyasından paketleri yükle"""
        try:
            capture = pyshark.FileCapture(self.pcap_file)
            
            count = 0
            for packet in capture:
                if packet_limit and count >= packet_limit:
                    break
                
                packet_info = self.extract_packet_info(packet)
                if packet_info:
                    self.packets.append(packet_info)
                    self.update_statistics(packet_info)
                
                count += 1
            
            capture.close()
            print(f"Loaded {len(self.packets)} packets")
            
        except Exception as e:
            print(f"Error loading packets: {e}")
    
    def extract_packet_info(self, packet):
        """Paket bilgilerini çıkar"""
        try:
            packet_info = {
                'timestamp': float(packet.sniff_timestamp),
                'length': int(packet.length),
                'protocol': packet.highest_layer
            }
            
            # IP layer information
            if hasattr(packet, 'ip'):
                packet_info.update({
                    'src_ip': packet.ip.src,
                    'dst_ip': packet.ip.dst,
                    'ttl': int(packet.ip.ttl),
                    'ip_flags': packet.ip.flags
                })
            
            # TCP layer information
            if hasattr(packet, 'tcp'):
                packet_info.update({
                    'src_port': int(packet.tcp.srcport),
                    'dst_port': int(packet.tcp.dstport),
                    'tcp_flags': packet.tcp.flags,
                    'seq_num': int(packet.tcp.seq),
                    'ack_num': int(packet.tcp.ack) if hasattr(packet.tcp, 'ack') else 0
                })
            
            # UDP layer information
            elif hasattr(packet, 'udp'):
                packet_info.update({
                    'src_port': int(packet.udp.srcport),
                    'dst_port': int(packet.udp.dstport)
                })
            
            # HTTP layer information
            if hasattr(packet, 'http'):
                http_info = {}
                if hasattr(packet.http, 'request_method'):
                    http_info['method'] = packet.http.request_method
                if hasattr(packet.http, 'request_uri'):
                    http_info['uri'] = packet.http.request_uri
                if hasattr(packet.http, 'host'):
                    http_info['host'] = packet.http.host
                if hasattr(packet.http, 'user_agent'):
                    http_info['user_agent'] = packet.http.user_agent
                
                packet_info['http'] = http_info
            
            # DNS layer information
            if hasattr(packet, 'dns'):
                dns_info = {}
                if hasattr(packet.dns, 'qry_name'):
                    dns_info['query'] = packet.dns.qry_name
                if hasattr(packet.dns, 'resp_name'):
                    dns_info['response'] = packet.dns.resp_name
                if hasattr(packet.dns, 'flags_response'):
                    dns_info['is_response'] = packet.dns.flags_response == '1'
                
                packet_info['dns'] = dns_info
            
            return packet_info
            
        except Exception as e:
            print(f"Error extracting packet info: {e}")
            return None
    
    def update_statistics(self, packet_info):
        """İstatistikleri güncelle"""
        # Protocol statistics
        self.protocols[packet_info['protocol']] += 1
        
        # Connection tracking
        if 'src_ip' in packet_info and 'dst_ip' in packet_info:
            connection_key = f"{packet_info['src_ip']}:{packet_info.get('src_port', 0)}-{packet_info['dst_ip']}:{packet_info.get('dst_port', 0)}"
            self.connections[connection_key].append(packet_info)
    
    def detect_suspicious_activities(self):
        """Şüpheli aktiviteleri tespit et"""
        self.suspicious_activities = []
        
        # Port scanning detection
        self.detect_port_scanning()
        
        # DDoS detection
        self.detect_ddos_patterns()
        
        # Suspicious DNS queries
        self.detect_suspicious_dns()
        
        # Data exfiltration patterns
        self.detect_data_exfiltration()
        
        # Malware communication patterns
        self.detect_malware_communication()
        
        return self.suspicious_activities
    
    def detect_port_scanning(self):
        """Port tarama tespiti"""
        src_port_counts = defaultdict(set)
        
        for packet in self.packets:
            if 'src_ip' in packet and 'dst_port' in packet:
                src_port_counts[packet['src_ip']].add(packet['dst_port'])
        
        # Detect sources scanning many ports
        for src_ip, ports in src_port_counts.items():
            if len(ports) > 50:  # Threshold for port scanning
                self.suspicious_activities.append({
                    'type': 'port_scanning',
                    'severity': 'HIGH',
                    'source_ip': src_ip,
                    'scanned_ports': len(ports),
                    'description': f"Port scanning detected from {src_ip} targeting {len(ports)} ports"
                })
    
    def detect_ddos_patterns(self):
        """DDoS saldırı tespiti"""
        # Count packets per source IP in time windows
        time_windows = defaultdict(lambda: defaultdict(int))
        
        for packet in self.packets:
            if 'src_ip' in packet:
                time_window = int(packet['timestamp']) // 60  # 1-minute windows
                time_windows[time_window][packet['src_ip']] += 1
        
        # Detect high packet rates
        for time_window, src_counts in time_windows.items():
            for src_ip, packet_count in src_counts.items():
                if packet_count > 1000:  # Threshold for DDoS
                    self.suspicious_activities.append({
                        'type': 'ddos_attack',
                        'severity': 'CRITICAL',
                        'source_ip': src_ip,
                        'packet_count': packet_count,
                        'time_window': time_window,
                        'description': f"Potential DDoS attack from {src_ip} with {packet_count} packets in 1 minute"
                    })
    
    def detect_suspicious_dns(self):
        """Şüpheli DNS sorguları tespit et"""
        suspicious_domains = [
            'bit.ly', 'tinyurl.com', 'pastebin.com',
            '.tk', '.ml', '.ga', '.cf'  # Suspicious TLDs
        ]
        
        for packet in self.packets:
            if 'dns' in packet and 'query' in packet['dns']:
                query = packet['dns']['query'].lower()
                
                # Check for suspicious domains
                for suspicious in suspicious_domains:
                    if suspicious in query:
                        self.suspicious_activities.append({
                            'type': 'suspicious_dns',
                            'severity': 'MEDIUM',
                            'query': query,
                            'source_ip': packet.get('src_ip', 'Unknown'),
                            'description': f"Suspicious DNS query to {query}"
                        })
                        break
                
                # Check for DGA (Domain Generation Algorithm) patterns
                if self.is_dga_domain(query):
                    self.suspicious_activities.append({
                        'type': 'dga_domain',
                        'severity': 'HIGH',
                        'query': query,
                        'source_ip': packet.get('src_ip', 'Unknown'),
                        'description': f"Potential DGA domain detected: {query}"
                    })
    
    def is_dga_domain(self, domain):
        """DGA domain tespiti"""
        # Simple heuristics for DGA detection
        if len(domain) < 6:
            return False
        
        # Check for high entropy (randomness)
        entropy = self.calculate_entropy(domain)
        if entropy > 4.5:
            return True
        
        # Check for consonant/vowel ratio
        vowels = 'aeiou'
        consonants = sum(1 for c in domain if c.isalpha() and c.lower() not in vowels)
        vowel_count = sum(1 for c in domain if c.lower() in vowels)
        
        if vowel_count > 0 and consonants / vowel_count > 3:
            return True
        
        return False
    
    def calculate_entropy(self, string):
        """String entropy hesapla"""
        import math
        
        # Calculate character frequency
        char_counts = Counter(string.lower())
        length = len(string)
        
        # Calculate entropy
        entropy = 0
        for count in char_counts.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    def detect_data_exfiltration(self):
        """Veri sızıntısı tespiti"""
        # Group outbound traffic by destination
        outbound_traffic = defaultdict(int)
        
        for packet in self.packets:
            if 'src_ip' in packet and 'dst_ip' in packet:
                # Assume internal network is 192.168.x.x or 10.x.x.x
                src_internal = self.is_internal_ip(packet['src_ip'])
                dst_external = not self.is_internal_ip(packet['dst_ip'])
                
                if src_internal and dst_external:
                    outbound_traffic[packet['dst_ip']] += packet.get('length', 0)
        
        # Detect large data transfers
        for dst_ip, total_bytes in outbound_traffic.items():
            if total_bytes > 100 * 1024 * 1024:  # 100MB threshold
                self.suspicious_activities.append({
                    'type': 'data_exfiltration',
                    'severity': 'HIGH',
                    'destination_ip': dst_ip,
                    'total_bytes': total_bytes,
                    'description': f"Large data transfer to external IP {dst_ip}: {total_bytes / (1024*1024):.2f} MB"
                })
    
    def is_internal_ip(self, ip):
        """IP adresinin internal olup olmadığını kontrol et"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except:
            return False
    
    def detect_malware_communication(self):
        """Malware iletişim tespiti"""
        # Known malware communication patterns
        suspicious_patterns = {
            'beaconing': self.detect_beaconing(),
            'c2_communication': self.detect_c2_communication(),
            'tor_usage': self.detect_tor_usage()
        }
        
        for pattern_type, detections in suspicious_patterns.items():
            self.suspicious_activities.extend(detections)
    
    def detect_beaconing(self):
        """Beacon trafiği tespiti"""
        beacons = []
        
        # Group connections by source-destination pair
        connection_times = defaultdict(list)
        
        for packet in self.packets:
            if 'src_ip' in packet and 'dst_ip' in packet:
                key = f"{packet['src_ip']}-{packet['dst_ip']}"
                connection_times[key].append(packet['timestamp'])
        
        # Analyze timing patterns
        for connection, timestamps in connection_times.items():
            if len(timestamps) >= 10:  # Minimum connections for pattern analysis
                intervals = []
                for i in range(1, len(timestamps)):
                    intervals.append(timestamps[i] - timestamps[i-1])
                
                # Check for regular intervals (beaconing)
                if len(intervals) > 5:
                    avg_interval = sum(intervals) / len(intervals)
                    variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
                    
                    # Low variance indicates regular beaconing
                    if variance < (avg_interval * 0.1) ** 2:
                        src_ip, dst_ip = connection.split('-')
                        beacons.append({
                            'type': 'beaconing',
                            'severity': 'HIGH',
                            'source_ip': src_ip,
                            'destination_ip': dst_ip,
                            'interval': avg_interval,
                            'connection_count': len(timestamps),
                            'description': f"Regular beaconing detected from {src_ip} to {dst_ip} every {avg_interval:.2f} seconds"
                        })
        
        return beacons
    
    def detect_c2_communication(self):
        """C2 sunucu iletişimi tespiti"""
        c2_indicators = []
        
        # Known C2 ports
        suspicious_ports = [4444, 5555, 6666, 8080, 9999, 31337]
        
        for packet in self.packets:
            if 'dst_port' in packet and packet['dst_port'] in suspicious_ports:
                if self.is_internal_ip(packet.get('src_ip', '')) and not self.is_internal_ip(packet.get('dst_ip', '')):
                    c2_indicators.append({
                        'type': 'c2_communication',
                        'severity': 'CRITICAL',
                        'source_ip': packet['src_ip'],
                        'destination_ip': packet['dst_ip'],
                        'port': packet['dst_port'],
                        'description': f"Potential C2 communication from {packet['src_ip']} to {packet['dst_ip']}:{packet['dst_port']}"
                    })
        
        return c2_indicators
    
    def detect_tor_usage(self):
        """Tor kullanımı tespiti"""
        tor_indicators = []
        
        # Known Tor ports
        tor_ports = [9001, 9030, 9050, 9051]
        
        for packet in self.packets:
            if 'dst_port' in packet and packet['dst_port'] in tor_ports:
                tor_indicators.append({
                    'type': 'tor_usage',
                    'severity': 'MEDIUM',
                    'source_ip': packet.get('src_ip', 'Unknown'),
                    'destination_ip': packet.get('dst_ip', 'Unknown'),
                    'port': packet['dst_port'],
                    'description': f"Potential Tor usage detected from {packet.get('src_ip', 'Unknown')}"
                })
        
        return tor_indicators
    
    def generate_network_timeline(self):
        """Network olayları timeline oluştur"""
        timeline = []
        
        for packet in self.packets:
            event = {
                'timestamp': datetime.fromtimestamp(packet['timestamp']),
                'event_type': 'network_packet',
                'protocol': packet['protocol'],
                'source': f"{packet.get('src_ip', 'Unknown')}:{packet.get('src_port', 0)}",
                'destination': f"{packet.get('dst_ip', 'Unknown')}:{packet.get('dst_port', 0)}",
                'size': packet.get('length', 0)
            }
            
            # Add protocol-specific information
            if 'http' in packet:
                event['details'] = {
                    'method': packet['http'].get('method'),
                    'uri': packet['http'].get('uri'),
                    'host': packet['http'].get('host')
                }
            elif 'dns' in packet:
                event['details'] = {
                    'query': packet['dns'].get('query'),
                    'is_response': packet['dns'].get('is_response', False)
                }
            
            timeline.append(event)
        
        # Sort by timestamp
        timeline.sort(key=lambda x: x['timestamp'])
        return timeline
    
    def export_analysis_report(self, output_file):
        """Analiz raporunu dışa aktar"""
        report = {
            'analysis_timestamp': datetime.now().isoformat(),
            'pcap_file': self.pcap_file,
            'summary': {
                'total_packets': len(self.packets),
                'unique_connections': len(self.connections),
                'protocols': dict(self.protocols),
                'suspicious_activities': len(self.suspicious_activities)
            },
            'suspicious_activities': self.suspicious_activities,
            'timeline': self.generate_network_timeline()[:100]  # Limit timeline entries
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        print(f"Network forensics report exported to: {output_file}")
        return output_file

# Usage example
if __name__ == "__main__":
    analyzer = NetworkForensicsAnalyzer("/path/to/capture.pcap")
    analyzer.load_packets(packet_limit=10000)
    analyzer.detect_suspicious_activities()
    analyzer.export_analysis_report("network_forensics_report.json")
```

## 🛠️ Uygulamalı Laboratuvar

### Forensic Lab Environment Setup

```bash
#!/bin/bash
# Forensic Laboratory Setup Script

echo "Setting up Digital Forensics Laboratory..."

# Create lab directory structure
mkdir -p ~/forensics-lab/{images,tools,cases,reports,evidence}

# Install essential forensic tools
echo "Installing forensic tools..."

# Autopsy and Sleuth Kit
sudo apt-get update
sudo apt-get install -y sleuthkit autopsy

# Volatility Framework
pip3 install volatility3

# Network analysis tools
sudo apt-get install -y wireshark tshark tcpdump

# File analysis tools
sudo apt-get install -y binwalk foremost scalpel

# Hex editors
sudo apt-get install -y hexedit ghex

# Disk imaging tools
sudo apt-get install -y dc3dd ddrescue

# Hash calculation tools
sudo apt-get install -y md5deep hashdeep

# YARA for pattern matching
sudo apt-get install -y yara

# Python forensic libraries
pip3 install pyshark pytsk3 pycrypto

echo "Forensic lab setup completed!"
echo "Lab directory: ~/forensics-lab/"
echo "Tools installed: Autopsy, Volatility, Wireshark, and more"
```

### Evidence Acquisition Script

```python
# Evidence Acquisition and Integrity Verification
import hashlib
import subprocess
import json
from datetime import datetime
import os

class EvidenceAcquisition:
    def __init__(self, case_id, investigator):
        self.case_id = case_id
        self.investigator = investigator
        self.evidence_log = []
        
    def create_disk_image(self, source_device, output_path, compression=True):
        """Disk imajı oluştur"""
        print(f"Creating disk image from {source_device}...")
        
        # Use dc3dd for forensic imaging
        cmd = [
            'dc3dd',
            f'if={source_device}',
            f'of={output_path}',
            'hash=sha256',
            'log=/tmp/dc3dd.log',
            'progress=on'
        ]
        
        if compression:
            cmd.extend(['compress=gzip'])
        
        try:
            # Start imaging process
            start_time = datetime.now()
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=7200)  # 2 hour timeout
            end_time = datetime.now()
            
            if result.returncode == 0:
                # Calculate hash of the image
                image_hash = self.calculate_file_hash(output_path)
                
                # Log evidence acquisition
                evidence_entry = {
                    'type': 'disk_image',
                    'source_device': source_device,
                    'image_path': output_path,
                    'acquisition_start': start_time.isoformat(),
                    'acquisition_end': end_time.isoformat(),
                    'duration_minutes': (end_time - start_time).total_seconds() / 60,
                    'image_hash_sha256': image_hash,
                    'investigator': self.investigator,
                    'case_id': self.case_id,
                    'tool_used': 'dc3dd',
                    'verification_status': 'pending'
                }
                
                self.evidence_log.append(evidence_entry)
                print(f"Disk imaging completed successfully")
                print(f"Image hash (SHA256): {image_hash}")
                
                return evidence_entry
            else:
                print(f"Disk imaging failed: {result.stderr}")
                return None
                
        except subprocess.TimeoutExpired:
            print("Disk imaging timed out")
            return None
        except Exception as e:
            print(f"Error during disk imaging: {e}")
            return None
    
    def calculate_file_hash(self, file_path, algorithm='sha256'):
        """Dosya hash değeri hesapla"""
        hash_obj = hashlib.new(algorithm)
        
        try:
            with open(file_path, 'rb') as f:
                # Read file in chunks to handle large files
                for chunk in iter(lambda: f.read(8192), b''):
                    hash_obj.update(chunk)
            
            return hash_obj.hexdigest()
        except Exception as e:
            print(f"Error calculating hash: {e}")
            return None
    
    def verify_image_integrity(self, image_path, expected_hash):
        """İmaj bütünlüğünü doğrula"""
        print(f"Verifying integrity of {image_path}...")
        
        current_hash = self.calculate_file_hash(image_path)
        
        if current_hash == expected_hash:
            print("Image integrity verified successfully")
            return True
        else:
            print(f"Image integrity verification FAILED")
            print(f"Expected: {expected_hash}")
            print(f"Current:  {current_hash}")
            return False
    
    def create_memory_dump(self, output_path):
        """Memory dump oluştur (Linux)"""
        print("Creating memory dump...")
        
        try:
            # Use LiME (Linux Memory Extractor) or similar tool
            cmd = ['sudo', 'insmod', '/path/to/lime.ko', f'path={output_path}', 'format=raw']
            
            start_time = datetime.now()
            result = subprocess.run(cmd, capture_output=True, text=True)
            end_time = datetime.now()
            
            if result.returncode == 0:
                # Calculate hash
                memory_hash = self.calculate_file_hash(output_path)
                
                evidence_entry = {
                    'type': 'memory_dump',
                    'dump_path': output_path,
                    'acquisition_start': start_time.isoformat(),
                    'acquisition_end': end_time.isoformat(),
                    'dump_hash_sha256': memory_hash,
                    'investigator': self.investigator,
                    'case_id': self.case_id,
                    'tool_used': 'LiME'
                }
                
                self.evidence_log.append(evidence_entry)
                print(f"Memory dump completed successfully")
                return evidence_entry
            else:
                print(f"Memory dump failed: {result.stderr}")
                return None
                
        except Exception as e:
            print(f"Error during memory dump: {e}")
            return None
    
    def collect_network_traffic(self, interface, duration_minutes, output_path):
        """Network trafiği topla"""
        print(f"Collecting network traffic on {interface} for {duration_minutes} minutes...")
        
        try:
            cmd = [
                'tcpdump',
                '-i', interface,
                '-w', output_path,
                '-G', str(duration_minutes * 60),
                '-W', '1'
            ]
            
            start_time = datetime.now()
            result = subprocess.run(cmd, timeout=duration_minutes * 60 + 30)
            end_time = datetime.now()
            
            if result.returncode == 0:
                # Calculate hash
                pcap_hash = self.calculate_file_hash(output_path)
                
                evidence_entry = {
                    'type': 'network_capture',
                    'interface': interface,
                    'capture_path': output_path,
                    'duration_minutes': duration_minutes,
                    'acquisition_start': start_time.isoformat(),
                    'acquisition_end': end_time.isoformat(),
                    'capture_hash_sha256': pcap_hash,
                    'investigator': self.investigator,
                    'case_id': self.case_id,
                    'tool_used': 'tcpdump'
                }
                
                self.evidence_log.append(evidence_entry)
                print(f"Network capture completed successfully")
                return evidence_entry
            else:
                print("Network capture failed")
                return None
                
        except Exception as e:
            print(f"Error during network capture: {e}")
            return None
    
    def generate_chain_of_custody(self, output_file):
        """Kanıt zinciri belgesi oluştur"""
        custody_document = {
            'case_information': {
                'case_id': self.case_id,
                'investigator': self.investigator,
                'creation_date': datetime.now().isoformat()
            },
            'evidence_items': self.evidence_log,
            'custody_transfers': [],
            'verification_log': []
        }
        
        # Add initial custody entry for each evidence item
        for evidence in self.evidence_log:
            custody_entry = {
                'evidence_id': evidence.get('image_path', evidence.get('dump_path', evidence.get('capture_path'))),
                'transfer_date': evidence.get('acquisition_end'),
                'from_person': 'System',
                'to_person': self.investigator,
                'purpose': 'Initial acquisition',
                'location': 'Forensic Laboratory',
                'signature': f"Digital signature: {self.investigator}"
            }
            custody_document['custody_transfers'].append(custody_entry)
        
        # Save to file
        with open(output_file, 'w') as f:
            json.dump(custody_document, f, indent=2)
        
        print(f"Chain of custody document created: {output_file}")
        return custody_document
    
    def export_evidence_summary(self, output_file):
        """Kanıt özeti raporu oluştur"""
        summary = {
            'case_id': self.case_id,
            'investigator': self.investigator,
            'evidence_count': len(self.evidence_log),
            'evidence_types': list(set(item['type'] for item in self.evidence_log)),
            'total_acquisition_time': self.calculate_total_acquisition_time(),
            'evidence_details': self.evidence_log
        }
        
        with open(output_file, 'w') as f:
            json.dump(summary, f, indent=2)
        
        print(f"Evidence summary exported: {output_file}")
        return summary
    
    def calculate_total_acquisition_time(self):
        """Toplam kanıt toplama süresini hesapla"""
        total_minutes = 0
        
        for evidence in self.evidence_log:
            if 'duration_minutes' in evidence:
                total_minutes += evidence['duration_minutes']
            elif 'acquisition_start' in evidence and 'acquisition_end' in evidence:
                start = datetime.fromisoformat(evidence['acquisition_start'])
                end = datetime.fromisoformat(evidence['acquisition_end'])
                total_minutes += (end - start).total_seconds() / 60
        
        return total_minutes

# Usage example
if __name__ == "__main__":
    # Initialize evidence acquisition
    acquisition = EvidenceAcquisition("CASE-2024-001", "John Doe")
    
    # Create disk image
    # disk_evidence = acquisition.create_disk_image("/dev/sdb", "/evidence/disk_image.dd")
    
    # Create memory dump
    # memory_evidence = acquisition.create_memory_dump("/evidence/memory.dump")
    
    # Collect network traffic
    # network_evidence = acquisition.collect_network_traffic("eth0", 30, "/evidence/traffic.pcap")
    
    # Generate documentation
     acquisition.generate_chain_of_custody("/evidence/chain_of_custody.json")
     acquisition.export_evidence_summary("/evidence/evidence_summary.json")
```

## 🎯 Pratik Egzersizler

### Egzersiz 1: Disk Forensics Challenge

```python
# Disk Forensics Challenge - Deleted File Recovery
import os
import struct
from datetime import datetime

class DiskForensicsChallenge:
    def __init__(self, disk_image_path):
        self.disk_image = disk_image_path
        self.deleted_files = []
        self.timeline_events = []
        
    def analyze_unallocated_space(self):
        """Unallocated space analizi"""
        print("Analyzing unallocated space for deleted files...")
        
        # File signature patterns
        file_signatures = {
            b'\xFF\xD8\xFF': {'ext': 'jpg', 'name': 'JPEG Image'},
            b'\x89PNG\r\n\x1a\n': {'ext': 'png', 'name': 'PNG Image'},
            b'%PDF': {'ext': 'pdf', 'name': 'PDF Document'},
            b'PK\x03\x04': {'ext': 'zip', 'name': 'ZIP Archive'},
            b'\x50\x4B\x03\x04': {'ext': 'docx', 'name': 'Word Document'}
        }
        
        try:
            with open(self.disk_image, 'rb') as f:
                chunk_size = 1024 * 1024  # 1MB chunks
                offset = 0
                
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    
                    # Search for file signatures
                    for signature, file_info in file_signatures.items():
                        pos = chunk.find(signature)
                        if pos != -1:
                            file_offset = offset + pos
                            recovered_file = self.attempt_file_recovery(f, file_offset, file_info)
                            if recovered_file:
                                self.deleted_files.append(recovered_file)
                    
                    offset += chunk_size
                    
        except Exception as e:
            print(f"Error analyzing unallocated space: {e}")
        
        return self.deleted_files
    
    def attempt_file_recovery(self, file_handle, offset, file_info):
        """Dosya kurtarma denemesi"""
        try:
            file_handle.seek(offset)
            
            # Read potential file header
            header = file_handle.read(512)
            
            # Estimate file size based on type
            estimated_size = self.estimate_file_size(header, file_info['ext'])
            
            if estimated_size > 0:
                file_handle.seek(offset)
                file_data = file_handle.read(estimated_size)
                
                recovered_file = {
                    'offset': offset,
                    'estimated_size': estimated_size,
                    'file_type': file_info['name'],
                    'extension': file_info['ext'],
                    'recovery_confidence': self.calculate_recovery_confidence(file_data),
                    'data_preview': file_data[:100]  # First 100 bytes
                }
                
                return recovered_file
                
        except Exception as e:
            print(f"Error recovering file at offset {offset}: {e}")
        
        return None
    
    def estimate_file_size(self, header, file_type):
        """Dosya boyutunu tahmin et"""
        if file_type == 'jpg':
            # Look for JPEG end marker
            return self.find_jpeg_end(header)
        elif file_type == 'png':
            # PNG files have size in header
            if len(header) >= 24:
                width = struct.unpack('>I', header[16:20])[0]
                height = struct.unpack('>I', header[20:24])[0]
                return width * height * 4 + 1024  # Rough estimate
        elif file_type == 'pdf':
            # Look for PDF trailer
            return 1024 * 1024  # Default 1MB for PDFs
        
        return 1024 * 100  # Default 100KB
    
    def find_jpeg_end(self, data):
        """JPEG dosya sonu bulma"""
        end_marker = b'\xFF\xD9'
        pos = data.find(end_marker)
        if pos != -1:
            return pos + 2
        return 1024 * 500  # Default 500KB
    
    def calculate_recovery_confidence(self, file_data):
        """Kurtarma güven seviyesi hesapla"""
        confidence = 0
        
        # Check for null bytes (indicates corruption)
        null_ratio = file_data.count(b'\x00') / len(file_data)
        if null_ratio < 0.1:
            confidence += 30
        
        # Check for repeated patterns (indicates valid structure)
        if len(set(file_data[::10])) > len(file_data) // 20:
            confidence += 40
        
        # Check file size reasonableness
        if 1024 < len(file_data) < 10 * 1024 * 1024:
            confidence += 30
        
        return min(confidence, 100)
    
    def generate_recovery_report(self):
        """Kurtarma raporu oluştur"""
        report = {
            'analysis_timestamp': datetime.now().isoformat(),
            'disk_image': self.disk_image,
            'total_recovered_files': len(self.deleted_files),
            'file_types': {},
            'high_confidence_recoveries': [],
            'detailed_findings': self.deleted_files
        }
        
        # Analyze file types
        for file_info in self.deleted_files:
            file_type = file_info['file_type']
            if file_type not in report['file_types']:
                report['file_types'][file_type] = 0
            report['file_types'][file_type] += 1
            
            # High confidence recoveries
            if file_info['recovery_confidence'] >= 70:
                report['high_confidence_recoveries'].append(file_info)
        
        return report

# Usage example for the challenge
if __name__ == "__main__":
    challenge = DiskForensicsChallenge("/path/to/challenge_disk.dd")
    deleted_files = challenge.analyze_unallocated_space()
    report = challenge.generate_recovery_report()
    
    print(f"Recovered {len(deleted_files)} deleted files")
    print(f"High confidence recoveries: {len(report['high_confidence_recoveries'])}")
```

### Egzersiz 2: Memory Forensics CTF

```python
# Memory Forensics CTF Challenge
import re
import base64
from collections import defaultdict

class MemoryForensicsCTF:
    def __init__(self, memory_dump_path):
        self.memory_dump = memory_dump_path
        self.findings = defaultdict(list)
        
    def search_for_passwords(self):
        """Memory'de şifre arama"""
        print("Searching for passwords in memory...")
        
        password_patterns = [
            rb'password[\s]*[:=][\s]*([^\s\n\r]{4,})',
            rb'pwd[\s]*[:=][\s]*([^\s\n\r]{4,})',
            rb'pass[\s]*[:=][\s]*([^\s\n\r]{4,})',
            rb'login[\s]*[:=][\s]*([^\s\n\r]{4,})'
        ]
        
        try:
            with open(self.memory_dump, 'rb') as f:
                chunk_size = 1024 * 1024
                overlap = 1024
                previous_chunk = b''
                
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    
                    # Combine with previous chunk for overlap
                    search_data = previous_chunk + chunk
                    
                    for pattern in password_patterns:
                        matches = re.finditer(pattern, search_data, re.IGNORECASE)
                        for match in matches:
                            password = match.group(1).decode('utf-8', errors='ignore')
                            if self.is_valid_password(password):
                                self.findings['passwords'].append({
                                    'password': password,
                                    'pattern': pattern.decode('utf-8', errors='ignore'),
                                    'context': search_data[max(0, match.start()-50):match.end()+50].decode('utf-8', errors='ignore')
                                })
                    
                    # Keep last part for overlap
                    previous_chunk = chunk[-overlap:] if len(chunk) >= overlap else chunk
                    
        except Exception as e:
            print(f"Error searching for passwords: {e}")
        
        return self.findings['passwords']
    
    def is_valid_password(self, password):
        """Geçerli şifre kontrolü"""
        # Filter out common false positives
        false_positives = ['http', 'https', 'file', 'path', 'temp', 'null', 'none']
        
        if len(password) < 4 or len(password) > 50:
            return False
        
        if password.lower() in false_positives:
            return False
        
        # Check for reasonable character distribution
        if password.count('\x00') > len(password) // 4:
            return False
        
        return True
    
    def extract_network_artifacts(self):
        """Network artifact'ları çıkar"""
        print("Extracting network artifacts...")
        
        # IP address patterns
        ip_pattern = rb'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        url_pattern = rb'https?://[^\s\n\r"<>]+'
        email_pattern = rb'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        
        try:
            with open(self.memory_dump, 'rb') as f:
                chunk_size = 1024 * 1024
                
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    
                    # Extract IP addresses
                    ip_matches = re.findall(ip_pattern, chunk)
                    for ip in ip_matches:
                        ip_str = ip.decode('utf-8', errors='ignore')
                        if self.is_valid_ip(ip_str):
                            self.findings['ip_addresses'].append(ip_str)
                    
                    # Extract URLs
                    url_matches = re.findall(url_pattern, chunk)
                    for url in url_matches:
                        url_str = url.decode('utf-8', errors='ignore')
                        self.findings['urls'].append(url_str)
                    
                    # Extract email addresses
                    email_matches = re.findall(email_pattern, chunk)
                    for email in email_matches:
                        email_str = email.decode('utf-8', errors='ignore')
                        self.findings['emails'].append(email_str)
                        
        except Exception as e:
            print(f"Error extracting network artifacts: {e}")
        
        # Remove duplicates
        for key in ['ip_addresses', 'urls', 'emails']:
            self.findings[key] = list(set(self.findings[key]))
        
        return {
            'ip_addresses': self.findings['ip_addresses'],
            'urls': self.findings['urls'],
            'emails': self.findings['emails']
        }
    
    def is_valid_ip(self, ip_str):
        """Geçerli IP adresi kontrolü"""
        try:
            parts = ip_str.split('.')
            if len(parts) != 4:
                return False
            
            for part in parts:
                num = int(part)
                if num < 0 or num > 255:
                    return False
            
            # Filter out common false positives
            if ip_str in ['0.0.0.0', '255.255.255.255']:
                return False
            
            return True
        except:
            return False
    
    def search_for_encryption_keys(self):
        """Şifreleme anahtarları arama"""
        print("Searching for encryption keys...")
        
        key_patterns = [
            rb'-----BEGIN [A-Z ]+-----[\s\S]*?-----END [A-Z ]+-----',  # PEM format
            rb'[A-Za-z0-9+/]{64,}={0,2}',  # Base64 encoded (potential keys)
            rb'[0-9a-fA-F]{32,128}',  # Hex encoded keys
        ]
        
        try:
            with open(self.memory_dump, 'rb') as f:
                chunk_size = 1024 * 1024
                overlap = 2048
                previous_chunk = b''
                
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    
                    search_data = previous_chunk + chunk
                    
                    for pattern in key_patterns:
                        matches = re.finditer(pattern, search_data)
                        for match in matches:
                            key_data = match.group(0)
                            if self.is_potential_key(key_data):
                                self.findings['encryption_keys'].append({
                                    'key_data': key_data.decode('utf-8', errors='ignore')[:200],  # Limit size
                                    'key_type': self.identify_key_type(key_data),
                                    'length': len(key_data)
                                })
                    
                    previous_chunk = chunk[-overlap:] if len(chunk) >= overlap else chunk
                    
        except Exception as e:
            print(f"Error searching for encryption keys: {e}")
        
        return self.findings['encryption_keys']
    
    def is_potential_key(self, key_data):
        """Potansiyel anahtar kontrolü"""
        # Minimum length check
        if len(key_data) < 32:
            return False
        
        # Check for PEM format
        if b'-----BEGIN' in key_data and b'-----END' in key_data:
            return True
        
        # Check for reasonable entropy
        unique_chars = len(set(key_data))
        if unique_chars < len(key_data) // 4:
            return False
        
        return True
    
    def identify_key_type(self, key_data):
        """Anahtar tipini belirle"""
        key_str = key_data.decode('utf-8', errors='ignore')
        
        if 'BEGIN RSA' in key_str:
            return 'RSA Private Key'
        elif 'BEGIN CERTIFICATE' in key_str:
            return 'X.509 Certificate'
        elif 'BEGIN PUBLIC KEY' in key_str:
            return 'Public Key'
        elif re.match(r'^[0-9a-fA-F]+$', key_str):
            return 'Hex Encoded Key'
        elif re.match(r'^[A-Za-z0-9+/]+=*$', key_str):
            return 'Base64 Encoded Key'
        else:
            return 'Unknown Key Format'
    
    def generate_ctf_report(self):
        """CTF raporu oluştur"""
        report = {
            'challenge_completed': datetime.now().isoformat(),
            'memory_dump': self.memory_dump,
            'findings_summary': {
                'passwords_found': len(self.findings['passwords']),
                'ip_addresses_found': len(self.findings['ip_addresses']),
                'urls_found': len(self.findings['urls']),
                'emails_found': len(self.findings['emails']),
                'encryption_keys_found': len(self.findings['encryption_keys'])
            },
            'detailed_findings': dict(self.findings),
            'ctf_flags': self.extract_ctf_flags()
        }
        
        return report
    
    def extract_ctf_flags(self):
        """CTF flag'lerini çıkar"""
        flags = []
        
        # Common CTF flag patterns
        flag_patterns = [
            rb'flag\{[^}]+\}',
            rb'FLAG\{[^}]+\}',
            rb'ctf\{[^}]+\}',
            rb'CTF\{[^}]+\}'
        ]
        
        try:
            with open(self.memory_dump, 'rb') as f:
                content = f.read(10 * 1024 * 1024)  # Read first 10MB
                
                for pattern in flag_patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    for match in matches:
                        flag = match.decode('utf-8', errors='ignore')
                        flags.append(flag)
                        
        except Exception as e:
            print(f"Error extracting CTF flags: {e}")
        
        return list(set(flags))  # Remove duplicates

# Usage example for CTF
if __name__ == "__main__":
    ctf = MemoryForensicsCTF("/path/to/ctf_memory.dmp")
    
    # Perform analysis
    passwords = ctf.search_for_passwords()
    network_artifacts = ctf.extract_network_artifacts()
    encryption_keys = ctf.search_for_encryption_keys()
    
    # Generate report
    report = ctf.generate_ctf_report()
    
    print(f"CTF Analysis Complete:")
    print(f"Passwords found: {len(passwords)}")
    print(f"Network artifacts: {sum(len(v) for v in network_artifacts.values())}")
    print(f"Encryption keys: {len(encryption_keys)}")
    print(f"CTF flags: {len(report['ctf_flags'])}")
```

## 🛠️ Önerilen Araçlar

### Ticari Forensic Araçları

#### EnCase Forensic
- **Özellikler**: Kapsamlı disk analizi, timeline analizi, rapor oluşturma
- **Kullanım Alanı**: Kolluk kuvvetleri, kurumsal araştırmalar
- **Avantajlar**: Güçlü analiz yetenekleri, yasal kabul edilebilirlik
- **Dezavantajlar**: Yüksek maliyet, öğrenme eğrisi

#### FTK (Forensic Toolkit)
- **Özellikler**: Hızlı indeksleme, e-mail analizi, şifre kırma
- **Kullanım Alanı**: Dijital araştırmalar, e-discovery
- **Avantajlar**: Hızlı performans, kullanıcı dostu arayüz
- **Dezavantajlar**: Kaynak tüketimi, lisans maliyeti

#### Cellebrite UFED
- **Özellikler**: Mobil cihaz analizi, uygulama verisi çıkarma
- **Kullanım Alanı**: Mobil forensics, kolluk kuvvetleri
- **Avantajlar**: Geniş cihaz desteği, otomatik analiz
- **Dezavantajlar**: Sadece mobil odaklı, pahalı

### Açık Kaynak Forensic Araçları

#### Autopsy/Sleuth Kit
```bash
# Autopsy kurulumu ve kullanımı
sudo apt-get install sleuthkit autopsy

# Disk imajı analizi
fls -r /path/to/disk.dd

# Dosya içeriği görüntüleme
icat /path/to/disk.dd 12345

# Timeline oluşturma
fls -m / -r /path/to/disk.dd > timeline.txt
mactime -b timeline.txt > timeline_readable.txt
```

#### Volatility Framework
```bash
# Volatility kurulumu
pip3 install volatility3

# Memory dump analizi
volatility -f memory.dmp windows.info
volatility -f memory.dmp windows.pslist
volatility -f memory.dmp windows.netscan
volatility -f memory.dmp windows.malfind
```

#### YARA Rules
```yara
// Malware detection rule
rule Suspicious_PowerShell_Commands
{
    meta:
        description = "Detects suspicious PowerShell commands"
        author = "ibrahimsql"
        date = "2025"
    
    strings:
        $cmd1 = "Invoke-Expression" nocase
        $cmd2 = "DownloadString" nocase
        $cmd3 = "System.Net.WebClient" nocase
        $cmd4 = "powershell -enc" nocase
        $cmd5 = "FromBase64String" nocase
    
    condition:
        any of ($cmd*)
}

rule Potential_Data_Exfiltration
{
    meta:
        description = "Detects potential data exfiltration patterns"
        author = "ibrahimsql"
    
    strings:
        $ftp1 = "ftp://" nocase
        $ftp2 = "sftp://" nocase
        $cloud1 = "dropbox.com" nocase
        $cloud2 = "drive.google.com" nocase
        $cloud3 = "onedrive.live.com" nocase
        $compress1 = ".zip" nocase
        $compress2 = ".rar" nocase
        $compress3 = ".7z" nocase
    
    condition:
        (any of ($ftp*) or any of ($cloud*)) and any of ($compress*)
}
```

## 📊 Yapılandırma En İyi Uygulamaları

### Forensic Workstation Setup

```bash
#!/bin/bash
# Professional Forensic Workstation Configuration

echo "Configuring forensic workstation..."

# Disable swap to prevent evidence contamination
sudo swapoff -a
sudo sed -i '/ swap / s/^/#/' /etc/fstab

# Configure write-blocking for USB devices
echo 'SUBSYSTEM=="usb", ATTR{authorized}="0"' | sudo tee /etc/udev/rules.d/99-usb-write-block.rules

# Install forensic tools
sudo apt-get update
sudo apt-get install -y \
    sleuthkit autopsy \
    volatility3 \
    wireshark tshark \
    binwalk foremost scalpel \
    dc3dd ddrescue \
    hashdeep md5deep \
    yara \
    hexedit ghex \
    python3-pip

# Install Python forensic libraries
pip3 install \
    pyshark \
    pytsk3 \
    pycrypto \
    yara-python \
    volatility3

# Create forensic directory structure
mkdir -p ~/forensics/{cases,tools,images,reports,scripts}

# Set up case management
cat > ~/forensics/new_case.sh << 'EOF'
#!/bin/bash
CASE_ID=$1
if [ -z "$CASE_ID" ]; then
    echo "Usage: $0 <case_id>"
    exit 1
fi

mkdir -p ~/forensics/cases/$CASE_ID/{evidence,analysis,reports,timeline}
echo "Case $CASE_ID created at $(date)" > ~/forensics/cases/$CASE_ID/case_log.txt
echo "Case directory created: ~/forensics/cases/$CASE_ID"
EOF

chmod +x ~/forensics/new_case.sh

echo "Forensic workstation configuration completed!"
```

### Evidence Handling Procedures

```python
# Evidence Handling and Chain of Custody Management
import json
import hashlib
import datetime
import uuid
from pathlib import Path

class EvidenceManager:
    def __init__(self, case_id, evidence_storage_path):
        self.case_id = case_id
        self.storage_path = Path(evidence_storage_path)
        self.custody_log = []
        self.evidence_registry = {}
        
    def register_evidence(self, evidence_path, description, source, investigator):
        """Kanıt kaydetme"""
        evidence_id = str(uuid.uuid4())
        evidence_file = Path(evidence_path)
        
        # Calculate hash
        evidence_hash = self.calculate_file_hash(evidence_path)
        
        # Create evidence entry
        evidence_entry = {
            'evidence_id': evidence_id,
            'case_id': self.case_id,
            'original_path': str(evidence_file),
            'filename': evidence_file.name,
            'file_size': evidence_file.stat().st_size,
            'description': description,
            'source': source,
            'acquisition_date': datetime.datetime.now().isoformat(),
            'investigator': investigator,
            'hash_sha256': evidence_hash,
            'status': 'acquired'
        }
        
        # Store in registry
        self.evidence_registry[evidence_id] = evidence_entry
        
        # Create custody entry
        custody_entry = {
            'evidence_id': evidence_id,
            'action': 'acquired',
            'timestamp': datetime.datetime.now().isoformat(),
            'person': investigator,
            'location': 'Evidence Storage',
            'notes': f'Evidence acquired from {source}'
        }
        
        self.custody_log.append(custody_entry)
        
        # Copy evidence to secure storage
        secure_path = self.storage_path / f"{evidence_id}_{evidence_file.name}"
        self.secure_copy(evidence_path, secure_path)
        
        return evidence_id
    
    def calculate_file_hash(self, file_path):
        """Dosya hash hesaplama"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    
    def secure_copy(self, source, destination):
        """Güvenli dosya kopyalama"""
        import shutil
        
        # Ensure destination directory exists
        destination.parent.mkdir(parents=True, exist_ok=True)
        
        # Copy file
        shutil.copy2(source, destination)
        
        # Verify integrity
        source_hash = self.calculate_file_hash(source)
        dest_hash = self.calculate_file_hash(destination)
        
        if source_hash != dest_hash:
            raise Exception(f"Hash mismatch during copy: {source} -> {destination}")
    
    def transfer_custody(self, evidence_id, from_person, to_person, purpose, location):
        """Kanıt zinciri transferi"""
        if evidence_id not in self.evidence_registry:
            raise ValueError(f"Evidence {evidence_id} not found")
        
        custody_entry = {
            'evidence_id': evidence_id,
            'action': 'transferred',
            'timestamp': datetime.datetime.now().isoformat(),
            'from_person': from_person,
            'to_person': to_person,
            'purpose': purpose,
            'location': location,
            'notes': f'Custody transferred for: {purpose}'
        }
        
        self.custody_log.append(custody_entry)
        
        # Update evidence status
        self.evidence_registry[evidence_id]['current_custodian'] = to_person
        self.evidence_registry[evidence_id]['current_location'] = location
    
    def verify_evidence_integrity(self, evidence_id):
        """Kanıt bütünlüğü doğrulama"""
        if evidence_id not in self.evidence_registry:
            raise ValueError(f"Evidence {evidence_id} not found")
        
        evidence = self.evidence_registry[evidence_id]
        stored_path = self.storage_path / f"{evidence_id}_{Path(evidence['original_path']).name}"
        
        if not stored_path.exists():
            return {'verified': False, 'error': 'Evidence file not found'}
        
        current_hash = self.calculate_file_hash(stored_path)
        original_hash = evidence['hash_sha256']
        
        verification_result = {
            'evidence_id': evidence_id,
            'verified': current_hash == original_hash,
            'original_hash': original_hash,
            'current_hash': current_hash,
            'verification_timestamp': datetime.datetime.now().isoformat()
        }
        
        # Log verification
        custody_entry = {
            'evidence_id': evidence_id,
            'action': 'verified',
            'timestamp': datetime.datetime.now().isoformat(),
            'person': 'System',
            'location': 'Evidence Storage',
            'notes': f'Integrity verification: {"PASSED" if verification_result["verified"] else "FAILED"}'
        }
        
        self.custody_log.append(custody_entry)
        
        return verification_result
    
    def generate_custody_report(self, evidence_id=None):
        """Kanıt zinciri raporu"""
        if evidence_id:
            # Single evidence report
            if evidence_id not in self.evidence_registry:
                raise ValueError(f"Evidence {evidence_id} not found")
            
            evidence_custody = [entry for entry in self.custody_log if entry['evidence_id'] == evidence_id]
            
            report = {
                'case_id': self.case_id,
                'evidence_id': evidence_id,
                'evidence_details': self.evidence_registry[evidence_id],
                'custody_chain': evidence_custody,
                'report_generated': datetime.datetime.now().isoformat()
            }
        else:
            # Full case report
            report = {
                'case_id': self.case_id,
                'total_evidence_items': len(self.evidence_registry),
                'evidence_registry': self.evidence_registry,
                'complete_custody_log': self.custody_log,
                'report_generated': datetime.datetime.now().isoformat()
            }
        
        return report
    
    def export_custody_documentation(self, output_file):
        """Kanıt zinciri belgelerini dışa aktar"""
        report = self.generate_custody_report()
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"Custody documentation exported to: {output_file}")
        return output_file

# Usage example
if __name__ == "__main__":
    # Initialize evidence manager
    manager = EvidenceManager("CASE-2024-001", "/secure/evidence/storage")
    
    # Register evidence
    evidence_id = manager.register_evidence(
        "/path/to/disk.dd",
        "Suspect's laptop hard drive image",
        "Laptop seized from suspect's residence",
        "Detective Smith"
    )
    
    # Transfer custody
    manager.transfer_custody(
        evidence_id,
        "Detective Smith",
        "Forensic Analyst Jones",
        "Digital forensic analysis",
        "Forensic Laboratory"
    )
    
    # Verify integrity
    verification = manager.verify_evidence_integrity(evidence_id)
    print(f"Evidence integrity: {'VERIFIED' if verification['verified'] else 'FAILED'}")
    
    # Export documentation
     manager.export_custody_documentation(f"custody_report_{manager.case_id}.json")
```

## 🎯 Gerçek Dünya Vaka Çalışmaları

### Vaka 1: Kurumsal Veri Sızıntısı Araştırması

**Senaryo**: Bir teknoloji şirketinde müşteri verilerinin dark web'de satıldığı tespit edildi.

**Forensic Yaklaşım**:
1. **Ağ Trafiği Analizi**: Anormal veri transferleri
2. **Endpoint Analizi**: Şüpheli çalışan bilgisayarları
3. **Email Forensics**: İç ve dış iletişim analizi
4. **Timeline Reconstruction**: Olay kronolojisi

**Bulgular**:
- İç kullanıcı tarafından gerçekleştirilen veri hırsızlığı
- USB cihazı ile veri transferi
- Şifrelenmiş dosyaların bulut depolama servisine yüklenmesi

### Vaka 2: Fidye Yazılımı Saldırısı Analizi

**Senaryo**: Hastane sistemlerinin fidye yazılımı ile şifrelenmesi.

**Forensic Yaklaşım**:
1. **Memory Analysis**: Aktif süreçler ve ağ bağlantıları
2. **Disk Forensics**: Şifreleme öncesi dosya durumu
3. **Network Forensics**: C&C sunucu iletişimi
4. **Malware Analysis**: Fidye yazılımı tersine mühendislik

**Bulgular**:
- Email phishing saldırısı ile başlangıç
- Lateral movement teknikleri
- Backup sistemlerinin hedeflenmesi

### Vaka 3: Mobil Cihaz Adli Analizi

**Senaryo**: Terör örgütü üyesi şüphelisinin telefon analizi.

**Forensic Yaklaşım**:
1. **Physical Extraction**: Tam cihaz imajı
2. **App Data Analysis**: Mesajlaşma uygulamaları
3. **Location Analysis**: GPS ve cell tower verileri
4. **Deleted Data Recovery**: Silinmiş içerik kurtarma

**Bulgular**:
- Şifrelenmiş mesajlaşma uygulaması kullanımı
- Gizli fotoğraf ve video dosyaları
- Konum bazlı hareket analizi

## 📝 Bilgi Kontrol Soruları

### Teorik Sorular

1. **Locard's Exchange Principle nedir ve dijital forensics'te nasıl uygulanır?**
   - Cevap: Her temas iz bırakır prensibi; dijital ortamda her işlem log, metadata, registry değişikliği gibi izler bırakır.

2. **Chain of Custody'nin yasal önemi nedir?**
   - Cevap: Kanıtın mahkemede kabul edilebilirliği için bütünlük ve güvenilirlik sağlar.

3. **Live forensics ile post-mortem forensics arasındaki farklar nelerdir?**
   - Cevap: Live: Sistem çalışırken analiz, volatile data korunur. Post-mortem: Sistem kapalı, disk imajı alınır.

4. **Anti-forensics teknikleri nelerdir?**
   - Cevap: Veri silme, şifreleme, steganografi, log temizleme, timestamp manipülasyonu.

### Pratik Sorular

5. **Bir Windows sisteminde son açılan dosyaları nasıl tespit edersiniz?**
   - Cevap: Recent folder, Jump Lists, Prefetch files, Registry (RecentDocs), LNK files.

6. **Memory dump'ta hangi artefaktları arayabilirsiniz?**
   - Cevap: Süreçler, ağ bağlantıları, şifreler, şifreleme anahtarları, injected code.

7. **NTFS dosya sisteminde silinmiş dosyaları nasıl kurtarırsınız?**
   - Cevap: MFT analizi, unallocated space tarama, file carving teknikleri.

## 🏆 Pratik Ödevler

### Ödev 1: Forensic Timeline Oluşturma

**Hedef**: Bir güvenlik olayının zaman çizelgesini oluşturmak.

**Gereksinimler**:
- Disk imajı analizi
- Log dosyası korelasyonu
- Super timeline oluşturma
- Olay kronolojisi raporu

**Teslim Edilecekler**:
- Timeline CSV dosyası
- Analiz raporu
- Kritik olayların özeti

### Ödev 2: Memory Forensics Challenge

**Hedef**: Memory dump'tan gizli bilgileri çıkarmak.

**Gereksinimler**:
- Volatility kullanımı
- Süreç analizi
- Ağ artefakt çıkarma
- Malware tespiti

**Teslim Edilecekler**:
- Volatility komut çıktıları
- Tespit edilen IOC'ler
- Teknik analiz raporu

### Ödev 3: Mobile Forensics Projesi

**Hedef**: Android cihaz forensic analizi.

**Gereksinimler**:
- ADB kullanımı
- SQLite veritabanı analizi
- App data extraction
- Deleted content recovery

**Teslim Edilecekler**:
- Extraction raporu
- Recovered data örnekleri
- Forensic findings özeti

## 📊 Performans Metrikleri

### Forensic Analysis Performance Tracker

```python
# Forensic Performance Metrics
import time
import psutil
import json
from datetime import datetime

class ForensicPerformanceTracker:
    def __init__(self, case_id):
        self.case_id = case_id
        self.metrics = {
            'case_id': case_id,
            'start_time': None,
            'end_time': None,
            'total_duration': 0,
            'tasks_completed': [],
            'system_resources': [],
            'evidence_processed': {
                'disk_images': 0,
                'memory_dumps': 0,
                'network_captures': 0,
                'mobile_devices': 0
            },
            'findings': {
                'files_recovered': 0,
                'artifacts_found': 0,
                'iocs_identified': 0,
                'timeline_events': 0
            }
        }
        
    def start_analysis(self):
        """Analiz başlangıcı"""
        self.metrics['start_time'] = datetime.now().isoformat()
        print(f"Starting forensic analysis for case: {self.case_id}")
        
    def end_analysis(self):
        """Analiz sonu"""
        self.metrics['end_time'] = datetime.now().isoformat()
        
        # Calculate duration
        start = datetime.fromisoformat(self.metrics['start_time'])
        end = datetime.fromisoformat(self.metrics['end_time'])
        self.metrics['total_duration'] = (end - start).total_seconds()
        
        print(f"Analysis completed. Duration: {self.metrics['total_duration']:.2f} seconds")
        
    def log_task_completion(self, task_name, duration, details=None):
        """Görev tamamlama kaydı"""
        task_entry = {
            'task_name': task_name,
            'completion_time': datetime.now().isoformat(),
            'duration_seconds': duration,
            'details': details or {}
        }
        
        self.metrics['tasks_completed'].append(task_entry)
        print(f"Task completed: {task_name} ({duration:.2f}s)")
        
    def log_system_resources(self):
        """Sistem kaynak kullanımı"""
        resource_snapshot = {
            'timestamp': datetime.now().isoformat(),
            'cpu_percent': psutil.cpu_percent(interval=1),
            'memory_percent': psutil.virtual_memory().percent,
            'disk_usage': psutil.disk_usage('/').percent,
            'network_io': dict(psutil.net_io_counters()._asdict())
        }
        
        self.metrics['system_resources'].append(resource_snapshot)
        
    def update_evidence_count(self, evidence_type, count=1):
        """Kanıt sayısı güncelleme"""
        if evidence_type in self.metrics['evidence_processed']:
            self.metrics['evidence_processed'][evidence_type] += count
            
    def update_findings_count(self, finding_type, count=1):
        """Bulgu sayısı güncelleme"""
        if finding_type in self.metrics['findings']:
            self.metrics['findings'][finding_type] += count
            
    def calculate_efficiency_metrics(self):
        """Verimlilik metrikleri"""
        if self.metrics['total_duration'] == 0:
            return {}
            
        total_evidence = sum(self.metrics['evidence_processed'].values())
        total_findings = sum(self.metrics['findings'].values())
        
        efficiency = {
            'evidence_per_hour': (total_evidence / self.metrics['total_duration']) * 3600,
            'findings_per_hour': (total_findings / self.metrics['total_duration']) * 3600,
            'avg_task_duration': sum(task['duration_seconds'] for task in self.metrics['tasks_completed']) / len(self.metrics['tasks_completed']) if self.metrics['tasks_completed'] else 0,
            'total_tasks_completed': len(self.metrics['tasks_completed'])
        }
        
        return efficiency
        
    def generate_performance_report(self):
        """Performans raporu"""
        efficiency = self.calculate_efficiency_metrics()
        
        report = {
            'case_metrics': self.metrics,
            'efficiency_metrics': efficiency,
            'resource_utilization': self.analyze_resource_usage(),
            'recommendations': self.generate_recommendations()
        }
        
        return report
        
    def analyze_resource_usage(self):
        """Kaynak kullanım analizi"""
        if not self.metrics['system_resources']:
            return {}
            
        cpu_values = [r['cpu_percent'] for r in self.metrics['system_resources']]
        memory_values = [r['memory_percent'] for r in self.metrics['system_resources']]
        
        return {
            'avg_cpu_usage': sum(cpu_values) / len(cpu_values),
            'max_cpu_usage': max(cpu_values),
            'avg_memory_usage': sum(memory_values) / len(memory_values),
            'max_memory_usage': max(memory_values),
            'resource_peaks': len([c for c in cpu_values if c > 80])
        }
        
    def generate_recommendations(self):
        """Performans önerileri"""
        recommendations = []
        
        resource_analysis = self.analyze_resource_usage()
        
        if resource_analysis.get('avg_cpu_usage', 0) > 80:
            recommendations.append("Consider upgrading CPU or distributing workload")
            
        if resource_analysis.get('avg_memory_usage', 0) > 85:
            recommendations.append("Increase system RAM for better performance")
            
        efficiency = self.calculate_efficiency_metrics()
        if efficiency.get('avg_task_duration', 0) > 300:  # 5 minutes
            recommendations.append("Optimize analysis workflows for faster processing")
            
        return recommendations
        
    def export_metrics(self, filename):
        """Metrikleri dışa aktar"""
        report = self.generate_performance_report()
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
            
        print(f"Performance metrics exported to: {filename}")

# Usage example
if __name__ == "__main__":
    tracker = ForensicPerformanceTracker("CASE-2024-001")
    
    # Start analysis
    tracker.start_analysis()
    
    # Simulate forensic tasks
    time.sleep(2)
    tracker.log_task_completion("Disk Image Acquisition", 120.5, {"size_gb": 500})
    tracker.update_evidence_count("disk_images", 1)
    
    time.sleep(1)
    tracker.log_system_resources()
    
    tracker.log_task_completion("Memory Analysis", 45.2, {"volatility_plugins": 15})
    tracker.update_evidence_count("memory_dumps", 1)
    tracker.update_findings_count("artifacts_found", 25)
    
    # End analysis
    tracker.end_analysis()
    
    # Export report
    tracker.export_metrics("forensic_performance_report.json")
```

## 🤖 Yapay Zeka ve Makine Öğrenimi Uygulamaları

### AI-Powered Forensic Analysis

```python
# AI-Enhanced Digital Forensics
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, LSTM, Dropout
import joblib

class AIForensicAnalyzer:
    def __init__(self):
        self.anomaly_detector = None
        self.malware_classifier = None
        self.timeline_analyzer = None
        self.scaler = StandardScaler()
        
    def train_anomaly_detector(self, normal_behavior_data):
        """Anormal davranış tespiti modeli"""
        print("Training anomaly detection model...")
        
        # Normalize data
        normalized_data = self.scaler.fit_transform(normal_behavior_data)
        
        # Train Isolation Forest
        self.anomaly_detector = IsolationForest(
            contamination=0.1,
            random_state=42,
            n_estimators=100
        )
        
        self.anomaly_detector.fit(normalized_data)
        
        # Save model
        joblib.dump(self.anomaly_detector, 'anomaly_detector.pkl')
        joblib.dump(self.scaler, 'scaler.pkl')
        
        print("Anomaly detection model trained and saved.")
        
    def detect_anomalies(self, behavior_data):
        """Anormal davranış tespiti"""
        if self.anomaly_detector is None:
            # Load pre-trained model
            self.anomaly_detector = joblib.load('anomaly_detector.pkl')
            self.scaler = joblib.load('scaler.pkl')
            
        # Normalize and predict
        normalized_data = self.scaler.transform(behavior_data)
        anomaly_scores = self.anomaly_detector.decision_function(normalized_data)
        anomalies = self.anomaly_detector.predict(normalized_data)
        
        # Create results DataFrame
        results = pd.DataFrame({
            'anomaly_score': anomaly_scores,
            'is_anomaly': anomalies == -1,
            'severity': self.calculate_severity(anomaly_scores)
        })
        
        return results
        
    def calculate_severity(self, scores):
        """Anormal davranış şiddeti hesaplama"""
        # Normalize scores to 0-100 scale
        min_score = scores.min()
        max_score = scores.max()
        
        if max_score == min_score:
            return np.full(len(scores), 50)
            
        normalized = (scores - min_score) / (max_score - min_score)
        severity = (1 - normalized) * 100  # Invert so lower scores = higher severity
        
        return severity
        
    def train_malware_classifier(self, features, labels):
        """Malware sınıflandırma modeli"""
        print("Training malware classification model...")
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            features, labels, test_size=0.2, random_state=42
        )
        
        # Train Random Forest classifier
        self.malware_classifier = RandomForestClassifier(
            n_estimators=200,
            max_depth=10,
            random_state=42,
            class_weight='balanced'
        )
        
        self.malware_classifier.fit(X_train, y_train)
        
        # Evaluate model
        train_accuracy = self.malware_classifier.score(X_train, y_train)
        test_accuracy = self.malware_classifier.score(X_test, y_test)
        
        print(f"Training accuracy: {train_accuracy:.3f}")
        print(f"Test accuracy: {test_accuracy:.3f}")
        
        # Save model
        joblib.dump(self.malware_classifier, 'malware_classifier.pkl')
        
        return {
            'train_accuracy': train_accuracy,
            'test_accuracy': test_accuracy,
            'feature_importance': dict(zip(
                range(len(features.columns)), 
                self.malware_classifier.feature_importances_
            ))
        }
        
    def classify_malware(self, file_features):
        """Malware sınıflandırma"""
        if self.malware_classifier is None:
            self.malware_classifier = joblib.load('malware_classifier.pkl')
            
        # Predict
        predictions = self.malware_classifier.predict(file_features)
        probabilities = self.malware_classifier.predict_proba(file_features)
        
        results = []
        for i, (pred, prob) in enumerate(zip(predictions, probabilities)):
            results.append({
                'file_index': i,
                'prediction': pred,
                'confidence': max(prob),
                'malware_probability': prob[1] if len(prob) > 1 else prob[0]
            })
            
        return results
        
    def build_timeline_analyzer(self, sequence_length=50):
        """Timeline analizi için LSTM modeli"""
        print("Building timeline analysis model...")
        
        model = Sequential([
            LSTM(128, return_sequences=True, input_shape=(sequence_length, 1)),
            Dropout(0.2),
            LSTM(64, return_sequences=False),
            Dropout(0.2),
            Dense(32, activation='relu'),
            Dense(1, activation='sigmoid')
        ])
        
        model.compile(
            optimizer='adam',
            loss='binary_crossentropy',
            metrics=['accuracy']
        )
        
        self.timeline_analyzer = model
        return model
        
    def train_timeline_analyzer(self, timeline_sequences, labels, epochs=50):
        """Timeline analizi modeli eğitimi"""
        if self.timeline_analyzer is None:
            self.build_timeline_analyzer()
            
        # Prepare data
        X = np.array(timeline_sequences)
        y = np.array(labels)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42
        )
        
        # Train model
        history = self.timeline_analyzer.fit(
            X_train, y_train,
            epochs=epochs,
            batch_size=32,
            validation_data=(X_test, y_test),
            verbose=1
        )
        
        # Save model
        self.timeline_analyzer.save('timeline_analyzer.h5')
        
        return history
        
    def analyze_timeline_patterns(self, timeline_sequence):
        """Timeline pattern analizi"""
        if self.timeline_analyzer is None:
            self.timeline_analyzer = tf.keras.models.load_model('timeline_analyzer.h5')
            
        # Prepare sequence
        sequence = np.array(timeline_sequence).reshape(1, -1, 1)
        
        # Predict
        prediction = self.timeline_analyzer.predict(sequence)[0][0]
        
        return {
            'suspicious_probability': prediction,
            'is_suspicious': prediction > 0.5,
            'confidence_level': abs(prediction - 0.5) * 2
        }
        
    def generate_ai_forensic_report(self, case_data):
        """AI destekli forensic rapor"""
        report = {
            'case_id': case_data.get('case_id', 'Unknown'),
            'analysis_timestamp': pd.Timestamp.now().isoformat(),
            'ai_findings': {
                'anomalies_detected': 0,
                'malware_samples': 0,
                'suspicious_timelines': 0,
                'confidence_scores': []
            },
            'recommendations': [],
            'risk_assessment': 'Low'
        }
        
        # Analyze anomalies
        if 'behavior_data' in case_data:
            anomaly_results = self.detect_anomalies(case_data['behavior_data'])
            anomalies = anomaly_results[anomaly_results['is_anomaly']]
            report['ai_findings']['anomalies_detected'] = len(anomalies)
            
            if len(anomalies) > 0:
                report['recommendations'].append(
                    f"Investigate {len(anomalies)} anomalous behaviors detected"
                )
                
        # Analyze malware
        if 'file_features' in case_data:
            malware_results = self.classify_malware(case_data['file_features'])
            malware_count = sum(1 for r in malware_results if r['prediction'] == 1)
            report['ai_findings']['malware_samples'] = malware_count
            
            if malware_count > 0:
                report['recommendations'].append(
                    f"Quarantine and analyze {malware_count} potential malware samples"
                )
                
        # Analyze timeline
        if 'timeline_sequences' in case_data:
            suspicious_count = 0
            for sequence in case_data['timeline_sequences']:
                result = self.analyze_timeline_patterns(sequence)
                if result['is_suspicious']:
                    suspicious_count += 1
                    
            report['ai_findings']['suspicious_timelines'] = suspicious_count
            
            if suspicious_count > 0:
                report['recommendations'].append(
                    f"Review {suspicious_count} suspicious timeline patterns"
                )
                
        # Calculate overall risk
        risk_factors = [
            report['ai_findings']['anomalies_detected'],
            report['ai_findings']['malware_samples'],
            report['ai_findings']['suspicious_timelines']
        ]
        
        total_risk = sum(risk_factors)
        if total_risk > 10:
            report['risk_assessment'] = 'High'
        elif total_risk > 5:
            report['risk_assessment'] = 'Medium'
        else:
            report['risk_assessment'] = 'Low'
            
        return report

# Usage example
if __name__ == "__main__":
    ai_analyzer = AIForensicAnalyzer()
    
    # Example: Generate synthetic data for demonstration
    np.random.seed(42)
    
    # Normal behavior data (for training)
    normal_data = np.random.normal(0, 1, (1000, 10))
    
    # Train anomaly detector
    ai_analyzer.train_anomaly_detector(normal_data)
    
    # Test data with some anomalies
    test_data = np.random.normal(0, 1, (100, 10))
    test_data[95:] = np.random.normal(5, 2, (5, 10))  # Add anomalies
    
    # Detect anomalies
    anomaly_results = ai_analyzer.detect_anomalies(test_data)
    print(f"Anomalies detected: {anomaly_results['is_anomaly'].sum()}")
    
    # Generate AI forensic report
    case_data = {
        'case_id': 'AI-CASE-001',
        'behavior_data': test_data
    }
    
    report = ai_analyzer.generate_ai_forensic_report(case_data)
    print(f"AI Forensic Analysis Complete - Risk Level: {report['risk_assessment']}")
```

## 🔮 Kuantum Dirençli Dijital Forensics

### Quantum-Safe Forensic Protocols

```python
# Quantum-Resistant Digital Forensics
import hashlib
import secrets
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import json
from datetime import datetime

class QuantumSafeForensics:
    def __init__(self):
        self.quantum_safe_algorithms = {
            'hash': 'SHA3-512',
            'kdf': 'PBKDF2-SHA3',
            'symmetric': 'AES-256-GCM',
            'signature': 'SPHINCS+'
        }
        
    def quantum_safe_hash(self, data):
        """Kuantum güvenli hash hesaplama"""
        if isinstance(data, str):
            data = data.encode('utf-8')
            
        # Use SHA3-512 for quantum resistance
        sha3_hash = hashlib.sha3_512(data)
        
        # Additional entropy mixing
        blake2_hash = hashlib.blake2b(data, digest_size=64)
        
        # Combine hashes for enhanced security
        combined = sha3_hash.digest() + blake2_hash.digest()
        final_hash = hashlib.sha3_512(combined).hexdigest()
        
        return final_hash
        
    def secure_evidence_storage(self, evidence_data, case_id, investigator_id):
        """Kuantum güvenli kanıt depolama"""
        # Generate quantum-safe encryption key
        salt = secrets.token_bytes(32)
        password = f"{case_id}:{investigator_id}:{datetime.now().isoformat()}"
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA3_512(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        
        key = kdf.derive(password.encode())
        
        # Encrypt evidence with AES-256-GCM
        iv = secrets.token_bytes(12)
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
        encryptor = cipher.encryptor()
        
        if isinstance(evidence_data, str):
            evidence_data = evidence_data.encode('utf-8')
            
        ciphertext = encryptor.update(evidence_data) + encryptor.finalize()
        
        # Create secure evidence package
        evidence_package = {
            'case_id': case_id,
            'investigator_id': investigator_id,
            'timestamp': datetime.now().isoformat(),
            'encryption_algorithm': 'AES-256-GCM',
            'kdf_algorithm': 'PBKDF2-SHA3-512',
            'salt': salt.hex(),
            'iv': iv.hex(),
            'auth_tag': encryptor.tag.hex(),
            'encrypted_data': ciphertext.hex(),
            'integrity_hash': self.quantum_safe_hash(evidence_data)
        }
        
        return evidence_package
        
    def verify_evidence_integrity(self, evidence_package, case_id, investigator_id):
        """Kuantum güvenli kanıt bütünlük doğrulama"""
        try:
            # Reconstruct decryption key
            salt = bytes.fromhex(evidence_package['salt'])
            password = f"{case_id}:{investigator_id}:{evidence_package['timestamp']}"
            
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA3_512(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            
            key = kdf.derive(password.encode())
            
            # Decrypt evidence
            iv = bytes.fromhex(evidence_package['iv'])
            auth_tag = bytes.fromhex(evidence_package['auth_tag'])
            ciphertext = bytes.fromhex(evidence_package['encrypted_data'])
            
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv, auth_tag))
            decryptor = cipher.decryptor()
            
            decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Verify integrity hash
            calculated_hash = self.quantum_safe_hash(decrypted_data)
            stored_hash = evidence_package['integrity_hash']
            
            verification_result = {
                'verified': calculated_hash == stored_hash,
                'calculated_hash': calculated_hash,
                'stored_hash': stored_hash,
                'decrypted_successfully': True,
                'verification_timestamp': datetime.now().isoformat()
            }
            
            if verification_result['verified']:
                verification_result['decrypted_data'] = decrypted_data
                
            return verification_result
            
        except Exception as e:
            return {
                'verified': False,
                'error': str(e),
                'decrypted_successfully': False,
                'verification_timestamp': datetime.now().isoformat()
            }
            
    def quantum_threat_assessment(self, forensic_data):
        """Kuantum tehdit değerlendirmesi"""
        assessment = {
            'assessment_date': datetime.now().isoformat(),
            'quantum_vulnerability_score': 0,
            'vulnerable_algorithms': [],
            'recommended_upgrades': [],
            'timeline_for_migration': 'Immediate'
        }
        
        # Check for vulnerable cryptographic algorithms
        vulnerable_patterns = {
            'RSA': {'score': 90, 'urgency': 'Critical'},
            'ECDSA': {'score': 85, 'urgency': 'High'},
            'DH': {'score': 80, 'urgency': 'High'},
            'MD5': {'score': 95, 'urgency': 'Critical'},
            'SHA1': {'score': 70, 'urgency': 'Medium'}
        }
        
        data_str = json.dumps(forensic_data, default=str).lower()
        
        for algorithm, risk_info in vulnerable_patterns.items():
            if algorithm.lower() in data_str:
                assessment['vulnerable_algorithms'].append({
                    'algorithm': algorithm,
                    'vulnerability_score': risk_info['score'],
                    'urgency': risk_info['urgency']
                })
                assessment['quantum_vulnerability_score'] += risk_info['score']
                
        # Normalize score
        if assessment['vulnerable_algorithms']:
            assessment['quantum_vulnerability_score'] = min(
                assessment['quantum_vulnerability_score'] / len(assessment['vulnerable_algorithms']), 
                100
            )
            
        # Generate recommendations
        if assessment['quantum_vulnerability_score'] > 80:
            assessment['recommended_upgrades'].extend([
                'Migrate to post-quantum cryptography immediately',
                'Implement quantum-safe key exchange protocols',
                'Update digital signature schemes to SPHINCS+ or Dilithium'
            ])
            assessment['timeline_for_migration'] = 'Immediate (0-6 months)'
            
        elif assessment['quantum_vulnerability_score'] > 50:
            assessment['recommended_upgrades'].extend([
                'Plan migration to quantum-resistant algorithms',
                'Implement hybrid classical-quantum cryptography',
                'Upgrade hash functions to SHA-3 family'
            ])
            assessment['timeline_for_migration'] = 'Short-term (6-18 months)'
            
        else:
            assessment['recommended_upgrades'].append(
                'Monitor quantum computing developments'
            )
            assessment['timeline_for_migration'] = 'Long-term (2-5 years)'
            
        return assessment
        
    def future_proof_evidence_chain(self, evidence_items):
        """Geleceğe dayanıklı kanıt zinciri"""
        future_proof_chain = {
            'chain_id': secrets.token_hex(16),
            'creation_timestamp': datetime.now().isoformat(),
            'quantum_safe_protocol_version': '1.0',
            'evidence_items': [],
            'chain_integrity_proof': None
        }
        
        # Process each evidence item
        for i, evidence in enumerate(evidence_items):
            # Create quantum-safe evidence entry
            evidence_entry = {
                'sequence_number': i + 1,
                'evidence_id': evidence.get('id', f'evidence_{i+1}'),
                'timestamp': datetime.now().isoformat(),
                'quantum_safe_hash': self.quantum_safe_hash(json.dumps(evidence, sort_keys=True)),
                'previous_hash': None,
                'metadata': evidence
            }
            
            # Link to previous evidence (blockchain-like)
            if future_proof_chain['evidence_items']:
                previous_entry = future_proof_chain['evidence_items'][-1]
                evidence_entry['previous_hash'] = previous_entry['quantum_safe_hash']
                
            future_proof_chain['evidence_items'].append(evidence_entry)
            
        # Create chain integrity proof
        chain_data = json.dumps(future_proof_chain['evidence_items'], sort_keys=True)
        future_proof_chain['chain_integrity_proof'] = self.quantum_safe_hash(chain_data)
        
        return future_proof_chain
        
    def verify_future_proof_chain(self, evidence_chain):
        """Geleceğe dayanıklı zincir doğrulama"""
        verification_result = {
            'chain_valid': True,
            'verification_timestamp': datetime.now().isoformat(),
            'issues_found': [],
            'integrity_verified': False
        }
        
        # Verify chain integrity proof
        chain_data = json.dumps(evidence_chain['evidence_items'], sort_keys=True)
        calculated_proof = self.quantum_safe_hash(chain_data)
        
        if calculated_proof != evidence_chain['chain_integrity_proof']:
            verification_result['chain_valid'] = False
            verification_result['issues_found'].append('Chain integrity proof mismatch')
        else:
            verification_result['integrity_verified'] = True
            
        # Verify individual evidence items
        for i, evidence_item in enumerate(evidence_chain['evidence_items']):
            # Verify hash
            metadata_str = json.dumps(evidence_item['metadata'], sort_keys=True)
            calculated_hash = self.quantum_safe_hash(metadata_str)
            
            if calculated_hash != evidence_item['quantum_safe_hash']:
                verification_result['chain_valid'] = False
                verification_result['issues_found'].append(
                    f'Evidence item {i+1} hash mismatch'
                )
                
            # Verify chain linkage
            if i > 0:
                previous_hash = evidence_chain['evidence_items'][i-1]['quantum_safe_hash']
                if evidence_item['previous_hash'] != previous_hash:
                    verification_result['chain_valid'] = False
                    verification_result['issues_found'].append(
                        f'Evidence item {i+1} chain linkage broken'
                    )
                    
        return verification_result

# Usage example
if __name__ == "__main__":
    quantum_forensics = QuantumSafeForensics()
    
    # Example evidence data
    evidence_data = "Confidential forensic evidence from Case-2024-001"
    
    # Secure storage
    evidence_package = quantum_forensics.secure_evidence_storage(
        evidence_data, "CASE-2024-001", "INVESTIGATOR-123"
    )
    
    print("Evidence securely stored with quantum-safe encryption")
    
    # Verify integrity
    verification = quantum_forensics.verify_evidence_integrity(
        evidence_package, "CASE-2024-001", "INVESTIGATOR-123"
    )
    
    print(f"Evidence integrity verified: {verification['verified']}")
    
    # Quantum threat assessment
    sample_forensic_data = {
        'encryption_used': ['RSA-2048', 'AES-256'],
        'hash_algorithms': ['SHA-256', 'MD5'],
        'digital_signatures': ['ECDSA']
    }
    
    threat_assessment = quantum_forensics.quantum_threat_assessment(sample_forensic_data)
    print(f"Quantum vulnerability score: {threat_assessment['quantum_vulnerability_score']:.1f}")
    print(f"Migration timeline: {threat_assessment['timeline_for_migration']}")
```

## 📚 Kaynaklar ve Referanslar

### Kitaplar
- **"Digital Forensics with Open Source Tools"** - Cory Altheide, Harlan Carvey
- **"The Art of Memory Forensics"** - Michael Hale Ligh, Andrew Case, Jamie Levy
- **"File System Forensic Analysis"** - Brian Carrier
- **"Malware Analyst's Cookbook"** - Michael Hale Ligh, Steven Adair
- **"Network Forensics: Tracking Hackers through Cyberspace"** - Sherri Davidoff

### Çevrimiçi Kaynaklar
- **SANS Digital Forensics**: https://www.sans.org/cyber-security-courses/digital-forensics/
- **Volatility Foundation**: https://www.volatilityfoundation.org/
- **Autopsy Digital Forensics**: https://www.autopsy.com/
- **NIST Computer Forensics Tool Testing**: https://www.nist.gov/itl/ssd/software-quality-group/computer-forensics-tool-testing-cftt

### Araç Dokümantasyonları
- **Sleuth Kit Documentation**: https://wiki.sleuthkit.org/
- **Wireshark User Guide**: https://www.wireshark.org/docs/
- **YARA Documentation**: https://yara.readthedocs.io/
- **Ghidra Software Reverse Engineering**: https://ghidra-sre.org/

### Sertifikasyon Programları
- **GCFA (GIAC Certified Forensic Analyst)**
- **GCFE (GIAC Certified Forensic Examiner)**
- **CCE (Certified Computer Examiner)**
- **CHFI (Computer Hacking Forensic Investigator)**
- **CFCE (Certified Forensic Computer Examiner)**

### CTF ve Pratik Platformları
- **DigForensics CTF**: https://www.amanhardikar.com/mindmaps/ForensicsChallenge.html
- **Forensics Contest**: https://forensicscontest.com/
- **DFRWS Challenges**: https://dfrws.org/forensic-challenges/
- **CyberDefenders**: https://cyberdefenders.org/

### Yasal ve Etik Kaynaklar
- **ISO/IEC 27037**: Guidelines for identification, collection, acquisition and preservation of digital evidence
- **NIST SP 800-86**: Guide to Integrating Forensic Techniques into Incident Response
- **RFC 3227**: Guidelines for Evidence Collection and Archiving
- **ACPO Good Practice Guide**: Digital Evidence

---

**Not**: Bu doküman eğitim amaçlıdır. Gerçek forensic analizlerde yasal prosedürlere uyulması ve uzman danışmanlığı alınması önemlidir.