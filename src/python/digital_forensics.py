#!/usr/bin/env python3
"""
Digital Forensics Analysis Framework
Comprehensive toolkit for digital evidence analysis and forensic investigations
"""

import os
import sys
import json
import hashlib
import subprocess
from datetime import datetime
from collections import defaultdict, Counter
import ipaddress

# Digital Evidence Principles
class DigitalEvidencePrinciples:
    """
    Digital evidence principles and validation
    """
    
    def __init__(self):
        self.chain_of_custody = []
        self.evidence_hashes = {}
    
    def calculate_hash(self, file_path, algorithm='sha256'):
        """Calculate file hash"""
        hash_func = hashlib.new(algorithm)
        
        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_func.update(chunk)
            
            file_hash = hash_func.hexdigest()
            self.evidence_hashes[file_path] = {
                'algorithm': algorithm,
                'hash': file_hash,
                'timestamp': datetime.now().isoformat()
            }
            
            return file_hash
        
        except Exception as e:
            print(f"Hash calculation failed: {e}")
            return None
    
    def verify_integrity(self, file_path, expected_hash, algorithm='sha256'):
        """Verify evidence integrity"""
        current_hash = self.calculate_hash(file_path, algorithm)
        
        if current_hash == expected_hash:
            print(f"✓ Integrity verified for {file_path}")
            return True
        else:
            print(f"✗ Integrity check failed for {file_path}")
            print(f"Expected: {expected_hash}")
            print(f"Current:  {current_hash}")
            return False
    
    def add_custody_entry(self, action, person, timestamp=None):
        """Add chain of custody entry"""
        if timestamp is None:
            timestamp = datetime.now().isoformat()
        
        entry = {
            'timestamp': timestamp,
            'action': action,
            'person': person
        }
        
        self.chain_of_custody.append(entry)
        return entry
    
    def export_custody_log(self, output_file):
        """Export chain of custody log"""
        with open(output_file, 'w') as f:
            json.dump({
                'chain_of_custody': self.chain_of_custody,
                'evidence_hashes': self.evidence_hashes
            }, f, indent=2)
        
        print(f"Custody log exported to: {output_file}")

# NTFS Forensic Analyzer
class NTFSForensicAnalyzer:
    """
    NTFS file system forensic analysis
    """
    
    def __init__(self, image_path):
        self.image_path = image_path
        self.boot_sector = None
        self.mft_entries = []
        self.deleted_files = []
    
    def parse_boot_sector(self):
        """Boot sector analysis"""
        try:
            with open(self.image_path, 'rb') as f:
                boot_data = f.read(512)  # Boot sector is 512 bytes
            
            # Parse NTFS boot sector
            self.boot_sector = {
                'oem_id': boot_data[3:11].decode('ascii', errors='ignore'),
                'bytes_per_sector': int.from_bytes(boot_data[11:13], 'little'),
                'sectors_per_cluster': boot_data[13],
                'total_sectors': int.from_bytes(boot_data[44:52], 'little'),
                'mft_cluster': int.from_bytes(boot_data[48:56], 'little'),
                'clusters_per_mft_record': boot_data[64]
            }
            
            print(f"NTFS Boot Sector Analysis:")
            print(f"OEM ID: {self.boot_sector['oem_id']}")
            print(f"Bytes per sector: {self.boot_sector['bytes_per_sector']}")
            print(f"Sectors per cluster: {self.boot_sector['sectors_per_cluster']}")
            print(f"Total sectors: {self.boot_sector['total_sectors']}")
            print(f"MFT cluster: {self.boot_sector['mft_cluster']}")
            
            return self.boot_sector
        
        except Exception as e:
            print(f"Boot sector analysis failed: {e}")
            return None
    
    def analyze_mft(self):
        """Master File Table analizi"""
        if not self.boot_sector:
            self.parse_boot_sector()
        
        try:
            # Calculate MFT location
            mft_offset = (self.boot_sector['mft_cluster'] * 
                         self.boot_sector['sectors_per_cluster'] * 
                         self.boot_sector['bytes_per_sector'])
            
            with open(self.image_path, 'rb') as f:
                f.seek(mft_offset)
                
                # Read first few MFT entries for analysis
                for i in range(100):  # Analyze first 100 entries
                    mft_entry = f.read(1024)  # Standard MFT entry size
                    
                    if mft_entry[:4] == b'FILE':
                        entry_info = self.parse_mft_entry(mft_entry, i)
                        if entry_info:
                            self.mft_entries.append(entry_info)
            
            print(f"Analyzed {len(self.mft_entries)} MFT entries")
            return self.mft_entries
        
        except Exception as e:
            print(f"MFT analysis failed: {e}")
            return []
    
    def parse_mft_entry(self, entry_data, entry_number):
        """MFT girişini parse et"""
        try:
            # Basic MFT entry parsing
            flags = int.from_bytes(entry_data[22:24], 'little')
            is_directory = bool(flags & 0x02)
            is_deleted = not bool(flags & 0x01)
            
            entry_info = {
                'entry_number': entry_number,
                'is_directory': is_directory,
                'is_deleted': is_deleted,
                'flags': flags
            }
            
            if is_deleted:
                self.deleted_files.append(entry_info)
            
            return entry_info
        
        except Exception as e:
            print(f"MFT entry parsing failed: {e}")
            return None
    
    def recover_deleted_files(self):
        """Silinmiş dosyaları kurtar"""
        recovered = []
        
        for deleted_file in self.deleted_files:
            if not deleted_file['is_directory']:
                # Attempt file recovery logic here
                recovery_info = {
                    'entry_number': deleted_file['entry_number'],
                    'recovery_status': 'Recoverable',
                    'confidence': 'Medium'
                }
                recovered.append(recovery_info)
        
        print(f"Found {len(recovered)} recoverable deleted files")
        return recovered

# Memory Forensics Analyzer
class MemoryForensicsAnalyzer:
    """
    Gelişmiş bellek adli analizi
    """
    
    def __init__(self, memory_dump):
        self.memory_dump = memory_dump
        self.profile = None
        self.analysis_results = {}
    
    def detect_profile(self):
        """Bellek dökümü profilini tespit et"""
        cmd = f"volatility -f {self.memory_dump} imageinfo"
        
        try:
            result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=300)
            output = result.stdout
            
            # Extract suggested profiles
            if "Suggested Profile(s)" in output:
                profile_line = [line for line in output.split('\n') if "Suggested Profile(s)" in line][0]
                profiles = profile_line.split(':')[1].strip().split(',')[0].strip()
                self.profile = profiles
                print(f"Detected profile: {self.profile}")
            
            return self.profile
        
        except Exception as e:
            print(f"Profile detection failed: {e}")
            return None
    
    def analyze_processes(self):
        """Process analizi yap"""
        if not self.profile:
            self.detect_profile()
        
        cmd = f"volatility -f {self.memory_dump} --profile={self.profile} pslist"
        
        try:
            result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=300)
            processes = self.parse_pslist_output(result.stdout)
            
            # Analyze for suspicious processes
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
            if line.strip() and not line.startswith('-'):
                parts = line.split()
                if len(parts) >= 6:
                    process = {
                        'name': parts[0],
                        'pid': int(parts[1]),
                        'ppid': int(parts[2]),
                        'threads': int(parts[3]),
                        'handles': int(parts[4]),
                        'start_time': ' '.join(parts[5:7]) if len(parts) > 6 else 'Unknown'
                    }
                    processes.append(process)
        
        return processes
    
    def detect_suspicious_processes(self, processes):
        """Şüpheli processleri tespit et"""
        suspicious = []
        
        # Known suspicious process names
        suspicious_names = [
            'nc.exe', 'netcat.exe', 'ncat.exe', 'psexec.exe',
            'mimikatz.exe', 'procdump.exe', 'pwdump.exe',
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
            if line.strip() and ('TCP' in line or 'UDP' in line):
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

# Network Forensics Analyzer
class NetworkForensicsAnalyzer:
    """
    Network Forensics Analysis Framework
    """
    
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.packets = []
        self.connections = defaultdict(list)
        self.protocols = Counter()
        self.suspicious_activities = []
    
    def load_packets(self, packet_limit=None):
        """PCAP dosyasından paketleri yükle (simulated)"""
        # This would normally use pyshark or similar library
        # For demonstration, we'll create a mock implementation
        print(f"Loading packets from {self.pcap_file}")
        
        # Mock packet data
        mock_packets = [
            {
                'timestamp': datetime.now().timestamp(),
                'src_ip': '192.168.1.100',
                'dst_ip': '10.0.0.1',
                'src_port': 12345,
                'dst_port': 80,
                'protocol': 'TCP',
                'length': 1500
            },
            {
                'timestamp': datetime.now().timestamp(),
                'src_ip': '192.168.1.100',
                'dst_ip': '8.8.8.8',
                'src_port': 53,
                'dst_port': 53,
                'protocol': 'UDP',
                'length': 64
            }
        ]
        
        self.packets = mock_packets[:packet_limit] if packet_limit else mock_packets
        print(f"Loaded {len(self.packets)} packets")
    
    def detect_suspicious_activities(self):
        """Şüpheli aktiviteleri tespit et"""
        self.suspicious_activities = []
        
        # Port scanning detection
        self.detect_port_scanning()
        
        # DDoS detection
        self.detect_ddos_patterns()
        
        # Data exfiltration patterns
        self.detect_data_exfiltration()
        
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
                    'source_ip': src_ip,
                    'ports_scanned': len(ports),
                    'severity': 'HIGH'
                })
    
    def detect_ddos_patterns(self):
        """DDoS kalıpları tespiti"""
        packet_counts = Counter()
        
        for packet in self.packets:
            if 'dst_ip' in packet:
                packet_counts[packet['dst_ip']] += 1
        
        # Detect high packet counts to single destination
        for dst_ip, count in packet_counts.items():
            if count > 1000:  # Threshold for potential DDoS
                self.suspicious_activities.append({
                    'type': 'potential_ddos',
                    'target_ip': dst_ip,
                    'packet_count': count,
                    'severity': 'HIGH'
                })
    
    def detect_data_exfiltration(self):
        """Veri sızdırma kalıpları tespiti"""
        large_transfers = []
        
        for packet in self.packets:
            if packet.get('length', 0) > 1400:  # Large packet threshold
                large_transfers.append(packet)
        
        if len(large_transfers) > 100:  # Many large transfers
            self.suspicious_activities.append({
                'type': 'potential_data_exfiltration',
                'large_packet_count': len(large_transfers),
                'severity': 'MEDIUM'
            })
    
    def generate_forensic_report(self):
        """Forensik rapor oluştur"""
        report = {
            'analysis_timestamp': datetime.now().isoformat(),
            'pcap_file': self.pcap_file,
            'total_packets': len(self.packets),
            'protocol_distribution': dict(self.protocols),
            'suspicious_activities': self.suspicious_activities,
            'summary': {
                'total_suspicious_events': len(self.suspicious_activities),
                'high_severity_events': len([a for a in self.suspicious_activities if a.get('severity') == 'HIGH'])
            }
        }
        
        return report

# Usage example
if __name__ == "__main__":
    print("Digital Forensics Analysis Framework")
    print("=====================================")
    
    # Example usage of different analyzers
    
    # Digital Evidence Principles
    evidence = DigitalEvidencePrinciples()
    evidence.add_custody_entry("Evidence collected", "Investigator John Doe")
    
    # Memory Forensics (example)
    # memory_analyzer = MemoryForensicsAnalyzer("/path/to/memory.dmp")
    # memory_analyzer.detect_profile()
    # memory_analyzer.analyze_processes()
    
    # Network Forensics (example)
    # network_analyzer = NetworkForensicsAnalyzer("/path/to/capture.pcap")
    # network_analyzer.load_packets()
    # network_analyzer.detect_suspicious_activities()
    
    print("Framework initialized successfully!")