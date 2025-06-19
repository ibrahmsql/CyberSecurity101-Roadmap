// Simple Port Scanner in Rust
// Build: rustc port_scanner.rs
// Usage: ./port_scanner <target> <start_port> <end_port> [threads]
// DISCLAIMER: For authorized testing only!

use std::env;
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};
use std::thread;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;

#[derive(Debug, Clone)]
struct ScanResult {
    port: u16,
    is_open: bool,
    service: String,
}

struct PortScanner {
    target: String,
    timeout: Duration,
    threads: usize,
}

impl PortScanner {
    fn new(target: String, timeout_ms: u64, threads: usize) -> Self {
        Self {
            target,
            timeout: Duration::from_millis(timeout_ms),
            threads,
        }
    }

    fn scan_port(&self, port: u16) -> ScanResult {
        let addr = format!("{}:{}", self.target, port);
        let is_open = match addr.to_socket_addrs() {
            Ok(mut addrs) => {
                if let Some(socket_addr) = addrs.next() {
                    TcpStream::connect_timeout(&socket_addr, self.timeout).is_ok()
                } else {
                    false
                }
            }
            Err(_) => false,
        };
        
        let service = self.detect_service(port);

        ScanResult {
            port,
            is_open,
            service,
        }
    }

    fn detect_service(&self, port: u16) -> String {
        match port {
            21 => "FTP".to_string(),
            22 => "SSH".to_string(),
            23 => "Telnet".to_string(),
            25 => "SMTP".to_string(),
            53 => "DNS".to_string(),
            80 => "HTTP".to_string(),
            110 => "POP3".to_string(),
            143 => "IMAP".to_string(),
            443 => "HTTPS".to_string(),
            993 => "IMAPS".to_string(),
            995 => "POP3S".to_string(),
            3389 => "RDP".to_string(),
            5432 => "PostgreSQL".to_string(),
            3306 => "MySQL".to_string(),
            1433 => "MSSQL".to_string(),
            6379 => "Redis".to_string(),
            27017 => "MongoDB".to_string(),
            _ => "Unknown".to_string(),
        }
    }

    fn scan_range(&self, start_port: u16, end_port: u16) -> Vec<ScanResult> {
        let start_time = Instant::now();
        let results = Arc::new(Mutex::new(Vec::new()));
        let total_ports = (end_port - start_port + 1) as usize;
        
        println!("[+] Scanning {} ports {}-{} with {} threads", 
                 self.target, start_port, end_port, self.threads);
        
        let chunk_size = (total_ports / self.threads).max(1);
        let mut handles = vec![];
        
        for chunk_start in (start_port..=end_port).step_by(chunk_size) {
            let chunk_end = (chunk_start + chunk_size as u16 - 1).min(end_port);
            let scanner = self.clone();
            let results_clone = Arc::clone(&results);
            
            let handle = thread::spawn(move || {
                for port in chunk_start..=chunk_end {
                    let result = scanner.scan_port(port);
                    if result.is_open {
                        println!("[+] Port {}: OPEN ({})", port, result.service);
                    }
                    results_clone.lock().unwrap().push(result);
                }
            });
            handles.push(handle);
        }
        
        for handle in handles {
            handle.join().unwrap();
        }
        
        let scan_time = start_time.elapsed();
        let results = Arc::try_unwrap(results).unwrap().into_inner().unwrap();
        let open_ports: Vec<_> = results.iter().filter(|r| r.is_open).collect();
        
        println!("\n=== Scan Results ===");
        println!("Total ports scanned: {}", total_ports);
        println!("Open ports found: {}", open_ports.len());
        println!("Scan time: {:.2}s", scan_time.as_secs_f64());
        
        if !open_ports.is_empty() {
            println!("\n=== Open Ports ===");
            for result in &open_ports {
                println!("Port {}: {} ({})", result.port, "OPEN", result.service);
            }
        }
        
        results
    }

    fn scan_common_ports(&self) -> Vec<ScanResult> {
        let common_ports = vec![
            21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995,
            1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017
        ];
        
        println!("[+] Scanning {} common ports on {}", common_ports.len(), self.target);
        
        let start_time = Instant::now();
        let results = Arc::new(Mutex::new(Vec::new()));
        let mut handles = vec![];
        
        let chunk_size = (common_ports.len() / self.threads).max(1);
        
        for chunk in common_ports.chunks(chunk_size) {
            let ports = chunk.to_vec();
            let scanner = self.clone();
            let results_clone = Arc::clone(&results);
            
            let handle = thread::spawn(move || {
                for port in ports {
                    let result = scanner.scan_port(port);
                    if result.is_open {
                        println!("[+] Port {}: OPEN ({})", port, result.service);
                    }
                    results_clone.lock().unwrap().push(result);
                }
            });
            handles.push(handle);
        }
        
        for handle in handles {
            handle.join().unwrap();
        }
        
        let scan_time = start_time.elapsed();
        let results = Arc::try_unwrap(results).unwrap().into_inner().unwrap();
        let open_ports: Vec<_> = results.iter().filter(|r| r.is_open).collect();
        
        println!("\n=== Common Ports Scan Results ===");
        println!("Total ports scanned: {}", common_ports.len());
        println!("Open ports found: {}", open_ports.len());
        println!("Scan time: {:.2}s", scan_time.as_secs_f64());
        
        if !open_ports.is_empty() {
            println!("\n=== Open Ports ===");
            for result in &open_ports {
                println!("Port {}: {} ({})", result.port, "OPEN", result.service);
            }
        }
        
        results
    }
}

impl Clone for PortScanner {
    fn clone(&self) -> Self {
        Self {
            target: self.target.clone(),
            timeout: self.timeout,
            threads: self.threads,
        }
    }
}

fn print_usage() {
    println!("Simple Port Scanner in Rust");
    println!("Usage: port_scanner <target> [start_port] [end_port] [threads]");
    println!("");
    println!("Arguments:");
    println!("  target      - Target IP address or hostname");
    println!("  start_port  - Starting port number (optional)");
    println!("  end_port    - Ending port number (optional)");
    println!("  threads     - Number of threads (optional, default: 50)");
    println!("");
    println!("Examples:");
    println!("  ./port_scanner 192.168.1.1              # Scan common ports");
    println!("  ./port_scanner 192.168.1.1 1 1000       # Scan ports 1-1000");
    println!("  ./port_scanner scanme.nmap.org 20 80 100 # Scan ports 20-80 with 100 threads");
    println!("  ./port_scanner 10.0.0.1 443 443         # Scan only port 443");
    println!("");
    println!("DISCLAIMER: For authorized testing only!");
}

fn main() {
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 || args.len() > 5 {
        print_usage();
        std::process::exit(1);
    }
    
    let target = args[1].clone();
    
    let scanner = if args.len() == 2 {
        // Only target provided, scan common ports
        let scanner = PortScanner::new(target, 1000, 50);
        scanner.scan_common_ports();
        return;
    } else if args.len() >= 4 {
        // Full range scan
        let start_port: u16 = match args[2].parse() {
            Ok(port) => port,
            Err(_) => {
                eprintln!("Error: Invalid start port number");
                std::process::exit(1);
            }
        };
        
        let end_port: u16 = match args[3].parse() {
            Ok(port) => port,
            Err(_) => {
                eprintln!("Error: Invalid end port number");
                std::process::exit(1);
            }
        };
        
        let threads = if args.len() == 5 {
            match args[4].parse() {
                Ok(t) => t,
                Err(_) => {
                    eprintln!("Error: Invalid thread count");
                    std::process::exit(1);
                }
            }
        } else {
            50
        };
        
        // Validate inputs
        if start_port == 0 || end_port > 65535 || start_port > end_port {
            eprintln!("Error: Invalid port range. Ports must be between 1-65535 and start <= end");
            std::process::exit(1);
        }
        
        if threads == 0 || threads > 1000 {
            eprintln!("Error: Thread count must be between 1-1000");
            std::process::exit(1);
        }
        
        let scanner = PortScanner::new(target, 1000, threads);
        scanner.scan_range(start_port, end_port);
    } else {
        print_usage();
        std::process::exit(1);
    };
}