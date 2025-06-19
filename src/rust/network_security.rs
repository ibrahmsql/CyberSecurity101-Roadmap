// Network Security Toolkit in Rust
// Build: cargo build --release
// Usage: ./netsec [command] [options]
// Requires Rust 1.56+

use std::env;
use std::net::{TcpStream, ToSocketAddrs, IpAddr};
use std::time::{Duration, Instant};
use std::thread;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::process;

#[derive(Debug, Clone)]
struct ScanResult {
    port: u16,
    is_open: bool,
    service: String,
    banner: Option<String>,
}

#[derive(Debug)]
struct ScanStats {
    total_ports: u32,
    open_ports: u32,
    scan_time: Duration,
}

struct NetworkScanner {
    target: String,
    timeout: Duration,
    threads: usize,
}

impl NetworkScanner {
    fn new(target: String, timeout_ms: u64, threads: usize) -> Self {
        Self {
            target,
            timeout: Duration::from_millis(timeout_ms),
            threads,
        }
    }

    fn scan_port(&self, port: u16) -> ScanResult {
        let addr = format!("{}:{}", self.target, port);
        let is_open = TcpStream::connect_timeout(&addr.parse().unwrap(), self.timeout).is_ok();
        
        let service = self.detect_service(port);
        let banner = if is_open {
            self.grab_banner(port)
        } else {
            None
        };

        ScanResult {
            port,
            is_open,
            service,
            banner,
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

    fn grab_banner(&self, port: u16) -> Option<String> {
        let addr = format!("{}:{}", self.target, port);
        if let Ok(mut stream) = TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_secs(3)) {
            let mut buffer = [0; 1024];
            if let Ok(bytes_read) = stream.read(&mut buffer) {
                if bytes_read > 0 {
                    let banner = String::from_utf8_lossy(&buffer[..bytes_read]).trim().to_string();
                    if !banner.is_empty() {
                        return Some(banner);
                    }
                }
            }
        }
        None
    }

    fn scan_range(&self, start_port: u16, end_port: u16) -> (Vec<ScanResult>, ScanStats) {
        let start_time = Instant::now();
        let results = Arc::new(Mutex::new(Vec::new()));
        let total_ports = (end_port - start_port + 1) as u32;
        
        println!("[+] Scanning {} ports {}-{} with {} threads", self.target, start_port, end_port, self.threads);
        
        let chunk_size = ((end_port - start_port + 1) as usize / self.threads).max(1);
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
                        if let Some(ref banner) = result.banner {
                            println!("    Banner: {}", banner);
                        }
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
        let open_ports = results.iter().filter(|r| r.is_open).count() as u32;
        
        let stats = ScanStats {
            total_ports,
            open_ports,
            scan_time,
        };
        
        (results, stats)
    }
}

impl Clone for NetworkScanner {
    fn clone(&self) -> Self {
        Self {
            target: self.target.clone(),
            timeout: self.timeout,
            threads: self.threads,
        }
    }
}

struct WebScanner {
    target: String,
    timeout: Duration,
}

impl WebScanner {
    fn new(target: String) -> Self {
        Self {
            target,
            timeout: Duration::from_secs(10),
        }
    }

    fn check_http_headers(&self) -> Result<(), Box<dyn std::error::Error>> {
        let url = if !self.target.starts_with("http") {
            format!("http://{}", self.target)
        } else {
            self.target.clone()
        };
        
        println!("[+] Analyzing HTTP headers for {}", url);
        
        // Simple HTTP request (in a real implementation, you'd use reqwest or similar)
        let host = url.replace("http://", "").replace("https://", "");
        let request = format!(
            "HEAD / HTTP/1.1\r\nHost: {}\r\nUser-Agent: NetSec-Scanner/1.0\r\nConnection: close\r\n\r\n",
            host
        );
        
        if let Ok(mut stream) = TcpStream::connect_timeout(&format!("{}:80", host).parse()?, self.timeout) {
            stream.write_all(request.as_bytes())?;
            
            let mut response = String::new();
            stream.read_to_string(&mut response)?;
            
            println!("Response:\n{}", response);
            
            // Check security headers
            let security_headers = [
                "X-Frame-Options",
                "X-XSS-Protection",
                "X-Content-Type-Options",
                "Strict-Transport-Security",
                "Content-Security-Policy",
            ];
            
            println!("\n[+] Security Headers Check:");
            for header in &security_headers {
                if response.contains(header) {
                    println!("[+] {}: Present", header);
                } else {
                    println!("[-] {}: Missing", header);
                }
            }
        }
        
        Ok(())
    }
}

struct SubdomainScanner {
    domain: String,
}

impl SubdomainScanner {
    fn new(domain: String) -> Self {
        Self { domain }
    }

    fn enumerate_subdomains(&self) {
        let subdomains = [
            "www", "mail", "ftp", "admin", "test", "dev", "staging",
            "api", "blog", "shop", "secure", "vpn", "remote", "portal",
            "app", "mobile", "m", "support", "help", "docs"
        ];
        
        println!("[+] Subdomain enumeration for {}", self.domain);
        
        for subdomain in &subdomains {
            let full_domain = format!("{}.{}", subdomain, self.domain);
            
            if let Ok(addrs) = format!("{}:80", full_domain).to_socket_addrs() {
                for addr in addrs {
                    println!("[+] Found: {} -> {}", full_domain, addr.ip());
                    break; // Just show the first IP
                }
            }
        }
    }
}

fn print_usage(program: &str) {
    println!("Network Security Toolkit in Rust");
    println!("Usage: {} [command] [options]\n", program);
    println!("Commands:");
    println!("  portscan <target> <start> <end> [threads] - TCP port scan");
    println!("  banner <target> <port>                    - Banner grabbing");
    println!("  headers <target>                          - HTTP headers analysis");
    println!("  subdomain <domain>                        - Subdomain enumeration");
    println!("\nExamples:");
    println!("  {} portscan 192.168.1.1 1 1000", program);
    println!("  {} portscan 192.168.1.1 1 1000 50", program);
    println!("  {} banner 192.168.1.1 80", program);
    println!("  {} headers example.com", program);
    println!("  {} subdomain example.com", program);
}

fn main() {
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        print_usage(&args[0]);
        process::exit(1);
    }
    
    match args[1].as_str() {
        "portscan" => {
            if args.len() < 5 {
                eprintln!("Usage: {} portscan <target> <start-port> <end-port> [threads]", args[0]);
                process::exit(1);
            }
            
            let target = args[2].clone();
            let start_port: u16 = args[3].parse().unwrap_or_else(|_| {
                eprintln!("Invalid start port");
                process::exit(1);
            });
            let end_port: u16 = args[4].parse().unwrap_or_else(|_| {
                eprintln!("Invalid end port");
                process::exit(1);
            });
            let threads = if args.len() > 5 {
                args[5].parse().unwrap_or(50)
            } else {
                50
            };
            
            let scanner = NetworkScanner::new(target, 2000, threads);
            let (results, stats) = scanner.scan_range(start_port, end_port);
            
            println!("\n=== Scan Results ===");
            println!("Total ports scanned: {}", stats.total_ports);
            println!("Open ports found: {}", stats.open_ports);
            println!("Scan time: {:.2?}", stats.scan_time);
            
            if stats.open_ports > 0 {
                println!("\n=== Open Ports ===");
                for result in results.iter().filter(|r| r.is_open) {
                    println!("Port {}: {} ({})", result.port, result.service, 
                           if result.banner.is_some() { "with banner" } else { "no banner" });
                }
            }
        },
        
        "banner" => {
            if args.len() != 4 {
                eprintln!("Usage: {} banner <target> <port>", args[0]);
                process::exit(1);
            }
            
            let target = args[2].clone();
            let port: u16 = args[3].parse().unwrap_or_else(|_| {
                eprintln!("Invalid port");
                process::exit(1);
            });
            
            let scanner = NetworkScanner::new(target.clone(), 3000, 1);
            println!("[+] Banner grabbing for {}:{}", target, port);
            
            if let Some(banner) = scanner.grab_banner(port) {
                println!("[+] Banner: {}", banner);
            } else {
                println!("[-] No banner received");
            }
        },
        
        "headers" => {
            if args.len() != 3 {
                eprintln!("Usage: {} headers <target>", args[0]);
                process::exit(1);
            }
            
            let target = args[2].clone();
            let scanner = WebScanner::new(target);
            
            if let Err(e) = scanner.check_http_headers() {
                eprintln!("Error analyzing headers: {}", e);
            }
        },
        
        "subdomain" => {
            if args.len() != 3 {
                eprintln!("Usage: {} subdomain <domain>", args[0]);
                process::exit(1);
            }
            
            let domain = args[2].clone();
            let scanner = SubdomainScanner::new(domain);
            scanner.enumerate_subdomains();
        },
        
        _ => {
            eprintln!("Unknown command: {}", args[1]);
            print_usage(&args[0]);
            process::exit(1);
        }
    }
}
