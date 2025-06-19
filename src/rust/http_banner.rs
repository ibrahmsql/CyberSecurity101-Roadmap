// http_banner.rs – Simple HTTP banner grabber (Rust)
// Build: rustc http_banner.rs
// Usage: ./http_banner <host> <port>
use std::env;
use std::io::{Write, Read};
use std::net::TcpStream;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: {} <host> <port>", args[0]);
        return;
    }
    let addr = format!("{}:{}", args[1], args[2]);
    match TcpStream::connect(&addr) {
        Ok(mut stream) => {
            let _ = stream.write_all(b"HEAD / HTTP/1.0\r\n\r\n");
            let mut buf = [0; 512];
            if let Ok(size) = stream.read(&mut buf) {
                let resp = String::from_utf8_lossy(&buf[..size]);
                println!("{}", resp);
            }
        },
        Err(e) => eprintln!("Connection error: {}", e),
    }
}
