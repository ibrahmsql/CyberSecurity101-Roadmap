# Network Security Toolkit in Crystal
# Build: crystal build network_security.cr --release
# Usage: ./network_security [command] [options]

require "socket"
require "http/client"
require "json"
require "time"
require "fiber"

struct ScanResult
  property port : Int32
  property is_open : Bool
  property service : String
  property banner : String?
  
  def initialize(@port : Int32, @is_open : Bool, @service : String, @banner : String? = nil)
  end
end

struct ScanStats
  property total_ports : Int32
  property open_ports : Int32
  property scan_time : Time::Span
  
  def initialize(@total_ports : Int32, @open_ports : Int32, @scan_time : Time::Span)
  end
end

class NetworkScanner
  property target : String
  property timeout : Time::Span
  property max_fibers : Int32
  
  def initialize(@target : String, timeout_ms : Int32 = 2000, @max_fibers : Int32 = 100)
    @timeout = timeout_ms.milliseconds
  end
  
  def detect_service(port : Int32) : String
    case port
    when 21   then "FTP"
    when 22   then "SSH"
    when 23   then "Telnet"
    when 25   then "SMTP"
    when 53   then "DNS"
    when 80   then "HTTP"
    when 110  then "POP3"
    when 143  then "IMAP"
    when 443  then "HTTPS"
    when 993  then "IMAPS"
    when 995  then "POP3S"
    when 3389 then "RDP"
    when 5432 then "PostgreSQL"
    when 3306 then "MySQL"
    when 1433 then "MSSQL"
    when 6379 then "Redis"
    when 27017 then "MongoDB"
    else "Unknown"
    end
  end
  
  def scan_port(port : Int32) : ScanResult
    is_open = false
    banner = nil
    
    begin
      socket = TCPSocket.new(@target, port, connect_timeout: @timeout)
      is_open = true
      
      # Try to grab banner
      socket.read_timeout = 3.seconds
      if data = socket.gets(1024, chomp: false)
        banner = data.strip unless data.empty?
      end
      socket.close
    rescue
      # Port is closed or filtered
    end
    
    service = detect_service(port)
    ScanResult.new(port, is_open, service, banner)
  end
  
  def scan_range(start_port : Int32, end_port : Int32) : Tuple(Array(ScanResult), ScanStats)
    start_time = Time.monotonic
    results = [] of ScanResult
    mutex = Mutex.new
    
    total_ports = end_port - start_port + 1
    puts "[+] Scanning #{@target} ports #{start_port}-#{end_port} with #{@max_fibers} fibers"
    
    channel = Channel(ScanResult).new(@max_fibers)
    
    # Start scanner fibers
    @max_fibers.times do
      spawn do
        loop do
          begin
            port = channel.receive
            result = scan_port(port.port)
            
            mutex.synchronize do
              results << result
              if result.is_open
                puts "[+] Port #{result.port}: OPEN (#{result.service})"
                if banner = result.banner
                  puts "    Banner: #{banner}"
                end
              end
            end
          rescue Channel::ClosedError
            break
          end
        end
      end
    end
    
    # Send ports to scan
    spawn do
      (start_port..end_port).each do |port|
        channel.send(ScanResult.new(port, false, ""))
      end
      channel.close
    end
    
    # Wait for all results
    while results.size < total_ports
      Fiber.yield
    end
    
    scan_time = Time.monotonic - start_time
    open_ports = results.count(&.is_open)
    
    stats = ScanStats.new(total_ports, open_ports, scan_time)
    {results, stats}
  end
end

class WebScanner
  property target : String
  
  def initialize(@target : String)
  end
  
  def check_http_headers
    url = @target.starts_with?("http") ? @target : "http://#{@target}"
    puts "[+] Analyzing HTTP headers for #{url}"
    
    begin
      response = HTTP::Client.head(url)
      
      puts "\nStatus: #{response.status_code} #{response.status_message}"
      puts "\nHeaders:"
      response.headers.each do |name, values|
        values.each do |value|
          puts "#{name}: #{value}"
        end
      end
      
      # Check security headers
      security_headers = [
        "X-Frame-Options",
        "X-XSS-Protection", 
        "X-Content-Type-Options",
        "Strict-Transport-Security",
        "Content-Security-Policy"
      ]
      
      puts "\n[+] Security Headers Check:"
      security_headers.each do |header|
        if response.headers.has_key?(header)
          puts "[+] #{header}: Present"
        else
          puts "[-] #{header}: Missing"
        end
      end
      
    rescue ex
      puts "Error: #{ex.message}"
    end
  end
end

class SubdomainScanner
  property domain : String
  
  def initialize(@domain : String)
  end
  
  def enumerate_subdomains(wordlist : String? = nil)
    subdomains = if wordlist && File.exists?(wordlist)
      File.read_lines(wordlist).map(&.strip).reject(&.empty?)
    else
      [
        "www", "mail", "ftp", "admin", "test", "dev", "staging",
        "api", "blog", "shop", "secure", "vpn", "remote", "portal",
        "app", "mobile", "m", "support", "help", "docs", "cdn",
        "assets", "static", "img", "images", "upload", "downloads"
      ]
    end
    
    puts "[+] Subdomain enumeration for #{@domain}"
    puts "[+] Testing #{subdomains.size} subdomains"
    
    found_count = 0
    
    subdomains.each do |subdomain|
      target = "#{subdomain}.#{@domain}"
      
      begin
        Socket::Addrinfo.resolve(target, "http") do |addr|
          puts "[+] Found: #{target} -> #{addr.ip_address}"
          found_count += 1
        end
      rescue
        # Subdomain not found
      end
    end
    
    puts "\n[+] Found #{found_count} subdomains"
  end
end

class DNSScanner
  property target : String
  
  def initialize(@target : String)
  end
  
  def dns_lookup
    puts "[+] DNS lookup for #{@target}"
    
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]
    
    record_types.each do |record_type|
      puts "\n--- #{record_type} Records ---"
      
      begin
        case record_type
        when "A"
          Socket::Addrinfo.resolve(@target, "http", Socket::Family::INET) do |addr|
            puts "#{@target} -> #{addr.ip_address}"
          end
        when "AAAA"
          Socket::Addrinfo.resolve(@target, "http", Socket::Family::INET6) do |addr|
            puts "#{@target} -> #{addr.ip_address}"
          end
        else
          puts "#{record_type} lookup not implemented in basic version"
        end
      rescue ex
        puts "No #{record_type} records found or error: #{ex.message}"
      end
    end
  end
end

def print_usage(program : String)
  puts "Network Security Toolkit in Crystal"
  puts "Usage: #{program} [command] [options]\n"
  puts "Commands:"
  puts "  portscan <target> <start> <end> [fibers]  - TCP port scan"
  puts "  banner <target> <port>                    - Banner grabbing"
  puts "  headers <target>                          - HTTP headers analysis"
  puts "  subdomain <domain> [wordlist]             - Subdomain enumeration"
  puts "  dns <domain>                              - DNS lookup"
  puts "\nExamples:"
  puts "  #{program} portscan 192.168.1.1 1 1000"
  puts "  #{program} portscan 192.168.1.1 1 1000 200"
  puts "  #{program} banner 192.168.1.1 80"
  puts "  #{program} headers example.com"
  puts "  #{program} subdomain example.com"
  puts "  #{program} subdomain example.com wordlist.txt"
  puts "  #{program} dns example.com"
end

if ARGV.size < 1
  print_usage(PROGRAM_NAME)
  exit 1
end

case ARGV[0]
when "portscan"
  if ARGV.size < 4
    puts "Usage: #{PROGRAM_NAME} portscan <target> <start-port> <end-port> [fibers]"
    exit 1
  end
  
  target = ARGV[1]
  start_port = ARGV[2].to_i
  end_port = ARGV[3].to_i
  fibers = ARGV.size > 4 ? ARGV[4].to_i : 100
  
  scanner = NetworkScanner.new(target, 2000, fibers)
  results, stats = scanner.scan_range(start_port, end_port)
  
  puts "\n=== Scan Results ==="
  puts "Total ports scanned: #{stats.total_ports}"
  puts "Open ports found: #{stats.open_ports}"
  puts "Scan time: #{stats.scan_time.total_seconds.round(2)}s"
  
  if stats.open_ports > 0
    puts "\n=== Open Ports ==="
    results.select(&.is_open).each do |result|
      banner_info = result.banner ? "with banner" : "no banner"
      puts "Port #{result.port}: #{result.service} (#{banner_info})"
    end
  end
  
when "banner"
  if ARGV.size != 3
    puts "Usage: #{PROGRAM_NAME} banner <target> <port>"
    exit 1
  end
  
  target = ARGV[1]
  port = ARGV[2].to_i
  
  scanner = NetworkScanner.new(target)
  puts "[+] Banner grabbing for #{target}:#{port}"
  
  result = scanner.scan_port(port)
  if result.banner
    puts "[+] Banner: #{result.banner}"
  else
    puts "[-] No banner received"
  end
  
when "headers"
  if ARGV.size != 2
    puts "Usage: #{PROGRAM_NAME} headers <target>"
    exit 1
  end
  
  target = ARGV[1]
  scanner = WebScanner.new(target)
  scanner.check_http_headers
  
when "subdomain"
  if ARGV.size < 2
    puts "Usage: #{PROGRAM_NAME} subdomain <domain> [wordlist]"
    exit 1
  end
  
  domain = ARGV[1]
  wordlist = ARGV.size > 2 ? ARGV[2] : nil
  
  scanner = SubdomainScanner.new(domain)
  scanner.enumerate_subdomains(wordlist)
  
when "dns"
  if ARGV.size != 2
    puts "Usage: #{PROGRAM_NAME} dns <domain>"
    exit 1
  end
  
  domain = ARGV[1]
  scanner = DNSScanner.new(domain)
  scanner.dns_lookup
  
else
  puts "Unknown command: #{ARGV[0]}"
  print_usage(PROGRAM_NAME)
  exit 1
end
