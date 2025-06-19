// Network Security Toolkit in Go
// Build: go build -o network_security network_security.go
// Usage: ./network_security <command> [options]
// DISCLAIMER: For authorized testing only!

package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type NetworkScanner struct {
	target  string
	threads int
	timeout time.Duration
	results []NetworkScanResult
	mutex   sync.Mutex
}

type NetworkScanResult struct {
	Port    int
	Status  string
	Service string
	Banner  string
}

func NewNetworkScanner(target string, threads int, timeout time.Duration) *NetworkScanner {
	return &NetworkScanner{
		target:  target,
		threads: threads,
		timeout: timeout,
		results: make([]NetworkScanResult, 0),
	}
}

func (ns *NetworkScanner) ScanPort(port int, wg *sync.WaitGroup, semaphore chan struct{}) {
	defer wg.Done()
	defer func() { <-semaphore }()

	address := fmt.Sprintf("%s:%d", ns.target, port)
	conn, err := net.DialTimeout("tcp", address, ns.timeout)

	if err != nil {
		return
	}

	defer conn.Close()

	// Try to grab banner
	banner := ns.grabBanner(conn)
	service := ns.identifyService(port, banner)

	result := NetworkScanResult{
		Port:    port,
		Status:  "open",
		Service: service,
		Banner:  banner,
	}

	ns.mutex.Lock()
	ns.results = append(ns.results, result)
	ns.mutex.Unlock()

	fmt.Printf("[+] Port %d/tcp open - %s\n", port, service)
}

func (ns *NetworkScanner) grabBanner(conn net.Conn) string {
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(buffer[:n]))
}

func (ns *NetworkScanner) identifyService(port int, banner string) string {
	commonPorts := map[int]string{
		21:   "FTP",
		22:   "SSH",
		23:   "Telnet",
		25:   "SMTP",
		53:   "DNS",
		80:   "HTTP",
		110:  "POP3",
		143:  "IMAP",
		443:  "HTTPS",
		993:  "IMAPS",
		995:  "POP3S",
		3306: "MySQL",
		3389: "RDP",
		5432: "PostgreSQL",
		8080: "HTTP-Alt",
	}

	if service, exists := commonPorts[port]; exists {
		return service
	}
	return "Unknown"
}

func (ns *NetworkScanner) PortScan(startPort, endPort int) {
	fmt.Printf("[+] Starting port scan on %s\n", ns.target)
	fmt.Printf("[+] Scanning ports %d-%d\n\n", startPort, endPort)

	start := time.Now()
	semaphore := make(chan struct{}, ns.threads)
	var wg sync.WaitGroup

	for port := startPort; port <= endPort; port++ {
		wg.Add(1)
		semaphore <- struct{}{}
		go ns.ScanPort(port, &wg, semaphore)
	}

	wg.Wait()

	elapsed := time.Since(start)
	fmt.Printf("\n[+] Scan completed in %v\n", elapsed)
	fmt.Printf("[+] Found %d open ports\n", len(ns.results))
}

func webScan(targetURL string) {
	fmt.Printf("[+] Starting web scan on %s\n\n", targetURL)

	// Create HTTP client with custom settings
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// Test basic connectivity
	resp, err := client.Get(targetURL)
	if err != nil {
		fmt.Printf("[-] Error connecting to %s: %v\n", targetURL, err)
		return
	}
	defer resp.Body.Close()

	fmt.Printf("[+] Status: %s\n", resp.Status)
	fmt.Printf("[+] Server: %s\n", resp.Header.Get("Server"))
	fmt.Printf("[+] Content-Type: %s\n", resp.Header.Get("Content-Type"))

	// Check for common security headers
	securityHeaders := map[string]string{
		"X-Frame-Options":           resp.Header.Get("X-Frame-Options"),
		"X-XSS-Protection":          resp.Header.Get("X-XSS-Protection"),
		"X-Content-Type-Options":    resp.Header.Get("X-Content-Type-Options"),
		"Strict-Transport-Security": resp.Header.Get("Strict-Transport-Security"),
		"Content-Security-Policy":   resp.Header.Get("Content-Security-Policy"),
	}

	fmt.Println("\n[+] Security Headers:")
	for header, value := range securityHeaders {
		if value != "" {
			fmt.Printf("  %s: %s\n", header, value)
		} else {
			fmt.Printf("  %s: [MISSING]\n", header)
		}
	}
}

func dirBust(targetURL, wordlistFile string) {
	fmt.Printf("[+] Starting directory enumeration on %s\n", targetURL)

	var wordlist []string
	var err error

	if wordlistFile != "" {
		wordlist, err = loadSecurityWordlist(wordlistFile)
		if err != nil {
			fmt.Printf("[-] Error loading wordlist: %v\n", err)
			return
		}
	} else {
		wordlist = getSecurityDefaultWordlist()
	}

	fmt.Printf("[+] Using wordlist with %d entries\n\n", len(wordlist))

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for _, path := range wordlist {
		url := fmt.Sprintf("%s/%s", strings.TrimSuffix(targetURL, "/"), strings.TrimPrefix(path, "/"))
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == 200 || resp.StatusCode == 301 || resp.StatusCode == 302 || resp.StatusCode == 403 {
			fmt.Printf("[%d] %s\n", resp.StatusCode, path)
		}
	}
}

func getHeaders(targetURL string) {
	fmt.Printf("[+] Getting headers for %s\n\n", targetURL)

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Head(targetURL)
	if err != nil {
		fmt.Printf("[-] Error: %v\n", err)
		return
	}
	defer resp.Body.Close()

	fmt.Printf("Status: %s\n", resp.Status)
	fmt.Println("Headers:")
	for name, values := range resp.Header {
		for _, value := range values {
			fmt.Printf("  %s: %s\n", name, value)
		}
	}
}

func loadSecurityWordlist(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var words []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			words = append(words, line)
		}
	}
	return words, scanner.Err()
}

func getSecurityDefaultWordlist() []string {
	return []string{
		"admin", "administrator", "login", "test", "demo", "backup",
		"api", "app", "assets", "css", "js", "images", "uploads",
		"files", "docs", "download", "temp", "cache", "logs",
		"config", "wp-admin", "wp-content", "phpmyadmin",
		"panel", "dashboard", "user", "account", "profile",
		"help", "support", "contact", "about", "info",
	}
}

func printUsage() {
	fmt.Println("Network Security Toolkit")
	fmt.Println("Usage:")
	fmt.Println("  portscan <target> <start-port> <end-port>")
	fmt.Println("  webscan <target-url>")
	fmt.Println("  dirbust <target-url> [wordlist-file]")
	fmt.Println("  headers <target-url>")
	fmt.Println("")
	fmt.Println("Examples:")
	fmt.Println("  ./network_security portscan 192.168.1.1 1 1000")
	fmt.Println("  ./network_security webscan https://example.com")
	fmt.Println("  ./network_security dirbust http://example.com")
	fmt.Println("  ./network_security headers https://example.com")
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "portscan":
		if len(os.Args) != 5 {
			fmt.Println("Usage: portscan <target> <start-port> <end-port>")
			os.Exit(1)
		}

		target := os.Args[2]
		startPort, err1 := strconv.Atoi(os.Args[3])
		endPort, err2 := strconv.Atoi(os.Args[4])

		if err1 != nil || err2 != nil {
			fmt.Println("Error: Invalid port numbers")
			os.Exit(1)
		}

		scanner := NewNetworkScanner(target, 100, time.Second)
		scanner.PortScan(startPort, endPort)

	case "webscan":
		if len(os.Args) != 3 {
			fmt.Println("Usage: webscan <target-url>")
			os.Exit(1)
		}
		webScan(os.Args[2])

	case "dirbust":
		if len(os.Args) < 3 {
			fmt.Println("Usage: dirbust <target-url> [wordlist-file]")
			os.Exit(1)
		}

		targetURL := os.Args[2]
		wordlistFile := ""
		if len(os.Args) > 3 {
			wordlistFile = os.Args[3]
		}
		dirBust(targetURL, wordlistFile)

	case "headers":
		if len(os.Args) != 3 {
			fmt.Println("Usage: headers <target-url>")
			os.Exit(1)
		}
		getHeaders(os.Args[2])

	default:
		fmt.Printf("Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}
