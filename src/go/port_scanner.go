// Advanced Port Scanner in Go
// Build: go build -o port_scanner port_scanner.go
// Usage: ./port_scanner <target> [options]
// DISCLAIMER: For authorized testing only!

package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type PortScanner struct {
	target    string
	startPort int
	endPort   int
	threads   int
	timeout   time.Duration
	openPorts []int
	mutex     sync.Mutex
}

type PortScanResult struct {
	Port   int
	Status string
	Banner string
}

func NewPortScanner(target string, startPort, endPort, threads int, timeout time.Duration) *PortScanner {
	return &PortScanner{
		target:    target,
		startPort: startPort,
		endPort:   endPort,
		threads:   threads,
		timeout:   timeout,
		openPorts: make([]int, 0),
	}
}

func (ps *PortScanner) ScanPort(port int, results chan<- PortScanResult) {
	address := fmt.Sprintf("%s:%d", ps.target, port)
	conn, err := net.DialTimeout("tcp", address, ps.timeout)

	if err != nil {
		results <- PortScanResult{Port: port, Status: "closed", Banner: ""}
		return
	}

	defer conn.Close()

	// Try to grab banner
	banner := ps.grabBanner(conn)

	ps.mutex.Lock()
	ps.openPorts = append(ps.openPorts, port)
	ps.mutex.Unlock()

	results <- PortScanResult{Port: port, Status: "open", Banner: banner}
}

func (ps *PortScanner) grabBanner(conn net.Conn) string {
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(buffer[:n]))
}

func (ps *PortScanner) Run() {
	fmt.Printf("[+] Starting port scan on %s\n", ps.target)
	fmt.Printf("[+] Scanning ports %d-%d with %d threads\n", ps.startPort, ps.endPort, ps.threads)
	fmt.Printf("[+] Timeout: %v\n\n", ps.timeout)

	start := time.Now()
	results := make(chan PortScanResult, ps.threads)
	semaphore := make(chan struct{}, ps.threads)

	var wg sync.WaitGroup

	// Start scanning
	for port := ps.startPort; port <= ps.endPort; port++ {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			semaphore <- struct{}{} // Acquire semaphore
			ps.ScanPort(p, results)
			<-semaphore // Release semaphore
		}(port)
	}

	// Close results channel when all goroutines are done
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect and display results
	openCount := 0
	for result := range results {
		if result.Status == "open" {
			openCount++
			if result.Banner != "" {
				fmt.Printf("[+] Port %d/tcp open - %s\n", result.Port, result.Banner)
			} else {
				fmt.Printf("[+] Port %d/tcp open\n", result.Port)
			}
		}
	}

	elapsed := time.Since(start)
	fmt.Printf("\n[+] Scan completed in %v\n", elapsed)
	fmt.Printf("[+] Found %d open ports\n", openCount)

	if len(ps.openPorts) > 0 {
		sort.Ints(ps.openPorts)
		fmt.Printf("[+] Open ports: %v\n", ps.openPorts)
	}
}

func printPortScanUsage() {
	fmt.Println("Advanced Port Scanner in Go")
	fmt.Println("Usage: port_scanner <target> [options]")
	fmt.Println("")
	fmt.Println("Options:")
	fmt.Println("  -p, --ports <range>    Port range (e.g., 1-1000, 80,443,8080)")
	fmt.Println("  -t, --threads <num>    Number of threads (default: 100)")
	fmt.Println("  --timeout <duration>   Connection timeout (default: 1s)")
	fmt.Println("  -h, --help            Show this help")
	fmt.Println("")
	fmt.Println("Examples:")
	fmt.Println("  ./port_scanner 192.168.1.1")
	fmt.Println("  ./port_scanner 192.168.1.1 -p 1-1000")
	fmt.Println("  ./port_scanner 192.168.1.1 -t 200 --timeout 2s")
}

func parsePortRange(portRange string) (int, int, error) {
	if strings.Contains(portRange, "-") {
		parts := strings.Split(portRange, "-")
		if len(parts) != 2 {
			return 0, 0, fmt.Errorf("invalid port range format")
		}

		startPort, err := strconv.Atoi(strings.TrimSpace(parts[0]))
		if err != nil {
			return 0, 0, err
		}

		endPort, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil {
			return 0, 0, err
		}

		return startPort, endPort, nil
	}

	// Single port
	port, err := strconv.Atoi(portRange)
	if err != nil {
		return 0, 0, err
	}
	return port, port, nil
}

func main() {
	var (
		portRange = flag.String("p", "1-1000", "Port range to scan")
		threads   = flag.Int("t", 100, "Number of threads")
		timeout   = flag.Duration("timeout", time.Second, "Connection timeout")
		help      = flag.Bool("h", false, "Show help")
	)

	flag.Parse()

	if *help {
		printPortScanUsage()
		return
	}

	if len(flag.Args()) < 1 {
		fmt.Println("Error: Target required")
		printPortScanUsage()
		os.Exit(1)
	}

	target := flag.Args()[0]

	// Validate target
	if net.ParseIP(target) == nil {
		// Try to resolve hostname
		_, err := net.LookupHost(target)
		if err != nil {
			fmt.Printf("Error: Cannot resolve target '%s': %v\n", target, err)
			os.Exit(1)
		}
	}

	startPort, endPort, err := parsePortRange(*portRange)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if startPort < 1 || endPort > 65535 || startPort > endPort {
		fmt.Println("Error: Invalid port range (1-65535)")
		os.Exit(1)
	}

	scanner := NewPortScanner(target, startPort, endPort, *threads, *timeout)
	scanner.Run()
}
