// Directory Buster in Go
// Build: go build -o dirbuster dirbuster.go
// Usage: ./dirbuster <target_url> [options]
// DISCLAIMER: For authorized testing only!

package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type DirBuster struct {
	targetURL    string
	wordlist     []string
	threads      int
	timeout      time.Duration
	userAgent    string
	statusFilter []int
	foundPaths   []string
	mutex        sync.Mutex
	client       *http.Client
}

type ScanResult struct {
	Path       string
	StatusCode int
	Size       int64
	Redirect   string
}

func NewDirBuster(targetURL string, wordlist []string, threads int, timeout time.Duration) *DirBuster {
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}

	return &DirBuster{
		targetURL:    strings.TrimSuffix(targetURL, "/"),
		wordlist:     wordlist,
		threads:      threads,
		timeout:      timeout,
		userAgent:    "DirBuster-Go/1.0",
		statusFilter: []int{200, 301, 302, 403, 401},
		foundPaths:   make([]string, 0),
		client:       client,
	}
}

func (db *DirBuster) TestPath(path string, results chan<- ScanResult) {
	url := fmt.Sprintf("%s/%s", db.targetURL, strings.TrimPrefix(path, "/"))

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return
	}

	req.Header.Set("User-Agent", db.userAgent)
	req.Header.Set("Accept", "*/*")

	resp, err := db.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	// Read response body to get size
	body, _ := io.ReadAll(resp.Body)
	size := int64(len(body))

	// Check if status code is in our filter
	for _, status := range db.statusFilter {
		if resp.StatusCode == status {
			redirect := ""
			if resp.StatusCode == 301 || resp.StatusCode == 302 {
				redirect = resp.Header.Get("Location")
			}

			db.mutex.Lock()
			db.foundPaths = append(db.foundPaths, path)
			db.mutex.Unlock()

			results <- ScanResult{
				Path:       path,
				StatusCode: resp.StatusCode,
				Size:       size,
				Redirect:   redirect,
			}
			return
		}
	}
}

func (db *DirBuster) Run() {
	fmt.Printf("[+] Starting directory enumeration on %s\n", db.targetURL)
	fmt.Printf("[+] Wordlist size: %d\n", len(db.wordlist))
	fmt.Printf("[+] Threads: %d\n", db.threads)
	fmt.Printf("[+] Timeout: %v\n\n", db.timeout)

	start := time.Now()
	results := make(chan ScanResult, db.threads)
	semaphore := make(chan struct{}, db.threads)

	var wg sync.WaitGroup

	// Test each path in wordlist
	for _, path := range db.wordlist {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			semaphore <- struct{}{} // Acquire semaphore
			db.TestPath(p, results)
			<-semaphore // Release semaphore
		}(path)
	}

	// Also test common file extensions
	commonExts := []string{".php", ".html", ".htm", ".asp", ".aspx", ".jsp", ".txt", ".xml", ".json"}
	for _, basePath := range db.wordlist {
		for _, ext := range commonExts {
			if !strings.Contains(basePath, ".") {
				wg.Add(1)
				go func(p string) {
					defer wg.Done()
					semaphore <- struct{}{}
					db.TestPath(p, results)
					<-semaphore
				}(basePath + ext)
			}
		}
	}

	// Close results channel when all goroutines are done
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect and display results
	foundCount := 0
	for result := range results {
		foundCount++
		statusColor := getStatusColor(result.StatusCode)

		if result.Redirect != "" {
			fmt.Printf("%s[%d]%s %s (Size: %d) -> %s\n",
				statusColor, result.StatusCode, "\033[0m", result.Path, result.Size, result.Redirect)
		} else {
			fmt.Printf("%s[%d]%s %s (Size: %d)\n",
				statusColor, result.StatusCode, "\033[0m", result.Path, result.Size)
		}
	}

	elapsed := time.Since(start)
	fmt.Printf("\n[+] Enumeration completed in %v\n", elapsed)
	fmt.Printf("[+] Found %d interesting paths\n", foundCount)
}

func getStatusColor(statusCode int) string {
	switch {
	case statusCode >= 200 && statusCode < 300:
		return "\033[32m" // Green
	case statusCode >= 300 && statusCode < 400:
		return "\033[33m" // Yellow
	case statusCode >= 400 && statusCode < 500:
		return "\033[31m" // Red
	default:
		return "\033[0m" // Default
	}
}

func loadWordlist(filename string) ([]string, error) {
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

func getDefaultWordlist() []string {
	return []string{
		"admin", "administrator", "login", "test", "demo", "backup", "config",
		"api", "app", "application", "assets", "css", "js", "javascript",
		"images", "img", "uploads", "files", "documents", "docs", "download",
		"downloads", "temp", "tmp", "cache", "logs", "log", "data", "db",
		"database", "sql", "mysql", "phpmyadmin", "wp-admin", "wp-content",
		"wp-includes", "wordpress", "cms", "panel", "cpanel", "control",
		"dashboard", "user", "users", "account", "accounts", "profile",
		"settings", "preferences", "help", "support", "contact", "about",
		"info", "information", "news", "blog", "forum", "search", "mail",
		"email", "webmail", "ftp", "ssh", "telnet", "secure", "security",
		"private", "public", "www", "web", "site", "home", "index", "main",
		"default", "error", "404", "403", "500", "robots.txt", "sitemap.xml",
		".htaccess", ".htpasswd", "web.config", "crossdomain.xml",
		"clientaccesspolicy.xml", "readme", "license", "changelog",
	}
}

func printDirBusterUsage() {
	fmt.Println("Directory Buster in Go")
	fmt.Println("Usage: dirbuster <target_url> [options]")
	fmt.Println("")
	fmt.Println("Options:")
	fmt.Println("  -w, --wordlist <file>  Wordlist file to use")
	fmt.Println("  -t, --threads <num>    Number of threads (default: 50)")
	fmt.Println("  --timeout <duration>   HTTP timeout (default: 10s)")
	fmt.Println("  -u, --user-agent <ua>  Custom User-Agent string")
	fmt.Println("  -s, --status <codes>   Status codes to show (default: 200,301,302,403,401)")
	fmt.Println("  -h, --help            Show this help")
	fmt.Println("")
	fmt.Println("Examples:")
	fmt.Println("  ./dirbuster http://example.com")
	fmt.Println("  ./dirbuster https://example.com -w wordlist.txt")
	fmt.Println("  ./dirbuster http://example.com -t 100 --timeout 5s")
	fmt.Println("  ./dirbuster http://example.com -s 200,403,500")
}

func parseStatusCodes(statusStr string) []int {
	var codes []int
	parts := strings.Split(statusStr, ",")
	for _, part := range parts {
		var code int
		if _, err := fmt.Sscanf(strings.TrimSpace(part), "%d", &code); err == nil {
			codes = append(codes, code)
		}
	}
	return codes
}

func main() {
	var (
		wordlistFile = flag.String("w", "", "Wordlist file")
		threads      = flag.Int("t", 50, "Number of threads")
		timeout      = flag.Duration("timeout", 10*time.Second, "HTTP timeout")
		userAgent    = flag.String("u", "DirBuster-Go/1.0", "User-Agent string")
		statusFilter = flag.String("s", "200,301,302,403,401", "Status codes to show")
		help         = flag.Bool("h", false, "Show help")
	)

	flag.Parse()

	if *help {
		printDirBusterUsage()
		return
	}

	if len(flag.Args()) < 1 {
		fmt.Println("Error: Target URL required")
		printDirBusterUsage()
		os.Exit(1)
	}

	targetURL := flag.Args()[0]

	// Validate URL
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "http://" + targetURL
	}

	// Load wordlist
	var wordlist []string
	var err error

	if *wordlistFile != "" {
		wordlist, err = loadWordlist(*wordlistFile)
		if err != nil {
			fmt.Printf("Error loading wordlist: %v\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Println("[!] No wordlist specified, using default wordlist")
		wordlist = getDefaultWordlist()
	}

	if len(wordlist) == 0 {
		fmt.Println("Error: Empty wordlist")
		os.Exit(1)
	}

	// Create directory buster
	db := NewDirBuster(targetURL, wordlist, *threads, *timeout)
	db.userAgent = *userAgent
	db.statusFilter = parseStatusCodes(*statusFilter)

	// Run the scan
	db.Run()
}
