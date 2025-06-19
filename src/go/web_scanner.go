// Web Vulnerability Scanner in Go
// Build: go build -o web_scanner web_scanner.go
// Usage: ./web_scanner <target_url> [options]
// DISCLAIMER: For authorized testing only!

package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

type WebScanner struct {
	targetURL string
	client    *http.Client
	results   []VulnResult
}

type VulnResult struct {
	VulnType    string
	Severity    string
	Description string
	URL         string
	Evidence    string
}

func NewWebScanner(targetURL string) *WebScanner {
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	return &WebScanner{
		targetURL: strings.TrimSuffix(targetURL, "/"),
		client:    client,
		results:   make([]VulnResult, 0),
	}
}

func (ws *WebScanner) addResult(vulnType, severity, description, url, evidence string) {
	result := VulnResult{
		VulnType:    vulnType,
		Severity:    severity,
		Description: description,
		URL:         url,
		Evidence:    evidence,
	}
	ws.results = append(ws.results, result)
}

func (ws *WebScanner) makeRequest(method, path string, body string) (*http.Response, error) {
	url := ws.targetURL + path
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "WebScanner-Go/1.0")
	req.Header.Set("Accept", "*/*")

	return ws.client.Do(req)
}

func (ws *WebScanner) CheckSecurityHeaders() {
	fmt.Println("[+] Checking security headers...")

	resp, err := ws.makeRequest("GET", "/", "")
	if err != nil {
		fmt.Printf("[-] Error checking headers: %v\n", err)
		return
	}
	defer resp.Body.Close()

	// Check for missing security headers
	securityHeaders := map[string]string{
		"X-Frame-Options":           "Clickjacking protection",
		"X-XSS-Protection":          "XSS protection",
		"X-Content-Type-Options":    "MIME type sniffing protection",
		"Strict-Transport-Security": "HTTPS enforcement",
		"Content-Security-Policy":   "Content injection protection",
		"Referrer-Policy":           "Referrer information control",
	}

	for header, description := range securityHeaders {
		if resp.Header.Get(header) == "" {
			ws.addResult(
				"Missing Security Header",
				"Medium",
				fmt.Sprintf("Missing %s header (%s)", header, description),
				ws.targetURL,
				header,
			)
		}
	}

	// Check for information disclosure headers
	server := resp.Header.Get("Server")
	if server != "" {
		ws.addResult(
			"Information Disclosure",
			"Low",
			"Server header reveals server information",
			ws.targetURL,
			server,
		)
	}

	xPoweredBy := resp.Header.Get("X-Powered-By")
	if xPoweredBy != "" {
		ws.addResult(
			"Information Disclosure",
			"Low",
			"X-Powered-By header reveals technology stack",
			ws.targetURL,
			xPoweredBy,
		)
	}
}

func (ws *WebScanner) CheckSQLInjection() {
	fmt.Println("[+] Checking for SQL injection vulnerabilities...")

	// Common SQL injection payloads
	payloads := []string{
		"'",
		"''",
		"' OR '1'='1",
		"' OR 1=1--",
		"' UNION SELECT NULL--",
		"1' AND 1=1--",
		"1' AND 1=2--",
	}

	// Test common parameters
	params := []string{"id", "user", "username", "email", "search", "q", "query"}

	for _, param := range params {
		for _, payload := range payloads {
			testURL := fmt.Sprintf("/?%s=%s", param, url.QueryEscape(payload))
			resp, err := ws.makeRequest("GET", testURL, "")
			if err != nil {
				continue
			}

			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			bodyStr := string(body)

			// Check for SQL error messages
			sqlErrors := []string{
				"SQL syntax",
				"mysql_fetch",
				"ORA-",
				"Microsoft OLE DB",
				"ODBC SQL Server Driver",
				"PostgreSQL query failed",
				"SQLite error",
			}

			for _, sqlError := range sqlErrors {
				if strings.Contains(bodyStr, sqlError) {
					ws.addResult(
						"SQL Injection",
						"High",
						"Possible SQL injection vulnerability detected",
						ws.targetURL+testURL,
						sqlError,
					)
					break
				}
			}
		}
	}
}

func (ws *WebScanner) CheckXSS() {
	fmt.Println("[+] Checking for XSS vulnerabilities...")

	// XSS payloads
	payloads := []string{
		"<script>alert('XSS')</script>",
		"<img src=x onerror=alert('XSS')>",
		"javascript:alert('XSS')",
		"<svg onload=alert('XSS')>",
	}

	params := []string{"q", "search", "query", "name", "comment", "message"}

	for _, param := range params {
		for _, payload := range payloads {
			testURL := fmt.Sprintf("/?%s=%s", param, url.QueryEscape(payload))
			resp, err := ws.makeRequest("GET", testURL, "")
			if err != nil {
				continue
			}

			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			bodyStr := string(body)

			// Check if payload is reflected in response
			if strings.Contains(bodyStr, payload) {
				ws.addResult(
					"Cross-Site Scripting (XSS)",
					"High",
					"Possible XSS vulnerability detected",
					ws.targetURL+testURL,
					payload,
				)
			}
		}
	}
}

func (ws *WebScanner) CheckDirectoryTraversal() {
	fmt.Println("[+] Checking for directory traversal vulnerabilities...")

	payloads := []string{
		"../../../etc/passwd",
		"..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
		"....//....//....//etc/passwd",
		"%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
	}

	params := []string{"file", "path", "page", "include", "doc", "document"}

	for _, param := range params {
		for _, payload := range payloads {
			testURL := fmt.Sprintf("/?%s=%s", param, url.QueryEscape(payload))
			resp, err := ws.makeRequest("GET", testURL, "")
			if err != nil {
				continue
			}

			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			bodyStr := string(body)

			// Check for signs of successful directory traversal
			if strings.Contains(bodyStr, "root:x:0:0") || strings.Contains(bodyStr, "# localhost") {
				ws.addResult(
					"Directory Traversal",
					"High",
					"Directory traversal vulnerability detected",
					ws.targetURL+testURL,
					payload,
				)
			}
		}
	}
}

func (ws *WebScanner) CheckSensitiveFiles() {
	fmt.Println("[+] Checking for sensitive files...")

	sensitiveFiles := []string{
		"/robots.txt",
		"/.htaccess",
		"/.htpasswd",
		"/web.config",
		"/config.php",
		"/wp-config.php",
		"/admin",
		"/phpmyadmin",
		"/backup",
		"/test",
		"/debug",
		"/.git/config",
		"/.svn/entries",
		"/crossdomain.xml",
		"/sitemap.xml",
	}

	for _, file := range sensitiveFiles {
		resp, err := ws.makeRequest("GET", file, "")
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == 200 {
			ws.addResult(
				"Sensitive File Exposure",
				"Medium",
				"Sensitive file accessible",
				ws.targetURL+file,
				fmt.Sprintf("HTTP %d", resp.StatusCode),
			)
		}
	}
}

func (ws *WebScanner) CheckSSL() {
	fmt.Println("[+] Checking SSL/TLS configuration...")

	if !strings.HasPrefix(ws.targetURL, "https://") {
		ws.addResult(
			"Insecure Transport",
			"Medium",
			"Website not using HTTPS",
			ws.targetURL,
			"HTTP protocol detected",
		)
		return
	}

	// Test HTTP redirect to HTTPS
	httpURL := strings.Replace(ws.targetURL, "https://", "http://", 1)
	resp, err := ws.client.Get(httpURL)
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode != 301 && resp.StatusCode != 302 {
			ws.addResult(
				"Missing HTTPS Redirect",
				"Medium",
				"HTTP version accessible without redirect to HTTPS",
				httpURL,
				fmt.Sprintf("HTTP %d", resp.StatusCode),
			)
		}
	}
}

func (ws *WebScanner) CheckCORS() {
	fmt.Println("[+] Checking CORS configuration...")

	req, err := http.NewRequest("GET", ws.targetURL, nil)
	if err != nil {
		return
	}

	req.Header.Set("Origin", "https://evil.com")
	resp, err := ws.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	acaoHeader := resp.Header.Get("Access-Control-Allow-Origin")
	if acaoHeader == "*" {
		ws.addResult(
			"CORS Misconfiguration",
			"Medium",
			"Wildcard CORS policy allows any origin",
			ws.targetURL,
			acaoHeader,
		)
	} else if acaoHeader == "https://evil.com" {
		ws.addResult(
			"CORS Misconfiguration",
			"High",
			"CORS policy reflects arbitrary origins",
			ws.targetURL,
			acaoHeader,
		)
	}
}

func (ws *WebScanner) CheckComments() {
	fmt.Println("[+] Checking for sensitive information in comments...")

	resp, err := ws.makeRequest("GET", "/", "")
	if err != nil {
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	// Look for sensitive patterns in HTML comments
	commentRegex := regexp.MustCompile(`<!--[\s\S]*?-->`)
	comments := commentRegex.FindAllString(bodyStr, -1)

	sensitivePatterns := []string{
		"password",
		"secret",
		"api[_-]?key",
		"token",
		"admin",
		"debug",
		"test",
		"TODO",
		"FIXME",
	}

	for _, comment := range comments {
		for _, pattern := range sensitivePatterns {
			matched, _ := regexp.MatchString("(?i)"+pattern, comment)
			if matched {
				ws.addResult(
					"Information Disclosure",
					"Low",
					"Sensitive information found in HTML comments",
					ws.targetURL,
					comment,
				)
				break
			}
		}
	}
}

func (ws *WebScanner) RunScan() {
	fmt.Printf("[+] Starting web vulnerability scan on %s\n\n", ws.targetURL)

	ws.CheckSecurityHeaders()
	ws.CheckSQLInjection()
	ws.CheckXSS()
	ws.CheckDirectoryTraversal()
	ws.CheckSensitiveFiles()
	ws.CheckSSL()
	ws.CheckCORS()
	ws.CheckComments()

	ws.PrintResults()
}

func (ws *WebScanner) PrintResults() {
	fmt.Printf("\n[+] Scan completed. Found %d potential vulnerabilities:\n\n", len(ws.results))

	if len(ws.results) == 0 {
		fmt.Println("[+] No vulnerabilities detected!")
		return
	}

	// Group by severity
	high := 0
	medium := 0
	low := 0

	for _, result := range ws.results {
		switch result.Severity {
		case "High":
			high++
			fmt.Printf("\033[31m[HIGH]\033[0m %s: %s\n", result.VulnType, result.Description)
		case "Medium":
			medium++
			fmt.Printf("\033[33m[MEDIUM]\033[0m %s: %s\n", result.VulnType, result.Description)
		case "Low":
			low++
			fmt.Printf("\033[32m[LOW]\033[0m %s: %s\n", result.VulnType, result.Description)
		}
		fmt.Printf("  URL: %s\n", result.URL)
		if result.Evidence != "" {
			fmt.Printf("  Evidence: %s\n", result.Evidence)
		}
		fmt.Println()
	}

	fmt.Printf("Summary: %d High, %d Medium, %d Low\n", high, medium, low)
}

func printWebScannerUsage() {
	fmt.Println("Web Vulnerability Scanner in Go")
	fmt.Println("Usage: web_scanner <target_url> [options]")
	fmt.Println("")
	fmt.Println("Options:")
	fmt.Println("  -h, --help    Show this help")
	fmt.Println("")
	fmt.Println("Examples:")
	fmt.Println("  ./web_scanner http://example.com")
	fmt.Println("  ./web_scanner https://example.com")
	fmt.Println("")
	fmt.Println("Checks performed:")
	fmt.Println("  - Security headers")
	fmt.Println("  - SQL injection")
	fmt.Println("  - Cross-site scripting (XSS)")
	fmt.Println("  - Directory traversal")
	fmt.Println("  - Sensitive file exposure")
	fmt.Println("  - SSL/TLS configuration")
	fmt.Println("  - CORS misconfiguration")
	fmt.Println("  - Information disclosure")
}

func main() {
	var help = flag.Bool("h", false, "Show help")
	flag.Parse()

	if *help {
		printWebScannerUsage()
		return
	}

	if len(flag.Args()) < 1 {
		fmt.Println("Error: Target URL required")
		printWebScannerUsage()
		os.Exit(1)
	}

	targetURL := flag.Args()[0]

	// Validate URL
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "http://" + targetURL
	}

	scanner := NewWebScanner(targetURL)
	scanner.RunScan()
}
