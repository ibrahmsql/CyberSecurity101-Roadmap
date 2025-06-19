// Hash Cracker in Go
// Build: go build -o hash_cracker hash_cracker.go
// Usage: ./hash_cracker <hash> [options]
// DISCLAIMER: For authorized testing only!

package main

import (
	"bufio"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"flag"
	"fmt"
	"hash"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
)

type HashCracker struct {
	targetHash string
	hashType   string
	wordlist   string
	threads    int
	found      bool
	result     string
	mutex      sync.Mutex
	attempts   int64
}

func NewHashCracker(targetHash, hashType, wordlist string, threads int) *HashCracker {
	return &HashCracker{
		targetHash: strings.ToLower(targetHash),
		hashType:   strings.ToLower(hashType),
		wordlist:   wordlist,
		threads:    threads,
		found:      false,
		attempts:   0,
	}
}

func (hc *HashCracker) getHasher() hash.Hash {
	switch hc.hashType {
	case "md5":
		return md5.New()
	case "sha1":
		return sha1.New()
	case "sha256":
		return sha256.New()
	case "sha512":
		return sha512.New()
	default:
		return nil
	}
}

func (hc *HashCracker) hashString(input string) string {
	hasher := hc.getHasher()
	if hasher == nil {
		return ""
	}

	hasher.Write([]byte(input))
	return hex.EncodeToString(hasher.Sum(nil))
}

func (hc *HashCracker) detectHashType(hash string) string {
	switch len(hash) {
	case 32:
		return "md5"
	case 40:
		return "sha1"
	case 64:
		return "sha256"
	case 128:
		return "sha512"
	default:
		return "unknown"
	}
}

func (hc *HashCracker) tryPassword(password string) bool {
	hc.mutex.Lock()
	hc.attempts++
	attempts := hc.attempts
	hc.mutex.Unlock()

	if attempts%10000 == 0 {
		fmt.Printf("\r[+] Tried %d passwords...", attempts)
	}

	if hc.found {
		return true
	}

	hashedPassword := hc.hashString(password)
	if hashedPassword == hc.targetHash {
		hc.mutex.Lock()
		if !hc.found {
			hc.found = true
			hc.result = password
			fmt.Printf("\n[+] Password found: %s\n", password)
		}
		hc.mutex.Unlock()
		return true
	}

	return false
}

func (hc *HashCracker) bruteForceWorker(charset string, minLen, maxLen int, wg *sync.WaitGroup, jobs <-chan string) {
	defer wg.Done()

	for password := range jobs {
		if hc.found {
			return
		}
		hc.tryPassword(password)
	}
}

func (hc *HashCracker) generatePasswords(charset string, length int, current string, results chan<- string) {
	if hc.found {
		return
	}

	if len(current) == length {
		select {
		case results <- current:
		default:
		}
		return
	}

	for _, char := range charset {
		if hc.found {
			return
		}
		hc.generatePasswords(charset, length, current+string(char), results)
	}
}

func (hc *HashCracker) bruteForce(charset string, minLen, maxLen int) {
	fmt.Printf("[+] Starting brute force attack...\n")
	fmt.Printf("[+] Charset: %s\n", charset)
	fmt.Printf("[+] Length range: %d-%d\n", minLen, maxLen)
	fmt.Printf("[+] Using %d threads\n\n", hc.threads)

	jobs := make(chan string, 1000)
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < hc.threads; i++ {
		wg.Add(1)
		go hc.bruteForceWorker(charset, minLen, maxLen, &wg, jobs)
	}

	// Generate passwords
	go func() {
		defer close(jobs)
		for length := minLen; length <= maxLen && !hc.found; length++ {
			passwords := make(chan string, 1000)
			go func(l int) {
				defer close(passwords)
				hc.generatePasswords(charset, l, "", passwords)
			}(length)

			for password := range passwords {
				if hc.found {
					break
				}
				select {
				case jobs <- password:
				default:
				}
			}
		}
	}()

	wg.Wait()
}

func (hc *HashCracker) dictionaryAttack() {
	fmt.Printf("[+] Starting dictionary attack with wordlist: %s\n", hc.wordlist)
	fmt.Printf("[+] Using %d threads\n\n", hc.threads)

	file, err := os.Open(hc.wordlist)
	if err != nil {
		fmt.Printf("[-] Error opening wordlist: %v\n", err)
		return
	}
	defer file.Close()

	passwords := make(chan string, 1000)
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < hc.threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for password := range passwords {
				if hc.found {
					return
				}
				hc.tryPassword(strings.TrimSpace(password))
			}
		}()
	}

	// Read wordlist and send to workers
	go func() {
		defer close(passwords)
		scanner := bufio.NewScanner(file)
		for scanner.Scan() && !hc.found {
			password := scanner.Text()
			select {
			case passwords <- password:
			default:
			}

			// Try common variations
			variations := []string{
				strings.ToUpper(password),
				strings.ToLower(password),
				strings.Title(password),
				password + "123",
				password + "!",
				"123" + password,
			}

			for _, variation := range variations {
				if hc.found {
					break
				}
				select {
				case passwords <- variation:
				default:
				}
			}
		}
	}()

	wg.Wait()
}

func (hc *HashCracker) commonPasswords() {
	fmt.Println("[+] Trying common passwords...")

	common := []string{
		"password", "123456", "password123", "admin", "letmein",
		"welcome", "monkey", "1234567890", "qwerty", "abc123",
		"Password1", "password1", "root", "toor", "pass",
		"test", "guest", "info", "adm", "mysql", "user",
		"administrator", "oracle", "ftp", "pi", "puppet",
		"ansible", "ec2-user", "vagrant", "azureuser",
		"12345", "54321", "123123", "000000", "1111",
		"2222", "1234", "12345678", "123456789", "1qaz2wsx",
		"qwertyuiop", "asdfghjkl", "zxcvbnm", "iloveyou",
		"princess", "rockyou", "1234567", "12345679",
		"sunshine", "football", "charlie", "aa123456",
		"donald", "bailey", "access", "master", "hello",
		"freedom", "whatever", "qazwsx", "trustno1",
	}

	for _, password := range common {
		if hc.found {
			break
		}
		hc.tryPassword(password)
	}
}

func (hc *HashCracker) crack() {
	start := time.Now()

	fmt.Printf("[+] Target hash: %s\n", hc.targetHash)
	fmt.Printf("[+] Hash type: %s\n", hc.hashType)
	fmt.Printf("[+] Threads: %d\n\n", hc.threads)

	// Try common passwords first
	hc.commonPasswords()

	if hc.found {
		elapsed := time.Since(start)
		fmt.Printf("\n[+] Hash cracked in %v\n", elapsed)
		fmt.Printf("[+] Attempts: %d\n", hc.attempts)
		return
	}

	// Try dictionary attack if wordlist provided
	if hc.wordlist != "" {
		hc.dictionaryAttack()

		if hc.found {
			elapsed := time.Since(start)
			fmt.Printf("\n[+] Hash cracked in %v\n", elapsed)
			fmt.Printf("[+] Attempts: %d\n", hc.attempts)
			return
		}
	}

	// Brute force attack
	fmt.Println("\n[+] Dictionary attack failed, starting brute force...")

	// Try different character sets
	charsets := []struct {
		name   string
		chars  string
		minLen int
		maxLen int
	}{
		{"digits", "0123456789", 1, 8},
		{"lowercase", "abcdefghijklmnopqrstuvwxyz", 1, 6},
		{"lowercase+digits", "abcdefghijklmnopqrstuvwxyz0123456789", 1, 6},
		{"alphanumeric", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", 1, 5},
	}

	for _, charset := range charsets {
		if hc.found {
			break
		}

		fmt.Printf("\n[+] Trying %s charset...\n", charset.name)
		hc.bruteForce(charset.chars, charset.minLen, charset.maxLen)
	}

	elapsed := time.Since(start)

	if hc.found {
		fmt.Printf("\n[+] Hash cracked in %v\n", elapsed)
		fmt.Printf("[+] Password: %s\n", hc.result)
	} else {
		fmt.Printf("\n[-] Hash not cracked after %v\n", elapsed)
		fmt.Printf("[-] Consider using a larger wordlist or different attack method\n")
	}

	fmt.Printf("[+] Total attempts: %d\n", hc.attempts)
}

func printHashCrackerUsage() {
	fmt.Println("Hash Cracker in Go")
	fmt.Println("Usage: hash_cracker <hash> [options]")
	fmt.Println("")
	fmt.Println("Options:")
	fmt.Println("  -t, --type <type>      Hash type (md5, sha1, sha256, sha512) [auto-detect]")
	fmt.Println("  -w, --wordlist <file>  Wordlist file for dictionary attack")
	fmt.Println("  -j, --threads <num>    Number of threads [CPU cores]")
	fmt.Println("  -h, --help             Show this help")
	fmt.Println("")
	fmt.Println("Examples:")
	fmt.Println("  ./hash_cracker 5d41402abc4b2a76b9719d911017c592")
	fmt.Println("  ./hash_cracker -t md5 5d41402abc4b2a76b9719d911017c592")
	fmt.Println("  ./hash_cracker -w rockyou.txt 5d41402abc4b2a76b9719d911017c592")
	fmt.Println("  ./hash_cracker -j 8 -w passwords.txt hash_here")
	fmt.Println("")
	fmt.Println("Supported hash types:")
	fmt.Println("  MD5     (32 characters)")
	fmt.Println("  SHA1    (40 characters)")
	fmt.Println("  SHA256  (64 characters)")
	fmt.Println("  SHA512  (128 characters)")
}

func main() {
	var (
		hashType = flag.String("t", "", "Hash type (md5, sha1, sha256, sha512)")
		wordlist = flag.String("w", "", "Wordlist file")
		threads  = flag.Int("j", runtime.NumCPU(), "Number of threads")
		help     = flag.Bool("h", false, "Show help")
	)

	flag.Parse()

	if *help {
		printHashCrackerUsage()
		return
	}

	if len(flag.Args()) < 1 {
		fmt.Println("Error: Hash required")
		printHashCrackerUsage()
		os.Exit(1)
	}

	targetHash := strings.TrimSpace(flag.Args()[0])

	// Auto-detect hash type if not specified
	if *hashType == "" {
		cracker := &HashCracker{}
		*hashType = cracker.detectHashType(targetHash)
		if *hashType == "unknown" {
			fmt.Println("Error: Unable to detect hash type. Please specify with -t")
			os.Exit(1)
		}
		fmt.Printf("[+] Auto-detected hash type: %s\n", *hashType)
	}

	// Validate hash type
	validTypes := []string{"md5", "sha1", "sha256", "sha512"}
	valid := false
	for _, validType := range validTypes {
		if strings.ToLower(*hashType) == validType {
			valid = true
			break
		}
	}

	if !valid {
		fmt.Printf("Error: Unsupported hash type: %s\n", *hashType)
		fmt.Println("Supported types: md5, sha1, sha256, sha512")
		os.Exit(1)
	}

	// Validate threads
	if *threads < 1 {
		*threads = 1
	} else if *threads > 100 {
		*threads = 100
	}

	cracker := NewHashCracker(targetHash, *hashType, *wordlist, *threads)
	cracker.crack()
}
