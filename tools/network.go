package tools

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sshpie/cascade/engine"
)

// --- Port Scanner ---

var commonPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995,
	3306, 3389, 5432, 6379, 8080, 8443, 8888, 9200, 27017,
}

type PortScanner struct{}

func (t *PortScanner) Name() string               { return "Port Scanner" }
func (t *PortScanner) Requires() []engine.DataKey { return []engine.DataKey{engine.KeyIPv4} }
func (t *PortScanner) Produces() []engine.DataKey { return nil }

func (t *PortScanner) Run(state *engine.State) (*engine.Result, error) {
	ip := state.First(engine.KeyIPv4)
	r := &engine.Result{Tool: t.Name(), Produces: make(map[engine.DataKey][]string)}

	type portResult struct {
		port int
		open bool
	}
	results := make(chan portResult, len(commonPorts))

	for _, port := range commonPorts {
		go func(p int) {
			addr := net.JoinHostPort(ip, strconv.Itoa(p))
			conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
			if err == nil {
				conn.Close()
				results <- portResult{p, true}
			} else {
				results <- portResult{p, false}
			}
		}(port)
	}

	var open []int
	for range commonPorts {
		res := <-results
		if res.open {
			open = append(open, res.port)
		}
	}

	sort.Ints(open)
	if len(open) == 0 {
		r.Findings = append(r.Findings, engine.Finding{Label: "Open Ports", Value: "none found"})
	} else {
		for _, p := range open {
			r.Findings = append(r.Findings, engine.Finding{Label: fmt.Sprintf("Port %d", p), Value: "open"})
		}
	}
	return r, nil
}

// --- HTTP Headers ---

type HTTPHeaders struct{}

func (t *HTTPHeaders) Name() string               { return "HTTP Headers" }
func (t *HTTPHeaders) Requires() []engine.DataKey { return []engine.DataKey{engine.KeyDomain} }
func (t *HTTPHeaders) Produces() []engine.DataKey { return nil }

func (t *HTTPHeaders) Run(state *engine.State) (*engine.Result, error) {
	domain := state.First(engine.KeyDomain)
	r := &engine.Result{Tool: t.Name(), Produces: make(map[engine.DataKey][]string)}

	for _, scheme := range []string{"https", "http"} {
		url := fmt.Sprintf("%s://%s", scheme, domain)
		resp, err := httpClient.Head(url)
		if err != nil {
			continue
		}
		resp.Body.Close()

		r.Findings = append(r.Findings, engine.Finding{Label: "URL", Value: url})
		r.Findings = append(r.Findings, engine.Finding{Label: "Status", Value: resp.Status})

		interesting := []string{
			"Server", "X-Powered-By", "X-Frame-Options",
			"Content-Security-Policy", "Strict-Transport-Security",
			"X-Content-Type-Options", "Referrer-Policy",
			"Set-Cookie", "Via", "CF-Ray", "X-Cache",
		}
		for _, h := range interesting {
			if val := resp.Header.Get(h); val != "" {
				r.Findings = append(r.Findings, engine.Finding{Label: h, Value: val})
			}
		}
		break
	}
	return r, nil
}

// --- Ping (TCP-based, no ICMP root requirement) ---

type Ping struct{}

func (t *Ping) Name() string               { return "Ping" }
func (t *Ping) Requires() []engine.DataKey { return []engine.DataKey{engine.KeyIPv4} }
func (t *Ping) Produces() []engine.DataKey { return nil }

func (t *Ping) Run(state *engine.State) (*engine.Result, error) {
	ip := state.First(engine.KeyIPv4)
	r := &engine.Result{Tool: t.Name(), Produces: make(map[engine.DataKey][]string)}

	// TCP ping on port 80 and 443 - no root required
	for _, port := range []int{80, 443} {
		start := time.Now()
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(port)), 3*time.Second)
		elapsed := time.Since(start)
		if err == nil {
			conn.Close()
			r.Findings = append(r.Findings, engine.Finding{
				Label: fmt.Sprintf("TCP/%d", port),
				Value: fmt.Sprintf("reachable (%s)", elapsed.Round(time.Millisecond)),
			})
			return r, nil
		}
	}
	r.Findings = append(r.Findings, engine.Finding{Label: "Result", Value: "host unreachable on TCP/80,443"})
	return r, nil
}

// --- Traceroute (TCP-based) ---

type Traceroute struct{}

func (t *Traceroute) Name() string               { return "Traceroute" }
func (t *Traceroute) Requires() []engine.DataKey { return []engine.DataKey{engine.KeyDomain} }
func (t *Traceroute) Produces() []engine.DataKey { return nil }

func (t *Traceroute) Run(state *engine.State) (*engine.Result, error) {
	domain := state.First(engine.KeyDomain)
	r := &engine.Result{Tool: t.Name(), Produces: make(map[engine.DataKey][]string)}

	// Use HackerTarget's mtr API (free, no key)
	url := fmt.Sprintf("https://api.hackertarget.com/mtr/?q=%s", domain)
	resp, err := httpClient.Get(url)
	if err != nil {
		return r, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return r, err
	}

	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "error") {
			continue
		}
		r.Findings = append(r.Findings, engine.Finding{Label: "Hop", Value: line})
	}
	return r, nil
}

// --- Reverse IP Lookup (HackerTarget) ---

type ReverseIPLookup struct{}

func (t *ReverseIPLookup) Name() string               { return "Reverse IP Lookup" }
func (t *ReverseIPLookup) Requires() []engine.DataKey { return []engine.DataKey{engine.KeyIPv4} }
func (t *ReverseIPLookup) Produces() []engine.DataKey { return nil }

func (t *ReverseIPLookup) Run(state *engine.State) (*engine.Result, error) {
	ip := state.First(engine.KeyIPv4)
	r := &engine.Result{Tool: t.Name(), Produces: make(map[engine.DataKey][]string)}

	url := fmt.Sprintf("https://api.hackertarget.com/reverseiplookup/?q=%s", ip)
	resp, err := httpClient.Get(url)
	if err != nil {
		return r, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return r, err
	}

	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "error") {
			continue
		}
		r.Findings = append(r.Findings, engine.Finding{Label: "Domain", Value: line})
	}
	if len(r.Findings) == 0 {
		r.Findings = append(r.Findings, engine.Finding{Label: "Result", Value: "no shared hosts found"})
	}
	return r, nil
}

// --- Find Shared DNS Servers (HackerTarget) ---

type FindSharedDNSServers struct{}

func (t *FindSharedDNSServers) Name() string               { return "Find Shared DNS Servers" }
func (t *FindSharedDNSServers) Requires() []engine.DataKey { return []engine.DataKey{engine.KeyNSHost} }
func (t *FindSharedDNSServers) Produces() []engine.DataKey { return nil }

func (t *FindSharedDNSServers) Run(state *engine.State) (*engine.Result, error) {
	ns := state.First(engine.KeyNSHost)
	r := &engine.Result{Tool: t.Name(), Produces: make(map[engine.DataKey][]string)}

	url := fmt.Sprintf("https://api.hackertarget.com/findshareddns/?q=%s", strings.TrimSuffix(ns, "."))
	resp, err := httpClient.Get(url)
	if err != nil {
		return r, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return r, err
	}

	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "error") {
			continue
		}
		r.Findings = append(r.Findings, engine.Finding{Label: "Shared Domain", Value: line})
	}
	if len(r.Findings) == 0 {
		r.Findings = append(r.Findings, engine.Finding{Label: "Result", Value: "no shared domains found"})
	}
	return r, nil
}

// --- IP History (crt.sh passive DNS correlation) ---

type IPHistory struct{}

func (t *IPHistory) Name() string               { return "IP History" }
func (t *IPHistory) Requires() []engine.DataKey { return []engine.DataKey{engine.KeyDomain} }
func (t *IPHistory) Produces() []engine.DataKey { return nil }

func (t *IPHistory) Run(state *engine.State) (*engine.Result, error) {
	domain := state.First(engine.KeyDomain)
	r := &engine.Result{Tool: t.Name(), Produces: make(map[engine.DataKey][]string)}

	// SecurityTrails free public endpoint (no key for basic)
	url := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", domain)
	resp, err := httpClient.Get(url)
	if err != nil {
		return r, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return r, err
	}

	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "error") {
			continue
		}
		parts := strings.SplitN(line, ",", 2)
		if len(parts) == 2 {
			r.Findings = append(r.Findings, engine.Finding{
				Label: parts[0],
				Value: parts[1],
			})
		}
	}
	if len(r.Findings) == 0 {
		r.Findings = append(r.Findings, engine.Finding{Label: "Result", Value: "no host records found"})
	}
	return r, nil
}

// --- Proxy Checker ---

type ProxyChecker struct{}

func (t *ProxyChecker) Name() string               { return "Proxy Checker" }
func (t *ProxyChecker) Requires() []engine.DataKey { return []engine.DataKey{engine.KeyIPv4} }
func (t *ProxyChecker) Produces() []engine.DataKey { return nil }

func (t *ProxyChecker) Run(state *engine.State) (*engine.Result, error) {
	ip := state.First(engine.KeyIPv4)
	r := &engine.Result{Tool: t.Name(), Produces: make(map[engine.DataKey][]string)}

	// Check common proxy ports
	proxyPorts := []struct {
		port int
		name string
	}{
		{3128, "Squid/HTTP"},
		{8080, "HTTP Proxy"},
		{1080, "SOCKS5"},
		{1081, "SOCKS4"},
		{8118, "Privoxy"},
	}

	found := false
	for _, pp := range proxyPorts {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(pp.port)), 2*time.Second)
		if err == nil {
			conn.Close()
			r.Findings = append(r.Findings, engine.Finding{
				Label: pp.name,
				Value: fmt.Sprintf("port %d open", pp.port),
			})
			found = true
		}
	}
	if !found {
		r.Findings = append(r.Findings, engine.Finding{Label: "Proxy", Value: "no open proxy ports detected"})
	}

	// Check if IP is in known proxy/VPN ASN list via ip-api abuse flag
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Get(
		fmt.Sprintf("http://ip-api.com/json/%s?fields=proxy,hosting,tor", ip))
	if err == nil {
		defer resp.Body.Close()
		var flags struct {
			Proxy   bool `json:"proxy"`
			Hosting bool `json:"hosting"`
			Tor     bool `json:"tor"`
		}
		if err := decodeJSON(resp.Body, &flags); err == nil {
			r.Findings = append(r.Findings,
				engine.Finding{Label: "Proxy Flag", Value: fmt.Sprintf("%v", flags.Proxy)},
				engine.Finding{Label: "Hosting/DC", Value: fmt.Sprintf("%v", flags.Hosting)},
				engine.Finding{Label: "Tor Exit", Value: fmt.Sprintf("%v", flags.Tor)},
			)
		}
	}

	return r, nil
}
