package tools

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/zellkernel/cascade/engine"
)

// resolvers lists DNS servers to try. System stub resolver first so it always
// works regardless of whether external port 53 is reachable.
var resolvers = []string{
	"127.0.0.53:53", // systemd-resolved stub
	"8.8.8.8:53",
	"1.1.1.1:53",
	"9.9.9.9:53",
	"208.67.222.222:53",
	"8.8.4.4:53",
}

func queryDNS(host, qtype string, server string) (*dns.Msg, error) {
	m := new(dns.Msg)
	qt, ok := dns.StringToType[qtype]
	if !ok {
		return nil, fmt.Errorf("unknown type %s", qtype)
	}
	m.SetQuestion(dns.Fqdn(host), qt)
	m.RecursionDesired = true

	// Try UDP first, fall back to TCP on failure (firewalled envs block UDP/53).
	udp := &dns.Client{Net: "udp", Timeout: 4 * time.Second}
	r, _, err := udp.Exchange(m, server)
	if err != nil {
		tcp := &dns.Client{Net: "tcp", Timeout: 8 * time.Second}
		r, _, err = tcp.Exchange(m, server)
	}
	return r, err
}

// --- DNS Record Lookup ---

type DNSRecordLookup struct{}

func (t *DNSRecordLookup) Name() string               { return "DNS Record Lookup" }
func (t *DNSRecordLookup) Requires() []engine.DataKey { return []engine.DataKey{engine.KeyDomain} }
func (t *DNSRecordLookup) Produces() []engine.DataKey {
	return []engine.DataKey{engine.KeyIPv4, engine.KeyIPv6}
}

func (t *DNSRecordLookup) Run(state *engine.State) (*engine.Result, error) {
	domain := state.First(engine.KeyDomain)
	r := &engine.Result{Tool: t.Name(), Produces: make(map[engine.DataKey][]string)}

	types := []string{"A", "AAAA", "CNAME"}
	for _, qt := range types {
		resp, err := queryDNS(domain, qt, resolvers[0])
		if err != nil {
			continue
		}
		for _, rr := range resp.Answer {
			switch v := rr.(type) {
			case *dns.A:
				r.Findings = append(r.Findings, engine.Finding{Label: "A", Value: v.A.String()})
				r.Produces[engine.KeyIPv4] = append(r.Produces[engine.KeyIPv4], v.A.String())
			case *dns.AAAA:
				r.Findings = append(r.Findings, engine.Finding{Label: "AAAA", Value: v.AAAA.String()})
				r.Produces[engine.KeyIPv6] = append(r.Produces[engine.KeyIPv6], v.AAAA.String())
			case *dns.CNAME:
				r.Findings = append(r.Findings, engine.Finding{Label: "CNAME", Value: v.Target})
			}
		}
	}
	return r, nil
}

// --- MX Lookup ---

type MXLookup struct{}

func (t *MXLookup) Name() string               { return "MX Lookup" }
func (t *MXLookup) Requires() []engine.DataKey { return []engine.DataKey{engine.KeyDomain} }
func (t *MXLookup) Produces() []engine.DataKey { return []engine.DataKey{engine.KeyMXHost} }

func (t *MXLookup) Run(state *engine.State) (*engine.Result, error) {
	domain := state.First(engine.KeyDomain)
	r := &engine.Result{Tool: t.Name(), Produces: make(map[engine.DataKey][]string)}

	resp, err := queryDNS(domain, "MX", resolvers[0])
	if err != nil {
		return r, err
	}
	for _, rr := range resp.Answer {
		if mx, ok := rr.(*dns.MX); ok {
			val := fmt.Sprintf("priority=%d host=%s", mx.Preference, mx.Mx)
			r.Findings = append(r.Findings, engine.Finding{Label: "MX", Value: val})
			r.Produces[engine.KeyMXHost] = append(r.Produces[engine.KeyMXHost], mx.Mx)
		}
	}
	return r, nil
}

// --- NS Lookup ---

type NSLookup struct{}

func (t *NSLookup) Name() string               { return "NS Lookup" }
func (t *NSLookup) Requires() []engine.DataKey { return []engine.DataKey{engine.KeyDomain} }
func (t *NSLookup) Produces() []engine.DataKey { return []engine.DataKey{engine.KeyNSHost} }

func (t *NSLookup) Run(state *engine.State) (*engine.Result, error) {
	domain := state.First(engine.KeyDomain)
	r := &engine.Result{Tool: t.Name(), Produces: make(map[engine.DataKey][]string)}

	resp, err := queryDNS(domain, "NS", resolvers[0])
	if err != nil {
		return r, err
	}
	for _, rr := range resp.Answer {
		if ns, ok := rr.(*dns.NS); ok {
			r.Findings = append(r.Findings, engine.Finding{Label: "NS", Value: ns.Ns})
			r.Produces[engine.KeyNSHost] = append(r.Produces[engine.KeyNSHost], ns.Ns)
		}
	}
	return r, nil
}

// --- SOA Lookup ---

type SOALookup struct{}

func (t *SOALookup) Name() string               { return "SOA Lookup" }
func (t *SOALookup) Requires() []engine.DataKey { return []engine.DataKey{engine.KeyDomain} }
func (t *SOALookup) Produces() []engine.DataKey { return nil }

func (t *SOALookup) Run(state *engine.State) (*engine.Result, error) {
	domain := state.First(engine.KeyDomain)
	r := &engine.Result{Tool: t.Name(), Produces: make(map[engine.DataKey][]string)}

	resp, err := queryDNS(domain, "SOA", resolvers[0])
	if err != nil {
		return r, err
	}
	for _, rr := range resp.Answer {
		if soa, ok := rr.(*dns.SOA); ok {
			r.Findings = append(r.Findings,
				engine.Finding{Label: "Primary NS", Value: soa.Ns},
				engine.Finding{Label: "Admin Email", Value: strings.Replace(soa.Mbox, ".", "@", 1)},
				engine.Finding{Label: "Serial", Value: fmt.Sprintf("%d", soa.Serial)},
				engine.Finding{Label: "Refresh", Value: fmt.Sprintf("%ds", soa.Refresh)},
				engine.Finding{Label: "Retry", Value: fmt.Sprintf("%ds", soa.Retry)},
				engine.Finding{Label: "Expire", Value: fmt.Sprintf("%ds", soa.Expire)},
				engine.Finding{Label: "TTL", Value: fmt.Sprintf("%ds", soa.Minttl)},
			)
		}
	}
	return r, nil
}

// --- SPF Lookup ---

type SPFLookup struct{}

func (t *SPFLookup) Name() string               { return "SPF Lookup" }
func (t *SPFLookup) Requires() []engine.DataKey { return []engine.DataKey{engine.KeyDomain} }
func (t *SPFLookup) Produces() []engine.DataKey { return nil }

func (t *SPFLookup) Run(state *engine.State) (*engine.Result, error) {
	domain := state.First(engine.KeyDomain)
	r := &engine.Result{Tool: t.Name(), Produces: make(map[engine.DataKey][]string)}

	resp, err := queryDNS(domain, "TXT", resolvers[0])
	if err != nil {
		return r, err
	}
	found := false
	for _, rr := range resp.Answer {
		if txt, ok := rr.(*dns.TXT); ok {
			for _, s := range txt.Txt {
				if strings.HasPrefix(s, "v=spf1") {
					r.Findings = append(r.Findings, engine.Finding{Label: "SPF", Value: s})
					found = true
				}
			}
		}
	}
	if !found {
		r.Findings = append(r.Findings, engine.Finding{Label: "SPF", Value: "not configured"})
	}
	return r, nil
}

// --- DMARC Lookup ---

type DMARCLookup struct{}

func (t *DMARCLookup) Name() string               { return "DMARC Lookup" }
func (t *DMARCLookup) Requires() []engine.DataKey { return []engine.DataKey{engine.KeyDomain} }
func (t *DMARCLookup) Produces() []engine.DataKey { return nil }

func (t *DMARCLookup) Run(state *engine.State) (*engine.Result, error) {
	domain := state.First(engine.KeyDomain)
	r := &engine.Result{Tool: t.Name(), Produces: make(map[engine.DataKey][]string)}

	resp, err := queryDNS("_dmarc."+domain, "TXT", resolvers[0])
	if err != nil {
		return r, err
	}
	found := false
	for _, rr := range resp.Answer {
		if txt, ok := rr.(*dns.TXT); ok {
			for _, s := range txt.Txt {
				if strings.HasPrefix(s, "v=DMARC1") {
					r.Findings = append(r.Findings, engine.Finding{Label: "DMARC", Value: s})
					found = true
					// Parse policy
					for _, part := range strings.Split(s, ";") {
						part = strings.TrimSpace(part)
						if strings.HasPrefix(part, "p=") {
							r.Findings = append(r.Findings, engine.Finding{Label: "Policy", Value: strings.TrimPrefix(part, "p=")})
						}
					}
				}
			}
		}
	}
	if !found {
		r.Findings = append(r.Findings, engine.Finding{Label: "DMARC", Value: "not configured"})
	}
	return r, nil
}

// --- DNSSEC Lookup ---

type DNSSECLookup struct{}

func (t *DNSSECLookup) Name() string               { return "DNSSEC Lookup" }
func (t *DNSSECLookup) Requires() []engine.DataKey { return []engine.DataKey{engine.KeyDomain} }
func (t *DNSSECLookup) Produces() []engine.DataKey { return nil }

func (t *DNSSECLookup) Run(state *engine.State) (*engine.Result, error) {
	domain := state.First(engine.KeyDomain)
	r := &engine.Result{Tool: t.Name(), Produces: make(map[engine.DataKey][]string)}

	resp, err := queryDNS(domain, "DNSKEY", resolvers[0])
	if err != nil {
		return r, err
	}

	if len(resp.Answer) == 0 {
		r.Findings = append(r.Findings, engine.Finding{Label: "DNSSEC", Value: "not enabled"})
		return r, nil
	}

	for _, rr := range resp.Answer {
		if key, ok := rr.(*dns.DNSKEY); ok {
			algo := dns.AlgorithmToString[key.Algorithm]
			r.Findings = append(r.Findings, engine.Finding{
				Label: "DNSKEY",
				Value: fmt.Sprintf("flags=%d protocol=%d algorithm=%s tag=%d",
					key.Flags, key.Protocol, algo, key.KeyTag()),
			})
		}
	}
	return r, nil
}

// --- DNS Propagation Checker ---

type DNSPropagation struct{}

func (t *DNSPropagation) Name() string               { return "DNS Propagation Checker" }
func (t *DNSPropagation) Requires() []engine.DataKey { return []engine.DataKey{engine.KeyDomain} }
func (t *DNSPropagation) Produces() []engine.DataKey { return nil }

func (t *DNSPropagation) Run(state *engine.State) (*engine.Result, error) {
	domain := state.First(engine.KeyDomain)
	r := &engine.Result{Tool: t.Name(), Produces: make(map[engine.DataKey][]string)}

	named := []struct {
		name string
		addr string
	}{
		{"System", "127.0.0.53:53"},
		{"Google", "8.8.8.8:53"},
		{"Cloudflare", "1.1.1.1:53"},
		{"Quad9", "9.9.9.9:53"},
		{"OpenDNS", "208.67.222.222:53"},
		{"Level3", "4.2.2.1:53"},
	}

	for _, ns := range named {
		resp, err := queryDNS(domain, "A", ns.addr)
		if err != nil {
			r.Findings = append(r.Findings, engine.Finding{Label: ns.name, Value: "timeout"})
			continue
		}
		var ips []string
		for _, rr := range resp.Answer {
			if a, ok := rr.(*dns.A); ok {
				ips = append(ips, a.A.String())
			}
		}
		if len(ips) == 0 {
			r.Findings = append(r.Findings, engine.Finding{Label: ns.name, Value: "no answer"})
		} else {
			r.Findings = append(r.Findings, engine.Finding{Label: ns.name, Value: strings.Join(ips, ", ")})
		}
	}
	return r, nil
}

// --- Reverse DNS Lookup ---

type ReverseDNSLookup struct{}

func (t *ReverseDNSLookup) Name() string               { return "Reverse DNS Lookup" }
func (t *ReverseDNSLookup) Requires() []engine.DataKey { return []engine.DataKey{engine.KeyIPv4} }
func (t *ReverseDNSLookup) Produces() []engine.DataKey { return []engine.DataKey{engine.KeyHostname} }

func (t *ReverseDNSLookup) Run(state *engine.State) (*engine.Result, error) {
	ip := state.First(engine.KeyIPv4)
	r := &engine.Result{Tool: t.Name(), Produces: make(map[engine.DataKey][]string)}

	names, err := net.LookupAddr(ip)
	if err != nil {
		r.Findings = append(r.Findings, engine.Finding{Label: "PTR", Value: "none"})
		return r, nil
	}
	for _, name := range names {
		name = strings.TrimSuffix(name, ".")
		r.Findings = append(r.Findings, engine.Finding{Label: "PTR", Value: name})
		r.Produces[engine.KeyHostname] = append(r.Produces[engine.KeyHostname], name)
	}
	return r, nil
}

// --- Hostname to IP ---

type HostnameToIP struct{}

func (t *HostnameToIP) Name() string               { return "Hostname to IP" }
func (t *HostnameToIP) Requires() []engine.DataKey { return []engine.DataKey{engine.KeyHostname} }
func (t *HostnameToIP) Produces() []engine.DataKey { return []engine.DataKey{engine.KeyIPv4} }

func (t *HostnameToIP) Run(state *engine.State) (*engine.Result, error) {
	host := state.First(engine.KeyHostname)
	r := &engine.Result{Tool: t.Name(), Produces: make(map[engine.DataKey][]string)}

	addrs, err := net.LookupHost(host)
	if err != nil {
		return r, err
	}
	for _, addr := range addrs {
		parsed := net.ParseIP(addr)
		if parsed == nil {
			continue
		}
		if parsed.To4() != nil {
			r.Findings = append(r.Findings, engine.Finding{Label: "IPv4", Value: addr})
			r.Produces[engine.KeyIPv4] = append(r.Produces[engine.KeyIPv4], addr)
		} else {
			r.Findings = append(r.Findings, engine.Finding{Label: "IPv6", Value: addr})
			r.Produces[engine.KeyIPv6] = append(r.Produces[engine.KeyIPv6], addr)
		}
	}
	return r, nil
}

// --- IP to Hostname (alias for Reverse DNS) ---

type IPToHostname struct{}

func (t *IPToHostname) Name() string               { return "IP to Hostname" }
func (t *IPToHostname) Requires() []engine.DataKey { return []engine.DataKey{engine.KeyIPv6} }
func (t *IPToHostname) Produces() []engine.DataKey { return []engine.DataKey{engine.KeyHostname} }

func (t *IPToHostname) Run(state *engine.State) (*engine.Result, error) {
	ip := state.First(engine.KeyIPv6)
	r := &engine.Result{Tool: t.Name(), Produces: make(map[engine.DataKey][]string)}

	names, err := net.LookupAddr(ip)
	if err != nil {
		r.Findings = append(r.Findings, engine.Finding{Label: "PTR", Value: "none"})
		return r, nil
	}
	for _, name := range names {
		name = strings.TrimSuffix(name, ".")
		r.Findings = append(r.Findings, engine.Finding{Label: "PTR", Value: name})
		r.Produces[engine.KeyHostname] = append(r.Produces[engine.KeyHostname], name)
	}
	return r, nil
}
