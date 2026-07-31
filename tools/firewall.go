package tools

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/zellkernel/cascade/engine"
)

// dnsA is an alias to avoid confusion in this file.
type dnsA = dns.A

// --- Chinese Firewall Test ---

type ChineseFirewallTest struct{}

func (t *ChineseFirewallTest) Name() string               { return "Chinese Firewall Test" }
func (t *ChineseFirewallTest) Requires() []engine.DataKey { return []engine.DataKey{engine.KeyDomain} }
func (t *ChineseFirewallTest) Produces() []engine.DataKey { return nil }

func (t *ChineseFirewallTest) Run(state *engine.State) (*engine.Result, error) {
	domain := state.First(engine.KeyDomain)
	r := &engine.Result{Tool: t.Name(), Produces: make(map[engine.DataKey][]string)}

	// blockedinchina.net API (free, no key)
	url := fmt.Sprintf("https://www.comparitech.com/privacy-security-tools/blockedinchina/?website=%s", domain)
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		// Fallback: DNS query via known Chinese resolvers and compare
		return t.dnsFallback(domain, r)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return t.dnsFallback(domain, r)
	}

	bodyStr := string(body)
	switch {
	case strings.Contains(bodyStr, "is blocked in China"):
		r.Findings = append(r.Findings, engine.Finding{Label: "Status", Value: "BLOCKED in China"})
	case strings.Contains(bodyStr, "is not blocked"):
		r.Findings = append(r.Findings, engine.Finding{Label: "Status", Value: "accessible in China"})
	default:
		return t.dnsFallback(domain, r)
	}
	return r, nil
}

func (t *ChineseFirewallTest) dnsFallback(domain string, r *engine.Result) (*engine.Result, error) {
	// Compare DNS resolution from Chinese resolver vs global
	// 114.114.114.114 is a common Chinese public DNS
	chinaResolver := "114.114.114.114:53"
	globalResolver := "8.8.8.8:53"

	chinaResp, err1 := queryDNS(domain, "A", chinaResolver)
	globalResp, err2 := queryDNS(domain, "A", globalResolver)

	if err1 != nil {
		r.Findings = append(r.Findings, engine.Finding{Label: "China DNS", Value: "timeout (possible block)"})
	} else {
		var chinaIPs []string
		for _, rr := range chinaResp.Answer {
			if a, ok := rr.(*dnsA); ok {
				chinaIPs = append(chinaIPs, a.A.String())
			}
		}
		if len(chinaIPs) == 0 {
			r.Findings = append(r.Findings, engine.Finding{Label: "China DNS", Value: "no answer (possible block)"})
		} else {
			r.Findings = append(r.Findings, engine.Finding{Label: "China DNS", Value: strings.Join(chinaIPs, ", ")})
		}
	}

	if err2 == nil {
		var globalIPs []string
		for _, rr := range globalResp.Answer {
			if a, ok := rr.(*dnsA); ok {
				globalIPs = append(globalIPs, a.A.String())
			}
		}
		r.Findings = append(r.Findings, engine.Finding{Label: "Global DNS", Value: strings.Join(globalIPs, ", ")})
	}

	r.Findings = append(r.Findings, engine.Finding{Label: "Note", Value: "DNS divergence suggests blocking; full GFW probe requires in-country vantage"})
	return r, nil
}

// --- Iranian Internet Firewall Test ---

type IranianFirewallTest struct{}

func (t *IranianFirewallTest) Name() string               { return "Iranian Internet Firewall Test" }
func (t *IranianFirewallTest) Requires() []engine.DataKey { return []engine.DataKey{engine.KeyDomain} }
func (t *IranianFirewallTest) Produces() []engine.DataKey { return nil }

func (t *IranianFirewallTest) Run(state *engine.State) (*engine.Result, error) {
	domain := state.First(engine.KeyDomain)
	r := &engine.Result{Tool: t.Name(), Produces: make(map[engine.DataKey][]string)}

	// DNS comparison using Iranian public resolver (10.202.10.10) vs global
	// Note: Iranian resolver unreachable from outside; use OONI explorer correlation
	iranResolver := "10.202.10.10:53" // state resolver, only reachable inside Iran
	globalResolver := "8.8.8.8:53"

	_, iranErr := queryDNS(domain, "A", iranResolver)
	globalResp, globalErr := queryDNS(domain, "A", globalResolver)

	if iranErr != nil {
		r.Findings = append(r.Findings, engine.Finding{
			Label: "Iranian Resolver",
			Value: "unreachable from current vantage (expected outside Iran)",
		})
	}

	if globalErr == nil {
		var ips []string
		for _, rr := range globalResp.Answer {
			if a, ok := rr.(*dnsA); ok {
				ips = append(ips, a.A.String())
			}
		}
		r.Findings = append(r.Findings, engine.Finding{Label: "Global DNS", Value: strings.Join(ips, ", ")})
	}

	// OONI API for known Iranian blocking (free, no key)
	ooniURL := fmt.Sprintf("https://api.ooni.io/api/v1/measurements?domain=%s&probe_cc=IR&limit=3", domain)
	ooniResp, err := (&http.Client{Timeout: 10 * time.Second}).Get(ooniURL)
	if err == nil {
		defer ooniResp.Body.Close()
		var ooni struct {
			Results []struct {
				Anomaly bool   `json:"anomaly"`
				TestURL string `json:"input"`
			} `json:"results"`
		}
		if decodeJSON(ooniResp.Body, &ooni) == nil && len(ooni.Results) > 0 {
			anomalyCount := 0
			for _, res := range ooni.Results {
				if res.Anomaly {
					anomalyCount++
				}
			}
			r.Findings = append(r.Findings, engine.Finding{
				Label: "OONI (Iran)",
				Value: fmt.Sprintf("%d/%d recent measurements show anomaly", anomalyCount, len(ooni.Results)),
			})
		}
	}

	r.Findings = append(r.Findings, engine.Finding{
		Label: "Note",
		Value: "Full probe requires in-country vantage or OONI probe data",
	})
	return r, nil
}
