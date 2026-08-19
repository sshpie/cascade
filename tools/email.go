package tools

import (
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
	"github.com/sshpie/cascade/engine"
)

// DNS-based real-time blacklists (no API key required).
var rblList = []struct {
	zone string
	name string
}{
	{"zen.spamhaus.org", "Spamhaus ZEN"},
	{"bl.spamcop.net", "SpamCop"},
	{"dnsbl.sorbs.net", "SORBS"},
	{"b.barracudacentral.org", "Barracuda"},
	{"dnsbl-1.uceprotect.net", "UCEPROTECT-1"},
	{"ips.backscatterer.org", "Backscatterer"},
	{"ix.dnsbl.manitu.net", "Manitu"},
	{"truncate.gbudb.net", "GBUdb"},
}

// reverseIP returns the reversed-octet label used to query DNS blacklists,
// e.g. "1.2.3.4" -> "4.3.2.1". DNSBLs are keyed on IPv4 only, so the input must
// be a real dotted-quad: parsing rejects IPv6 (incl. the ::ffff:a.b.c.d mapped
// form) and any string that merely happens to contain three dots. Returns ""
// when the input is not a valid IPv4 address, which callers treat as "skip".
func reverseIP(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	v4 := parsed.To4()
	if v4 == nil {
		return ""
	}
	// Reconstruct from the canonical 4-byte form so non-canonical spellings
	// (leading zeros, mapped form) never reach the RBL query.
	parts := strings.Split(v4.String(), ".")
	if len(parts) != 4 {
		return ""
	}
	return parts[3] + "." + parts[2] + "." + parts[1] + "." + parts[0]
}

// --- Email Blacklist Check ---

type EmailBlacklistCheck struct{}

func (t *EmailBlacklistCheck) Name() string               { return "Email Blacklist Check" }
func (t *EmailBlacklistCheck) Requires() []engine.DataKey { return []engine.DataKey{engine.KeyIPv4} }
func (t *EmailBlacklistCheck) Produces() []engine.DataKey { return nil }

func (t *EmailBlacklistCheck) Run(state *engine.State) (*engine.Result, error) {
	ip := state.First(engine.KeyIPv4)
	r := &engine.Result{Tool: t.Name(), Produces: make(map[engine.DataKey][]string)}

	reversed := reverseIP(ip)
	if reversed == "" {
		return r, fmt.Errorf("invalid IP: %s", ip)
	}

	type rblResult struct {
		name   string
		listed bool
		txt    string
	}
	results := make(chan rblResult, len(rblList))

	for _, rbl := range rblList {
		go func(rbl struct {
			zone string
			name string
		}) {
			query := reversed + "." + rbl.zone
			resp, err := queryDNS(query, "A", resolvers[0])
			if err != nil || resp == nil || len(resp.Answer) == 0 {
				results <- rblResult{rbl.name, false, ""}
				return
			}
			// Get TXT for reason
			txt := ""
			txtResp, err := queryDNS(query, "TXT", resolvers[0])
			if err == nil && txtResp != nil {
				for _, rr := range txtResp.Answer {
					if t, ok := rr.(*dns.TXT); ok {
						txt = strings.Join(t.Txt, " ")
						break
					}
				}
			}
			results <- rblResult{rbl.name, true, txt}
		}(rbl)
	}

	listedCount := 0
	for range rblList {
		res := <-results
		if res.listed {
			listedCount++
			val := "LISTED"
			if res.txt != "" {
				val += " - " + res.txt
			}
			r.Findings = append(r.Findings, engine.Finding{Label: res.name, Value: val})
		} else {
			r.Findings = append(r.Findings, engine.Finding{Label: res.name, Value: "clean"})
		}
	}

	summary := fmt.Sprintf("Listed on %d/%d blacklists", listedCount, len(rblList))
	r.Findings = append([]engine.Finding{{Label: "Summary", Value: summary}}, r.Findings...)
	return r, nil
}

// --- Spam Database Lookup (same as email blacklist, MX-focused) ---

type SpamDatabaseLookup struct{}

func (t *SpamDatabaseLookup) Name() string               { return "Spam Database Lookup" }
func (t *SpamDatabaseLookup) Requires() []engine.DataKey { return []engine.DataKey{engine.KeyMXHost} }
func (t *SpamDatabaseLookup) Produces() []engine.DataKey { return nil }

func (t *SpamDatabaseLookup) Run(state *engine.State) (*engine.Result, error) {
	mxHost := state.First(engine.KeyMXHost)
	r := &engine.Result{Tool: t.Name(), Produces: make(map[engine.DataKey][]string)}

	// Resolve MX host to IP then check RBLs
	addrs, err := netLookupHost(mxHost)
	if err != nil || len(addrs) == 0 {
		r.Findings = append(r.Findings, engine.Finding{Label: "MX Host", Value: "could not resolve " + mxHost})
		return r, nil
	}

	ip := addrs[0]
	reversed := reverseIP(ip)
	if reversed == "" {
		return r, nil
	}

	listed := 0
	for _, rbl := range rblList {
		query := reversed + "." + rbl.zone
		resp, err := queryDNS(query, "A", resolvers[0])
		if err == nil && resp != nil && len(resp.Answer) > 0 {
			listed++
			r.Findings = append(r.Findings, engine.Finding{Label: rbl.name, Value: "LISTED"})
		}
	}
	r.Findings = append([]engine.Finding{
		{Label: "MX Host", Value: mxHost},
		{Label: "MX IP", Value: ip},
		{Label: "Listed", Value: fmt.Sprintf("%d/%d blacklists", listed, len(rblList))},
	}, r.Findings...)
	return r, nil
}

// netLookupHost wraps net.LookupHost for use in email.go
func netLookupHost(host string) ([]string, error) {
	return netResolve(host)
}

// --- Free Email Lookup ---

// Canonical list of free/disposable email providers.
var freeEmailProviders = map[string]struct{}{
	"gmail.com": {}, "yahoo.com": {}, "hotmail.com": {}, "outlook.com": {},
	"protonmail.com": {}, "icloud.com": {}, "aol.com": {}, "live.com": {},
	"msn.com": {}, "yandex.com": {}, "mail.ru": {}, "zoho.com": {},
	"tutanota.com": {}, "fastmail.com": {}, "gmx.com": {}, "gmx.de": {},
	"web.de": {}, "mailinator.com": {}, "guerrillamail.com": {}, "temp-mail.org": {},
	"throwam.com": {}, "sharklasers.com": {}, "guerrillamailblock.com": {},
}

type FreeEmailLookup struct{}

func (t *FreeEmailLookup) Name() string               { return "Free Email Lookup" }
func (t *FreeEmailLookup) Requires() []engine.DataKey { return []engine.DataKey{engine.KeyEmail} }
func (t *FreeEmailLookup) Produces() []engine.DataKey { return nil }

func (t *FreeEmailLookup) Run(state *engine.State) (*engine.Result, error) {
	email := state.First(engine.KeyEmail)
	r := &engine.Result{Tool: t.Name(), Produces: make(map[engine.DataKey][]string)}

	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return r, fmt.Errorf("invalid email: %s", email)
	}
	domain := strings.ToLower(parts[1])

	if _, free := freeEmailProviders[domain]; free {
		r.Findings = append(r.Findings, engine.Finding{Label: "Type", Value: "free/consumer provider"})
	} else {
		r.Findings = append(r.Findings, engine.Finding{Label: "Type", Value: "custom domain (likely business)"})
	}
	r.Findings = append(r.Findings, engine.Finding{Label: "Domain", Value: domain})
	return r, nil
}
