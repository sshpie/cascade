package tools

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/zellkernel/cascade/engine"
)

// whoisServer returns the correct WHOIS server for a TLD.
func whoisServer(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return "whois.iana.org"
	}
	tld := parts[len(parts)-1]
	servers := map[string]string{
		"com":  "whois.verisign-grs.com",
		"net":  "whois.verisign-grs.com",
		"org":  "whois.pir.org",
		"io":   "whois.nic.io",
		"co":   "whois.nic.co",
		"us":   "whois.nic.us",
		"uk":   "whois.nic.uk",
		"de":   "whois.denic.de",
		"info": "whois.afilias.net",
		"biz":  "whois.biz",
		"ai":   "whois.nic.ai",
		"app":  "whois.nic.google",
		"dev":  "whois.nic.google",
	}
	if s, ok := servers[tld]; ok {
		return s
	}
	return "whois.iana.org"
}

func rawWhois(domain string) (string, error) {
	server := whoisServer(domain)
	conn, err := net.DialTimeout("tcp", server+":43", 10*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	fmt.Fprintf(conn, "%s\r\n", domain)
	buf, err := io.ReadAll(conn)
	if err != nil {
		return "", err
	}
	return string(buf), nil
}

func parseWhoisField(raw, field string) string {
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(line), strings.ToLower(field)+":") {
			val := strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
			if val != "" {
				return val
			}
		}
	}
	return ""
}

// --- Whois Lookup ---

type WhoisLookup struct{}

func (t *WhoisLookup) Name() string               { return "Whois Lookup" }
func (t *WhoisLookup) Requires() []engine.DataKey { return []engine.DataKey{engine.KeyDomain} }

// Produces must list every key Run can write to state, or the GUI dependency
// graph mis-draws edges. Run emits KeyOrg (Registrant Organization) AND
// KeyRegistrantEmail (the input ReverseWhoisLookup requires); both belong here.
func (t *WhoisLookup) Produces() []engine.DataKey {
	return []engine.DataKey{engine.KeyOrg, engine.KeyRegistrantEmail}
}

func (t *WhoisLookup) Run(state *engine.State) (*engine.Result, error) {
	domain := state.First(engine.KeyDomain)
	r := &engine.Result{Tool: t.Name(), Produces: make(map[engine.DataKey][]string)}

	raw, err := rawWhois(domain)
	if err != nil {
		return r, err
	}

	fields := []string{
		"Registrar", "Registrar URL", "Registrant Organization",
		"Registrant Country", "Registrant Email",
		"Creation Date", "Updated Date", "Registry Expiry Date",
		"Name Server", "DNSSEC",
	}
	for _, f := range fields {
		if val := parseWhoisField(raw, f); val != "" {
			r.Findings = append(r.Findings, engine.Finding{Label: f, Value: val})
			switch f {
			case "Registrant Organization":
				r.Produces[engine.KeyOrg] = []string{val}
			case "Registrant Email":
				r.Produces[engine.KeyRegistrantEmail] = []string{val}
			}
		}
	}
	return r, nil
}

// --- Abuse Contact Lookup (RDAP) ---

type AbuseContactLookup struct{}

func (t *AbuseContactLookup) Name() string               { return "Abuse Contact Lookup" }
func (t *AbuseContactLookup) Requires() []engine.DataKey { return []engine.DataKey{engine.KeyIPv4} }
func (t *AbuseContactLookup) Produces() []engine.DataKey { return []engine.DataKey{engine.KeyAbuse} }

func (t *AbuseContactLookup) Run(state *engine.State) (*engine.Result, error) {
	ip := state.First(engine.KeyIPv4)
	r := &engine.Result{Tool: t.Name(), Produces: make(map[engine.DataKey][]string)}

	// ARIN RDAP (covers ARIN, redirects others)
	resp, err := httpClient.Get(fmt.Sprintf("https://rdap.arin.net/registry/ip/%s", ip))
	if err != nil {
		return r, err
	}
	defer resp.Body.Close()

	var rdap map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&rdap); err != nil {
		return r, err
	}

	// Walk entities for abuse role
	if entities, ok := rdap["entities"].([]interface{}); ok {
		for _, e := range entities {
			entity, ok := e.(map[string]interface{})
			if !ok {
				continue
			}
			roles, _ := entity["roles"].([]interface{})
			for _, role := range roles {
				if role == "abuse" {
					if vcard, ok := entity["vcardArray"].([]interface{}); ok && len(vcard) > 1 {
						if entries, ok := vcard[1].([]interface{}); ok {
							for _, entry := range entries {
								fields, ok := entry.([]interface{})
								if !ok || len(fields) < 4 {
									continue
								}
								if fields[0] == "email" {
									email := fmt.Sprintf("%v", fields[3])
									r.Findings = append(r.Findings, engine.Finding{Label: "Abuse Email", Value: email})
									r.Produces[engine.KeyAbuse] = []string{email}
								}
								if fields[0] == "fn" {
									r.Findings = append(r.Findings, engine.Finding{Label: "Abuse Contact", Value: fmt.Sprintf("%v", fields[3])})
								}
							}
						}
					}
				}
			}
		}
	}

	if name, ok := rdap["name"].(string); ok {
		r.Findings = append(r.Findings, engine.Finding{Label: "Network Name", Value: name})
	}
	if handle, ok := rdap["handle"].(string); ok {
		r.Findings = append(r.Findings, engine.Finding{Label: "Handle", Value: handle})
	}
	return r, nil
}

// --- Reverse Whois Lookup ---
// HackerTarget reverse whois requires an email address as input.
// We seed from the registrant email extracted during Whois Lookup.

type ReverseWhoisLookup struct{}

func (t *ReverseWhoisLookup) Name() string { return "Reverse Whois Lookup" }
func (t *ReverseWhoisLookup) Requires() []engine.DataKey {
	return []engine.DataKey{engine.KeyRegistrantEmail}
}
func (t *ReverseWhoisLookup) Produces() []engine.DataKey { return nil }

func (t *ReverseWhoisLookup) Run(state *engine.State) (*engine.Result, error) {
	email := state.First(engine.KeyRegistrantEmail)
	r := &engine.Result{Tool: t.Name(), Produces: make(map[engine.DataKey][]string)}

	url := fmt.Sprintf("https://api.hackertarget.com/reversewhois/?q=%s", email)
	resp, err := httpClient.Get(url)
	if err != nil {
		return r, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return r, err
	}

	text := strings.TrimSpace(string(body))
	// Guard against HTML error pages
	if strings.HasPrefix(text, "<") || strings.HasPrefix(text, "error") {
		r.Findings = append(r.Findings, engine.Finding{Label: "Result", Value: "no matches (rate-limited or no data)"})
		return r, nil
	}

	lines := strings.Split(text, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		r.Findings = append(r.Findings, engine.Finding{Label: "Domain", Value: line})
	}
	if len(r.Findings) == 0 {
		r.Findings = append(r.Findings, engine.Finding{Label: "Result", Value: "no matches"})
	}
	return r, nil
}
