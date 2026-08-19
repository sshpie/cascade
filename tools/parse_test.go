package tools

import (
	"testing"

	"github.com/sshpie/cascade/engine"
)

func TestReverseIP(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"1.2.3.4", "4.3.2.1"},
		{"8.8.8.8", "8.8.8.8"},
		{"192.168.0.1", "1.0.168.192"},
		{"", ""},                      // not an IP
		{"1.2.3", ""},                 // too few octets
		{"1.2.3.4.5", ""},             // too many octets
		{"999.1.1.1", ""},             // octet out of range -> not a valid IP
		{"1.2.3.x", ""},               // non-numeric octet
		{"2001:db8::1", ""},           // IPv6 is not an RBL-addressable v4 label
		{"::ffff:1.2.3.4", "4.3.2.1"}, // IPv4-mapped IPv6 canonicalizes to its v4
		{"01.02.03.04", ""},           // leading-zero octets rejected (octal ambiguity)
	}
	for _, tc := range tests {
		if got := reverseIP(tc.in); got != tc.want {
			t.Errorf("reverseIP(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestLookupOUI(t *testing.T) {
	tests := []struct {
		name, mac, want string
	}{
		{"vmware colon", "00:50:56:c0:00:08", "VMware"},
		{"vmware lowercase", "00:50:56:aa:bb:cc", "VMware"},
		{"hyphen separator normalized", "00-0C-29-12-34-56", "VMware (Workstation)"},
		{"docker prefix", "02:42:ac:11:00:02", "Docker"},
		{"unknown prefix", "DE:AD:BE:EF:00:01", "unknown (not in local OUI table)"},
		{"too short to have a prefix", "00:50", "unknown"},
		{"empty", "", "unknown"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := lookupOUI(tc.mac); got != tc.want {
				t.Errorf("lookupOUI(%q) = %q, want %q", tc.mac, got, tc.want)
			}
		})
	}
}

func TestWhoisServer(t *testing.T) {
	tests := []struct {
		domain, want string
	}{
		{"example.com", "whois.verisign-grs.com"},
		{"example.net", "whois.verisign-grs.com"},
		{"example.org", "whois.pir.org"},
		{"foo.bar.io", "whois.nic.io"}, // multi-label: uses the last label
		{"thing.app", "whois.nic.google"},
		{"thing.dev", "whois.nic.google"},
		{"unknown.zzz", "whois.iana.org"}, // unmapped TLD falls back to IANA
		{"nodot", "whois.iana.org"},       // no TLD at all
	}
	for _, tc := range tests {
		if got := whoisServer(tc.domain); got != tc.want {
			t.Errorf("whoisServer(%q) = %q, want %q", tc.domain, got, tc.want)
		}
	}
}

func TestParseWhoisField(t *testing.T) {
	raw := `Domain Name: EXAMPLE.COM
Registrar: MarkMonitor Inc.
Registrar URL: http://www.markmonitor.com
Registrant Organization: Example Holdings, LLC
Registrant Email:
Updated Date: 2024-08-14T07:01:34Z
   Name Server: A.IANA-SERVERS.NET
DNSSEC: signedDelegation`

	tests := []struct {
		field, want string
	}{
		{"Registrar", "MarkMonitor Inc."},
		{"Registrant Organization", "Example Holdings, LLC"}, // value contains a comma
		{"Registrar URL", "http://www.markmonitor.com"},      // value contains its own colon
		{"Name Server", "A.IANA-SERVERS.NET"},                // leading whitespace tolerated
		{"DNSSEC", "signedDelegation"},
		{"registrar", "MarkMonitor Inc."}, // field match is case-insensitive
		{"Registrant Email", ""},          // present but blank -> empty
		{"Reseller", ""},                  // absent field -> empty
	}
	for _, tc := range tests {
		if got := parseWhoisField(raw, tc.field); got != tc.want {
			t.Errorf("parseWhoisField(%q) = %q, want %q", tc.field, got, tc.want)
		}
	}
}

// FreeEmailLookup classifies a target email as a free/consumer provider or a
// custom (likely business) domain. This is the pure decision the tool makes;
// the test drives it through the engine State exactly as production does.
func TestFreeEmailLookupClassification(t *testing.T) {
	tests := []struct {
		name, email, wantType string
	}{
		{"gmail is free", "bob@gmail.com", "free/consumer provider"},
		{"case-insensitive domain", "bob@GMAIL.COM", "free/consumer provider"},
		{"disposable provider listed as free", "x@mailinator.com", "free/consumer provider"},
		{"custom domain is business", "ceo@acme-corp.com", "custom domain (likely business)"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st := engine.NewState()
			st.Set(engine.KeyEmail, tc.email)
			res, err := (&FreeEmailLookup{}).Run(st)
			if err != nil {
				t.Fatalf("Run returned error: %v", err)
			}
			gotType := findingValue(res, "Type")
			if gotType != tc.wantType {
				t.Errorf("classification of %q = %q, want %q", tc.email, gotType, tc.wantType)
			}
		})
	}
}

func TestFreeEmailLookupRejectsMalformed(t *testing.T) {
	st := engine.NewState()
	st.Set(engine.KeyEmail, "not-an-email")
	if _, err := (&FreeEmailLookup{}).Run(st); err == nil {
		t.Error("expected error for malformed email, got nil")
	}
}

// findingValue returns the Value of the first finding with the given Label.
func findingValue(r *engine.Result, label string) string {
	for _, f := range r.Findings {
		if f.Label == label {
			return f.Value
		}
	}
	return ""
}
