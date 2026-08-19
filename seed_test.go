package main

import (
	"reflect"
	"testing"

	"github.com/sshpie/cascade/engine"
)

// seed() is the single target-type classifier shared by the CLI and the GUI.
// A misclassification silently routes the whole cascade down the wrong branch,
// so the detection order (IPv4/IPv6 -> MAC -> email -> domain) is load-bearing.
func TestSeedDetection(t *testing.T) {
	tests := []struct {
		name   string
		target string
		want   map[engine.DataKey][]string
	}{
		{
			name:   "ipv4 literal",
			target: "8.8.8.8",
			want:   map[engine.DataKey][]string{engine.KeyIPv4: {"8.8.8.8"}},
		},
		{
			name:   "ipv6 literal",
			target: "2001:4860:4860::8888",
			want:   map[engine.DataKey][]string{engine.KeyIPv6: {"2001:4860:4860::8888"}},
		},
		{
			name:   "ipv4-mapped ipv6 is classified ipv4 (To4 is non-nil)",
			target: "::ffff:1.2.3.4",
			want:   map[engine.DataKey][]string{engine.KeyIPv4: {"::ffff:1.2.3.4"}},
		},
		{
			name:   "mac colon form",
			target: "00:50:56:c0:00:08",
			want:   map[engine.DataKey][]string{engine.KeyMAC: {"00:50:56:c0:00:08"}},
		},
		{
			name:   "mac hyphen form",
			target: "00-50-56-C0-00-08",
			want:   map[engine.DataKey][]string{engine.KeyMAC: {"00-50-56-C0-00-08"}},
		},
		{
			name:   "email seeds both email and its domain",
			target: "alice@example.com",
			want: map[engine.DataKey][]string{
				engine.KeyEmail:  {"alice@example.com"},
				engine.KeyDomain: {"example.com"},
			},
		},
		{
			name:   "bare domain",
			target: "example.com",
			want:   map[engine.DataKey][]string{engine.KeyDomain: {"example.com"}},
		},
		{
			name:   "domain with https scheme is stripped",
			target: "https://example.com/path?q=1",
			want:   map[engine.DataKey][]string{engine.KeyDomain: {"example.com"}},
		},
		{
			name:   "domain with http scheme is stripped",
			target: "http://sub.example.com/x",
			want:   map[engine.DataKey][]string{engine.KeyDomain: {"sub.example.com"}},
		},
		{
			name:   "surrounding whitespace is trimmed",
			target: "  example.com  ",
			want:   map[engine.DataKey][]string{engine.KeyDomain: {"example.com"}},
		},
		{
			name:   "email with empty domain part falls through to email only",
			target: "alice@",
			want:   map[engine.DataKey][]string{engine.KeyEmail: {"alice@"}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := engine.New()
			seed(e, tc.target)
			got := e.State().Snapshot()
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("seed(%q) -> %v, want %v", tc.target, got, tc.want)
			}
		})
	}
}
