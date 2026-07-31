package main

import (
	"net"
	"strings"

	"github.com/zellkernel/cascade/engine"
	"github.com/zellkernel/cascade/tools"
)

// allTools is the single source of truth for the tool set. Both the CLI path
// (register) and the GUI server (graph + per-run engine) build their node list
// from here so the two can never drift.
//
// Returns a fresh slice of fresh tool instances on every call. The tools are
// stateless value-receivers-on-pointer structs, but handing out fresh pointers
// per engine keeps each GUI run fully isolated.
func allTools() []engine.Node {
	return []engine.Node{
		// DNS
		&tools.DNSRecordLookup{},
		&tools.MXLookup{},
		&tools.NSLookup{},
		&tools.SOALookup{},
		&tools.SPFLookup{},
		&tools.DMARCLookup{},
		&tools.DNSSECLookup{},
		&tools.DNSPropagation{},
		&tools.ReverseDNSLookup{},
		&tools.HostnameToIP{},
		&tools.IPToHostname{},

		// Geo / ASN
		&tools.IPLocationFinder{},
		&tools.ASNLookup{},

		// Whois
		&tools.WhoisLookup{},
		&tools.AbuseContactLookup{},
		&tools.ReverseWhoisLookup{},

		// Network
		&tools.PortScanner{},
		&tools.HTTPHeaders{},
		&tools.Ping{},
		&tools.Traceroute{},
		&tools.ReverseIPLookup{},
		&tools.FindSharedDNSServers{},
		&tools.IPHistory{},
		&tools.ProxyChecker{},

		// Email
		&tools.EmailBlacklistCheck{},
		&tools.SpamDatabaseLookup{},
		&tools.FreeEmailLookup{},

		// Firewall
		&tools.ChineseFirewallTest{},
		&tools.IranianFirewallTest{},

		// MAC
		&tools.MACAddressLookup{},
	}
}

// register wires the shared tool set into an engine (CLI path).
func register(e *engine.Engine) {
	e.Register(allTools()...)
}

// seed detects the target type and populates initial state. Shared by the CLI
// and the GUI /run handler so detection logic lives in exactly one place.
//
// Detection order: IP (v4/v6) -> MAC -> email (+domain part) -> domain.
func seed(e *engine.Engine, target string) {
	target = strings.TrimSpace(target)

	// IP literal?
	if ip := net.ParseIP(target); ip != nil {
		if ip.To4() != nil {
			e.Seed(engine.KeyIPv4, target)
		} else {
			e.Seed(engine.KeyIPv6, target)
		}
		return
	}

	// MAC address?
	if _, err := net.ParseMAC(target); err == nil {
		e.Seed(engine.KeyMAC, target)
		return
	}

	// Email? seed both the email and its domain part.
	if strings.Contains(target, "@") {
		e.Seed(engine.KeyEmail, target)
		parts := strings.Split(target, "@")
		if len(parts) == 2 && parts[1] != "" {
			e.Seed(engine.KeyDomain, parts[1])
		}
		return
	}

	// Default: a domain. Strip scheme and any path.
	target = strings.TrimPrefix(target, "https://")
	target = strings.TrimPrefix(target, "http://")
	target = strings.Split(target, "/")[0]
	e.Seed(engine.KeyDomain, target)
}
