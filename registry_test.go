package main

import (
	"testing"

	"github.com/sshpie/cascade/engine"
)

// The registry is the single source of truth for both the CLI and the GUI graph.
// These are structural fitness checks: they keep the DAG self-consistent so a
// new or edited tool cannot silently orphan a dependency or break the count the
// README and GUI promise.

func TestRegistryToolCount(t *testing.T) {
	const want = 30 // "all 30 ViewDNS tools" per the CLI short description
	if got := len(allTools()); got != want {
		t.Errorf("allTools() has %d tools, want %d", got, want)
	}
}

func TestRegistryIsStableAcrossCalls(t *testing.T) {
	// Both the CLI and the GUI graph rebuild from allTools(); they rely on the
	// same node set in the same order on every call. (Run isolation is provided
	// by a fresh engine.Engine/State per run, not by these stateless tool structs;
	// see the engine package tests.)
	a := allTools()
	b := allTools()
	if len(a) != len(b) {
		t.Fatalf("allTools() returned %d then %d nodes", len(a), len(b))
	}
	for i := range a {
		if a[i].Name() != b[i].Name() {
			t.Errorf("node %d differs across calls: %q vs %q", i, a[i].Name(), b[i].Name())
		}
	}
}

func TestRegistryToolNamesAreUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, n := range allTools() {
		name := n.Name()
		if name == "" {
			t.Error("a tool has an empty Name()")
		}
		if seen[name] {
			t.Errorf("duplicate tool name %q", name)
		}
		seen[name] = true
	}
}

// seedKeys are the data keys seed() can populate before any tool runs.
var seedKeys = map[engine.DataKey]bool{
	engine.KeyIPv4:   true,
	engine.KeyIPv6:   true,
	engine.KeyMAC:    true,
	engine.KeyEmail:  true,
	engine.KeyDomain: true,
}

// Every Requires key must be reachable: either a seed key or produced by some
// tool. An orphan requirement is a dead node that can never fire.
func TestRegistryNoOrphanRequirements(t *testing.T) {
	tools := allTools()
	producible := map[engine.DataKey]bool{}
	for k := range seedKeys {
		producible[k] = true
	}
	for _, n := range tools {
		for _, k := range n.Produces() {
			producible[k] = true
		}
	}
	for _, n := range tools {
		for _, req := range n.Requires() {
			if !producible[req] {
				t.Errorf("tool %q requires %q, which no seed or tool produces (dead node)",
					n.Name(), req)
			}
		}
	}
}

// Pin the producer/consumer chain that the missing-Produces bug broke:
// WhoisLookup must declare KeyRegistrantEmail so ReverseWhoisLookup's
// requirement is satisfiable and the GUI graph draws the real edge.
func TestRegistryRegistrantEmailEdge(t *testing.T) {
	declares := func(keys []engine.DataKey, want engine.DataKey) bool {
		for _, k := range keys {
			if k == want {
				return true
			}
		}
		return false
	}

	var whoisProducesEmail, reverseRequiresEmail bool
	for _, n := range allTools() {
		switch n.Name() {
		case "Whois Lookup":
			whoisProducesEmail = declares(n.Produces(), engine.KeyRegistrantEmail)
		case "Reverse Whois Lookup":
			reverseRequiresEmail = declares(n.Requires(), engine.KeyRegistrantEmail)
		}
	}
	if !whoisProducesEmail {
		t.Error("Whois Lookup does not declare KeyRegistrantEmail in Produces(); GUI graph edge will be missing")
	}
	if !reverseRequiresEmail {
		t.Error("Reverse Whois Lookup no longer requires KeyRegistrantEmail; chain changed")
	}
}
