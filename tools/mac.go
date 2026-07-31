package tools

import (
	"fmt"
	"io"
	"strings"

	"github.com/zellkernel/cascade/engine"
)

// Partial IEEE OUI table (top 50 vendors by prevalence).
// Full table available at https://standards-oui.ieee.org/oui/oui.txt
var ouiTable = map[string]string{
	"00:00:0C": "Cisco Systems",
	"00:50:56": "VMware",
	"00:0C:29": "VMware (Workstation)",
	"00:05:69": "VMware",
	"00:1A:A0": "Dell",
	"00:14:22": "Dell",
	"B8:AC:6F": "Dell",
	"00:1B:21": "Intel Corporate",
	"A4:C3:F0": "Apple",
	"3C:22:FB": "Apple",
	"00:1C:42": "Parallels",
	"00:03:FF": "Microsoft",
	"00:15:5D": "Microsoft (Hyper-V)",
	"00:E0:4C": "Realtek Semiconductor",
	"00:23:AE": "Cisco-Linksys",
	"00:18:F8": "Cisco",
	"00:1F:CA": "Cisco",
	"FC:FB:FB": "Cisco",
	"00:04:96": "Extreme Networks",
	"00:1B:11": "D-Link",
	"14:DD:A9": "Amazon Technologies",
	"0A:4B:C8": "Amazon Technologies",
	"2C:54:91": "Google",
	"F4:F5:D8": "Google",
	"54:EE:75": "Google",
	"00:26:B9": "Dell",
	"E4:BE:ED": "HP",
	"00:1E:4F": "HP",
	"00:17:08": "HP",
	"00:1C:C4": "HP",
	"00:30:48": "Supermicro",
	"AC:1F:6B": "Supermicro",
	"00:25:90": "Supermicro",
	"78:2B:CB": "Intel Corporate",
	"00:1B:77": "Intel Corporate",
	"8C:8D:28": "Intel Corporate",
	"00:50:F2": "Microsoft",
	"44:38:39": "Cumulus Networks",
	"00:16:3E": "Xen Source (AWS/Xen VMs)",
	"02:42:AC": "Docker",
}

func lookupOUI(mac string) string {
	mac = strings.ToUpper(strings.ReplaceAll(mac, "-", ":"))
	if len(mac) < 8 {
		return "unknown"
	}
	prefix := mac[:8]
	if vendor, ok := ouiTable[prefix]; ok {
		return vendor
	}
	return "unknown (not in local OUI table)"
}

// --- MAC Address Lookup ---

type MACAddressLookup struct{}

func (t *MACAddressLookup) Name() string               { return "MAC Address Lookup" }
func (t *MACAddressLookup) Requires() []engine.DataKey { return []engine.DataKey{engine.KeyMAC} }
func (t *MACAddressLookup) Produces() []engine.DataKey { return nil }

func (t *MACAddressLookup) Run(state *engine.State) (*engine.Result, error) {
	mac := state.First(engine.KeyMAC)
	r := &engine.Result{Tool: t.Name(), Produces: make(map[engine.DataKey][]string)}

	vendor := lookupOUI(mac)
	r.Findings = append(r.Findings,
		engine.Finding{Label: "MAC", Value: mac},
		engine.Finding{Label: "Vendor", Value: vendor},
	)

	// Enrich via macvendors.com API (free, no key, rate-limited)
	resp, err := httpClient.Get(fmt.Sprintf("https://api.macvendors.com/%s", mac))
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == 200 {
			body, readErr := io.ReadAll(resp.Body)
			if readErr == nil {
				if v := strings.TrimSpace(string(body)); v != "" && v != vendor {
					r.Findings = append(r.Findings, engine.Finding{Label: "Vendor (API)", Value: v})
				}
			}
		}
	}
	return r, nil
}
