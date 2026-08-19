package tools

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/sshpie/cascade/engine"
)

// ipAPIResponse maps ip-api.com free JSON response (no key required).
type ipAPIResponse struct {
	Status      string  `json:"status"`
	Country     string  `json:"country"`
	CountryCode string  `json:"countryCode"`
	Region      string  `json:"regionName"`
	City        string  `json:"city"`
	Zip         string  `json:"zip"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
	ISP         string  `json:"isp"`
	Org         string  `json:"org"`
	AS          string  `json:"as"`
	Query       string  `json:"query"`
}

var httpClient = &http.Client{Timeout: 10 * time.Second}

// --- IP Location Finder ---

type IPLocationFinder struct{}

func (t *IPLocationFinder) Name() string               { return "IP Location Finder" }
func (t *IPLocationFinder) Requires() []engine.DataKey { return []engine.DataKey{engine.KeyIPv4} }
func (t *IPLocationFinder) Produces() []engine.DataKey {
	return []engine.DataKey{engine.KeyASN, engine.KeyOrg}
}

func (t *IPLocationFinder) Run(state *engine.State) (*engine.Result, error) {
	ip := state.First(engine.KeyIPv4)
	r := &engine.Result{Tool: t.Name(), Produces: make(map[engine.DataKey][]string)}

	resp, err := httpClient.Get(fmt.Sprintf("http://ip-api.com/json/%s?fields=status,country,countryCode,regionName,city,zip,lat,lon,isp,org,as,query", ip))
	if err != nil {
		return r, err
	}
	defer resp.Body.Close()

	var data ipAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return r, err
	}
	if data.Status != "success" {
		return r, fmt.Errorf("ip-api returned status: %s", data.Status)
	}

	r.Findings = []engine.Finding{
		{Label: "IP", Value: data.Query},
		{Label: "Country", Value: fmt.Sprintf("%s (%s)", data.Country, data.CountryCode)},
		{Label: "Region", Value: data.Region},
		{Label: "City", Value: data.City},
		{Label: "ZIP", Value: data.Zip},
		{Label: "Coordinates", Value: fmt.Sprintf("%.4f, %.4f", data.Lat, data.Lon)},
		{Label: "ISP", Value: data.ISP},
		{Label: "Organization", Value: data.Org},
		{Label: "AS", Value: data.AS},
	}

	if data.AS != "" {
		r.Produces[engine.KeyASN] = []string{data.AS}
	}
	if data.Org != "" {
		r.Produces[engine.KeyOrg] = []string{data.Org}
	}
	return r, nil
}

// --- ASN Lookup (Team Cymru whois) ---

type ASNLookup struct{}

func (t *ASNLookup) Name() string               { return "ASN Lookup" }
func (t *ASNLookup) Requires() []engine.DataKey { return []engine.DataKey{engine.KeyASN} }
func (t *ASNLookup) Produces() []engine.DataKey { return nil }

func (t *ASNLookup) Run(state *engine.State) (*engine.Result, error) {
	asn := state.First(engine.KeyASN)
	r := &engine.Result{Tool: t.Name(), Produces: make(map[engine.DataKey][]string)}
	// ASN already enriched by IPLocationFinder; display what we have.
	r.Findings = append(r.Findings, engine.Finding{Label: "ASN", Value: asn})
	return r, nil
}
