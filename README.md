# cascade

DNS/IP reconnaissance cascade. Seed one value — domain, IP, email, or MAC — and every tool whose inputs are satisfied fires automatically, feeding its outputs into the next layer until the graph is saturated. 30 lookups, no API keys.

![cascade GUI — live dependency-DAG](docs/gui.png)

```
go install github.com/zellkernel/cascade@latest
```

## Three ways to run it, one engine

- **CLI** — `cascade <target>`, streamed to the terminal, `-j` for JSON.
- **GUI** — `cascade gui`, the live dependency-DAG in your browser over Server-Sent Events.
- **App** — `cascade app`, the same UI in a standalone, frameless window (no tabs, no address bar).

All three share the same 30-tool registry and cascade engine. The default build is pure Go, no CGo — `go build` for Linux and Windows with nothing to install.

## How the cascade works

You provide one seed. cascade detects its type (IPv4, IPv6, domain, email, MAC) and runs every tool whose required inputs exist. Each tool's outputs (an IP, a hostname, an ASN, an MX host, a registrant email) become inputs for the next wave. A single domain fans out into DNS, WHOIS, and abuse-contact lookups; the resolved IP feeds geolocation, port scanning, reverse-IP and blacklist checks; the derived hostname, ASN, and org chain even further. A null result is logged, not a dead end.

## CLI

```
cascade <target> [-j output.json]
```

```
cascade cloudflare.com
cascade 104.16.133.229
cascade user@example.com
cascade 00:50:56:ab:cd:ef
cascade cloudflare.com -j results.json
```

![cascade CLI](docs/cli.png)

## GUI

```
cascade gui
```

Binds `127.0.0.1` on a free port, opens your browser, and serves the UI from the binary itself (assets embedded with `go:embed` — nothing to install, no external CDN). Type a target and watch the cascade propagate: the seed node fans data-keys out to the tools that consume them, and each tool animates idle → running → done/error as results stream into the panel on the right. Toggle between the layered **columns** view and a **graph** view, then export the whole run as JSON.

The UI is **fully keyboard-navigable and screen-reader friendly**: a skip link, real labels, focusable nodes/rows/cards (Enter/Space to drill in), `aria-live` streaming regions, a real progress bar, and a dynamic page title that reports run progress. Status is encoded by **shape *and* color** (`○ ◐ ● ✗`), so it stays readable for color-blind users. If the connection drops mid-run, the UI says so and **keeps the partial results** rather than wiping them.

## Standalone window

```
cascade app
```

Serves the same UI in a frameless desktop window instead of a browser tab. By default it opens an installed Chromium browser (Chrome / Edge / Brave / Chromium) in `--app=` mode with a throwaway profile — a standalone window with no tabs or address bar, and still a plain pure-Go build. If no Chromium browser is found it falls back to your default browser.

For a **true native OS webview** window (no browser dependency), build with the `webview` tag:

```
# Linux (needs CGo + a system webview):
sudo apt install libwebkit2gtk-4.1-dev
CGO_ENABLED=1 go build -tags webview -o cascade .

# Windows: the Edge WebView2 runtime ships with Win10/11; build on Windows
#          (or cross-compile with a mingw toolchain):
go build -tags webview -o cascade.exe .
```

This uses the OS webview (WebKitGTK on Linux, WebView2 on Windows, WKWebView on macOS) and renders the exact same UI. Note: on Ubuntu 24.04 only `webkit2gtk-4.1` is packaged while the upstream `webview_go` pin targets `webkit2gtk-4.0`, so a `pkg-config` shim mapping 4.0 → 4.1 may be required. The default (non-webview) build has none of these dependencies.

## Tools

| Tool | Input |
|------|-------|
| DNS Record Lookup | domain |
| MX Lookup | domain |
| NS Lookup | domain |
| SOA Lookup | domain |
| SPF Lookup | domain |
| DMARC Lookup | domain |
| DNSSEC Lookup | domain |
| DNS Propagation Checker | domain |
| Whois Lookup | domain |
| HTTP Headers | domain |
| IP History | domain |
| Chinese Firewall Test | domain |
| Iranian Firewall Test | domain |
| Traceroute | domain |
| Find Shared DNS Servers | ns_host (from NS Lookup) |
| Spam Database Lookup | mx_host (from MX Lookup) |
| Reverse Whois Lookup | registrant_email (from Whois) |
| Reverse DNS Lookup | ipv4 |
| IP Location Finder | ipv4 |
| Abuse Contact Lookup | ipv4 |
| Port Scanner | ipv4 |
| Ping | ipv4 |
| Reverse IP Lookup | ipv4 |
| Email Blacklist Check | ipv4 |
| Proxy Checker | ipv4 |
| IP to Hostname | ipv6 |
| Hostname to IP | hostname (from Reverse DNS) |
| ASN Lookup | asn (from IP Location) |
| Free Email Lookup | email |
| MAC Address Lookup | mac |

No API keys required. Lookups use system DNS, public WHOIS/RDAP, and free no-key endpoints.

## Build from source

```
git clone https://github.com/zellkernel/cascade
cd cascade
go build -o cascade .

# cross-compile (pure Go, no CGo)
GOOS=linux   go build -o cascade .
GOOS=windows go build -o cascade.exe .
```

## Tests

```
go test ./...          # engine DAG/state, seed detection, tool parsing, registry fitness
go test -race ./...    # race-clean under the detector
```

The suite covers the load-bearing logic — the dependency-cascade engine, seed-type detection, the pure parsing in the tools, and a registry fitness check that fails if any tool requires a data key nothing produces.

## License

MIT. Part of the  toolchain.
