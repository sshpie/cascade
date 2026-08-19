package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/sshpie/cascade/engine"
)

// webgui assets are embedded at build time. Pure Go, no runtime asset path.
//
//go:embed webgui/index.html webgui/favicon.svg
var webFS embed.FS

// --- SSE wire types -------------------------------------------------------

// sseFinding mirrors engine.Finding for the wire (lowercase json keys, never
// nil sub array so the client can assume []).
type sseFinding struct {
	Label string       `json:"label"`
	Value string       `json:"value"`
	Sub   []sseFinding `json:"sub"`
}

// sseResult is the payload of a `result` event.
type sseResult struct {
	Tool     string              `json:"tool"`
	Findings []sseFinding        `json:"findings"`
	Produces map[string][]string `json:"produces"`
	Error    string              `json:"error"`
}

// graphNode is one element of the /graph JSON array.
type graphNode struct {
	Name     string   `json:"name"`
	Requires []string `json:"requires"`
	Produces []string `json:"produces"`
}

// --- server wiring --------------------------------------------------------

// startServer binds 127.0.0.1 on a free OS-assigned port and serves the recon
// UI from a background goroutine. It returns the URL and a channel that carries
// the eventual server error, so callers can either block on it (browser modes)
// or run a native UI on the main thread while the server runs (webview mode).
func startServer() (string, <-chan error, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, fmt.Errorf("bind: %w", err)
	}
	addr := ln.Addr().(*net.TCPAddr)
	url := fmt.Sprintf("http://127.0.0.1:%d/", addr.Port)

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/favicon.ico", handleFavicon)
	mux.HandleFunc("/favicon.svg", handleFavicon)
	mux.HandleFunc("/graph", handleGraph)
	mux.HandleFunc("/run", handleRun)

	errc := make(chan error, 1)
	go func() { errc <- (&http.Server{Handler: mux}).Serve(ln) }()
	return url, errc, nil
}

// serveGUI serves the UI and opens it in the OS default browser, then blocks
// until the server dies. This is the zero-dependency default.
func serveGUI() error {
	url, errc, err := startServer()
	if err != nil {
		return err
	}
	fmt.Printf("cascade gui » %s\n", url)
	openBrowser(url) // best effort; UI works regardless
	return <-errc
}

// serveApp serves the UI in a frameless standalone window via an installed
// Chromium-based browser (chrome/edge/brave/chromium) launched with --app=.
// No new dependencies, still a plain `go build`. Falls back to the default
// browser if no Chromium binary is found.
func serveApp() error {
	url, errc, err := startServer()
	if err != nil {
		return err
	}
	fmt.Printf("cascade app » %s\n", url)
	openAppWindow(url)
	return <-errc
}

// handleIndex serves the embedded single-page UI.
func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	data, err := webFS.ReadFile("webgui/index.html")
	if err != nil {
		http.Error(w, "index not embedded", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}

// handleFavicon serves the embedded SVG favicon (also at /favicon.ico to kill
// the browser's automatic probe). Browsers honor the Content-Type over the path.
func handleFavicon(w http.ResponseWriter, r *http.Request) {
	data, err := webFS.ReadFile("webgui/favicon.svg")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	_, _ = w.Write(data)
}

// handleGraph emits the static tool DAG: one object per tool with its required
// and produced keys. The UI draws the dependency map from this.
func handleGraph(w http.ResponseWriter, r *http.Request) {
	nodes := allTools()
	out := make([]graphNode, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, graphNode{
			Name:     n.Name(),
			Requires: keysToStrings(n.Requires()),
			Produces: keysToStrings(n.Produces()),
		})
	}
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(out)
}

// handleRun runs a fresh engine for ?target=X and streams Server-Sent Events.
//
// Event order on the wire:
//
//	seed   {<key>:[vals]}            once, immediately after seeding
//	result {tool,findings,produces,error}  one per tool, as each finishes
//	state  {<key>:[vals], ...}       once, after every tool has run
//	done   {}                        very last
//
// engine.OnResult fires from MANY goroutines concurrently (the engine runs
// each wave under a sync.WaitGroup). An http.ResponseWriter is NOT safe for
// concurrent writes, so every result is funneled through a buffered channel
// that exactly one writer goroutine (this handler) drains. That serializes all
// SSE writes onto a single goroutine and removes the data race entirely.
func handleRun(w http.ResponseWriter, r *http.Request) {
	target := strings.TrimSpace(r.URL.Query().Get("target"))
	if target == "" {
		http.Error(w, "missing target", http.StatusBadRequest)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	// SSE headers.
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("Connection", "keep-alive")
	h.Set("X-Accel-Buffering", "no") // defeat any reverse-proxy buffering
	w.WriteHeader(http.StatusOK)

	ctx := r.Context()

	// Build the engine for this run.
	e := engine.New()
	seed(e, target)
	register(e)

	// Emit the seed event first, from the just-seeded state.
	if !writeEvent(w, flusher, "seed", e.State().Snapshot()) {
		return
	}

	// resultCh carries every tool result from the engine's worker goroutines to
	// this single SSE-writer goroutine. Buffered so a finishing tool never
	// blocks the engine wave on a slow/disconnected client; we also honor
	// ctx.Done() inside OnResult so a dead client cannot wedge the engine.
	resultCh := make(chan *engine.Result, len(allTools()))

	e.OnResult = func(res *engine.Result) {
		select {
		case resultCh <- res:
		case <-ctx.Done():
			// client gone; drop the result, don't block the wave.
		}
	}

	// Run the engine in its own goroutine; close resultCh when it's done so the
	// drain loop below terminates cleanly.
	engineDone := make(chan struct{})
	go func() {
		e.Run()
		close(resultCh)
		close(engineDone)
	}()

	// Drain results onto the wire as they arrive. This is the ONLY goroutine
	// that ever touches w, so writes are inherently serialized.
	for {
		select {
		case <-ctx.Done():
			// Client disconnected mid-run. The engine keeps going to completion
			// in the background (OnResult selects on ctx.Done and drops), but we
			// stop writing.
			return
		case res, more := <-resultCh:
			if !more {
				goto finish
			}
			if !writeEvent(w, flusher, "result", toSSEResult(res)) {
				return // write failed: client gone
			}
		}
	}

finish:
	// Make sure the engine goroutine has fully returned before snapshotting the
	// final state (it has, since resultCh is closed only after e.Run() returns,
	// but wait on engineDone to be unambiguous).
	<-engineDone

	if !writeEvent(w, flusher, "state", e.State().Snapshot()) {
		return
	}
	_ = writeEvent(w, flusher, "done", struct{}{})
}

// --- SSE write helpers ----------------------------------------------------

// writeEvent serializes one SSE frame and flushes. Returns false if the write
// failed (client disconnected), which the caller uses to bail out.
func writeEvent(w http.ResponseWriter, flusher http.Flusher, event string, payload any) bool {
	data, err := json.Marshal(payload)
	if err != nil {
		data = []byte("{}")
	}
	if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, data); err != nil {
		return false
	}
	flusher.Flush()
	return true
}

// toSSEResult converts an engine.Result into the wire shape: lowercase keys,
// never-nil findings/sub/produces so the client never has to null-check.
func toSSEResult(r *engine.Result) sseResult {
	out := sseResult{
		Tool:     r.Tool,
		Findings: make([]sseFinding, 0, len(r.Findings)),
		Produces: map[string][]string{},
	}
	if r.Err != nil {
		out.Error = r.Err.Error()
	}
	for _, f := range r.Findings {
		sf := sseFinding{Label: f.Label, Value: f.Value, Sub: make([]sseFinding, 0, len(f.Sub))}
		for _, s := range f.Sub {
			sf.Sub = append(sf.Sub, sseFinding{Label: s.Label, Value: s.Value, Sub: []sseFinding{}})
		}
		out.Findings = append(out.Findings, sf)
	}
	for k, v := range r.Produces {
		out.Produces[string(k)] = v
	}
	return out
}

// keysToStrings flattens []engine.DataKey to []string for JSON, never nil.
func keysToStrings(keys []engine.DataKey) []string {
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, string(k))
	}
	return out
}

// --- browser launcher -----------------------------------------------------

// openBrowser opens url in the OS default browser. Best-effort: a failure is
// silent because the URL is also printed to stdout. The command is detached so
// the launcher process exiting never tears down the browser.
func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		// rundll32 avoids the cmd.exe quoting pitfalls around `&` in URLs.
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default: // linux, *bsd
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
}

// chromiumCandidates lists Chromium-based browser binaries per OS, in
// preference order. --app= opens a frameless, tab-less, address-bar-less
// window that reads as a native app.
func chromiumCandidates() []string {
	switch runtime.GOOS {
	case "windows":
		pf := os.Getenv("ProgramFiles")
		pf86 := os.Getenv("ProgramFiles(x86)")
		local := os.Getenv("LocalAppData")
		return []string{
			pf + `\Google\Chrome\Application\chrome.exe`,
			pf86 + `\Google\Chrome\Application\chrome.exe`,
			local + `\Google\Chrome\Application\chrome.exe`,
			pf + `\Microsoft\Edge\Application\msedge.exe`,
			pf86 + `\Microsoft\Edge\Application\msedge.exe`,
		}
	case "darwin":
		return []string{
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
			"/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
			"/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
			"/Applications/Chromium.app/Contents/MacOS/Chromium",
		}
	default: // linux, *bsd
		return []string{
			"google-chrome", "google-chrome-stable", "chromium", "chromium-browser",
			"microsoft-edge", "microsoft-edge-stable", "brave-browser", "vivaldi",
		}
	}
}

// openAppWindow launches the UI as a frameless standalone window using the
// first Chromium-based browser found. Each gets its own throwaway profile dir
// so the app window is independent of the user's normal browsing session.
// Falls back to the default browser if no Chromium binary is present.
func openAppWindow(url string) {
	for _, bin := range chromiumCandidates() {
		path, err := exec.LookPath(bin)
		if err != nil {
			if _, statErr := os.Stat(bin); statErr != nil {
				continue
			}
			path = bin
		}
		profile := filepath.Join(os.TempDir(), "cascade-app-profile")
		cmd := exec.Command(path,
			"--app="+url,
			"--user-data-dir="+profile,
			"--no-first-run",
			"--no-default-browser-check",
		)
		if err := cmd.Start(); err == nil {
			return
		}
	}
	// No Chromium browser found — degrade to the default browser.
	fmt.Println("(no Chromium browser found for --app window; opening default browser)")
	openBrowser(url)
}
