package output

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/sshpie/cascade/engine"
)

var (
	header = color.New(color.FgCyan, color.Bold)
	label  = color.New(color.FgWhite, color.Bold)
	value  = color.New(color.FgWhite)
	errClr = color.New(color.FgRed)
	dimClr = color.New(color.FgHiBlack)
	banner = color.New(color.FgMagenta, color.Bold)
)

func Banner(target string) {
	banner.Println("╔════════════════════════════════════════╗")
	banner.Printf("║  CASCADE  »  %s\n", target)
	banner.Println("╚════════════════════════════════════════╝")
	fmt.Println()
}

// Result prints a single tool result to stdout.
func Result(r *engine.Result) {
	if r.Err != nil {
		errClr.Printf("  ✗ %s\n", r.Tool)
		dimClr.Printf("    %v\n\n", r.Err)
		return
	}
	if len(r.Findings) == 0 {
		dimClr.Printf("  – %s: no findings\n\n", r.Tool)
		return
	}

	header.Printf("  ▸ %s\n", r.Tool)
	for _, f := range r.Findings {
		if len(f.Sub) > 0 {
			label.Printf("    %-28s", f.Label+":")
			value.Println(f.Value)
			for _, sub := range f.Sub {
				dimClr.Printf("      %-26s", sub.Label+":")
				value.Println(sub.Value)
			}
		} else {
			label.Printf("    %-28s", f.Label+":")
			value.Println(f.Value)
		}
	}
	fmt.Println()
}

// JSON writes all results as a JSON array to the given file (or stdout if "-").
func JSON(results []*engine.Result, path string) error {
	type jsonFinding struct {
		Label string        `json:"label"`
		Value string        `json:"value"`
		Sub   []jsonFinding `json:"sub,omitempty"`
	}
	type jsonResult struct {
		Tool     string        `json:"tool"`
		Findings []jsonFinding `json:"findings"`
		Error    string        `json:"error,omitempty"`
	}

	var out []jsonResult
	for _, r := range results {
		jr := jsonResult{Tool: r.Tool}
		if r.Err != nil {
			jr.Error = r.Err.Error()
		}
		for _, f := range r.Findings {
			jf := jsonFinding{Label: f.Label, Value: f.Value}
			for _, s := range f.Sub {
				jf.Sub = append(jf.Sub, jsonFinding{Label: s.Label, Value: s.Value})
			}
			jr.Findings = append(jr.Findings, jf)
		}
		out = append(out, jr)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if path != "-" && path != "" {
		f, err := os.Create(path)
		if err != nil {
			return err
		}
		defer f.Close()
		enc = json.NewEncoder(f)
		enc.SetIndent("", "  ")
	}
	return enc.Encode(out)
}

// Summary prints the state snapshot at the end.
func Summary(state map[engine.DataKey][]string) {
	fmt.Println(strings.Repeat("─", 44))
	header.Println("  STATE SNAPSHOT")
	fmt.Println(strings.Repeat("─", 44))
	for k, vals := range state {
		label.Printf("  %-20s", string(k)+":")
		value.Println(strings.Join(vals, ", "))
	}
	fmt.Println()
}
