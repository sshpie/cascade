package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/zellkernel/cascade/engine"
	"github.com/zellkernel/cascade/output"
	"github.com/spf13/cobra"
)

var jsonOut string

func main() {
	root := &cobra.Command{
		Use:   "cascade <target>",
		Short: "DNS/IP reconnaissance cascade — all 30 ViewDNS tools, no API keys",
		Args:  cobra.ExactArgs(1),
		RunE:  run,
	}
	root.Flags().StringVarP(&jsonOut, "json", "j", "", "write JSON results to file (- for stdout)")

	gui := &cobra.Command{
		Use:   "gui",
		Short: "Launch the web UI in your browser (binds 127.0.0.1 on a free port)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return serveGUI()
		},
	}
	root.AddCommand(gui)

	app := &cobra.Command{
		Use:   "app",
		Short: "Launch the UI as a standalone window (frameless Chromium; -tags webview for native)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return nativeApp()
		},
	}
	root.AddCommand(app)

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func run(cmd *cobra.Command, args []string) error {
	target := strings.TrimSpace(args[0])
	output.Banner(target)

	e := engine.New()
	e.OnResult = output.Result

	// Seed state based on what the target looks like.
	seed(e, target)

	// Register the shared tool set.
	register(e)

	results := e.Run()

	output.Summary(e.State().Snapshot())

	if jsonOut != "" {
		if err := output.JSON(results, jsonOut); err != nil {
			return fmt.Errorf("json output: %w", err)
		}
	}
	return nil
}
