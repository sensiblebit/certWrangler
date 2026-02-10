package main

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/sensiblebit/certkit/internal"
)

var version = "dev"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--version" {
		fmt.Println("certkit version " + version)
		os.Exit(0)
	}

	cfg := internal.ParseFlags()

	// Handle stdin
	if cfg.InputPath == "-" {
		if err := internal.ProcessFile("-", cfg); err != nil {
			slog.Error(err.Error())
			os.Exit(1)
		}
		return
	}

	// Walk directory
	err := filepath.Walk(cfg.InputPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			if err := internal.ProcessFile(path, cfg); err != nil {
				slog.Warn(fmt.Sprintf("Error processing %s: %v", path, err))
			}
		}
		return nil
	})

	if err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}

	// Resolve non-root certificate AKIs using issuer's computed SHA256 SKI
	if err := cfg.DB.ResolveAKIs(); err != nil {
		slog.Warn(fmt.Sprintf("Failed to resolve AKIs: %v", err))
	}

	// Export bundles if requested
	if cfg.ExportBundles {
		if err := os.MkdirAll(cfg.OutDir, 0755); err != nil {
			slog.Error(fmt.Sprintf("Failed to create output directory %s: %v", cfg.OutDir, err))
			os.Exit(1)
		}
		if err := internal.ExportBundles(cfg.BundleConfigs, cfg.OutDir, cfg.DB, cfg.ForceExport); err != nil {
			slog.Error(fmt.Sprintf("Failed to export bundles: %v", err))
			os.Exit(1)
		}
	}

	if err := cfg.DB.DumpDB(); err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
}
