package internal

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
)

func parseLogLevel(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warning", "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelDebug
	}
}

func ParseFlags() *Config {
	cfg := &Config{}
	var logLevel, passwordFile, passwordList, dbPath, bundlesConfigPath string

	flag.StringVar(&cfg.InputPath, "input", "", "Path to certificate file or directory (use - for stdin)")
	flag.StringVar(&logLevel, "log-level", "debug", "Log level: debug, info, warning, error")
	flag.StringVar(&dbPath, "db", "", "SQLite database path (default: in-memory)")
	flag.StringVar(&bundlesConfigPath, "bundles-config", "./bundles.yaml", "Path to bundle config YAML")
	flag.StringVar(&passwordFile, "password-file", "", "File containing passwords, one per line")
	flag.StringVar(&passwordList, "passwords", "", "Comma-separated passwords for encrypted keys")
	flag.BoolVar(&cfg.ExportBundles, "export", false, "Export certificate bundles")
	flag.BoolVar(&cfg.ForceExport, "force", false, "Allow export of untrusted certificate bundles")
	flag.StringVar(&cfg.OutDir, "out", "./bundles", "Output directory for exported bundles")
	flag.Parse()

	// Set up global logger
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: parseLogLevel(logLevel)})))

	cfg.Passwords = ProcessPasswords(passwordList, passwordFile)

	// Initialize the database
	db, err := NewDB(dbPath)
	if err != nil {
		slog.Error(fmt.Sprintf("Failed to initialize database: %v", err))
		os.Exit(1)
	}
	cfg.DB = db

	// Load bundle configurations
	bundleConfigs, err := LoadBundleConfigs(bundlesConfigPath)
	if err != nil {
		slog.Warn(fmt.Sprintf("Failed to load bundle configurations: %v", err))
		bundleConfigs = []BundleConfig{}
	}
	cfg.BundleConfigs = bundleConfigs

	// Validate input path
	if cfg.InputPath == "-" {
		// stdin mode, no validation needed
	} else if cfg.InputPath == "" {
		flag.Usage()
		slog.Error("No input path specified")
		os.Exit(1)
	} else if _, err := os.Stat(cfg.InputPath); err != nil {
		if os.IsNotExist(err) {
			slog.Error(fmt.Sprintf("Input path %s does not exist", cfg.InputPath))
			os.Exit(1)
		}
		slog.Error(fmt.Sprintf("Error accessing input path %s: %v", cfg.InputPath, err))
		os.Exit(1)
	}
	return cfg
}
