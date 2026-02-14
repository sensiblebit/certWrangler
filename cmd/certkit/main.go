package main

import (
	"errors"
	"fmt"
	"os"
	"runtime/debug"
)

var version = "dev"

func init() {
	// Safety net: prevent runaway memory from malformed binary files triggering
	// pathological ASN.1 allocations. 1GB is generous for any cert operation.
	debug.SetMemoryLimit(1 << 30)
}

// ValidationError indicates a certificate validation failure (chain invalid,
// key mismatch, expired). Commands return this to signal exit code 2.
type ValidationError struct {
	Message string
}

func (e *ValidationError) Error() string { return e.Message }

func main() {
	rootCmd.Version = version
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		var ve *ValidationError
		if errors.As(err, &ve) {
			os.Exit(2)
		}
		os.Exit(1)
	}
}
