package internal

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	"github.com/sensiblebit/certkit"
)

// VerifyInput holds the parsed certificate data and verification options.
type VerifyInput struct {
	Cert           *x509.Certificate
	Key            crypto.PrivateKey
	ExtraCerts     []*x509.Certificate
	CustomRoots    []*x509.Certificate
	CheckKeyMatch  bool
	CheckChain     bool
	ExpiryDuration time.Duration
	TrustStore     string
}

// VerifyResult holds the results of certificate verification checks.
type VerifyResult struct {
	KeyMatch    *bool    `json:"key_match,omitempty"`
	KeyMatchErr string   `json:"key_match_error,omitempty"`
	ChainValid  *bool    `json:"chain_valid,omitempty"`
	ChainErr    string   `json:"chain_error,omitempty"`
	Expiry      *bool    `json:"expires_within,omitempty"`
	ExpiryInfo  string   `json:"expiry_info,omitempty"`
	Subject     string   `json:"subject"`
	NotAfter    string   `json:"not_after"`
	Errors      []string `json:"errors,omitempty"`
}

// VerifyCert verifies a certificate with optional key matching, chain validation, and expiry checking.
func VerifyCert(ctx context.Context, input *VerifyInput) (*VerifyResult, error) {
	result := &VerifyResult{
		Subject:  input.Cert.Subject.String(),
		NotAfter: input.Cert.NotAfter.UTC().Format(time.RFC3339),
	}

	// Key-cert match check
	if input.CheckKeyMatch && input.Key != nil {
		match, err := certkit.KeyMatchesCert(input.Key, input.Cert)
		if err != nil {
			result.KeyMatchErr = fmt.Sprintf("comparing key: %v", err)
			result.Errors = append(result.Errors, result.KeyMatchErr)
		} else {
			result.KeyMatch = &match
			if !match {
				result.Errors = append(result.Errors, "key does not match certificate")
			}
		}
	}

	// Chain validation
	if input.CheckChain {
		opts := certkit.DefaultOptions()
		opts.TrustStore = input.TrustStore
		opts.ExtraIntermediates = input.ExtraCerts
		opts.CustomRoots = input.CustomRoots
		_, err := certkit.Bundle(ctx, input.Cert, opts)
		valid := err == nil
		result.ChainValid = &valid
		if err != nil {
			result.ChainErr = err.Error()
			result.Errors = append(result.Errors, fmt.Sprintf("chain validation: %s", err.Error()))
		}
	}

	// Expiry check
	if input.ExpiryDuration > 0 {
		expires := certkit.CertExpiresWithin(input.Cert, input.ExpiryDuration)
		result.Expiry = &expires
		if expires {
			result.ExpiryInfo = fmt.Sprintf("certificate expires within %s (not after: %s)", input.ExpiryDuration, result.NotAfter)
			result.Errors = append(result.Errors, result.ExpiryInfo)
		} else {
			result.ExpiryInfo = fmt.Sprintf("certificate does not expire within %s", input.ExpiryDuration)
		}
	}

	return result, nil
}

// FormatVerifyResult formats a verify result as human-readable text.
func FormatVerifyResult(r *VerifyResult) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "Certificate: %s\n", r.Subject)
	fmt.Fprintf(&sb, "  Not After: %s\n", r.NotAfter)

	if r.KeyMatch != nil {
		if *r.KeyMatch {
			sb.WriteString("  Key Match: OK\n")
		} else {
			sb.WriteString("  Key Match: MISMATCH\n")
		}
	} else if r.KeyMatchErr != "" {
		fmt.Fprintf(&sb, "  Key Match: ERROR (%s)\n", r.KeyMatchErr)
	}

	if r.ChainValid != nil {
		if *r.ChainValid {
			sb.WriteString("  Chain:     VALID\n")
		} else {
			fmt.Fprintf(&sb, "  Chain:     INVALID (%s)\n", r.ChainErr)
		}
	}

	if r.Expiry != nil {
		fmt.Fprintf(&sb, "  Expiry:    %s\n", r.ExpiryInfo)
	}

	if len(r.Errors) > 0 {
		fmt.Fprintf(&sb, "\nVerification FAILED (%d error(s))\n", len(r.Errors))
	} else {
		sb.WriteString("\nVerification OK\n")
	}

	return sb.String()
}
