package certkit

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/breml/rootcerts/embedded"
)

// BundleResult holds the resolved chain and metadata.
type BundleResult struct {
	Leaf          *x509.Certificate
	Intermediates []*x509.Certificate
	Roots         []*x509.Certificate
	Warnings      []string
}

// BundleOptions configures chain resolution.
type BundleOptions struct {
	ExtraIntermediates []*x509.Certificate
	FetchAIA           bool
	AIATimeoutMs       int
	AIAMaxDepth        int
	TrustStore         string // "system", "mozilla", "custom"
	CustomRoots        []*x509.Certificate
	Verify             bool
	IncludeRoot        bool
}

// DefaultOptions returns sensible defaults.
func DefaultOptions() BundleOptions {
	return BundleOptions{
		FetchAIA:     true,
		AIATimeoutMs: 2000,
		AIAMaxDepth:  5,
		TrustStore:   "system",
		Verify:       true,
		IncludeRoot:  true,
	}
}

// FetchLeafFromURL connects to the given HTTPS URL via TLS and returns the
// leaf (server) certificate from the handshake.
func FetchLeafFromURL(rawURL string, timeoutMs int) (*x509.Certificate, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parsing URL: %w", err)
	}

	host := parsed.Hostname()
	port := parsed.Port()
	if port == "" {
		port = "443"
	}

	dialer := &tls.Dialer{
		Config: &tls.Config{
			ServerName: host,
		},
	}
	dialer.NetDialer = &net.Dialer{
		Timeout: time.Duration(timeoutMs) * time.Millisecond,
	}

	conn, err := dialer.DialContext(context.Background(), "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, fmt.Errorf("TLS dial to %s:%s: %w", host, port, err)
	}
	defer func() { _ = conn.Close() }()

	tlsConn := conn.(*tls.Conn)
	certs := tlsConn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates returned by %s:%s", host, port)
	}
	return certs[0], nil
}

// FetchAIACertificates follows AIA CA Issuers URLs to fetch intermediate certificates.
func FetchAIACertificates(cert *x509.Certificate, timeoutMs int, maxDepth int) ([]*x509.Certificate, []string) {
	var fetched []*x509.Certificate
	var warnings []string

	client := &http.Client{Timeout: time.Duration(timeoutMs) * time.Millisecond}
	seen := make(map[string]bool)
	queue := []*x509.Certificate{cert}

	for depth := 0; depth < maxDepth && len(queue) > 0; depth++ {
		current := queue[0]
		queue = queue[1:]

		for _, aiaURL := range current.IssuingCertificateURL {
			if seen[aiaURL] {
				continue
			}
			seen[aiaURL] = true

			issuer, err := fetchCertFromURL(client, aiaURL)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("AIA fetch failed for %s: %v", aiaURL, err))
				continue
			}
			fetched = append(fetched, issuer)
			queue = append(queue, issuer)
		}
	}
	return fetched, warnings
}

// fetchCertFromURL fetches a single certificate (DER or PEM) from a URL.
func fetchCertFromURL(client *http.Client, certURL string) (*x509.Certificate, error) {
	resp, err := client.Get(certURL)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB limit
	if err != nil {
		return nil, err
	}

	// Try DER first (most AIA URLs serve DER)
	cert, err := x509.ParseCertificate(body)
	if err == nil {
		return cert, nil
	}

	// Fall back to PEM
	cert, pemErr := ParsePEMCertificate(body)
	if pemErr == nil {
		return cert, nil
	}

	return nil, fmt.Errorf("could not parse as DER (%v) or PEM (%v)", err, pemErr)
}

// Bundle resolves the full certificate chain for a leaf certificate.
func Bundle(leaf *x509.Certificate, opts BundleOptions) (*BundleResult, error) {
	result := &BundleResult{Leaf: leaf}

	// Build intermediate pool
	intermediatePool := x509.NewCertPool()
	var allIntermediates []*x509.Certificate

	for _, cert := range opts.ExtraIntermediates {
		intermediatePool.AddCert(cert)
		allIntermediates = append(allIntermediates, cert)
	}

	if opts.FetchAIA {
		aiaCerts, warnings := FetchAIACertificates(leaf, opts.AIATimeoutMs, opts.AIAMaxDepth)
		result.Warnings = append(result.Warnings, warnings...)
		for _, cert := range aiaCerts {
			intermediatePool.AddCert(cert)
			allIntermediates = append(allIntermediates, cert)
		}
	}

	// Build root pool
	var rootPool *x509.CertPool
	switch opts.TrustStore {
	case "system":
		var err error
		rootPool, err = x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("loading system cert pool: %w", err)
		}
	case "mozilla":
		rootPool = x509.NewCertPool()
		if !rootPool.AppendCertsFromPEM([]byte(embedded.MozillaCACertificatesPEM())) {
			return nil, fmt.Errorf("failed to parse embedded Mozilla root certificates")
		}
	case "custom":
		rootPool = x509.NewCertPool()
		for _, cert := range opts.CustomRoots {
			rootPool.AddCert(cert)
		}
	default:
		return nil, fmt.Errorf("unknown trust_store: %q", opts.TrustStore)
	}

	// Verify
	if opts.Verify {
		verifyOpts := x509.VerifyOptions{
			Intermediates: intermediatePool,
			Roots:         rootPool,
		}
		chains, err := leaf.Verify(verifyOpts)
		if err != nil {
			return nil, fmt.Errorf("chain verification failed: %w", err)
		}

		// Pick shortest valid chain
		best := chains[0]
		for _, chain := range chains[1:] {
			if len(chain) < len(best) {
				best = chain
			}
		}

		// Extract intermediates and root from verified chain
		// Chain order: [leaf, intermediate1, ..., root]
		if len(best) > 2 {
			result.Intermediates = best[1 : len(best)-1]
		}
		if len(best) > 1 {
			result.Roots = []*x509.Certificate{best[len(best)-1]}
		}
	} else {
		// No verification — just pass through what we have
		result.Intermediates = allIntermediates
	}

	return result, nil
}
