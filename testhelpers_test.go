package certkit

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"
)

// generateTestPKI creates a self-signed CA, intermediate, and leaf cert for testing.
func generateTestPKI(t *testing.T) (caPEM, intermediatePEM, leafPEM string) {
	t.Helper()
	ca, inter, leaf, _ := generateTestPKIWithKey(t)
	return ca, inter, leaf
}

// generateTestPKIWithKey creates a self-signed CA, intermediate, leaf cert, and leaf private key.
func generateTestPKIWithKey(t *testing.T) (caPEM, intermediatePEM, leafPEM, leafKeyPEM string) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caBytes, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caBytes}))

	caCert, _ := x509.ParseCertificate(caBytes)
	intKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	intTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Test Intermediate"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	intBytes, err := x509.CreateCertificate(rand.Reader, intTemplate, caCert, &intKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	intermediatePEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: intBytes}))

	intCert, _ := x509.ParseCertificate(intBytes)
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "test.example.com"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafBytes, err := x509.CreateCertificate(rand.Reader, leafTemplate, intCert, &leafKey.PublicKey, intKey)
	if err != nil {
		t.Fatal(err)
	}
	leafPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafBytes}))

	keyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	leafKeyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))

	return caPEM, intermediatePEM, leafPEM, leafKeyPEM
}

// generateLeafWithSANs creates a self-signed leaf certificate with Subject, DNS SANs,
// IP SANs, and URI SANs for CSR generation tests.
func generateLeafWithSANs(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uri, _ := url.Parse("spiffe://example.com/workload")
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "test.example.com",
			Organization: []string{"Test Org"},
			Country:      []string{"US"},
		},
		DNSNames:    []string{"test.example.com", "www.test.example.com"},
		IPAddresses: []net.IP{net.ParseIP("10.0.0.1"), net.ParseIP("::1")},
		URIs:        []*url.URL{uri},
		NotBefore:   time.Now().Add(-1 * time.Hour),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

// badSSLChain holds the results of a TLS handshake with a badssl.com endpoint.
type badSSLChain struct {
	leaf          *x509.Certificate
	intermediates []*x509.Certificate
	allCerts      []*x509.Certificate
}

// fetchBadSSLChain connects to a badssl.com host via TLS (with InsecureSkipVerify
// since many endpoints have intentionally invalid certificates) and returns
// the peer certificates from the handshake. Skips the test on connection failure.
func fetchBadSSLChain(t *testing.T, host string) badSSLChain {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 10 * time.Second},
		Config: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // required for intentionally broken TLS endpoints
			ServerName:         host,
		},
	}

	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, "443"))
	if err != nil {
		t.Skipf("cannot connect to %s: %v", host, err)
	}
	defer func() { _ = conn.Close() }()

	tlsConn := conn.(*tls.Conn)
	certs := tlsConn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		t.Skipf("no certificates returned by %s", host)
	}

	result := badSSLChain{
		leaf:     certs[0],
		allCerts: certs,
	}
	if len(certs) > 1 {
		result.intermediates = certs[1:]
	}
	return result
}

// skipIfBadSSLUnavailable is a sentinel check for table-driven tests. It
// attempts a quick TLS connection to badssl.com and skips if unreachable.
func skipIfBadSSLUnavailable(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 5 * time.Second},
		Config:    &tls.Config{},
	}
	conn, err := dialer.DialContext(ctx, "tcp", "badssl.com:443")
	if err != nil {
		t.Skipf("badssl.com unavailable: %v", err)
	}
	_ = conn.Close()
}
