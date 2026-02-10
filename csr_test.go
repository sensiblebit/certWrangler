package certkit

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
)

func TestGenerateCSR_withKey(t *testing.T) {
	leaf, key := generateLeafWithSANs(t)

	csrPEM, keyPEM, err := GenerateCSR(leaf, key)
	if err != nil {
		t.Fatal(err)
	}

	if keyPEM != "" {
		t.Error("expected empty keyPEM when private key is provided")
	}

	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		t.Fatal("failed to decode CSR PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("CSR signature invalid: %v", err)
	}

	if csr.Subject.CommonName != leaf.Subject.CommonName {
		t.Errorf("CN=%q, want %q", csr.Subject.CommonName, leaf.Subject.CommonName)
	}
	if len(csr.Subject.Organization) != 1 || csr.Subject.Organization[0] != "Test Org" {
		t.Errorf("Organization=%v, want [Test Org]", csr.Subject.Organization)
	}
	if len(csr.DNSNames) != 2 {
		t.Errorf("DNSNames count=%d, want 2", len(csr.DNSNames))
	}
	if len(csr.IPAddresses) != 2 {
		t.Errorf("IPAddresses count=%d, want 2", len(csr.IPAddresses))
	}
	if len(csr.URIs) != 1 || csr.URIs[0].String() != "spiffe://example.com/workload" {
		t.Errorf("URIs=%v, want [spiffe://example.com/workload]", csr.URIs)
	}
}

func TestGenerateCSR_autoGenerate(t *testing.T) {
	leaf, _ := generateLeafWithSANs(t)

	csrPEM, keyPEM, err := GenerateCSR(leaf, nil)
	if err != nil {
		t.Fatal(err)
	}

	if keyPEM == "" {
		t.Fatal("expected non-empty keyPEM for auto-generated key")
	}

	keyBlock, _ := pem.Decode([]byte(keyPEM))
	if keyBlock == nil || keyBlock.Type != "PRIVATE KEY" {
		t.Fatal("failed to decode key PEM or wrong block type")
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, ok := parsedKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PrivateKey, got %T", parsedKey)
	}
	if ecKey.Curve != elliptic.P256() {
		t.Errorf("expected P-256 curve, got %v", ecKey.Curve.Params().Name)
	}

	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		t.Fatal("failed to decode CSR PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("CSR signature invalid: %v", err)
	}

	if csr.Subject.CommonName != leaf.Subject.CommonName {
		t.Errorf("CN=%q, want %q", csr.Subject.CommonName, leaf.Subject.CommonName)
	}
	if len(csr.DNSNames) != 2 {
		t.Errorf("DNSNames count=%d, want 2", len(csr.DNSNames))
	}
}

func TestGenerateCSR_nonSignerKey(t *testing.T) {
	leaf, _ := generateLeafWithSANs(t)
	_, _, err := GenerateCSR(leaf, struct{}{})
	if err == nil {
		t.Error("expected error for non-Signer key")
	}
	if !strings.Contains(err.Error(), "does not implement crypto.Signer") {
		t.Errorf("error should mention crypto.Signer, got: %v", err)
	}
}

// Suppress unused import warnings
var _ = rand.Reader
