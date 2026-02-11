package internal

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"
	"time"

	"github.com/sensiblebit/certkit"
)

func TestVerifyCert_KeyMatch(t *testing.T) {
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "verify.example.com", []string{"verify.example.com"}, nil)

	result, err := VerifyCert(context.Background(), &VerifyInput{
		Cert:          leaf.cert,
		Key:           leaf.key,
		CheckKeyMatch: true,
		TrustStore:    "mozilla",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.KeyMatch == nil || !*result.KeyMatch {
		t.Error("expected key to match certificate")
	}
	if len(result.Errors) != 0 {
		t.Errorf("expected no errors, got %v", result.Errors)
	}
}

func TestVerifyCert_KeyMismatch(t *testing.T) {
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "mismatch.example.com", []string{"mismatch.example.com"}, nil)

	// Generate a different key
	wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	result, err := VerifyCert(context.Background(), &VerifyInput{
		Cert:          leaf.cert,
		Key:           wrongKey,
		CheckKeyMatch: true,
		TrustStore:    "mozilla",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.KeyMatch == nil || *result.KeyMatch {
		t.Error("expected key mismatch")
	}
	if len(result.Errors) == 0 {
		t.Error("expected errors for key mismatch")
	}
}

func TestVerifyCert_ExpiryCheck(t *testing.T) {
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "expiry.example.com", []string{"expiry.example.com"}, nil)

	// Cert expires in ~365 days, so 400d should trigger
	result, err := VerifyCert(context.Background(), &VerifyInput{
		Cert:           leaf.cert,
		ExpiryDuration: 400 * 24 * time.Hour,
		TrustStore:     "mozilla",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Expiry == nil || !*result.Expiry {
		t.Error("expected expiry warning for 400d window")
	}

	// 30d window should not trigger
	result, err = VerifyCert(context.Background(), &VerifyInput{
		Cert:           leaf.cert,
		ExpiryDuration: 30 * 24 * time.Hour,
		TrustStore:     "mozilla",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Expiry == nil || *result.Expiry {
		t.Error("expected no expiry warning for 30d window")
	}
}

func TestVerifyCert_ExpiredCert(t *testing.T) {
	ca := newRSACA(t)
	leaf := newExpiredLeaf(t, ca)

	result, err := VerifyCert(context.Background(), &VerifyInput{
		Cert:           leaf.cert,
		ExpiryDuration: 1 * time.Hour,
		TrustStore:     "mozilla",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Expiry == nil || !*result.Expiry {
		t.Error("expected expired cert to trigger expiry warning")
	}
}

func TestVerifyCert_PKCS12(t *testing.T) {
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "p12.example.com", []string{"p12.example.com"}, nil)
	p12Data := newPKCS12Bundle(t, leaf, ca, "changeit")

	contents, err := ParseContainerData(p12Data, []string{"changeit"})
	if err != nil {
		t.Fatal(err)
	}

	result, err := VerifyCert(context.Background(), &VerifyInput{
		Cert:          contents.Leaf,
		Key:           contents.Key,
		ExtraCerts:    contents.ExtraCerts,
		CheckKeyMatch: true,
		CheckChain:    true,
		TrustStore:    "custom",
		CustomRoots:   contents.ExtraCerts,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.KeyMatch == nil || !*result.KeyMatch {
		t.Error("expected key match for p12 embedded key")
	}
	if result.ChainValid == nil || !*result.ChainValid {
		t.Error("expected chain to be valid with p12 embedded intermediates")
	}
}

func TestVerifyCert_JKS(t *testing.T) {
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "jks.example.com", []string{"jks.example.com"}, nil)
	jksData := newJKSBundle(t, leaf, ca, "changeit")

	contents, err := ParseContainerData(jksData, []string{"changeit"})
	if err != nil {
		t.Fatal(err)
	}

	result, err := VerifyCert(context.Background(), &VerifyInput{
		Cert:          contents.Leaf,
		Key:           contents.Key,
		ExtraCerts:    contents.ExtraCerts,
		CheckKeyMatch: true,
		CheckChain:    true,
		TrustStore:    "custom",
		CustomRoots:   []*x509.Certificate{ca.cert},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.KeyMatch == nil || !*result.KeyMatch {
		t.Error("expected key match for JKS embedded key")
	}
	if result.ChainValid == nil || !*result.ChainValid {
		t.Error("expected chain to be valid with JKS embedded intermediates")
	}
}

func TestVerifyCert_PKCS7(t *testing.T) {
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "p7b.example.com", []string{"p7b.example.com"}, nil)

	p7bData, err := certkit.EncodePKCS7([]*x509.Certificate{leaf.cert, ca.cert})
	if err != nil {
		t.Fatal(err)
	}

	contents, err := ParseContainerData(p7bData, nil)
	if err != nil {
		t.Fatal(err)
	}

	result, err := VerifyCert(context.Background(), &VerifyInput{
		Cert:        contents.Leaf,
		ExtraCerts:  contents.ExtraCerts,
		CheckChain:  true,
		TrustStore:  "custom",
		CustomRoots: []*x509.Certificate{ca.cert},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.KeyMatch != nil {
		t.Error("expected no key match check for p7b (no key)")
	}
	if result.ChainValid == nil || !*result.ChainValid {
		t.Error("expected chain to be valid with p7b intermediates")
	}
}

func TestFormatVerifyResult_OK(t *testing.T) {
	match := true
	result := &VerifyResult{
		Subject:  "CN=test",
		NotAfter: "2030-01-01T00:00:00Z",
		KeyMatch: &match,
	}
	output := FormatVerifyResult(result)
	if output == "" {
		t.Error("expected non-empty output")
	}
}
