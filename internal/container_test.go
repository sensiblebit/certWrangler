package internal

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/sensiblebit/certkit"
)

func TestLoadContainerFile_PKCS12(t *testing.T) {
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "p12.example.com", []string{"p12.example.com"}, nil)
	p12Data := newPKCS12Bundle(t, leaf, ca, "changeit")

	dir := t.TempDir()
	p12File := filepath.Join(dir, "test.p12")
	if err := os.WriteFile(p12File, p12Data, 0600); err != nil {
		t.Fatal(err)
	}

	contents, err := LoadContainerFile(p12File, []string{"changeit"})
	if err != nil {
		t.Fatal(err)
	}
	if contents.Leaf == nil {
		t.Fatal("expected leaf certificate")
	}
	if contents.Key == nil {
		t.Error("expected embedded key")
	}
	if len(contents.ExtraCerts) == 0 {
		t.Error("expected CA cert in extras")
	}
}

func TestLoadContainerFile_JKS(t *testing.T) {
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "jks.example.com", []string{"jks.example.com"}, nil)
	jksData := newJKSBundle(t, leaf, ca, "changeit")

	dir := t.TempDir()
	jksFile := filepath.Join(dir, "test.jks")
	if err := os.WriteFile(jksFile, jksData, 0600); err != nil {
		t.Fatal(err)
	}

	contents, err := LoadContainerFile(jksFile, []string{"changeit"})
	if err != nil {
		t.Fatal(err)
	}
	if contents.Leaf == nil {
		t.Fatal("expected leaf certificate")
	}
	if contents.Key == nil {
		t.Error("expected embedded key")
	}
	if len(contents.ExtraCerts) == 0 {
		t.Error("expected CA cert in extras")
	}
}

func TestLoadContainerFile_PKCS7(t *testing.T) {
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "p7b.example.com", []string{"p7b.example.com"}, nil)

	p7bData, err := certkit.EncodePKCS7([]*x509.Certificate{leaf.cert, ca.cert})
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	p7bFile := filepath.Join(dir, "test.p7b")
	if err := os.WriteFile(p7bFile, p7bData, 0644); err != nil {
		t.Fatal(err)
	}

	contents, err := LoadContainerFile(p7bFile, nil)
	if err != nil {
		t.Fatal(err)
	}
	if contents.Leaf == nil {
		t.Fatal("expected leaf certificate")
	}
	if contents.Key != nil {
		t.Error("expected no key from p7b")
	}
	if len(contents.ExtraCerts) == 0 {
		t.Error("expected CA cert in extras")
	}
}

func TestLoadContainerFile_PEM(t *testing.T) {
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "pem.example.com", []string{"pem.example.com"}, nil)

	// PEM with leaf + CA
	pemData := slices.Concat(leaf.certPEM, ca.certPEM)

	dir := t.TempDir()
	pemFile := filepath.Join(dir, "chain.pem")
	if err := os.WriteFile(pemFile, pemData, 0644); err != nil {
		t.Fatal(err)
	}

	contents, err := LoadContainerFile(pemFile, nil)
	if err != nil {
		t.Fatal(err)
	}
	if contents.Leaf == nil {
		t.Fatal("expected leaf certificate")
	}
	if contents.Key != nil {
		t.Error("expected no key from PEM certs")
	}
	if len(contents.ExtraCerts) == 0 {
		t.Error("expected CA cert in extras")
	}
}

func TestLoadContainerFile_DER(t *testing.T) {
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "der.example.com", []string{"der.example.com"}, nil)

	dir := t.TempDir()
	derFile := filepath.Join(dir, "cert.der")
	if err := os.WriteFile(derFile, leaf.certDER, 0644); err != nil {
		t.Fatal(err)
	}

	contents, err := LoadContainerFile(derFile, nil)
	if err != nil {
		t.Fatal(err)
	}
	if contents.Leaf == nil {
		t.Fatal("expected leaf certificate")
	}
	if contents.Key != nil {
		t.Error("expected no key from DER")
	}
	if len(contents.ExtraCerts) != 0 {
		t.Error("expected no extras from single DER cert")
	}
}

func TestLoadContainerFile_NotFound(t *testing.T) {
	_, err := LoadContainerFile("/nonexistent/file.pem", nil)
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestLoadContainerFile_InvalidData(t *testing.T) {
	dir := t.TempDir()
	badFile := filepath.Join(dir, "garbage.bin")
	if err := os.WriteFile(badFile, []byte("not a certificate"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadContainerFile(badFile, []string{"changeit"})
	if err == nil {
		t.Error("expected error for invalid data")
	}
}
