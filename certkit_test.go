package certkit

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestParsePEMCertificate(t *testing.T) {
	_, _, leafPEM := generateTestPKI(t)

	cert, err := ParsePEMCertificate([]byte(leafPEM))
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "test.example.com" {
		t.Errorf("got CN=%q, want test.example.com", cert.Subject.CommonName)
	}
}

func TestParsePEMCertificates_empty(t *testing.T) {
	_, err := ParsePEMCertificates([]byte("not a cert"))
	if err == nil {
		t.Error("expected error for invalid PEM")
	}
}

func TestParsePEMCertificates_mixedBlockTypes(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "mixed-test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)

	var pemData []byte
	pemData = append(pemData, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})...)
	pemData = append(pemData, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})...)

	certs, err := ParsePEMCertificates(pemData)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 1 {
		t.Errorf("expected 1 cert (skipping non-CERTIFICATE block), got %d", len(certs))
	}
	if certs[0].Subject.CommonName != "mixed-test" {
		t.Errorf("CN=%q, want mixed-test", certs[0].Subject.CommonName)
	}
}

func TestParsePEMCertificates_invalidDER(t *testing.T) {
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("garbage DER")})

	_, err := ParsePEMCertificates(pemData)
	if err == nil {
		t.Error("expected error for invalid certificate DER")
	}
	if !strings.Contains(err.Error(), "parsing certificate") {
		t.Errorf("error should mention parsing certificate, got: %v", err)
	}
}

func TestParsePEMCertificate_errorPassthrough(t *testing.T) {
	_, err := ParsePEMCertificate([]byte("not valid PEM"))
	if err == nil {
		t.Error("expected error from ParsePEMCertificate")
	}
	if !strings.Contains(err.Error(), "no certificates found") {
		t.Errorf("expected 'no certificates found' error, got: %v", err)
	}
}

func TestCertFingerprint(t *testing.T) {
	_, _, leafPEM := generateTestPKI(t)
	cert, _ := ParsePEMCertificate([]byte(leafPEM))

	fp := CertFingerprint(cert)
	if len(fp) != 64 { // SHA-256 hex = 64 chars
		t.Errorf("fingerprint length %d, want 64", len(fp))
	}
}

func TestCertToPEM(t *testing.T) {
	_, _, leafPEM := generateTestPKI(t)
	cert, _ := ParsePEMCertificate([]byte(leafPEM))

	pemStr := CertToPEM(cert)
	if len(pemStr) == 0 {
		t.Error("empty PEM output")
	}

	// Round-trip
	cert2, err := ParsePEMCertificate([]byte(pemStr))
	if err != nil {
		t.Fatal(err)
	}
	if cert2.Subject.CommonName != cert.Subject.CommonName {
		t.Error("round-trip CN mismatch")
	}
}

func TestCertSKID_RFC7093(t *testing.T) {
	_, _, leafPEM := generateTestPKI(t)
	leaf, _ := ParsePEMCertificate([]byte(leafPEM))

	skid := CertSKID(leaf)
	if skid == "" {
		t.Fatal("CertSKID returned empty string")
	}

	// RFC 7093 Method 1: leftmost 160 bits of SHA-256 = 20 bytes
	// 20 bytes = 40 hex chars + 19 colons = 59 chars
	if len(skid) != 59 {
		t.Errorf("SKID length %d, want 59 (20 bytes colon-separated)", len(skid))
	}

	// Verify it matches manual computation
	var spki struct {
		Algorithm asn1.RawValue
		PublicKey asn1.BitString
	}
	_, err := asn1.Unmarshal(leaf.RawSubjectPublicKeyInfo, &spki)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(spki.PublicKey.Bytes)
	expected := ColonHex(hash[:20])
	if skid != expected {
		t.Errorf("SKID mismatch:\n  got:  %s\n  want: %s", skid, expected)
	}
}

func TestCertSKIDEmbedded(t *testing.T) {
	caPEM, _, leafPEM := generateTestPKI(t)

	ca, _ := ParsePEMCertificate([]byte(caPEM))
	leaf, _ := ParsePEMCertificate([]byte(leafPEM))

	caSKID := CertSKIDEmbedded(ca)
	if caSKID != "" && (!strings.Contains(caSKID, ":") || len(caSKID) < 5) {
		t.Errorf("CA embedded SKID format unexpected: %q", caSKID)
	}

	leafAKID := CertAKIDEmbedded(leaf)
	if leafAKID != "" && (!strings.Contains(leafAKID, ":") || len(leafAKID) < 5) {
		t.Errorf("Leaf embedded AKID format unexpected: %q", leafAKID)
	}
}

func TestCertSKID_vs_Embedded(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	var spki struct {
		Algorithm asn1.RawValue
		PublicKey asn1.BitString
	}
	pubKeyDER, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if _, err := asn1.Unmarshal(pubKeyDER, &spki); err != nil {
		t.Fatal(err)
	}
	sha1Hash := sha1.Sum(spki.PublicKey.Bytes)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		SubjectKeyId: sha1Hash[:], // SHA-1 embedded SKID
	}
	certBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certBytes)

	computed := CertSKID(cert)
	embedded := CertSKIDEmbedded(cert)

	if len(computed) != 59 {
		t.Errorf("computed SKID length %d, want 59", len(computed))
	}
	if len(embedded) != 59 {
		t.Errorf("embedded SKID length %d, want 59", len(embedded))
	}
	if computed == embedded {
		t.Error("computed (truncated SHA-256) should differ from embedded (SHA-1)")
	}
}

func TestCertSKID_RFC7093Embedded(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	var spki struct {
		Algorithm asn1.RawValue
		PublicKey asn1.BitString
	}
	pubKeyDER, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if _, err := asn1.Unmarshal(pubKeyDER, &spki); err != nil {
		t.Fatal(err)
	}
	sha256Hash := sha256.Sum256(spki.PublicKey.Bytes)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "modern-ca"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		SubjectKeyId: sha256Hash[:20], // RFC 7093: truncated SHA-256, 20 bytes
	}
	certBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certBytes)

	computed := CertSKID(cert)
	embedded := CertSKIDEmbedded(cert)

	if computed != embedded {
		t.Errorf("when CA embeds RFC 7093 SKID, computed and embedded should match:\n  computed: %s\n  embedded: %s", computed, embedded)
	}
	if len(computed) != 59 {
		t.Errorf("computed length %d, want 59", len(computed))
	}
}

func TestCertSKID_FullSHA256Embedded(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	var spki struct {
		Algorithm asn1.RawValue
		PublicKey asn1.BitString
	}
	pubKeyDER, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if _, err := asn1.Unmarshal(pubKeyDER, &spki); err != nil {
		t.Fatal(err)
	}
	sha256Hash := sha256.Sum256(spki.PublicKey.Bytes)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "full-sha256-ca"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		SubjectKeyId: sha256Hash[:], // Full 32-byte SHA-256 (non-standard)
	}
	certBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certBytes)

	computed := CertSKID(cert)
	embedded := CertSKIDEmbedded(cert)

	if len(computed) != 59 {
		t.Errorf("computed length %d, want 59", len(computed))
	}
	if len(embedded) != 95 {
		t.Errorf("embedded length %d, want 95", len(embedded))
	}
	if computed == embedded {
		t.Error("truncated computed should differ from full embedded")
	}
}

func TestCertSKIDEmbedded_empty(t *testing.T) {
	cert := &x509.Certificate{SubjectKeyId: nil}
	if got := CertSKIDEmbedded(cert); got != "" {
		t.Errorf("expected empty string for nil SubjectKeyId, got %q", got)
	}
}

func TestCertAKIDEmbedded_empty(t *testing.T) {
	cert := &x509.Certificate{AuthorityKeyId: nil}
	if got := CertAKIDEmbedded(cert); got != "" {
		t.Errorf("expected empty string for nil AuthorityKeyId, got %q", got)
	}
}

func TestCertSKID_errorReturnsEmpty(t *testing.T) {
	cert := &x509.Certificate{RawSubjectPublicKeyInfo: []byte{}}
	skid := CertSKID(cert)
	if skid != "" {
		t.Errorf("expected empty string for invalid SPKI, got %q", skid)
	}
}

func TestExtractPublicKeyBitString_invalidDER(t *testing.T) {
	_, err := extractPublicKeyBitString([]byte("garbage"))
	if err == nil {
		t.Error("expected error for invalid DER")
	}
	if !strings.Contains(err.Error(), "parsing SubjectPublicKeyInfo") {
		t.Errorf("error should mention parsing SubjectPublicKeyInfo, got: %v", err)
	}
}

func TestColonHex(t *testing.T) {
	tests := []struct {
		input    []byte
		expected string
	}{
		{[]byte{0x5c, 0x15, 0x76}, "5c:15:76"},
		{[]byte{0x00}, "00"},
		{[]byte{0xff, 0x00, 0xab}, "ff:00:ab"},
		{nil, ""},
	}
	for _, tt := range tests {
		got := ColonHex(tt.input)
		if got != tt.expected {
			t.Errorf("ColonHex(%x) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestParsePEMPrivateKey(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalECPrivateKey(key)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})

	parsed, err := ParsePEMPrivateKey(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := parsed.(*ecdsa.PrivateKey); !ok {
		t.Errorf("expected *ecdsa.PrivateKey, got %T", parsed)
	}
}

func TestParsePEMPrivateKey_PKCS8(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	parsed, err := ParsePEMPrivateKey(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := parsed.(*ecdsa.PrivateKey); !ok {
		t.Errorf("expected *ecdsa.PrivateKey, got %T", parsed)
	}
}

func TestParsePEMPrivateKey_RSAPKCS1(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der := x509.MarshalPKCS1PrivateKey(key)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})

	parsed, err := ParsePEMPrivateKey(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := parsed.(*rsa.PrivateKey); !ok {
		t.Errorf("expected *rsa.PrivateKey, got %T", parsed)
	}
}

func TestParsePEMPrivateKey_PKCS8Error(t *testing.T) {
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("garbage")})

	_, err := ParsePEMPrivateKey(pemBytes)
	if err == nil {
		t.Error("expected error for invalid PKCS#8 data")
	}
	if !strings.Contains(err.Error(), "PRIVATE KEY") {
		t.Errorf("error should mention PRIVATE KEY, got: %v", err)
	}
}

func TestParsePEMPrivateKey_unsupportedBlockType(t *testing.T) {
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "DSA PRIVATE KEY", Bytes: []byte("whatever")})

	_, err := ParsePEMPrivateKey(pemBytes)
	if err == nil {
		t.Error("expected error for unsupported block type")
	}
	if !strings.Contains(err.Error(), "unsupported PEM block type") {
		t.Errorf("error should mention unsupported PEM block type, got: %v", err)
	}
}

func TestParsePEMPrivateKey_invalid(t *testing.T) {
	_, err := ParsePEMPrivateKey([]byte("not a key"))
	if err == nil {
		t.Error("expected error for invalid PEM")
	}
}

func TestKeyAlgorithmName(t *testing.T) {
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)

	tests := []struct {
		name     string
		key      interface{}
		expected string
	}{
		{"ECDSA", ecKey, "ECDSA"},
		{"RSA", rsaKey, "RSA"},
		{"Ed25519", edKey, "Ed25519"},
		{"nil", nil, "unknown"},
		{"unsupported", struct{}{}, "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := KeyAlgorithmName(tt.key)
			if got != tt.expected {
				t.Errorf("KeyAlgorithmName(%T) = %q, want %q", tt.key, got, tt.expected)
			}
		})
	}
}

func TestPublicKeyAlgorithmName(t *testing.T) {
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)

	tests := []struct {
		name     string
		key      interface{}
		expected string
	}{
		{"ECDSA", &ecKey.PublicKey, "ECDSA"},
		{"RSA", &rsaKey.PublicKey, "RSA"},
		{"Ed25519", edPub, "Ed25519"},
		{"nil", nil, "unknown"},
		{"unsupported", struct{}{}, "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := PublicKeyAlgorithmName(tt.key)
			if got != tt.expected {
				t.Errorf("PublicKeyAlgorithmName(%T) = %q, want %q", tt.key, got, tt.expected)
			}
		})
	}
}

func TestParsePEMCertificateRequest(t *testing.T) {
	leaf, key := generateLeafWithSANs(t)
	csrPEM, _, err := GenerateCSR(leaf, key)
	if err != nil {
		t.Fatal(err)
	}

	csr, err := ParsePEMCertificateRequest([]byte(csrPEM))
	if err != nil {
		t.Fatal(err)
	}
	if csr.Subject.CommonName != "test.example.com" {
		t.Errorf("CN=%q, want test.example.com", csr.Subject.CommonName)
	}
	if len(csr.DNSNames) != 2 {
		t.Errorf("DNSNames count=%d, want 2", len(csr.DNSNames))
	}
}

func TestParsePEMCertificateRequest_invalidPEM(t *testing.T) {
	_, err := ParsePEMCertificateRequest([]byte("not valid PEM"))
	if err == nil {
		t.Error("expected error for invalid PEM")
	}
	if !strings.Contains(err.Error(), "no PEM block found") {
		t.Errorf("error should mention no PEM block, got: %v", err)
	}
}

func TestParsePEMCertificateRequest_wrongBlockType(t *testing.T) {
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("whatever")})
	_, err := ParsePEMCertificateRequest(pemData)
	if err == nil {
		t.Error("expected error for wrong block type")
	}
	if !strings.Contains(err.Error(), "expected CERTIFICATE REQUEST") {
		t.Errorf("error should mention expected block type, got: %v", err)
	}
}

func TestParsePEMCertificateRequest_invalidDER(t *testing.T) {
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: []byte("garbage")})
	_, err := ParsePEMCertificateRequest(pemData)
	if err == nil {
		t.Error("expected error for invalid DER")
	}
	if !strings.Contains(err.Error(), "parsing certificate request") {
		t.Errorf("error should mention parsing, got: %v", err)
	}
}

func TestMarshalPrivateKeyToPEM_ECDSA(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pemStr, err := MarshalPrivateKeyToPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(pemStr, "PRIVATE KEY") {
		t.Error("expected PEM output to contain PRIVATE KEY")
	}

	parsed, err := ParsePEMPrivateKey([]byte(pemStr))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := parsed.(*ecdsa.PrivateKey); !ok {
		t.Errorf("expected *ecdsa.PrivateKey, got %T", parsed)
	}
}

func TestMarshalPrivateKeyToPEM_RSA(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	pemStr, err := MarshalPrivateKeyToPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(pemStr, "PRIVATE KEY") {
		t.Error("expected PEM output to contain PRIVATE KEY")
	}
}

func TestMarshalPrivateKeyToPEM_Ed25519(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	pemStr, err := MarshalPrivateKeyToPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(pemStr, "PRIVATE KEY") {
		t.Error("expected PEM output to contain PRIVATE KEY")
	}
}

func TestMarshalPrivateKeyToPEM_unsupported(t *testing.T) {
	_, err := MarshalPrivateKeyToPEM(struct{}{})
	if err == nil {
		t.Error("expected error for unsupported key type")
	}
	if !strings.Contains(err.Error(), "marshaling private key") {
		t.Errorf("error should mention marshaling, got: %v", err)
	}
}

func TestComputeSKID_RFC7093Method1(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	skid, err := ComputeSKID(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(skid) != 20 {
		t.Errorf("expected 20 bytes, got %d", len(skid))
	}
}

func TestComputeSKIDLegacy_SHA1(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	skid, err := ComputeSKIDLegacy(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(skid) != 20 {
		t.Errorf("expected 20 bytes, got %d", len(skid))
	}
}

func TestComputeSKID_VsLegacy_Different(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	modern, _ := ComputeSKID(&key.PublicKey)
	legacy, _ := ComputeSKIDLegacy(&key.PublicKey)
	if string(modern) == string(legacy) {
		t.Error("RFC 7093 M1 and legacy SHA-1 should produce different results")
	}
}

func TestComputeSKID_Deterministic(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	s1, _ := ComputeSKID(&key.PublicKey)
	s2, _ := ComputeSKID(&key.PublicKey)
	if string(s1) != string(s2) {
		t.Error("ComputeSKID should be deterministic")
	}
}

func TestGetCertificateType_Root(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Root CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)
	if got := GetCertificateType(cert); got != "root" {
		t.Errorf("expected root, got %s", got)
	}
}

func TestGetCertificateType_Leaf(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "leaf"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)
	if got := GetCertificateType(cert); got != "leaf" {
		t.Errorf("expected leaf, got %s", got)
	}
}

func TestGetPublicKey_RSA(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	pub, err := GetPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := pub.(*rsa.PublicKey); !ok {
		t.Errorf("expected *rsa.PublicKey, got %T", pub)
	}
}

func TestGetPublicKey_ECDSA(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pub, err := GetPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := pub.(*ecdsa.PublicKey); !ok {
		t.Errorf("expected *ecdsa.PublicKey, got %T", pub)
	}
}

func TestGetPublicKey_Ed25519(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	pub, err := GetPublicKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := pub.(ed25519.PublicKey); !ok {
		t.Errorf("expected ed25519.PublicKey, got %T", pub)
	}
}

func TestGetPublicKey_UnsupportedType(t *testing.T) {
	_, err := GetPublicKey(struct{}{})
	if err == nil {
		t.Error("expected error for unsupported type")
	}
}

func TestIsPEM_True(t *testing.T) {
	if !IsPEM([]byte("-----BEGIN CERTIFICATE-----\nfoo\n-----END CERTIFICATE-----")) {
		t.Error("expected true for PEM data")
	}
}

func TestIsPEM_False(t *testing.T) {
	if IsPEM([]byte{0x30, 0x82, 0x01}) {
		t.Error("expected false for DER data")
	}
}
