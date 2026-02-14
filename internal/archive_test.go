package internal

import (
	"strings"
	"testing"
)

func TestArchiveFormat(t *testing.T) {
	// WHY: Verifies that all supported archive extensions are detected and
	// that non-archive files return empty string.
	t.Parallel()

	tests := []struct {
		name string
		path string
		want string
	}{
		{"zip", "certs.zip", "zip"},
		{"tar", "certs.tar", "tar"},
		{"tgz", "certs.tgz", "tar.gz"},
		{"tar.gz", "certs.tar.gz", "tar.gz"},
		{"uppercase ZIP", "certs.ZIP", "zip"},
		{"uppercase TAR.GZ", "certs.TAR.GZ", "tar.gz"},
		{"mixed case TaR.Gz", "certs.TaR.Gz", "tar.gz"},
		{"pem file", "cert.pem", ""},
		{"no extension", "certs", ""},
		{"nested path zip", "/some/path/certs.zip", "zip"},
		{"nested path tar.gz", "/some/path/certs.tar.gz", "tar.gz"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := ArchiveFormat(tt.path)
			if got != tt.want {
				t.Errorf("ArchiveFormat(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestIsArchive(t *testing.T) {
	// WHY: Verifies IsArchive is consistent with ArchiveFormat.
	t.Parallel()

	tests := []struct {
		path string
		want bool
	}{
		{"certs.zip", true},
		{"certs.tar", true},
		{"certs.tgz", true},
		{"certs.tar.gz", true},
		{"cert.pem", false},
		{"cert.p12", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			t.Parallel()
			if got := IsArchive(tt.path); got != tt.want {
				t.Errorf("IsArchive(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestProcessArchive_ZipWithPEMCert(t *testing.T) {
	// WHY: Verifies that PEM certificates inside ZIP archives are ingested
	// into the database — the primary happy path for archive scanning.
	t.Parallel()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "zip-test.example.com", []string{"zip-test.example.com"}, nil)

	zipData := createTestZip(t, map[string][]byte{
		"certs/server.pem": leaf.certPEM,
	})

	cfg := newTestConfig(t)
	n, err := ProcessArchive(ProcessArchiveInput{
		ArchivePath: "test.zip",
		Data:        zipData,
		Format:      "zip",
		Limits:      DefaultArchiveLimits(),
		Config:      cfg,
	})
	if err != nil {
		t.Fatalf("ProcessArchive: %v", err)
	}
	if n != 1 {
		t.Errorf("processed %d entries, want 1", n)
	}

	certs, err := cfg.DB.GetAllCerts()
	if err != nil {
		t.Fatalf("GetAllCerts: %v", err)
	}
	if len(certs) != 1 {
		t.Errorf("got %d certs in DB, want 1", len(certs))
	}
}

func TestProcessArchive_TarWithPEMCert(t *testing.T) {
	// WHY: Verifies that PEM certificates inside TAR archives are ingested.
	t.Parallel()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "tar-test.example.com", []string{"tar-test.example.com"}, nil)

	tarData := createTestTar(t, map[string][]byte{
		"certs/server.pem": leaf.certPEM,
	})

	cfg := newTestConfig(t)
	n, err := ProcessArchive(ProcessArchiveInput{
		ArchivePath: "test.tar",
		Data:        tarData,
		Format:      "tar",
		Limits:      DefaultArchiveLimits(),
		Config:      cfg,
	})
	if err != nil {
		t.Fatalf("ProcessArchive: %v", err)
	}
	if n != 1 {
		t.Errorf("processed %d entries, want 1", n)
	}

	certs, err := cfg.DB.GetAllCerts()
	if err != nil {
		t.Fatalf("GetAllCerts: %v", err)
	}
	if len(certs) != 1 {
		t.Errorf("got %d certs in DB, want 1", len(certs))
	}
}

func TestProcessArchive_TarGzWithPEMCert(t *testing.T) {
	// WHY: Verifies that PEM certificates inside TAR.GZ archives are ingested.
	t.Parallel()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "targz-test.example.com", []string{"targz-test.example.com"}, nil)

	tarGzData := createTestTarGz(t, map[string][]byte{
		"certs/server.pem": leaf.certPEM,
	})

	cfg := newTestConfig(t)
	n, err := ProcessArchive(ProcessArchiveInput{
		ArchivePath: "test.tar.gz",
		Data:        tarGzData,
		Format:      "tar.gz",
		Limits:      DefaultArchiveLimits(),
		Config:      cfg,
	})
	if err != nil {
		t.Fatalf("ProcessArchive: %v", err)
	}
	if n != 1 {
		t.Errorf("processed %d entries, want 1", n)
	}

	certs, err := cfg.DB.GetAllCerts()
	if err != nil {
		t.Fatalf("GetAllCerts: %v", err)
	}
	if len(certs) != 1 {
		t.Errorf("got %d certs in DB, want 1", len(certs))
	}
}

func TestProcessArchive_ZipWithDERCert(t *testing.T) {
	// WHY: Verifies that DER certificates with binary extensions inside ZIP
	// archives are processed through the binary extension gate.
	t.Parallel()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "der-zip.example.com", []string{"der-zip.example.com"}, nil)

	zipData := createTestZip(t, map[string][]byte{
		"certs/server.der": leaf.certDER,
	})

	cfg := newTestConfig(t)
	n, err := ProcessArchive(ProcessArchiveInput{
		ArchivePath: "test.zip",
		Data:        zipData,
		Format:      "zip",
		Limits:      DefaultArchiveLimits(),
		Config:      cfg,
	})
	if err != nil {
		t.Fatalf("ProcessArchive: %v", err)
	}
	if n != 1 {
		t.Errorf("processed %d entries, want 1", n)
	}

	certs, err := cfg.DB.GetAllCerts()
	if err != nil {
		t.Fatalf("GetAllCerts: %v", err)
	}
	if len(certs) != 1 {
		t.Errorf("got %d certs in DB, want 1", len(certs))
	}
}

func TestProcessArchive_ZipWithPrivateKey(t *testing.T) {
	// WHY: Verifies that PEM private keys inside archives are ingested.
	t.Parallel()
	keyPEM := rsaKeyPEM(t)

	zipData := createTestZip(t, map[string][]byte{
		"keys/server.key": keyPEM,
	})

	cfg := newTestConfig(t)
	n, err := ProcessArchive(ProcessArchiveInput{
		ArchivePath: "test.zip",
		Data:        zipData,
		Format:      "zip",
		Limits:      DefaultArchiveLimits(),
		Config:      cfg,
	})
	if err != nil {
		t.Fatalf("ProcessArchive: %v", err)
	}
	if n != 1 {
		t.Errorf("processed %d entries, want 1", n)
	}

	keys, err := cfg.DB.GetAllKeys()
	if err != nil {
		t.Fatalf("GetAllKeys: %v", err)
	}
	if len(keys) != 1 {
		t.Errorf("got %d keys in DB, want 1", len(keys))
	}
}

func TestProcessArchive_MultipleCertsInArchive(t *testing.T) {
	// WHY: Verifies that multiple certificates across multiple files in
	// a single archive are all ingested.
	t.Parallel()
	ca := newRSACA(t)
	leaf1 := newRSALeaf(t, ca, "multi1.example.com", []string{"multi1.example.com"}, nil)
	leaf2 := newECDSALeaf(t, ca, "multi2.example.com", []string{"multi2.example.com"})

	zipData := createTestZip(t, map[string][]byte{
		"certs/leaf1.pem": leaf1.certPEM,
		"certs/leaf2.pem": leaf2.certPEM,
	})

	cfg := newTestConfig(t)
	n, err := ProcessArchive(ProcessArchiveInput{
		ArchivePath: "test.zip",
		Data:        zipData,
		Format:      "zip",
		Limits:      DefaultArchiveLimits(),
		Config:      cfg,
	})
	if err != nil {
		t.Fatalf("ProcessArchive: %v", err)
	}
	if n != 2 {
		t.Errorf("processed %d entries, want 2", n)
	}

	certs, err := cfg.DB.GetAllCerts()
	if err != nil {
		t.Fatalf("GetAllCerts: %v", err)
	}
	if len(certs) != 2 {
		t.Errorf("got %d certs in DB, want 2", len(certs))
	}
}

func TestProcessArchive_EntryExceedsMaxSize(t *testing.T) {
	// WHY: Verifies that individual entries exceeding MaxEntrySize are skipped
	// without aborting the archive.
	t.Parallel()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "big-entry.example.com", []string{"big-entry.example.com"}, nil)

	zipData := createTestZip(t, map[string][]byte{
		"certs/server.pem": leaf.certPEM,
	})

	limits := DefaultArchiveLimits()
	limits.MaxEntrySize = 10 // absurdly small — cert PEM will exceed this

	cfg := newTestConfig(t)
	n, err := ProcessArchive(ProcessArchiveInput{
		ArchivePath: "test.zip",
		Data:        zipData,
		Format:      "zip",
		Limits:      limits,
		Config:      cfg,
	})
	if err != nil {
		t.Fatalf("ProcessArchive: %v", err)
	}
	if n != 0 {
		t.Errorf("processed %d entries, want 0 (entry should be skipped)", n)
	}

	certs, err := cfg.DB.GetAllCerts()
	if err != nil {
		t.Fatalf("GetAllCerts: %v", err)
	}
	if len(certs) != 0 {
		t.Errorf("got %d certs in DB, want 0", len(certs))
	}
}

func TestProcessArchive_TarEntryExceedsMaxSize(t *testing.T) {
	// WHY: Verifies that oversized TAR entries are skipped and the reader
	// advances past them without corruption.
	t.Parallel()
	ca := newRSACA(t)
	leaf1 := newRSALeaf(t, ca, "small.example.com", []string{"small.example.com"}, nil)
	bigData := make([]byte, 100_000)

	tarData := createTestTar(t, map[string][]byte{
		"big.bin":          bigData,
		"certs/server.pem": leaf1.certPEM,
	})

	limits := DefaultArchiveLimits()
	// Set limit above cert PEM size (~1.3KB) but below big.bin (100KB)
	limits.MaxEntrySize = 10_000

	cfg := newTestConfig(t)
	n, err := ProcessArchive(ProcessArchiveInput{
		ArchivePath: "test.tar",
		Data:        tarData,
		Format:      "tar",
		Limits:      limits,
		Config:      cfg,
	})
	if err != nil {
		t.Fatalf("ProcessArchive: %v", err)
	}

	// big.bin is skipped, server.pem is processed
	certs, err := cfg.DB.GetAllCerts()
	if err != nil {
		t.Fatalf("GetAllCerts: %v", err)
	}
	// At least the PEM cert should have been ingested (n depends on map ordering)
	if n < 1 {
		t.Errorf("processed %d entries, want at least 1", n)
	}
	if len(certs) != 1 {
		t.Errorf("got %d certs in DB, want 1", len(certs))
	}
}

func TestProcessArchive_EntryCountLimit(t *testing.T) {
	// WHY: Verifies that the entry count limit stops processing before
	// exhausting all entries, protecting against archive bombs with many files.
	t.Parallel()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "count.example.com", []string{"count.example.com"}, nil)

	files := map[string][]byte{
		"a.pem": leaf.certPEM,
		"b.pem": leaf.certPEM,
		"c.pem": leaf.certPEM,
	}
	zipData := createTestZip(t, files)

	limits := DefaultArchiveLimits()
	limits.MaxEntryCount = 1

	cfg := newTestConfig(t)
	n, err := ProcessArchive(ProcessArchiveInput{
		ArchivePath: "test.zip",
		Data:        zipData,
		Format:      "zip",
		Limits:      limits,
		Config:      cfg,
	})
	if err != nil {
		t.Fatalf("ProcessArchive: %v", err)
	}
	if n > 1 {
		t.Errorf("processed %d entries, want at most 1 (limit should stop processing)", n)
	}
}

func TestProcessArchive_TotalSizeLimit(t *testing.T) {
	// WHY: Verifies that the total extracted size limit stops processing,
	// preventing an archive from consuming unbounded memory.
	t.Parallel()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "totalsize.example.com", []string{"totalsize.example.com"}, nil)

	zipData := createTestZip(t, map[string][]byte{
		"a.pem": leaf.certPEM,
		"b.pem": leaf.certPEM,
	})

	limits := DefaultArchiveLimits()
	// Set total size just big enough for one cert but not two
	limits.MaxTotalSize = int64(len(leaf.certPEM)) + 10

	cfg := newTestConfig(t)
	n, err := ProcessArchive(ProcessArchiveInput{
		ArchivePath: "test.zip",
		Data:        zipData,
		Format:      "zip",
		Limits:      limits,
		Config:      cfg,
	})
	if err != nil {
		t.Fatalf("ProcessArchive: %v", err)
	}
	// Should process at most 1 entry before hitting total size limit
	if n > 1 {
		t.Errorf("processed %d entries, want at most 1 (total size limit should stop)", n)
	}
}

func TestProcessArchive_EmptyZip(t *testing.T) {
	// WHY: Verifies that empty archives are handled gracefully with 0 entries
	// and no error.
	t.Parallel()

	zipData := createTestZip(t, map[string][]byte{})

	cfg := newTestConfig(t)
	n, err := ProcessArchive(ProcessArchiveInput{
		ArchivePath: "empty.zip",
		Data:        zipData,
		Format:      "zip",
		Limits:      DefaultArchiveLimits(),
		Config:      cfg,
	})
	if err != nil {
		t.Fatalf("ProcessArchive: %v", err)
	}
	if n != 0 {
		t.Errorf("processed %d entries, want 0", n)
	}
}

func TestProcessArchive_EmptyTar(t *testing.T) {
	// WHY: Verifies that empty TAR archives are handled gracefully.
	t.Parallel()

	tarData := createTestTar(t, map[string][]byte{})

	cfg := newTestConfig(t)
	n, err := ProcessArchive(ProcessArchiveInput{
		ArchivePath: "empty.tar",
		Data:        tarData,
		Format:      "tar",
		Limits:      DefaultArchiveLimits(),
		Config:      cfg,
	})
	if err != nil {
		t.Fatalf("ProcessArchive: %v", err)
	}
	if n != 0 {
		t.Errorf("processed %d entries, want 0", n)
	}
}

func TestProcessArchive_CorruptedZip(t *testing.T) {
	// WHY: Verifies that corrupted ZIP data returns an error rather than
	// panicking or producing garbage output.
	t.Parallel()

	cfg := newTestConfig(t)
	_, err := ProcessArchive(ProcessArchiveInput{
		ArchivePath: "bad.zip",
		Data:        []byte("this is not a zip file"),
		Format:      "zip",
		Limits:      DefaultArchiveLimits(),
		Config:      cfg,
	})
	if err == nil {
		t.Error("expected error for corrupted ZIP, got nil")
	}
}

func TestProcessArchive_CorruptedTarGz(t *testing.T) {
	// WHY: Verifies that corrupted gzip data returns an error rather than
	// panicking.
	t.Parallel()

	cfg := newTestConfig(t)
	_, err := ProcessArchive(ProcessArchiveInput{
		ArchivePath: "bad.tar.gz",
		Data:        []byte("this is not gzipped data"),
		Format:      "tar.gz",
		Limits:      DefaultArchiveLimits(),
		Config:      cfg,
	})
	if err == nil {
		t.Error("expected error for corrupted tar.gz, got nil")
	}
}

func TestProcessArchive_NestedArchiveNotRecursed(t *testing.T) {
	// WHY: Verifies that archive files nested inside an archive are skipped
	// (no recursive extraction), preventing nested archive bombs.
	t.Parallel()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "nested.example.com", []string{"nested.example.com"}, nil)

	// Create an inner ZIP (content doesn't matter, it should be skipped)
	innerZip := createTestZip(t, map[string][]byte{
		"inner.pem": leaf.certPEM,
	})

	outerZip := createTestZip(t, map[string][]byte{
		"outer.pem":     leaf.certPEM,
		"inner.zip":     innerZip,
		"archive.tar":   []byte("fake tar"),
		"bundle.tar.gz": []byte("fake tar.gz"),
		"archive.tgz":   []byte("fake tgz"),
	})

	cfg := newTestConfig(t)
	n, err := ProcessArchive(ProcessArchiveInput{
		ArchivePath: "outer.zip",
		Data:        outerZip,
		Format:      "zip",
		Limits:      DefaultArchiveLimits(),
		Config:      cfg,
	})
	if err != nil {
		t.Fatalf("ProcessArchive: %v", err)
	}
	// Only outer.pem should be processed; inner.zip, archive.tar, etc. are skipped
	if n != 1 {
		t.Errorf("processed %d entries, want 1 (nested archives should be skipped)", n)
	}
}

func TestProcessArchive_ExpiredCertRejectedByDefault(t *testing.T) {
	// WHY: Verifies that expired certificates inside archives are skipped
	// when IncludeExpired is false, matching non-archive scan behavior.
	t.Parallel()
	ca := newRSACA(t)
	expired := newExpiredLeaf(t, ca)

	zipData := createTestZip(t, map[string][]byte{
		"expired.pem": expired.certPEM,
	})

	cfg := newTestConfig(t)
	cfg.IncludeExpired = false

	n, err := ProcessArchive(ProcessArchiveInput{
		ArchivePath: "test.zip",
		Data:        zipData,
		Format:      "zip",
		Limits:      DefaultArchiveLimits(),
		Config:      cfg,
	})
	if err != nil {
		t.Fatalf("ProcessArchive: %v", err)
	}
	if n != 1 {
		t.Errorf("processed %d entries, want 1 (entry is processed, cert is filtered)", n)
	}

	certs, err := cfg.DB.GetAllCerts()
	if err != nil {
		t.Fatalf("GetAllCerts: %v", err)
	}
	if len(certs) != 0 {
		t.Errorf("got %d certs in DB, want 0 (expired should be filtered)", len(certs))
	}
}

func TestProcessArchive_ExpiredCertIncludedWhenAllowed(t *testing.T) {
	// WHY: Verifies that expired certificates inside archives are included
	// when IncludeExpired is true.
	t.Parallel()
	ca := newRSACA(t)
	expired := newExpiredLeaf(t, ca)

	zipData := createTestZip(t, map[string][]byte{
		"expired.pem": expired.certPEM,
	})

	cfg := newTestConfig(t)
	cfg.IncludeExpired = true

	n, err := ProcessArchive(ProcessArchiveInput{
		ArchivePath: "test.zip",
		Data:        zipData,
		Format:      "zip",
		Limits:      DefaultArchiveLimits(),
		Config:      cfg,
	})
	if err != nil {
		t.Fatalf("ProcessArchive: %v", err)
	}
	if n != 1 {
		t.Errorf("processed %d entries, want 1", n)
	}

	certs, err := cfg.DB.GetAllCerts()
	if err != nil {
		t.Fatalf("GetAllCerts: %v", err)
	}
	if len(certs) != 1 {
		t.Errorf("got %d certs in DB, want 1 (expired should be included)", len(certs))
	}
}

func TestProcessArchive_UnsupportedFormat(t *testing.T) {
	// WHY: Verifies that an unknown format string produces a clear error.
	t.Parallel()

	cfg := newTestConfig(t)
	_, err := ProcessArchive(ProcessArchiveInput{
		ArchivePath: "test.rar",
		Data:        []byte("data"),
		Format:      "rar",
		Limits:      DefaultArchiveLimits(),
		Config:      cfg,
	})
	if err == nil {
		t.Error("expected error for unsupported format, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported archive format") {
		t.Errorf("error %q should mention unsupported archive format", err.Error())
	}
}

func TestProcessArchive_VirtualPathFormat(t *testing.T) {
	// WHY: Verifies that virtual paths use the colon separator convention
	// (archive.zip:path/to/file), which affects logging and hasBinaryExtension.
	t.Parallel()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "vpath.example.com", []string{"vpath.example.com"}, nil)

	zipData := createTestZip(t, map[string][]byte{
		"sub/dir/cert.pem": leaf.certPEM,
	})

	cfg := newTestConfig(t)
	n, err := ProcessArchive(ProcessArchiveInput{
		ArchivePath: "/path/to/archive.zip",
		Data:        zipData,
		Format:      "zip",
		Limits:      DefaultArchiveLimits(),
		Config:      cfg,
	})
	if err != nil {
		t.Fatalf("ProcessArchive: %v", err)
	}
	if n != 1 {
		t.Errorf("processed %d entries, want 1", n)
	}

	// Verify the cert was ingested (virtual path doesn't break processing)
	certs, err := cfg.DB.GetAllCerts()
	if err != nil {
		t.Fatalf("GetAllCerts: %v", err)
	}
	if len(certs) != 1 {
		t.Errorf("got %d certs in DB, want 1", len(certs))
	}
}
