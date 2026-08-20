package innoextract

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Peiratooo/innoextract-go/internal/loader"
)

func TestSample661Integration(t *testing.T) {
	sample := os.Getenv("INNOEXTRACT_SAMPLE")
	if sample == "" {
		sample = filepath.Join("..", "extract", "B4验机-2.3.1-windows-setup.exe")
	}
	if _, err := os.Stat(sample); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			t.Skipf("6.6.1 sample is not available: %s", sample)
		}
		t.Fatal(err)
	}

	file, err := os.Open(sample)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if stat.Size() != 50_589_128 {
		t.Fatalf("sample size = %d, want 50589128", stat.Size())
	}
	offsets, err := loader.Locate(file)
	if err != nil {
		t.Fatal(err)
	}
	if offsets.Revision != 2 || offsets.HeaderOffset != 0x2F34178 || offsets.DataOffset != 0xD0400 || offsets.ExeOffset != 0x2F399F8 {
		t.Fatalf("loader offsets = %+v", offsets)
	}

	archive, err := Open(file)
	if err != nil {
		t.Fatal(err)
	}
	info := archive.Info()
	if !strings.HasPrefix(info.DataVersion, "6.6.1") {
		t.Fatalf("sample data version = %q, want 6.6.1", info.DataVersion)
	}

	entries := archive.Files()
	if len(entries) == 0 {
		t.Fatal("sample returned no file entries")
	}
	if err := archive.Verify(); err != nil {
		t.Fatal(err)
	}

	files, err := archive.Extract()
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("sample extracted no files")
	}
	for _, extracted := range files {
		if extracted.Path == "" || filepath.IsAbs(filepath.FromSlash(extracted.Path)) || strings.ContainsRune(extracted.Path, '\\') {
			t.Errorf("unsafe extracted path %q", extracted.Path)
		}
		if uint64(len(extracted.Data)) != extracted.Size {
			t.Errorf("%s: data length %d, entry size %d", extracted.Path, len(extracted.Data), extracted.Size)
		}
		sum := sha256.Sum256(extracted.Data)
		if extracted.SHA256 != "" && !strings.EqualFold(extracted.SHA256, hex.EncodeToString(sum[:])) {
			t.Errorf("%s: SHA256 = %q, calculated %x", extracted.Path, extracted.SHA256, sum)
		}
	}
}
