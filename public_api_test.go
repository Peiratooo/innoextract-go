package innoextract

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/Peiratooo/innoextract-go/internal/format"
)

func TestOptionsValidateAndApply(t *testing.T) {
	cfg := defaultOptions()
	if cfg.memoryLimit != defaultMemoryLimit {
		t.Fatalf("default memory limit = %d, want %d", cfg.memoryLimit, defaultMemoryLimit)
	}
	if cfg.headerLimit != defaultHeaderLimit {
		t.Fatalf("default header limit = %d, want %d", cfg.headerLimit, defaultHeaderLimit)
	}

	provider := SliceProvider(func(uint32) (io.ReaderAt, error) {
		return bytes.NewReader(nil), nil
	})
	for name, option := range map[string]Option{
		"password": WithPassword("secret"),
		"codepage": WithCodepage(1252),
		"slices":   WithSliceProvider(provider),
		"memory":   WithMemoryLimit(4096),
	} {
		if err := option(&cfg); err != nil {
			t.Fatalf("%s option returned error: %v", name, err)
		}
	}
	if cfg.password != "secret" || cfg.codepage != 1252 || cfg.slices == nil || cfg.memoryLimit != 4096 {
		t.Fatalf("options were not applied: %#v", cfg)
	}

	for name, option := range map[string]Option{
		"zero codepage":   WithCodepage(0),
		"nil slices":      WithSliceProvider(nil),
		"zero memory":     WithMemoryLimit(0),
		"negative memory": WithMemoryLimit(-1),
	} {
		if err := option(&cfg); err == nil {
			t.Errorf("%s accepted invalid input", name)
		}
	}
}

func TestInfoReturnsIndependentMetadataCopy(t *testing.T) {
	a := &Archive{data: &format.Archive{
		Version: format.Version{Major: 6, Minor: 6, Patch: 1},
		Header: format.Header{
			AppName:    "Example",
			AppVersion: "1.2.3",
			AppID:      "{example}",
			Publisher:  "Publisher",
			Encrypted:  true,
		},
		Languages: []format.Language{{Name: "en", DisplayName: "English", ID: 1033, Codepage: 1200}},
		Registry: []format.RegistryEntry{{
			Key:   `Software\GOG.com\Games\123456`,
			Name:  "gameID",
			Value: "123456",
		}},
	}}

	first := a.Info()
	if first.DataVersion != "6.6.1" || first.AppName != "Example" || !first.Encrypted {
		t.Fatalf("unexpected info: %#v", first)
	}
	if first.GOGGameID != "123456" || len(first.Languages) != 1 {
		t.Fatalf("unexpected derived info: %#v", first)
	}

	first.Languages[0].Name = "mutated"
	first.Languages[0].ID = 9999
	first.Languages = append(first.Languages, Language{Name: "mutated"})
	second := a.Info()
	if len(second.Languages) != 1 || second.Languages[0].Name != "en" || second.Languages[0].ID != 1033 {
		t.Fatalf("Info leaked mutable language state: %#v", second.Languages)
	}
}

func TestFilesReturnsSafeIndependentManifestAndPreservesDuplicates(t *testing.T) {
	a := &Archive{data: &format.Archive{Files: []format.FileEntry{
		{Destination: `C:\payload\..\bin\tool.exe`, Size: 7, Location: 99},
		{Destination: `bin/tool.exe`, Size: 7, Location: 99},
	}}}

	first := a.Files()
	if len(first) != 2 {
		t.Fatalf("Files returned %d entries, want 2", len(first))
	}
	if first[0].Index != 0 || first[1].Index != 1 {
		t.Fatalf("entry indexes = %d, %d", first[0].Index, first[1].Index)
	}
	if first[0].Path != "bin/tool.exe" || first[1].Path != "bin/tool.exe" {
		t.Fatalf("unexpected normalized paths: %#v", first)
	}

	first[0].Path = "changed"
	first[0].Size = 123
	first = append(first, Entry{Path: "caller-only"})
	second := a.Files()
	if len(second) != 2 || second[0].Path != "bin/tool.exe" || second[0].Size != 7 {
		t.Fatalf("Files leaked mutable state: %#v", second)
	}
}

func TestExtractErrorSupportsErrorsIsAndAs(t *testing.T) {
	aggregate := &ExtractError{Failures: []EntryError{
		{Entry: Entry{Index: 1, Path: "bin/one.dll"}, Err: ErrChecksumMismatch},
		{Entry: Entry{Index: 2, Path: "bin/two.dll"}, Err: ErrCorrupt},
	}}
	if got, want := aggregate.Error(), "bin/one.dll: checksum mismatch; bin/two.dll: corrupt setup data"; got != want {
		t.Fatalf("ExtractError.Error() = %q, want %q", got, want)
	}
	if !errors.Is(aggregate, ErrChecksumMismatch) || !errors.Is(aggregate, ErrCorrupt) {
		t.Fatal("ExtractError does not expose entry causes through errors.Is")
	}
	var entry EntryError
	if !errors.As(aggregate, &entry) || entry.Entry.Path != "bin/one.dll" {
		t.Fatalf("errors.As did not find first EntryError: %#v", entry)
	}
	var extracted *ExtractError
	if !errors.As(aggregate, &extracted) || extracted != aggregate {
		t.Fatal("errors.As did not find ExtractError")
	}

	var empty *ExtractError
	if empty.Error() != "" {
		t.Fatalf("nil ExtractError.Error() = %q, want empty string", empty.Error())
	}
}

func TestOpenRejectsNilReaderWithSentinel(t *testing.T) {
	archive, err := Open(nil)
	if archive != nil {
		t.Fatal("Open(nil) returned an archive")
	}
	if !errors.Is(err, ErrInvalidFormat) {
		t.Fatalf("Open(nil) error = %v, want ErrInvalidFormat", err)
	}
}
