package gog

import (
	"bytes"
	"testing"

	"github.com/Peiratooo/innoextract-go/internal/format"
)

func TestGameID(t *testing.T) {
	entries := []format.RegistryEntry{
		{Key: `software\gog.com\games\fallback`, Name: "InstallPath", Value: `C:\Games`},
		{Key: `SOFTWARE\GOG.COM\GAMES\fallback`, Name: "gameID", Value: "actual-id"},
		{Key: `SOFTWARE\GOG.com\Games\fallback\nested`, Name: "gameID", Value: "wrong"},
	}
	if got := GameID(entries); got != "actual-id" {
		t.Fatalf("GameID() = %q, want actual-id", got)
	}

	if got := GameID([]format.RegistryEntry{{Key: `SOFTWARE\GOG.com\Games\only-id`}}); got != "only-id" {
		t.Fatalf("fallback GameID() = %q, want only-id", got)
	}
}

func TestParseFunctionCall(t *testing.T) {
	got := parseFunctionCall(` before_install('a''b', plain, 'with spaces'); `, "before_install")
	want := []string{"a'b", "plain", "with spaces"}
	if len(got) != len(want) {
		t.Fatalf("parseFunctionCall() = %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("parseFunctionCall()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	if got := parseFunctionCall(`before_install('unterminated)`, "before_install"); got != nil {
		t.Fatalf("malformed parseFunctionCall() = %#v, want nil", got)
	}
}

func TestApplyGalaxyPartsAndConstraints(t *testing.T) {
	archive := &format.Archive{
		Files: []format.FileEntry{
			{
				Destination:   "hash.part1",
				BeforeInstall: `before_install('00112233445566778899aabbccddeeff','game.pak','2');`,
				AfterInstall:  `after_install('part1','100','5');`,
				Check:         `check_if_install('en#zh#','32','windows');`,
				Location:      0,
			},
			{
				Destination:  "hash.part2",
				AfterInstall: `after_install('part2','100','7');`,
				Check:        `check_if_install('en#zh#','64','windows');`,
				Location:     1,
			},
		},
		DataEntries: []format.DataEntry{{}, {}},
	}

	Apply(archive)

	first := archive.Files[0]
	if first.Destination != "game.pak" || first.Size != 12 {
		t.Fatalf("first Galaxy file = destination %q, size %d; want game.pak, 12", first.Destination, first.Size)
	}
	if first.Checksum.Type != format.ChecksumMD5 || !bytes.Equal(first.Checksum.Data, []byte{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
	}) {
		t.Fatalf("first Galaxy checksum = %#v, want parsed MD5", first.Checksum)
	}
	if len(first.AdditionalLocations) != 1 || first.AdditionalLocations[0] != 1 {
		t.Fatalf("additional locations = %#v, want [1]", first.AdditionalLocations)
	}
	if archive.Files[1].Destination != "" {
		t.Fatalf("part destination = %q, want empty", archive.Files[1].Destination)
	}
	if !first.Bits32 || first.Bits64 || archive.Files[1].Bits32 || archive.Files[1].Bits64 {
		t.Fatalf("architecture constraints were not applied: first=(%v,%v), second=(%v,%v)", first.Bits32, first.Bits64, archive.Files[1].Bits32, archive.Files[1].Bits64)
	}
	if first.Components != "game" || archive.Files[1].Components != "" {
		t.Fatalf("default components = %q, %q; want game and empty part", first.Components, archive.Files[1].Components)
	}
	if archive.DataEntries[0].UncompressedSize != 5 || archive.DataEntries[1].UncompressedSize != 7 {
		t.Fatalf("uncompressed sizes = %d, %d; want 5, 7", archive.DataEntries[0].UncompressedSize, archive.DataEntries[1].UncompressedSize)
	}
	if archive.DataEntries[0].File.Filter != format.ZlibFilter || archive.DataEntries[1].File.Filter != format.ZlibFilter {
		t.Fatalf("Galaxy parts did not select zlib filters")
	}
	if len(archive.Languages) != 2 || !hasLanguage(archive.Languages, "en") || !hasLanguage(archive.Languages, "zh") {
		t.Fatalf("synthetic languages = %#v, want en and zh", archive.Languages)
	}

	// Reapplying is harmless for callers that run post-processing defensively.
	Apply(archive)
	if len(archive.Files[0].AdditionalLocations) != 1 || len(archive.Languages) != 2 {
		t.Fatalf("Apply is not idempotent: locations=%#v languages=%#v", archive.Files[0].AdditionalLocations, archive.Languages)
	}
}

func TestApplyPreservesDuplicateCandidates(t *testing.T) {
	archive := &format.Archive{Files: []format.FileEntry{
		{Destination: `bin\tool.exe`},
		{Destination: `bin/tool.exe`},
	}}
	Apply(archive)
	if len(archive.Files) != 2 {
		t.Fatalf("Apply removed duplicate candidates; got %d files", len(archive.Files))
	}
}

func TestApplyDoesNotTreatOrdinaryChecksAsGalaxy(t *testing.T) {
	archive := &format.Archive{Files: []format.FileEntry{{
		Destination: "ordinary.bin",
		Check:       `check_if_install('en#zh#','32');`,
	}}}
	Apply(archive)
	if archive.Files[0].Components != "" || archive.Files[0].Bits32 || archive.Files[0].Languages != "" {
		t.Fatalf("ordinary Inno check was treated as Galaxy metadata: %#v", archive.Files[0])
	}
	if len(archive.Languages) != 0 {
		t.Fatalf("ordinary Inno check created languages: %#v", archive.Languages)
	}
}

func TestApplyIgnoresMalformedGalaxyMarkers(t *testing.T) {
	archive := &format.Archive{
		Files: []format.FileEntry{{
			Destination:   "keep.bin",
			BeforeInstall: `before_install('not-an-md5','keep.bin','2');`,
			AfterInstall:  `after_install('part','100','not-a-number');`,
			Location:      0,
		}},
		DataEntries: []format.DataEntry{{}},
	}
	Apply(archive)
	if archive.Files[0].Destination != "keep.bin" || archive.Files[0].Size != 0 {
		t.Fatalf("malformed Galaxy marker changed file: %#v", archive.Files[0])
	}
	if archive.DataEntries[0].File.Filter != format.NoFilter {
		t.Fatalf("malformed Galaxy marker changed data filter")
	}
}
