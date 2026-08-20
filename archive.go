package innoextract

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/Peiratooo/innoextract-go/internal/format"
	"github.com/Peiratooo/innoextract-go/internal/gog"
	"github.com/Peiratooo/innoextract-go/internal/pathutil"
	"github.com/Peiratooo/innoextract-go/internal/setup"
	"github.com/Peiratooo/innoextract-go/internal/stream"
)

func Open(r io.ReaderAt, opts ...Option) (*Archive, error) {
	if r == nil {
		return nil, fmt.Errorf("%w: nil reader", ErrInvalidFormat)
	}
	cfg := defaultOptions()
	for _, apply := range opts {
		if apply == nil {
			return nil, fmt.Errorf("nil option")
		}
		if err := apply(&cfg); err != nil {
			return nil, err
		}
	}
	parsed, err := setup.Parse(r, setup.Options{Codepage: cfg.codepage, HeaderLimit: cfg.headerLimit})
	if err != nil {
		return nil, err
	}
	gog.Apply(parsed)
	return &Archive{r: r, opts: cfg, data: parsed}, nil
}

func (a *Archive) Info() Info {
	if a == nil || a.data == nil {
		return Info{}
	}
	h := a.data.Header
	info := Info{
		DataVersion: a.data.Version.String(),
		AppName:     h.AppName,
		AppVersion:  h.AppVersion,
		AppID:       h.AppID,
		Publisher:   h.Publisher,
		Encrypted:   h.Encrypted,
		GOGGameID:   gog.GameID(a.data.Registry),
		Languages:   make([]Language, len(a.data.Languages)),
	}
	for i, language := range a.data.Languages {
		info.Languages[i] = Language{
			Name: language.Name, DisplayName: language.DisplayName,
			ID: language.ID, Codepage: language.Codepage,
		}
	}
	return info
}

func (a *Archive) Files() []Entry {
	if a == nil || a.data == nil {
		return nil
	}
	entries := make([]Entry, len(a.data.Files))
	for i := range a.data.Files {
		entries[i] = a.entry(i)
	}
	return entries
}

func (a *Archive) Extract() ([]File, error) {
	return a.extract(false)
}

func (a *Archive) Verify() error {
	_, err := a.extract(true)
	return err
}

func (a *Archive) extract(verifyOnly bool) ([]File, error) {
	if a == nil || a.data == nil || a.r == nil {
		return nil, fmt.Errorf("%w: nil archive", ErrInvalidFormat)
	}
	var slices func(uint32) (io.ReaderAt, error)
	if a.opts.slices != nil {
		slices = func(index uint32) (io.ReaderAt, error) { return a.opts.slices(index) }
	}
	results, failures, err := stream.Extract(a.r, a.data, stream.Options{
		Password: a.opts.password, MemoryLimit: a.opts.memoryLimit, Slices: slices,
	}, verifyOnly)
	files := make([]File, 0, len(results))
	if !verifyOnly {
		for _, result := range results {
			if result.FileIndex < 0 || result.FileIndex >= len(a.data.Files) {
				continue
			}
			digest := sha256.Sum256(result.Data)
			files = append(files, File{
				Entry: a.entry(result.FileIndex), Data: result.Data,
				SHA256: hex.EncodeToString(digest[:]),
			})
		}
	}
	if err != nil {
		return files, err
	}
	if len(failures) == 0 {
		return files, nil
	}
	aggregate := &ExtractError{Failures: make([]EntryError, 0, len(failures))}
	for _, failure := range failures {
		entry := Entry{Index: failure.FileIndex, Path: "<archive>"}
		if failure.FileIndex >= 0 && failure.FileIndex < len(a.data.Files) {
			entry = a.entry(failure.FileIndex)
		}
		aggregate.Failures = append(aggregate.Failures, EntryError{Entry: entry, Err: failure.Err})
	}
	return files, aggregate
}

func (a *Archive) entry(index int) Entry {
	f := a.data.Files[index]
	entry := Entry{
		Index: index, Path: pathutil.Clean(f.Destination), Size: f.Size,
		Languages: f.Languages, Components: f.Components, Tasks: f.Tasks, Check: f.Check,
		Temporary: f.Temporary, Bits32: f.Bits32, Bits64: f.Bits64,
	}
	if int(f.Location) < len(a.data.DataEntries) {
		data := a.data.DataEntries[f.Location]
		if entry.Size == 0 {
			entry.Size = data.UncompressedSize
		}
		entry.CompressedSize = data.Chunk.Size
		entry.Encrypted = data.Chunk.Encryption != format.Plaintext
		checksum := f.Checksum
		if checksum.Type == format.ChecksumNone {
			checksum = data.File.Checksum
		}
		entry.ChecksumType = publicChecksumType(checksum.Type)
		entry.Checksum = hex.EncodeToString(checksum.Data)
	}
	return entry
}

func publicChecksumType(t format.ChecksumType) ChecksumType {
	switch t {
	case format.ChecksumAdler32:
		return ChecksumAdler32
	case format.ChecksumCRC32:
		return ChecksumCRC32
	case format.ChecksumMD5:
		return ChecksumMD5
	case format.ChecksumSHA1:
		return ChecksumSHA1
	case format.ChecksumSHA256:
		return ChecksumSHA256
	default:
		return ChecksumNone
	}
}
