package stream

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/Peiratooo/innoextract-go/internal/fault"
	"github.com/Peiratooo/innoextract-go/internal/format"
)

func TestSliceSourceReadsAcrossProviders(t *testing.T) {
	providers := map[uint32][]byte{2: []byte("abc"), 3: []byte("def")}
	source, err := newSliceSourceWithProvider(bytes.NewReader(nil), &format.Archive{}, format.Chunk{
		FirstSlice: 2, LastSlice: 3, Offset: 1,
	}, func(index uint32) (io.ReaderAt, error) {
		return bytes.NewReader(providers[index]), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(source)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "bcdef" {
		t.Fatalf("cross-slice data = %q", got)
	}
}

func TestExternalSliceRequiresProvider(t *testing.T) {
	archive := &format.Archive{Header: format.Header{BaseFilename: "setup"}}
	_, err := newSliceSourceWithProvider(bytes.NewReader(nil), archive, format.Chunk{}, nil)
	if !errors.Is(err, fault.ErrMissingSlice) {
		t.Fatalf("error = %v, want ErrMissingSlice", err)
	}
}
