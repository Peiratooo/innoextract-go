package stream

import (
	"bytes"
	"compress/zlib"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"testing"

	"github.com/Peiratooo/innoextract-go/internal/fault"
	"github.com/Peiratooo/innoextract-go/internal/format"
)

func TestExtractStoredAndVerifyFinalChecksum(t *testing.T) {
	const payload = "hello from a chunk"
	archive, raw := testArchive([]byte(payload), format.Stored, format.NoFilter, []byte(payload), []byte(payload))

	results, failures, err := Extract(bytes.NewReader(raw), archive, Options{MemoryLimit: 1 << 20}, false)
	if err != nil {
		t.Fatalf("Extract returned archive error: %v", err)
	}
	if len(failures) != 0 || len(results) != 1 || string(results[0].Data) != payload {
		t.Fatalf("Extract = results %#v, failures %#v", results, failures)
	}

	archive.Files[0].Checksum.Data[0] ^= 0xff
	results, failures, err = Extract(bytes.NewReader(raw), archive, Options{MemoryLimit: 1 << 20}, true)
	if err != nil {
		t.Fatalf("Verify returned archive error: %v", err)
	}
	if len(results) != 0 || len(failures) != 1 {
		t.Fatalf("Verify = results %#v, failures %#v", results, failures)
	}
}

func TestExtractZlibFilterChecksCompressedBytes(t *testing.T) {
	const payload = "zlib-filter payload"
	var compressed bytes.Buffer
	zw := zlib.NewWriter(&compressed)
	if _, err := zw.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	archive, raw := testArchive(compressed.Bytes(), format.Stored, format.ZlibFilter, compressed.Bytes(), []byte(payload))
	archive.DataEntries[0].UncompressedSize = uint64(len(payload))
	archive.Files[0].Size = uint64(len(payload))
	results, failures, err := Extract(bytes.NewReader(raw), archive, Options{MemoryLimit: 1 << 20}, false)
	if err != nil {
		t.Fatalf("Extract returned archive error: %v", err)
	}
	if len(failures) != 0 || len(results) != 1 || string(results[0].Data) != payload {
		t.Fatalf("Extract = results %#v, failures %#v", results, failures)
	}
}

func TestExtractReservesAggregateBeforeOutputAllocation(t *testing.T) {
	const payload = "12345"
	archive, raw := testArchive([]byte(payload), format.Stored, format.NoFilter, []byte(payload), nil)
	second := archive.Files[0]
	second.Destination = "second"
	archive.Files = append(archive.Files, second)

	reader := &countingReaderAt{reader: bytes.NewReader(raw)}
	results, failures, err := Extract(reader, archive, Options{MemoryLimit: int64(len(payload) + 1)}, false)
	if err != nil {
		t.Fatalf("Extract returned archive error: %v", err)
	}
	if len(results) != 0 || len(failures) != 2 {
		t.Fatalf("Extract = results %#v, failures %#v", results, failures)
	}
	if reader.reads != 0 {
		t.Fatalf("Extract read %d times after aggregate output allocation had already failed", reader.reads)
	}
}

func TestExtractInstructionFilterHonorsRemainingMemory(t *testing.T) {
	encoded := []byte{0xe8, 5, 0, 0, 0}
	decoded := []byte{0xe8, 0, 0, 0, 0}
	archive, raw := testArchive(encoded, format.Stored, format.Instruction5309, decoded, decoded)

	// The output buffer and materialized chunk exactly consume the budget.
	// The instruction filter needs another len(encoded) bytes and must fail
	// instead of allocating beyond MemoryLimit.
	limit := int64(len(encoded) + len(decoded))
	results, failures, err := Extract(bytes.NewReader(raw), archive, Options{MemoryLimit: limit}, false)
	if err != nil {
		t.Fatalf("Extract returned archive error: %v", err)
	}
	if len(results) != 0 || len(failures) != 1 {
		t.Fatalf("Extract = results %#v, failures %#v", results, failures)
	}
	if !errors.Is(failures[0].Err, fault.ErrLimitExceeded) {
		t.Fatalf("failure = %v, want ErrLimitExceeded", failures[0].Err)
	}
}

func TestExtractZlibFilterHonorsRemainingMemory(t *testing.T) {
	payload := bytes.Repeat([]byte("A"), 256)
	var compressed bytes.Buffer
	zw := zlib.NewWriter(&compressed)
	if _, err := zw.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	archive, raw := testArchive(compressed.Bytes(), format.Stored, format.ZlibFilter, compressed.Bytes(), payload)
	archive.DataEntries[0].UncompressedSize = uint64(len(payload))
	archive.Files[0].Size = uint64(len(payload))

	// Output + chunk consume the entire budget. The zlib-filter output is a
	// transient allocation and must therefore be rejected.
	limit := int64(len(payload) + compressed.Len())
	results, failures, err := Extract(bytes.NewReader(raw), archive, Options{MemoryLimit: limit}, false)
	if err != nil {
		t.Fatalf("Extract returned archive error: %v", err)
	}
	if len(results) != 0 || len(failures) != 1 {
		t.Fatalf("Extract = results %#v, failures %#v", results, failures)
	}
	if !errors.Is(failures[0].Err, fault.ErrLimitExceeded) {
		t.Fatalf("failure = %v, want ErrLimitExceeded", failures[0].Err)
	}
}

func TestInstruction5309ContinuesAfterBlockBoundary(t *testing.T) {
	source := make([]byte, 0x10020)
	// This opcode cannot be transformed because its address crosses the
	// 64-KiB optimization block boundary. It must not disable filtering for
	// the rest of the file.
	source[0xffff] = 0xe8
	source[0x10005] = 0xe8
	source[0x10006] = 0x00
	source[0x10007] = 0x10

	decoded := decodeInstruction5200(source, true)
	want := []byte{0xf6, 0x0f, 0xff, 0xff}
	if !bytes.Equal(decoded[0x10006:0x1000a], want) {
		t.Fatalf("decoded address = % x, want % x", decoded[0x10006:0x1000a], want)
	}
}

func TestChunkCompressionMethods(t *testing.T) {
	const payload = "hello compression"
	var zlibData bytes.Buffer
	zw := zlib.NewWriter(&zlibData)
	_, _ = zw.Write([]byte(payload))
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		method format.Compression
		data   []byte
	}{
		{"stored", format.Stored, []byte(payload)},
		{"zlib", format.Zlib, zlibData.Bytes()},
		{"bzip2", format.BZip2, mustHex("425a6839314159265359aaccf160000002118040000a67d8002000310340d020069a18d3a78108d87780f177245385090aaccf1600")},
		{"lzma1", format.LZMA1, mustHex("5d0000100000341949ee8de912140997ae148e1c90add8996f898bffe3100000")},
		{"lzma2", format.LZMA2, mustHex("1001001068656c6c6f20636f6d7072657373696f6e00")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reader, closer, err := newChunkDecoder(bytes.NewReader(test.data), test.method, 1<<20)
			if err != nil {
				t.Fatal(err)
			}
			if closer != nil {
				defer closer.Close()
			}
			got, err := io.ReadAll(reader)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != payload {
				t.Fatalf("decoded = %q", got)
			}
		})
	}
}

func TestLZMAReadersBufferInput(t *testing.T) {
	tests := []struct {
		name   string
		method format.Compression
		data   []byte
	}{
		{"lzma1", format.LZMA1, mustHex("5d0000100000341949ee8de912140997ae148e1c90add8996f898bffe3100000")},
		{"lzma2", format.LZMA2, mustHex("1001001068656c6c6f20636f6d7072657373696f6e00")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source := &countingReader{Reader: bytes.NewReader(test.data)}
			reader, closer, err := newChunkDecoder(source, test.method, 1<<20)
			if err != nil {
				t.Fatal(err)
			}
			if closer != nil {
				defer closer.Close()
			}
			if _, err := io.ReadAll(reader); err != nil {
				t.Fatal(err)
			}
			if source.reads > 2 {
				t.Fatalf("source Read calls = %d, want at most 2", source.reads)
			}
		})
	}
}

type countingReader struct {
	io.Reader
	reads int
}

func (r *countingReader) Read(p []byte) (int, error) {
	r.reads++
	return r.Reader.Read(p)
}

func TestInstructionFilterVectors(t *testing.T) {
	encoded := []byte{0xe8, 5, 0, 0, 0}
	want := []byte{0xe8, 0, 0, 0, 0}
	for name, got := range map[string][]byte{
		"4108": decodeInstruction4108(encoded),
		"5200": decodeInstruction5200(encoded, false),
		"5309": decodeInstruction5200(encoded, true),
	} {
		if !bytes.Equal(got, want) {
			t.Errorf("%s decoded = % x, want % x", name, got, want)
		}
	}
}

func mustHex(value string) []byte {
	data, err := hex.DecodeString(value)
	if err != nil {
		panic(err)
	}
	return data
}

func testArchive(chunkData []byte, compression format.Compression, filter format.FileFilter, segmentChecksumData, publicData []byte) (*format.Archive, []byte) {
	chunk := append([]byte("zlb\x1a"), chunkData...)
	entry := format.DataEntry{
		Chunk:            format.Chunk{FirstSlice: 0, LastSlice: 0, Offset: 0, Size: uint64(len(chunkData)), Compression: compression},
		File:             format.StoredFile{Offset: 0, Size: uint64(len(chunkData)), Filter: filter},
		UncompressedSize: uint64(len(segmentChecksumData)),
	}
	entry.File.Checksum = sha256Checksum(segmentChecksumData)
	file := format.FileEntry{Destination: "payload", Location: 0, Size: uint64(len(publicData))}
	if publicData != nil {
		file.Checksum = sha256Checksum(publicData)
	}
	archive := &format.Archive{
		Offsets:     format.Offsets{DataOffset: 0},
		Files:       []format.FileEntry{file},
		DataEntries: []format.DataEntry{entry},
	}
	return archive, chunk
}

func sha256Checksum(data []byte) format.Checksum {
	sum := sha256.Sum256(data)
	return format.Checksum{Type: format.ChecksumSHA256, Data: append([]byte(nil), sum[:]...)}
}

type countingReaderAt struct {
	reader io.ReaderAt
	reads  int
}

func (r *countingReaderAt) ReadAt(p []byte, off int64) (int, error) {
	r.reads++
	return r.reader.ReadAt(p, off)
}
