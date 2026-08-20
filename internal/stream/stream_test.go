package stream

import (
	"bytes"
	"compress/zlib"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"testing"

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

	results, failures, err := Extract(bytes.NewReader(raw), archive, Options{MemoryLimit: int64(len(payload) + 1)}, false)
	if err != nil {
		t.Fatalf("Extract returned archive error: %v", err)
	}
	if len(results) != 0 || len(failures) != 2 {
		t.Fatalf("Extract = results %#v, failures %#v", results, failures)
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
