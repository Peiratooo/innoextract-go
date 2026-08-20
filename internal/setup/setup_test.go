package setup

import (
	"encoding/binary"
	"errors"
	"hash/crc32"
	"testing"

	"github.com/Peiratooo/innoextract-go/internal/fault"
	"github.com/Peiratooo/innoextract-go/internal/format"
)

func TestReadBlock67UsesUint64StoredSize(t *testing.T) {
	payload := []byte("abc")
	raw := make([]byte, 4+len(payload))
	binary.LittleEndian.PutUint32(raw, crc32.ChecksumIEEE(payload))
	copy(raw[4:], payload)

	headerFields := make([]byte, 9)
	binary.LittleEndian.PutUint64(headerFields, uint64(len(raw)))
	header := make([]byte, 13)
	binary.LittleEndian.PutUint32(header, crc32.ChecksumIEEE(headerFields))
	copy(header[4:], headerFields)
	input := append(header, raw...)

	got, next, err := readBlock(newReaderAt(input), 0, format.Version{Major: 6, Minor: 7}, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) || next != int64(len(input)) {
		t.Fatalf("block = %q, next = %d", got, next)
	}
}

func Test67FlagSetsConsumeEightBytes(t *testing.T) {
	v := format.Version{Major: 6, Minor: 7}
	headerCursor := cursor{b: []byte{1, 2, 3, 4, 5, 6, 7, 8}}
	flags, err := readHeaderFlags(&headerCursor, v)
	if err != nil || flags != 0x0807060504030201 || headerCursor.remaining() != 0 {
		t.Fatalf("header flags = %#x, remaining=%d, err=%v", flags, headerCursor.remaining(), err)
	}
	fileCursor := cursor{b: []byte{8, 7, 6, 5, 4, 3, 2, 1}}
	flags, err = readFileFlags(&fileCursor, v)
	if err != nil || flags != 0x0102030405060708 || fileCursor.remaining() != 0 {
		t.Fatalf("file flags = %#x, remaining=%d, err=%v", flags, fileCursor.remaining(), err)
	}
}

func TestOuterEncryptionHeader(t *testing.T) {
	header := make([]byte, 53)
	header[4] = 1
	binary.LittleEndian.PutUint32(header, crc32.ChecksumIEEE(header[4:]))
	encrypted, next, err := readEncryptionHeader(newReaderAt(header), 0)
	if err != nil || !encrypted || next != 53 {
		t.Fatalf("encrypted=%v next=%d err=%v", encrypted, next, err)
	}
	header[52] ^= 1
	_, _, err = readEncryptionHeader(newReaderAt(header), 0)
	if !errors.Is(err, fault.ErrChecksumMismatch) {
		t.Fatalf("bad header error = %v", err)
	}
}

type byteReaderAt []byte

func newReaderAt(data []byte) byteReaderAt { return byteReaderAt(data) }

func (r byteReaderAt) ReadAt(p []byte, off int64) (int, error) {
	return copy(p, r[off:]), nil
}
