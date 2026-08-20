// Package setup decodes the metadata streams used by modern Inno Setup files.
package setup

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"math"
	"strings"
	"unicode/utf16"

	"github.com/Peiratooo/innoextract-go/internal/fault"
	"github.com/Peiratooo/innoextract-go/internal/format"
	"github.com/Peiratooo/innoextract-go/internal/loader"
	"github.com/ulikunitz/xz/lzma"
)

const defaultHeaderLimit int64 = 64 << 20

// Options controls setup metadata parsing. Codepage is used only for legacy
// ANSI setup data; 6.x installers are Unicode and always use UTF-16LE.
type Options struct {
	Codepage    uint32
	HeaderLimit int64
}

type cursor struct {
	b       []byte
	pos     int
	strings int
	phase   string
}

func (c *cursor) remaining() int { return len(c.b) - c.pos }

func (c *cursor) read(n int) ([]byte, error) {
	if n < 0 || n > c.remaining() {
		return nil, fmt.Errorf("%w: truncated %s at header offset %#x: need %d bytes, have %d", fault.ErrCorrupt, c.phase, c.pos, n, c.remaining())
	}
	b := c.b[c.pos : c.pos+n]
	c.pos += n
	return b, nil
}

func (c *cursor) u8() (uint8, error) {
	b, err := c.read(1)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

func (c *cursor) u16() (uint16, error) {
	b, err := c.read(2)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint16(b), nil
}

func (c *cursor) i16() (int16, error) {
	v, err := c.u16()
	return int16(v), err
}

func (c *cursor) u32() (uint32, error) {
	b, err := c.read(4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b), nil
}

func (c *cursor) i32() (int32, error) {
	v, err := c.u32()
	return int32(v), err
}

func (c *cursor) u64() (uint64, error) {
	b, err := c.read(8)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(b), nil
}

func (c *cursor) i64() (int64, error) {
	v, err := c.u64()
	return int64(v), err
}

func (c *cursor) stringRaw(limit int64) ([]byte, error) {
	start := c.pos
	index := c.strings
	c.strings++
	n, err := c.u32()
	if err != nil {
		return nil, err
	}
	if uint64(n) > uint64(c.remaining()) || int64(n) > limit {
		return nil, fmt.Errorf("%w: %s string %d at header offset %#x has length %d", fault.ErrLimitExceeded, c.phase, index, start, n)
	}
	return c.read(int(n))
}

func (c *cursor) stringUTF16(limit int64) (string, error) {
	b, err := c.stringRaw(limit)
	if err != nil {
		return "", err
	}
	if len(b)%2 != 0 {
		// Preserve the stream position while making malformed UTF-16 benign.
		b = append(b, 0)
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return string(utf16.Decode(u)), nil
}

func (c *cursor) skipString(limit int64) error {
	_, err := c.stringRaw(limit)
	return err
}

func (c *cursor) bool8() (bool, error) {
	v, err := c.u8()
	return v != 0, err
}

func (c *cursor) skip(n int) error {
	_, err := c.read(n)
	return err
}

func Parse(r io.ReaderAt, opts Options) (*format.Archive, error) {
	if r == nil {
		return nil, fmt.Errorf("%w: nil reader", fault.ErrInvalidFormat)
	}
	if opts.HeaderLimit <= 0 {
		opts.HeaderLimit = defaultHeaderLimit
	}
	offsets, err := loader.Locate(r)
	if err != nil {
		return nil, err
	}
	if offsets.HeaderOffset > math.MaxInt64 {
		return nil, fmt.Errorf("%w: setup header offset overflows int64", fault.ErrCorrupt)
	}
	position := int64(offsets.HeaderOffset)
	version, err := readVersion(r, position)
	if err != nil {
		return nil, err
	}
	if version.Major != 6 || version.Minor > 7 {
		return nil, fmt.Errorf("%w: Inno Setup %s", fault.ErrUnsupportedVersion, version.String())
	}

	outerEncrypted := false
	if versionAtLeast(version, 6, 5, 0) {
		outerEncrypted, position, err = readEncryptionHeader(r, position+64)
		if err != nil {
			return nil, err
		}
	} else {
		position += 64
	}

	primary, next, err := readBlock(r, position, version, opts.HeaderLimit)
	if err != nil {
		return nil, err
	}
	c := cursor{b: primary, phase: "header"}
	header, counts, headerFlags, err := parseHeader(&c, version, outerEncrypted, opts.HeaderLimit)
	if err != nil {
		return nil, err
	}

	archive := &format.Archive{Offsets: offsets, Version: version, Header: header}
	c.phase = "language"
	archive.Languages = make([]format.Language, 0, counts.languages)
	for i := 0; i < counts.languages; i++ {
		lang, err := parseLanguage(&c, version, opts.HeaderLimit)
		if err != nil {
			return nil, err
		}
		archive.Languages = append(archive.Languages, lang)
	}
	// Decode the rest of the strings with the same UTF-16LE policy. A custom
	// codepage is intentionally not applied to Unicode setup data.
	_ = opts.Codepage

	c.phase = "message"
	for i := 0; i < counts.messages; i++ {
		if err := skipMessage(&c, version, opts.HeaderLimit); err != nil {
			return nil, err
		}
	}
	c.phase = "permission"
	for i := 0; i < counts.permissions; i++ {
		if err := c.skipString(opts.HeaderLimit); err != nil {
			return nil, err
		}
	}
	c.phase = "type"
	for i := 0; i < counts.types; i++ {
		if err := skipType(&c, version, opts.HeaderLimit); err != nil {
			return nil, err
		}
	}
	c.phase = "component"
	for i := 0; i < counts.components; i++ {
		if err := skipComponent(&c, version, opts.HeaderLimit); err != nil {
			return nil, err
		}
	}
	c.phase = "task"
	for i := 0; i < counts.tasks; i++ {
		if err := skipTask(&c, version, opts.HeaderLimit); err != nil {
			return nil, err
		}
	}
	c.phase = "directory"
	for i := 0; i < counts.directories; i++ {
		if err := skipDirectory(&c, version, opts.HeaderLimit); err != nil {
			return nil, err
		}
	}
	c.phase = "ISSig key"
	for i := 0; i < counts.issigKeys; i++ {
		if err := skipISSigKey(&c, opts.HeaderLimit); err != nil {
			return nil, err
		}
	}
	archive.Files = make([]format.FileEntry, 0, counts.files)
	c.phase = "file"
	for i := 0; i < counts.files; i++ {
		entry, err := parseFile(&c, version, opts.HeaderLimit)
		if err != nil {
			return nil, err
		}
		archive.Files = append(archive.Files, entry)
	}
	c.phase = "icon"
	for i := 0; i < counts.icons; i++ {
		if err := skipIcon(&c, version, opts.HeaderLimit); err != nil {
			return nil, err
		}
	}
	c.phase = "INI"
	for i := 0; i < counts.inis; i++ {
		if err := skipINI(&c, version, opts.HeaderLimit); err != nil {
			return nil, err
		}
	}
	archive.Registry = make([]format.RegistryEntry, 0, counts.registries)
	c.phase = "registry"
	for i := 0; i < counts.registries; i++ {
		entry, err := parseRegistry(&c, version, opts.HeaderLimit)
		if err != nil {
			return nil, err
		}
		archive.Registry = append(archive.Registry, entry)
	}
	for i := 0; i < counts.deletes+counts.uninstallDeletes; i++ {
		if err := skipDelete(&c, version, opts.HeaderLimit); err != nil {
			return nil, err
		}
	}
	for i := 0; i < counts.runs+counts.uninstallRuns; i++ {
		if err := skipRun(&c, version, opts.HeaderLimit); err != nil {
			return nil, err
		}
	}
	if err := skipWizardAndDLLs(&c, version, header.Compression, counts.sevenZip, opts.HeaderLimit); err != nil {
		return nil, err
	}
	if c.remaining() != 0 {
		return nil, fmt.Errorf("%w: unknown data at end of primary header stream", fault.ErrCorrupt)
	}

	secondary, _, err := readBlock(r, next, version, opts.HeaderLimit)
	if err != nil {
		return nil, err
	}
	dc := cursor{b: secondary}
	archive.DataEntries = make([]format.DataEntry, 0, counts.dataEntries)
	for i := 0; i < counts.dataEntries; i++ {
		entry, err := parseDataEntry(&dc, version, header.Compression)
		if err != nil {
			return nil, err
		}
		archive.DataEntries = append(archive.DataEntries, entry)
	}
	if dc.remaining() != 0 {
		return nil, fmt.Errorf("%w: unknown data at end of secondary header stream", fault.ErrCorrupt)
	}
	_ = headerFlags
	return archive, nil
}

func readVersion(r io.ReaderAt, off int64) (format.Version, error) {
	b, err := readAt(r, off, 64)
	if err != nil {
		return format.Version{}, err
	}
	n := bytes.IndexByte(b, 0)
	if n >= 0 {
		b = b[:n]
	}
	s := string(b)
	const prefix = "Inno Setup Setup Data ("
	if !strings.HasPrefix(s, prefix) {
		return format.Version{}, fmt.Errorf("%w: missing setup data version", fault.ErrInvalidFormat)
	}
	inside := strings.TrimSuffix(strings.TrimPrefix(s, prefix), ")")
	inside = strings.TrimSpace(strings.TrimSuffix(inside, "(u)"))
	parts := strings.Split(inside, ".")
	if len(parts) < 3 || len(parts) > 4 {
		return format.Version{}, fmt.Errorf("%w: invalid setup version %q", fault.ErrInvalidFormat, s)
	}
	var nums [4]uint8
	for i := range parts {
		var n int
		if _, err := fmt.Sscanf(parts[i], "%d", &n); err != nil || n < 0 || n > 255 {
			return format.Version{}, fmt.Errorf("%w: invalid setup version %q", fault.ErrInvalidFormat, s)
		}
		nums[i] = uint8(n)
	}
	v := format.Version{Major: nums[0], Minor: nums[1], Patch: nums[2], Revision: nums[3], Known: true}
	v.Unicode = v.Major >= 6 || strings.Contains(s, "(u)") || strings.Contains(s, "(U)")
	return v, nil
}

func versionAtLeast(v format.Version, a, b, c uint8) bool {
	if v.Major != a {
		return v.Major > a
	}
	if v.Minor != b {
		return v.Minor > b
	}
	return v.Patch >= c
}

func versionBefore(v format.Version, a, b, c, d uint8) bool {
	if v.Major != a {
		return v.Major < a
	}
	if v.Minor != b {
		return v.Minor < b
	}
	if v.Patch != c {
		return v.Patch < c
	}
	return v.Revision < d
}

func readEncryptionHeader(r io.ReaderAt, off int64) (bool, int64, error) {
	b, err := readAt(r, off, 53)
	if err != nil {
		return false, off, err
	}
	if crc32.ChecksumIEEE(b[4:]) != binary.LittleEndian.Uint32(b[:4]) {
		return false, off, fmt.Errorf("%w: encryption header checksum", fault.ErrChecksumMismatch)
	}
	return b[4] != 0, off + 53, nil
}

func readAt(r io.ReaderAt, off int64, n int) ([]byte, error) {
	if off < 0 || n < 0 || int64(n) > math.MaxInt64-off {
		return nil, fmt.Errorf("%w: invalid reader range", fault.ErrCorrupt)
	}
	b := make([]byte, n)
	got, err := r.ReadAt(b, off)
	if got != n {
		if err == nil {
			err = io.ErrUnexpectedEOF
		}
		return nil, fmt.Errorf("%w: read at %#x: %v", fault.ErrCorrupt, off, err)
	}
	return b, nil
}

func readBlock(r io.ReaderAt, off int64, v format.Version, limit int64) ([]byte, int64, error) {
	headerLen := int64(9)
	if versionAtLeast(v, 6, 7, 0) {
		headerLen = 13
	}
	h, err := readAt(r, off, int(headerLen))
	if err != nil {
		return nil, off, err
	}
	expected := binary.LittleEndian.Uint32(h)
	var stored uint64
	if headerLen == 13 {
		stored = binary.LittleEndian.Uint64(h[4:12])
	} else {
		stored = uint64(binary.LittleEndian.Uint32(h[4:8]))
	}
	if stored > uint64(limit) || stored > uint64(math.MaxInt64-headerLen) {
		return nil, off, fmt.Errorf("%w: setup block size %d", fault.ErrLimitExceeded, stored)
	}
	if crc32.ChecksumIEEE(h[4:]) != expected {
		return nil, off, fmt.Errorf("%w: block header checksum", fault.ErrChecksumMismatch)
	}
	raw, err := readAt(r, off+headerLen, int(stored))
	if err != nil {
		return nil, off, err
	}
	stream, err := unwrapBlockChunks(raw)
	if err != nil {
		return nil, off, err
	}
	compressed := h[len(h)-1] != 0
	if !compressed {
		if int64(len(stream)) > limit {
			return nil, off, fmt.Errorf("%w: decompressed block", fault.ErrLimitExceeded)
		}
		return stream, off + headerLen + int64(stored), nil
	}
	var decoded []byte
	if versionAtLeast(v, 4, 1, 6) {
		decoded, err = decodeRawLZMA1(stream, limit)
	} else {
		decoded, err = decodeZlib(stream, limit)
	}
	if err != nil {
		return nil, off, err
	}
	return decoded, off + headerLen + int64(stored), nil
}

func unwrapBlockChunks(raw []byte) ([]byte, error) {
	var out bytes.Buffer
	for len(raw) > 0 {
		if len(raw) < 4 {
			return nil, fmt.Errorf("%w: truncated block chunk checksum", fault.ErrCorrupt)
		}
		want := binary.LittleEndian.Uint32(raw)
		raw = raw[4:]
		n := len(raw)
		if n > 4096 {
			n = 4096
		}
		if n == 0 {
			return nil, fmt.Errorf("%w: empty block chunk", fault.ErrCorrupt)
		}
		part := raw[:n]
		if crc32.ChecksumIEEE(part) != want {
			return nil, fmt.Errorf("%w: block chunk checksum", fault.ErrChecksumMismatch)
		}
		_, _ = out.Write(part)
		raw = raw[n:]
	}
	return out.Bytes(), nil
}

func decodeZlib(stream []byte, limit int64) ([]byte, error) {
	zr, err := zlib.NewReader(bytes.NewReader(stream))
	if err != nil {
		return nil, fmt.Errorf("%w: zlib: %v", fault.ErrCorrupt, err)
	}
	defer zr.Close()
	return readLimited(zr, limit)
}

func decodeRawLZMA1(stream []byte, limit int64) ([]byte, error) {
	if len(stream) < 5 {
		return nil, fmt.Errorf("%w: short LZMA header", fault.ErrCorrupt)
	}
	// Inno stores the classic five-byte properties/dictionary header but omits
	// the eight-byte uncompressed-size field. Add an unknown-size field for the
	// xz/lzma reader.
	header := make([]byte, 13)
	copy(header, stream[:5])
	for i := 5; i < 13; i++ {
		header[i] = 0xff
	}
	cap := int(limit)
	if cap < 1<<20 {
		cap = 1 << 20
	}
	if int64(cap) > int64(math.MaxInt32) {
		cap = math.MaxInt32
	}
	lr, err := (lzma.ReaderConfig{DictCap: cap}).NewReader(bytes.NewReader(append(header, stream[5:]...)))
	if err != nil {
		return nil, fmt.Errorf("%w: LZMA: %v", fault.ErrCorrupt, err)
	}
	return readLimited(lr, limit)
}

func readLimited(r io.Reader, limit int64) ([]byte, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("%w: non-positive limit", fault.ErrLimitExceeded)
	}
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%w: decompressed data", fault.ErrLimitExceeded)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: decompression: %v", fault.ErrCorrupt, err)
	}
	return b, nil
}

type counts struct {
	languages, messages, permissions, types, components, tasks, directories int
	issigKeys, files, dataEntries, icons, inis, registries                  int
	deletes, uninstallDeletes, runs, uninstallRuns                          int
	sevenZip                                                                bool
}

func countInt(v uint32) (int, error) {
	if uint64(v) > uint64(math.MaxInt) {
		return 0, fmt.Errorf("%w: entry count overflows int", fault.ErrLimitExceeded)
	}
	return int(v), nil
}

func parseHeader(c *cursor, v format.Version, outerEncrypted bool, limit int64) (format.Header, counts, uint64, error) {
	var h format.Header
	var n counts
	var err error
	if h.AppName, err = c.stringUTF16(limit); err != nil {
		return h, n, 0, err
	}
	if _, err = c.stringUTF16(limit); err != nil {
		return h, n, 0, err
	}
	if h.AppID, err = c.stringUTF16(limit); err != nil {
		return h, n, 0, err
	}
	if _, err = c.stringUTF16(limit); err != nil {
		return h, n, 0, err
	}
	if h.Publisher, err = c.stringUTF16(limit); err != nil {
		return h, n, 0, err
	}
	if err = c.skipString(limit); err != nil {
		return h, n, 0, err
	} // publisher URL
	if err = c.skipString(limit); err != nil {
		return h, n, 0, err
	} // support phone
	if err = c.skipString(limit); err != nil {
		return h, n, 0, err
	} // support URL
	if err = c.skipString(limit); err != nil {
		return h, n, 0, err
	} // updates URL
	if h.AppVersion, err = c.stringUTF16(limit); err != nil {
		return h, n, 0, err
	}
	for i := 0; i < 2; i++ {
		if err = c.skipString(limit); err != nil {
			return h, n, 0, err
		}
	} // default dir/group
	if h.BaseFilename, err = c.stringUTF16(limit); err != nil {
		return h, n, 0, err
	}
	for i := 0; i < 4; i++ {
		if err = c.skipString(limit); err != nil {
			return h, n, 0, err
		}
	}
	for i := 0; i < 2; i++ {
		if err = c.skipString(limit); err != nil {
			return h, n, 0, err
		}
	}
	if err = c.skipString(limit); err != nil {
		return h, n, 0, err
	}
	for i := 0; i < 4; i++ {
		if err = c.skipString(limit); err != nil {
			return h, n, 0, err
		}
	}
	if err = c.skipString(limit); err != nil {
		return h, n, 0, err
	}
	if err = c.skipString(limit); err != nil {
		return h, n, 0, err
	}
	if err = c.skipString(limit); err != nil {
		return h, n, 0, err
	}
	if err = c.skipString(limit); err != nil {
		return h, n, 0, err
	}
	if versionAtLeast(v, 5, 6, 1) {
		if err = c.skipString(limit); err != nil {
			return h, n, 0, err
		}
		if err = c.skipString(limit); err != nil {
			return h, n, 0, err
		}
	}
	if versionAtLeast(v, 6, 3, 0) {
		if err = c.skipString(limit); err != nil {
			return h, n, 0, err
		}
		if err = c.skipString(limit); err != nil {
			return h, n, 0, err
		}
	}
	if versionAtLeast(v, 6, 4, 2) {
		if err = c.skipString(limit); err != nil {
			return h, n, 0, err
		}
	}
	if versionAtLeast(v, 6, 5, 0) {
		sevenZipLibrary, readErr := c.stringRaw(limit)
		if readErr != nil {
			return h, n, 0, readErr
		}
		n.sevenZip = len(sevenZipLibrary) != 0
	}
	if versionAtLeast(v, 6, 7, 0) {
		for i := 0; i < 5; i++ {
			if err = c.skipString(limit); err != nil {
				return h, n, 0, err
			}
		}
	}
	for i := 0; i < 3; i++ {
		if err = c.skipString(limit); err != nil {
			return h, n, 0, err
		}
	} // license/info
	if err = c.skipString(limit); err != nil {
		return h, n, 0, err
	} // compiled code

	if n.languages, err = readCount(c); err != nil {
		return h, n, 0, err
	}
	if n.messages, err = readCount(c); err != nil {
		return h, n, 0, err
	}
	if n.permissions, err = readCount(c); err != nil {
		return h, n, 0, err
	}
	if n.types, err = readCount(c); err != nil {
		return h, n, 0, err
	}
	if n.components, err = readCount(c); err != nil {
		return h, n, 0, err
	}
	if n.tasks, err = readCount(c); err != nil {
		return h, n, 0, err
	}
	if n.directories, err = readCount(c); err != nil {
		return h, n, 0, err
	}
	if versionAtLeast(v, 6, 5, 0) {
		if n.issigKeys, err = readCount(c); err != nil {
			return h, n, 0, err
		}
	}
	if n.files, err = readCount(c); err != nil {
		return h, n, 0, err
	}
	if n.dataEntries, err = readCount(c); err != nil {
		return h, n, 0, err
	}
	if n.icons, err = readCount(c); err != nil {
		return h, n, 0, err
	}
	if n.inis, err = readCount(c); err != nil {
		return h, n, 0, err
	}
	if n.registries, err = readCount(c); err != nil {
		return h, n, 0, err
	}
	if n.deletes, err = readCount(c); err != nil {
		return h, n, 0, err
	}
	if n.uninstallDeletes, err = readCount(c); err != nil {
		return h, n, 0, err
	}
	if n.runs, err = readCount(c); err != nil {
		return h, n, 0, err
	}
	if n.uninstallRuns, err = readCount(c); err != nil {
		return h, n, 0, err
	}
	if err = skipWindowsRange(c, v); err != nil {
		return h, n, 0, err
	}

	if versionBefore(v, 6, 4, 0, 1) {
		if _, err = c.u32(); err != nil {
			return h, n, 0, err
		}
		if _, err = c.u32(); err != nil {
			return h, n, 0, err
		}
	}
	if versionAtLeast(v, 6, 6, 0) {
		if _, err = c.u32(); err != nil {
			return h, n, 0, err
		}
		if _, err = c.u32(); err != nil {
			return h, n, 0, err
		}
		if _, err = c.u8(); err != nil {
			return h, n, 0, err
		}
	} else {
		if versionAtLeast(v, 6, 0, 0) {
			if _, err = c.u8(); err != nil {
				return h, n, 0, err
			}
			if _, err = c.u32(); err != nil {
				return h, n, 0, err
			}
			if _, err = c.u32(); err != nil {
				return h, n, 0, err
			}
		}
	}
	if versionAtLeast(v, 5, 5, 7) {
		if _, err = c.u8(); err != nil {
			return h, n, 0, err
		}
	}
	if versionAtLeast(v, 6, 5, 2) {
		if _, err = c.u32(); err != nil {
			return h, n, 0, err
		}
		if _, err = c.u32(); err != nil {
			return h, n, 0, err
		}
	}
	if versionAtLeast(v, 6, 7, 0) {
		if _, err = c.u32(); err != nil {
			return h, n, 0, err
		}
	}
	if versionAtLeast(v, 6, 6, 0) {
		if _, err = c.u32(); err != nil {
			return h, n, 0, err
		}
		if _, err = c.u32(); err != nil {
			return h, n, 0, err
		}
	}
	if versionAtLeast(v, 6, 7, 0) {
		if _, err = c.u32(); err != nil {
			return h, n, 0, err
		}
	}
	if versionAtLeast(v, 6, 6, 1) {
		if _, err = c.u8(); err != nil {
			return h, n, 0, err
		}
	}
	if versionAtLeast(v, 6, 7, 0) {
		if _, err = c.u8(); err != nil {
			return h, n, 0, err
		}
		if _, err = c.u8(); err != nil {
			return h, n, 0, err
		}
	}

	if versionAtLeast(v, 6, 5, 0) {
		// Encryption metadata was moved to the outer stream.
	} else if versionAtLeast(v, 6, 4, 0) {
		h.Password = format.Checksum{Type: format.ChecksumPBKDF2SHA256XChaCha20, Data: mustReadCursor(c, 4)}
		h.PasswordSalt, err = c.read(44)
		if err != nil {
			return h, n, 0, err
		}
	} else {
		h.Password = format.Checksum{Type: format.ChecksumSHA1, Data: mustReadCursor(c, 20)}
		h.PasswordSalt, err = c.read(8)
		if err != nil {
			return h, n, 0, err
		}
	}
	if _, err = c.i64(); err != nil {
		return h, n, 0, err
	}
	if h.SlicesPerDisk, err = c.u32(); err != nil {
		return h, n, 0, err
	}
	if err = c.skip(1); err != nil {
		return h, n, 0, err
	} // uninstall log mode
	if err = c.skip(1); err != nil {
		return h, n, 0, err
	} // dir exists warning
	if err = c.skip(1); err != nil {
		return h, n, 0, err
	} // privileges required
	if versionAtLeast(v, 5, 7, 0) {
		if err = c.skip(1); err != nil {
			return h, n, 0, err
		}
	}
	if err = c.skip(2); err != nil {
		return h, n, 0, err
	} // language dialog/detection
	compression, err := c.u8()
	if err != nil {
		return h, n, 0, err
	}
	h.Compression = mapCompression(compression)
	if versionAtLeast(v, 6, 3, 0) {
		// expressions were already consumed above
	}
	if err = c.skip(2); err != nil {
		return h, n, 0, err
	} // disable dir/program pages
	if versionAtLeast(v, 5, 5, 0) {
		if _, err = c.u64(); err != nil {
			return h, n, 0, err
		}
	}
	flags, err := readHeaderFlags(c, v)
	if err != nil {
		return h, n, 0, err
	}
	if versionAtLeast(v, 6, 5, 0) {
		h.Encrypted = outerEncrypted
	} else {
		h.Encrypted = flags&(uint64(1)<<headerEncryptionBit(v)) != 0
	}
	h.UnsupportedEncryption = h.Encrypted
	return h, n, flags, nil
}

func mustReadCursor(c *cursor, n int) []byte {
	b, _ := c.read(n)
	return append([]byte(nil), b...)
}

func readCount(c *cursor) (int, error) {
	n, err := c.u32()
	if err != nil {
		return 0, err
	}
	return countInt(n)
}

func mapCompression(v uint8) format.Compression {
	switch v {
	case 0:
		return format.Stored
	case 1:
		return format.Zlib
	case 2:
		return format.BZip2
	case 3:
		return format.LZMA1
	case 4:
		return format.LZMA2
	default:
		return format.UnknownCompression
	}
}

func readHeaderFlags(c *cursor, v format.Version) (uint64, error) {
	n := (headerFlagCount(v) + 7) / 8
	if versionAtLeast(v, 6, 7, 0) {
		n = 8
	}
	b, err := c.read(n)
	if err != nil {
		return 0, err
	}
	var bits uint64
	for i, x := range b {
		bits |= uint64(x) << (8 * i)
	}
	return bits, nil
}

func headerEncryptionBit(v format.Version) int {
	for i, name := range headerFlagNames(v) {
		if name == "EncryptionUsed" {
			return i
		}
	}
	return -1
}

func headerFlagCount(v format.Version) int {
	return len(headerFlagNames(v))
}

func headerFlagNames(v format.Version) []string {
	var out []string
	add := func(name string, ok bool) {
		if ok {
			out = append(out, name)
		}
	}
	add("DisableStartupPrompt", true)
	add("Uninstallable", versionBefore(v, 5, 3, 10, 0))
	add("CreateAppDir", true)
	add("DisableDirPage", versionBefore(v, 5, 3, 3, 0))
	add("DisableDirExistsWarning", versionBefore(v, 1, 3, 6, 0))
	add("DisableProgramGroupPage", versionBefore(v, 5, 3, 3, 0))
	add("AllowNoIcons", true)
	add("AlwaysRestart", true)
	add("AlwaysUsePersonalGroup", true)
	for _, name := range []string{"WindowVisible", "WindowShowCaption", "WindowResizable", "WindowStartMaximized"} {
		add(name, versionBefore(v, 6, 4, 0, 1))
	}
	add("EnableDirDoesntExistWarning", true)
	add("DisableAppendDir", versionBefore(v, 4, 1, 2, 0))
	add("Password", true)
	add("AllowRootDirectory", true)
	add("DisableFinishedPage", true)
	add("AdminPrivilegesRequired", versionBefore(v, 3, 0, 4, 0))
	add("AlwaysCreateUninstallIcon", versionBefore(v, 3, 0, 0, 0))
	add("OverwriteUninstRegEntries", versionBefore(v, 1, 3, 6, 0))
	add("ChangesAssociations", versionBefore(v, 5, 6, 1, 0))
	add("CreateUninstallRegKey", versionBefore(v, 5, 3, 8, 0))
	add("UsePreviousAppDir", versionBefore(v, 6, 7, 0, 0))
	add("BackColorHorizontal", versionBefore(v, 6, 4, 0, 1))
	add("UsePreviousGroup", versionBefore(v, 6, 7, 0, 0))
	add("UpdateUninstallLogAppName", true)
	add("UsePreviousSetupType", versionBefore(v, 6, 7, 0, 0))
	add("DisableReadyMemo", true)
	add("AlwaysShowComponentsList", true)
	add("FlatComponentsList", true)
	add("ShowComponentSizes", true)
	add("UsePreviousTasks", versionBefore(v, 6, 7, 0, 0))
	add("DisableReadyPage", true)
	add("AlwaysShowDirOnReadyPage", true)
	add("AlwaysShowGroupOnReadyPage", true)
	add("AllowUNCPath", true)
	add("UserInfoPage", true)
	add("UsePreviousUserInfo", versionBefore(v, 6, 7, 0, 0))
	add("UninstallRestartComputer", true)
	add("RestartIfNeededByRun", true)
	add("ShowTasksTreeLines", true)
	add("ShowLanguageDialog", false)
	add("DetectLanguageUsingLocale", false)
	add("AllowCancelDuringInstall", true)
	add("WizardImageStretch", true)
	add("AppendDefaultDirName", true)
	add("AppendDefaultGroupName", true)
	add("EncryptionUsed", versionBefore(v, 6, 5, 0, 0))
	add("ChangesEnvironment", versionBefore(v, 5, 6, 1, 0))
	add("ShowUndisplayableLanguages", false)
	add("SetupLogging", true)
	add("SignedUninstaller", true)
	add("UsePreviousLanguage", true)
	add("DisableWelcomePage", true)
	add("CloseApplications", true)
	add("RestartApplications", true)
	add("AllowNetworkDrive", true)
	add("ForceCloseApplications", true)
	add("AppNameHasConsts", true)
	add("UsePreviousPrivileges", true)
	add("WizardResizable", versionBefore(v, 6, 6, 0, 0))
	add("UninstallLogging", versionAtLeast(v, 6, 3, 0))
	add("WizardModern", versionAtLeast(v, 6, 6, 0))
	add("WizardBorderStyled", versionAtLeast(v, 6, 6, 0))
	add("WizardKeepAspectRatio", versionAtLeast(v, 6, 6, 0))
	add("WizardLightButtonsUnstyled", versionAtLeast(v, 6, 6, 0) && versionBefore(v, 6, 7, 0, 0))
	add("RedirectionGuard", versionAtLeast(v, 6, 7, 0))
	add("WizardBevelsHidden", versionAtLeast(v, 6, 7, 0))
	return out
}

func skipWindowsRange(c *cursor, v format.Version) error {
	_ = v
	// A range contains begin and end windows_version values. Each value has
	// WinVersion (4), NTVersion (4), and the NT service-pack pair (2).
	return c.skip(20)
}

func skipWindowsVersion(c *cursor, v format.Version) error {
	_ = v
	// The main setup header stores one windows_version, not a range.
	return c.skip(10)
}

func parseLanguage(c *cursor, v format.Version, limit int64) (format.Language, error) {
	var l format.Language
	var err error
	if versionAtLeast(v, 4, 0, 0) {
		l.Name, err = c.stringUTF16(limit)
		if err != nil {
			return l, err
		}
	}
	if l.DisplayName, err = c.stringUTF16(limit); err != nil {
		return l, err
	}
	if err = c.skipString(limit); err != nil {
		return l, err
	} // dialog font
	if !versionAtLeast(v, 6, 6, 0) {
		if err = c.skipString(limit); err != nil {
			return l, err
		}
	} // title font (removed in 6.6)
	if err = c.skipString(limit); err != nil {
		return l, err
	} // welcome font
	if !versionAtLeast(v, 6, 6, 0) {
		if err = c.skipString(limit); err != nil {
			return l, err
		}
	} // copyright font (removed in 6.6)
	if err = c.skipString(limit); err != nil {
		return l, err
	} // data
	for i := 0; i < 3; i++ {
		if err = c.skipString(limit); err != nil {
			return l, err
		}
	}
	if versionAtLeast(v, 6, 6, 0) {
		x, e := c.u16()
		if e != nil {
			return l, e
		}
		l.ID = uint32(x)
	} else {
		x, e := c.u32()
		if e != nil {
			return l, e
		}
		l.ID = x
	}
	l.Codepage = 1200
	// Numeric font/layout fields follow the language ID. In 6.6 the title
	// and copyright sizes became two base-scale integers.
	if err = c.skip(4); err != nil { // dialog font size
		return l, err
	}
	if versionAtLeast(v, 6, 6, 0) {
		if err = c.skip(8); err != nil { // base scale height/width
			return l, err
		}
	} else {
		if err = c.skip(4); err != nil { // title font size
			return l, err
		}
	}
	if err = c.skip(4); err != nil { // welcome font size
		return l, err
	}
	if !versionAtLeast(v, 6, 6, 0) {
		if err = c.skip(4); err != nil { // copyright font size
			return l, err
		}
	}
	if versionAtLeast(v, 5, 2, 3) {
		if err = c.skip(1); err != nil {
			return l, err
		}
	}
	if l.Name == "" {
		l.Name = "default"
	}
	return l, nil
}

func skipMessage(c *cursor, v format.Version, limit int64) error {
	if err := c.skipString(limit); err != nil {
		return err
	}
	if err := c.skipString(limit); err != nil {
		return err
	}
	_, err := c.i32()
	return err
}

func skipType(c *cursor, v format.Version, limit int64) error {
	for i := 0; i < 2; i++ {
		if err := c.skipString(limit); err != nil {
			return err
		}
	}
	if err := skipWindowsRange(c, v); err != nil {
		return err
	}
	if err := c.skip(1); err != nil {
		return err
	}
	if err := c.skip(1); err != nil {
		return err
	}
	return c.skip(8)
}

func skipComponent(c *cursor, v format.Version, limit int64) error {
	for i := 0; i < 5; i++ {
		if err := c.skipString(limit); err != nil {
			return err
		}
	}
	if _, err := c.u64(); err != nil {
		return err
	}
	if versionAtLeast(v, 6, 7, 0) {
		if err := c.skip(1); err != nil {
			return err
		}
	} else {
		if err := c.skip(4); err != nil {
			return err
		}
	}
	if err := c.skip(1); err != nil {
		return err
	}
	if err := skipWindowsRange(c, v); err != nil {
		return err
	}
	if err := c.skip(1); err != nil {
		return err
	}
	return c.skip(8)
}

func skipTask(c *cursor, v format.Version, limit int64) error {
	for i := 0; i < 6; i++ {
		if err := c.skipString(limit); err != nil {
			return err
		}
	}
	if versionAtLeast(v, 6, 7, 0) {
		if err := c.skip(1); err != nil {
			return err
		}
	} else {
		if err := c.skip(4); err != nil {
			return err
		}
	}
	if err := c.skip(1); err != nil {
		return err
	}
	if err := skipWindowsRange(c, v); err != nil {
		return err
	}
	return c.skip(1)
}

func skipDirectory(c *cursor, v format.Version, limit int64) error {
	if err := c.skipString(limit); err != nil {
		return err
	}
	for i := 0; i < 4; i++ {
		if err := c.skipString(limit); err != nil {
			return err
		}
	}
	if err := c.skip(4); err != nil {
		return err
	}
	if err := skipWindowsRange(c, v); err != nil {
		return err
	}
	if err := c.skip(2); err != nil {
		return err
	}
	return c.skip(1)
}

func skipISSigKey(c *cursor, limit int64) error {
	for i := 0; i < 3; i++ {
		if err := c.skipString(limit); err != nil {
			return err
		}
	}
	return nil
}

func parseFile(c *cursor, v format.Version, limit int64) (format.FileEntry, error) {
	var f format.FileEntry
	var err error
	if f.Source, err = c.stringUTF16(limit); err != nil {
		return f, err
	}
	if f.Destination, err = c.stringUTF16(limit); err != nil {
		return f, err
	}
	if err = c.skipString(limit); err != nil { // install font name
		return f, err
	}
	if err = c.skipString(limit); err != nil { // strong assembly name
		return f, err
	}
	if f.Components, err = c.stringUTF16(limit); err != nil {
		return f, err
	}
	if f.Tasks, err = c.stringUTF16(limit); err != nil {
		return f, err
	}
	if f.Languages, err = c.stringUTF16(limit); err != nil {
		return f, err
	}
	if f.Check, err = c.stringUTF16(limit); err != nil {
		return f, err
	}
	if f.AfterInstall, err = c.stringUTF16(limit); err != nil {
		return f, err
	}
	if f.BeforeInstall, err = c.stringUTF16(limit); err != nil {
		return f, err
	}
	if versionAtLeast(v, 6, 5, 0) {
		for i := 0; i < 5; i++ {
			if err = c.skipString(limit); err != nil {
				return f, err
			}
		}
		if err = c.skipString(limit); err != nil {
			return f, err
		}
		verificationDigest := mustReadCursor(c, 32)
		verification, readErr := c.u8()
		if readErr != nil {
			return f, readErr
		}
		if verification == 1 { // TSetupFileVerificationType.FileVerificationHash
			f.Checksum = format.Checksum{Type: format.ChecksumSHA256, Data: verificationDigest}
		}
		if verification > 2 {
			return f, fmt.Errorf("%w: unsupported file verification type %d", fault.ErrCorrupt, verification)
		}
	}
	if err = skipWindowsRange(c, v); err != nil {
		return f, err
	}
	if f.Location, err = c.u32(); err != nil {
		return f, err
	}
	if _, err = c.u32(); err != nil {
		return f, err
	}
	if f.Size, err = c.u64(); err != nil {
		return f, err
	}
	if err = c.skip(2); err != nil {
		return f, err
	}
	flags, err := readFileFlags(c, v)
	if err != nil {
		return f, err
	}
	f.Temporary = flags&(1<<3) != 0
	f.DontCopy = flags&(1<<19) != 0
	f.Bits32 = flags&(1<<26) != 0
	f.Bits64 = flags&(1<<27) != 0
	if err = c.skip(1); err != nil {
		return f, err
	}
	return f, nil
}

func readFileFlags(c *cursor, v format.Version) (uint64, error) {
	n := 5
	if versionAtLeast(v, 6, 7, 0) {
		n = 8
	}
	b, err := c.read(n)
	if err != nil {
		return 0, err
	}
	var out uint64
	for i, x := range b {
		out |= uint64(x) << (8 * i)
	}
	return out, nil
}

func parseRegistry(c *cursor, v format.Version, limit int64) (format.RegistryEntry, error) {
	var e format.RegistryEntry
	var err error
	if e.Key, err = c.stringUTF16(limit); err != nil {
		return e, err
	}
	if e.Name, err = c.stringUTF16(limit); err != nil {
		return e, err
	}
	if e.Value, err = c.stringUTF16(limit); err != nil {
		return e, err
	}
	for i := 0; i < 4; i++ {
		if err = c.skipString(limit); err != nil {
			return e, err
		}
	}
	if err = skipWindowsRange(c, v); err != nil {
		return e, err
	}
	if err = c.skip(4 + 2 + 1 + 2); err != nil {
		return e, err
	}
	return e, nil
}

func skipIcon(c *cursor, v format.Version, limit int64) error {
	for i := 0; i < 6; i++ {
		if err := c.skipString(limit); err != nil {
			return err
		}
	}
	if err := skipCondition(c, v, limit); err != nil {
		return err
	}
	if versionAtLeast(v, 5, 3, 5) {
		if err := c.skipString(limit); err != nil {
			return err
		}
	}
	if versionAtLeast(v, 6, 1, 0) {
		if err := c.skip(16); err != nil {
			return err
		}
	}
	if err := skipWindowsRange(c, v); err != nil {
		return err
	}
	if err := c.skip(4 + 4 + 1 + 2); err != nil {
		return err
	}
	return c.skip(1)
}

func skipINI(c *cursor, v format.Version, limit int64) error {
	for i := 0; i < 4; i++ {
		if err := c.skipString(limit); err != nil {
			return err
		}
	}
	if err := skipCondition(c, v, limit); err != nil {
		return err
	}
	if err := skipWindowsRange(c, v); err != nil {
		return err
	}
	return c.skip(1)
}

func skipDelete(c *cursor, v format.Version, limit int64) error {
	if err := c.skipString(limit); err != nil {
		return err
	}
	if err := skipCondition(c, v, limit); err != nil {
		return err
	}
	if err := skipWindowsRange(c, v); err != nil {
		return err
	}
	return c.skip(1)
}

func skipRun(c *cursor, v format.Version, limit int64) error {
	for i := 0; i < 7; i++ {
		if err := c.skipString(limit); err != nil {
			return err
		}
	}
	if err := skipCondition(c, v, limit); err != nil {
		return err
	}
	if err := skipWindowsRange(c, v); err != nil {
		return err
	}
	if err := c.skip(4 + 1); err != nil {
		return err
	}
	return c.skip(2)
}

func skipCondition(c *cursor, v format.Version, limit int64) error {
	n := 0
	if versionAtLeast(v, 2, 0, 0) {
		n = 2
	}
	if versionAtLeast(v, 4, 0, 1) {
		n++
	}
	if versionAtLeast(v, 4, 0, 0) {
		n++
	}
	if versionAtLeast(v, 4, 1, 0) {
		n += 2
	}
	for i := 0; i < n; i++ {
		if err := c.skipString(limit); err != nil {
			return err
		}
	}
	return nil
}

func skipWizardAndDLLs(c *cursor, v format.Version, compression format.Compression, sevenZip bool, limit int64) error {
	group := func() error {
		n := 1
		if versionAtLeast(v, 5, 6, 0) {
			var err error
			x, e := c.u32()
			if e != nil {
				return e
			}
			n, err = countInt(x)
			if err != nil {
				return err
			}
		}
		for i := 0; i < n; i++ {
			if err := c.skipString(limit); err != nil {
				return err
			}
		}
		return nil
	}
	if err := group(); err != nil {
		return err
	}
	if err := group(); err != nil {
		return err
	}
	if versionAtLeast(v, 6, 7, 0) {
		if err := group(); err != nil {
			return err
		}
	}
	if versionAtLeast(v, 6, 6, 0) {
		if err := group(); err != nil {
			return err
		}
		if err := group(); err != nil {
			return err
		}
		if versionAtLeast(v, 6, 7, 0) {
			if err := group(); err != nil {
				return err
			}
		}
	}
	if compression == format.BZip2 || (compression == format.Zlib && versionAtLeast(v, 4, 2, 6)) {
		if err := c.skipString(limit); err != nil {
			return err
		}
	}
	if versionAtLeast(v, 6, 5, 0) && sevenZip {
		if err := c.skipString(limit); err != nil {
			return err
		}
	}
	return nil
}

func parseDataEntry(c *cursor, v format.Version, compression format.Compression) (format.DataEntry, error) {
	var d format.DataEntry
	var err error
	if d.Chunk.FirstSlice, err = c.u32(); err != nil {
		return d, err
	}
	if d.Chunk.LastSlice, err = c.u32(); err != nil {
		return d, err
	}
	if versionAtLeast(v, 6, 5, 2) {
		if d.Chunk.Offset, err = c.u64(); err != nil {
			return d, err
		}
	} else {
		x, e := c.u32()
		err = e
		d.Chunk.Offset = uint64(x)
		if err != nil {
			return d, err
		}
	}
	d.Chunk.SortOffset = d.Chunk.Offset
	if d.File.Offset, err = c.u64(); err != nil {
		return d, err
	}
	if d.File.Size, err = c.u64(); err != nil {
		return d, err
	}
	if d.Chunk.Size, err = c.u64(); err != nil {
		return d, err
	}
	d.UncompressedSize = d.File.Size
	if versionAtLeast(v, 6, 4, 0) {
		d.File.Checksum = format.Checksum{Type: format.ChecksumSHA256, Data: mustReadCursor(c, 32)}
	} else {
		d.File.Checksum = format.Checksum{Type: format.ChecksumSHA1, Data: mustReadCursor(c, 20)}
	}
	if _, err = c.i64(); err != nil {
		return d, err
	}
	if err = c.skip(8); err != nil {
		return d, err
	}
	flags, err := readDataFlags(c, v)
	if err != nil {
		return d, err
	}
	if versionAtLeast(v, 6, 3, 0) && !versionAtLeast(v, 6, 4, 3) {
		if err = c.skip(1); err != nil {
			return d, err
		}
	}
	if flags&(1<<4) != 0 {
		d.Chunk.Compression = compression
	} else {
		d.Chunk.Compression = format.Stored
	}
	if flags&(1<<3) != 0 {
		if versionAtLeast(v, 6, 4, 0) {
			d.Chunk.Encryption = format.XChaCha20
		} else {
			d.Chunk.Encryption = format.ARC4SHA1
		}
	} else {
		d.Chunk.Encryption = format.Plaintext
	}
	if flags&(1<<2) != 0 {
		d.File.Filter = format.Instruction5309
	}
	return d, nil
}

func readDataFlags(c *cursor, v format.Version) (uint64, error) {
	n := 1
	if versionAtLeast(v, 6, 3, 0) && !versionAtLeast(v, 6, 4, 3) {
		n = 2
	}
	b, err := c.read(n)
	if err != nil {
		return 0, err
	}
	var out uint64
	for i, x := range b {
		out |= uint64(x) << (8 * i)
	}
	return out, nil
}
