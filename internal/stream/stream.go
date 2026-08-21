// Package stream decodes the compressed data portions described by the
// parser's internal format model.  It intentionally knows nothing about
// output paths or installation semantics.
package stream

import (
	"bufio"
	"bytes"
	"compress/bzip2"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"

	"github.com/Peiratooo/innoextract-go/internal/crypto"
	"github.com/Peiratooo/innoextract-go/internal/fault"
	"github.com/Peiratooo/innoextract-go/internal/format"
	"github.com/ulikunitz/xz/lzma"
)

const (
	defaultMemoryLimit = int64(1 << 30)
	chunkMagic         = "zlb\x1a"
	maxReadBuffer      = 32 << 10
)

var (
	errBadChunkMagic = errors.New("bad chunk magic")
	errBadSliceMagic = errors.New("bad slice magic")
)

// Options controls data-stream decoding.  Slices is used only when the
// archive stores data outside the executable.  A slice ReaderAt may either
// expose the raw payload or the complete .bin file; the latter is validated
// and its 12-byte slice header is hidden by this package.
type Options struct {
	Password    string
	MemoryLimit int64
	Slices      func(uint32) (io.ReaderAt, error)
}

// Result contains one successfully decoded archive file.  FileIndex is the
// index into format.Archive.Files.  In verifyOnly mode Data is nil.
type Result struct {
	FileIndex int
	Data      []byte
}

// Failure contains a file-local extraction failure.  Archive-wide structural
// errors are returned as the third result from Extract.
type Failure struct {
	FileIndex int
	Err       error
}

// Extract decodes all files described by a parsed archive.  It returns
// successful files and file-local failures separately so callers can report a
// useful partial result.  Password and archive-wide format errors are returned
// as the final error.
func Extract(r io.ReaderAt, a *format.Archive, opts Options, verifyOnly bool) ([]Result, []Failure, error) {
	if r == nil || a == nil {
		return nil, nil, fmt.Errorf("%w: nil reader or archive", fault.ErrInvalidFormat)
	}
	if opts.MemoryLimit == 0 {
		opts.MemoryLimit = defaultMemoryLimit
	}
	if opts.MemoryLimit < 0 {
		return nil, nil, fmt.Errorf("%w: negative memory limit", fault.ErrLimitExceeded)
	}

	key, err := archiveKey(a, opts.Password)
	if err != nil {
		return nil, nil, err
	}

	files := make([]fileAssembly, len(a.Files))
	groups, err := buildGroups(a, files)
	if err != nil {
		return nil, nil, err
	}

	budget := memoryBudget{limit: opts.MemoryLimit}
	if err := allocateFileBuffers(a, files, verifyOnly, &budget); err != nil {
		return nil, nil, err
	}
	/*
		The output buffers are reserved as one aggregate before the first
		allocation.  Apart from making the memory limit deterministic, this
		prevents a large archive from allocating several successful files and
		only discovering the aggregate limit halfway through the loop.
	*/
	for i := range files {
		if files[i].failed || !files[i].assemble {
			continue
		}
		files[i].data = make([]byte, int(files[i].totalSize))
	}

	// Process groups in source order.  The decoder is deliberately recreated
	// for each group; a solid stream is decoded once and then shared by every
	// file segment in that group.
	for _, group := range groups {
		if !groupNeeded(group, files) {
			continue
		}
		chunkData, err := decodeChunk(r, a, group.chunk, key, opts, budget.available())
		if err != nil {
			for _, ref := range group.refs {
				markFailure(files, ref.fileIndex, err)
			}
			continue
		}
		if err := budget.reserve(uint64(len(chunkData))); err != nil {
			for _, ref := range group.refs {
				markFailure(files, ref.fileIndex, err)
			}
			continue
		}

		for _, ref := range group.refs {
			if files[ref.fileIndex].failed {
				continue
			}
			segment, err := decodeFileSegment(chunkData, ref.entry.File, budget.available())
			if err != nil {
				markFailure(files, ref.fileIndex, err)
				continue
			}

			// NoFilter returns a slice of chunkData and does not allocate. All
			// other filters materialize a temporary buffer that must remain
			// inside the extraction memory budget until it has been copied.
			var transient uint64
			if ref.entry.File.Filter != format.NoFilter {
				transient = uint64(len(segment))
				if err := budget.reserve(transient); err != nil {
					markFailure(files, ref.fileIndex, err)
					continue
				}
			}

			var segmentErr error
			if ref.expectedSize != 0 && uint64(len(segment)) != ref.expectedSize {
				segmentErr = fmt.Errorf("%w: decoded size %d, expected %d", fault.ErrCorrupt, len(segment), ref.expectedSize)
			} else if files[ref.fileIndex].assemble {
				if ref.destOffset > uint64(len(files[ref.fileIndex].data)) || uint64(len(segment)) > uint64(len(files[ref.fileIndex].data))-ref.destOffset {
					segmentErr = fmt.Errorf("%w: file segment exceeds output", fault.ErrCorrupt)
				} else {
					copy(files[ref.fileIndex].data[int(ref.destOffset):], segment)
				}
			}
			budget.release(transient)
			if segmentErr != nil {
				markFailure(files, ref.fileIndex, segmentErr)
			}
		}
		budget.release(uint64(len(chunkData)))
	}

	results := make([]Result, 0, len(a.Files))
	failures := make([]Failure, 0)
	for i := range files {
		if files[i].skip {
			continue
		}
		if files[i].failed {
			failures = append(failures, Failure{FileIndex: i, Err: files[i].err})
			continue
		}
		if err := verifyFinalChecksum(a.Files[i], files[i].data, files[i].totalSize); err != nil {
			failures = append(failures, Failure{FileIndex: i, Err: err})
			continue
		}
		data := files[i].data
		if verifyOnly {
			data = nil
		}
		results = append(results, Result{FileIndex: i, Data: data})
	}
	return results, failures, nil
}

type fileAssembly struct {
	data      []byte
	totalSize uint64
	assemble  bool
	skip      bool
	failed    bool
	err       error
}

type segmentRef struct {
	fileIndex    int
	entry        format.DataEntry
	destOffset   uint64
	expectedSize uint64
}

type chunkGroup struct {
	chunk format.Chunk
	refs  []segmentRef
}

// buildGroups validates file locations and creates one group per unique
// chunk.  File segments retain their public-file destination offset so GOG
// Galaxy-style multipart entries can be assembled without filesystem output.
func buildGroups(a *format.Archive, files []fileAssembly) ([]chunkGroup, error) {
	groups := make([]chunkGroup, 0)
	groupIndex := make(map[format.Chunk]int)

	for fileIndex, file := range a.Files {
		// Inno uses an out-of-range location for external [Files] copy
		// commands. They are part of the manifest but have no archive payload.
		if int(file.Location) >= len(a.DataEntries) {
			files[fileIndex].skip = true
			continue
		}
		locations := make([]uint32, 0, 1+len(file.AdditionalLocations))
		locations = append(locations, file.Location)
		locations = append(locations, file.AdditionalLocations...)
		if len(locations) == 0 {
			markFailure(files, fileIndex, fmt.Errorf("%w: no data location", fault.ErrCorrupt))
			continue
		}

		var total uint64
		for _, location := range locations {
			if int(location) >= len(a.DataEntries) {
				markFailure(files, fileIndex, fmt.Errorf("%w: data entry %d", fault.ErrCorrupt, location))
				break
			}
			entry := a.DataEntries[location]
			if math.MaxUint64-total < entry.UncompressedSize {
				markFailure(files, fileIndex, fmt.Errorf("%w: multipart size overflow", fault.ErrCorrupt))
				break
			}
			total += entry.UncompressedSize
		}
		if files[fileIndex].failed {
			continue
		}
		if file.Size != 0 {
			total = file.Size
		}
		files[fileIndex].totalSize = total

		var dest uint64
		for _, location := range locations {
			entry := a.DataEntries[location]
			idx, ok := groupIndex[entry.Chunk]
			if !ok {
				idx = len(groups)
				groupIndex[entry.Chunk] = idx
				groups = append(groups, chunkGroup{chunk: entry.Chunk})
			}
			groups[idx].refs = append(groups[idx].refs, segmentRef{
				fileIndex:    fileIndex,
				entry:        entry,
				destOffset:   dest,
				expectedSize: entry.UncompressedSize,
			})
			if math.MaxUint64-dest < entry.UncompressedSize {
				markFailure(files, fileIndex, fmt.Errorf("%w: multipart destination overflow", fault.ErrCorrupt))
				break
			}
			dest += entry.UncompressedSize
		}
	}

	// Ensure files in a solid chunk are processed in source order.  This is
	// not required after chunk materialization, but keeps the behavior and
	// diagnostics aligned with the original extractor.
	for i := range groups {
		sort.SliceStable(groups[i].refs, func(x, y int) bool {
			return groups[i].refs[x].entry.File.Offset < groups[i].refs[y].entry.File.Offset
		})
	}
	return groups, nil
}

func groupNeeded(group chunkGroup, files []fileAssembly) bool {
	for _, ref := range group.refs {
		if ref.fileIndex < 0 || ref.fileIndex >= len(files) {
			continue
		}
		file := files[ref.fileIndex]
		if !file.skip && !file.failed {
			return true
		}
	}
	return false
}

// allocateFileBuffers determines the complete output footprint before it
// allocates any backing arrays.  verifyOnly still needs an assembled buffer
// for files that carry a public checksum; files without one can be validated
// from their per-segment checksums alone.
func allocateFileBuffers(a *format.Archive, files []fileAssembly, verifyOnly bool, budget *memoryBudget) error {
	var total uint64
	for i := range files {
		if files[i].skip || files[i].failed || (verifyOnly && a.Files[i].Checksum.Type == format.ChecksumNone) {
			continue
		}
		files[i].assemble = true
		if files[i].totalSize > uint64(maxInt()) {
			markFailure(files, i, fmt.Errorf("%w: output size %d", fault.ErrLimitExceeded, files[i].totalSize))
			files[i].assemble = false
			continue
		}
		if math.MaxUint64-total < files[i].totalSize {
			markFailure(files, i, fmt.Errorf("%w: aggregate output size overflow", fault.ErrLimitExceeded))
			files[i].assemble = false
			continue
		}
		total += files[i].totalSize
	}
	if err := budget.reserve(total); err != nil {
		for i := range files {
			if files[i].assemble {
				markFailure(files, i, err)
				files[i].assemble = false
			}
		}
	}
	return nil
}

func verifyFinalChecksum(entry format.FileEntry, data []byte, totalSize uint64) error {
	if entry.Checksum.Type == format.ChecksumNone {
		return nil
	}
	if uint64(len(data)) != totalSize {
		return fmt.Errorf("%w: final file size", fault.ErrCorrupt)
	}
	got, err := crypto.Sum(entry.Checksum.Type, data)
	if err != nil {
		return fmt.Errorf("%w: final checksum: %v", fault.ErrCorrupt, err)
	}
	if !crypto.EqualChecksum(entry.Checksum.Type, got, entry.Checksum.Data) {
		return fault.ErrChecksumMismatch
	}
	return nil
}

func archiveKey(a *format.Archive, password string) ([]byte, error) {
	if !a.Header.Encrypted && !a.Header.UnsupportedEncryption {
		return nil, nil
	}
	if a.Header.UnsupportedEncryption {
		return nil, fault.ErrUnsupportedEncryption
	}
	if password == "" {
		return nil, fault.ErrPasswordRequired
	}
	if a.Header.Password.Type == format.ChecksumPBKDF2SHA256XChaCha20 {
		key, err := crypto.DeriveXChaChaKey([]byte(password), a.Header.PasswordSalt)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", fault.ErrUnsupportedEncryption, err)
		}
		if !crypto.VerifyXChaChaPassword(key, a.Header.Password.Data) {
			return nil, fault.ErrIncorrectPassword
		}
		return key, nil
	}
	valid, err := crypto.VerifyPassword(a.Header.Password.Type, a.Header.PasswordSalt, []byte(password), a.Header.Password.Data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", fault.ErrUnsupportedEncryption, err)
	}
	if !valid {
		return nil, fault.ErrIncorrectPassword
	}
	return []byte(password), nil
}

func decodeChunk(r io.ReaderAt, a *format.Archive, chunk format.Chunk, key []byte, opts Options, limit int64) ([]byte, error) {
	base, err := newSliceSourceWithProvider(r, a, chunk, opts.Slices)
	if err != nil {
		return nil, err
	}
	magic := make([]byte, len(chunkMagic))
	if _, err := io.ReadFull(base, magic); err != nil {
		return nil, fmt.Errorf("%w: %v", fault.ErrCorrupt, err)
	}
	if string(magic) != chunkMagic {
		return nil, fmt.Errorf("%w: %v", fault.ErrCorrupt, errBadChunkMagic)
	}

	var source io.Reader = io.LimitReader(base, uint64ReaderLimit(chunk.Size))
	if chunk.Encryption != format.Plaintext {
		if len(key) == 0 {
			return nil, fault.ErrPasswordRequired
		}
		switch chunk.Encryption {
		case format.ARC4MD5, format.ARC4SHA1:
			salt := make([]byte, 8)
			if _, err := io.ReadFull(base, salt); err != nil {
				return nil, fmt.Errorf("%w: chunk salt: %v", fault.ErrCorrupt, err)
			}
			t := format.ChecksumMD5
			if chunk.Encryption == format.ARC4SHA1 {
				t = format.ChecksumSHA1
			}
			saltedKey, err := crypto.PasswordChecksum(t, salt, key)
			if err != nil {
				return nil, err
			}
			cipher, err := crypto.NewARC4(saltedKey)
			if err != nil {
				return nil, err
			}
			cipher.Discard(1000)
			source = &xorReader{src: io.LimitReader(base, uint64ReaderLimit(chunk.Size)), xor: cipher.XORKeyStream}
		case format.XChaCha20:
			cipher, err := crypto.NewXChaCha(key, chunk.Offset, chunk.FirstSlice)
			if err != nil {
				return nil, fmt.Errorf("%w: %v", fault.ErrUnsupportedEncryption, err)
			}
			source = &xorReader{src: io.LimitReader(base, uint64ReaderLimit(chunk.Size)), xor: cipher.XORKeyStream}
		default:
			return nil, fault.ErrUnsupportedEncryption
		}
	}

	decoded, closer, err := newChunkDecoder(source, chunk.Compression, limit)
	if err != nil {
		return nil, err
	}
	if closer != nil {
		defer closer.Close()
	}
	data, err := readAllLimit(decoded, limit)
	if err != nil {
		if errors.Is(err, fault.ErrLimitExceeded) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: chunk decompression: %v", fault.ErrCorrupt, err)
	}
	return data, nil
}

func newChunkDecoder(source io.Reader, method format.Compression, limit int64) (io.Reader, io.ReadCloser, error) {
	switch method {
	case format.Stored:
		return source, nil, nil
	case format.Zlib:
		z, err := zlib.NewReader(source)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: zlib: %v", fault.ErrCorrupt, err)
		}
		return z, z, nil
	case format.BZip2:
		return bzip2.NewReader(source), nil, nil
	case format.LZMA1:
		return newLZMA1Reader(source, limit)
	case format.LZMA2:
		return newLZMA2Reader(source, limit)
	default:
		return nil, nil, fault.ErrUnsupportedCompression
	}
}

func newLZMA1Reader(source io.Reader, limit int64) (io.Reader, io.ReadCloser, error) {
	props := make([]byte, 5)
	if _, err := io.ReadFull(source, props); err != nil {
		return nil, nil, fmt.Errorf("%w: LZMA1 header: %v", fault.ErrCorrupt, err)
	}
	dict := binary.LittleEndian.Uint32(props[1:])
	if err := checkDictionary(dict, limit); err != nil {
		return nil, nil, err
	}
	header := make([]byte, lzma.HeaderLen)
	copy(header, props)
	for i := 5; i < len(header); i++ {
		header[i] = 0xff
	}
	// The xz/lzma decoder consumes compressed input through ReadByte. Without
	// an io.ByteReader here, its fallback issues one upstream Read per byte;
	// sliceSource turns each of those into a ReaderAt.ReadAt call. Buffer the
	// complete synthetic LZMA stream so byte reads stay in memory.
	buffered := bufio.NewReaderSize(io.MultiReader(bytes.NewReader(header), source), maxReadBuffer)
	reader, err := (lzma.ReaderConfig{DictCap: int(dict)}).NewReader(buffered)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: LZMA1 init: %v", fault.ErrCorrupt, err)
	}
	return reader, nil, nil
}

func newLZMA2Reader(source io.Reader, limit int64) (io.Reader, io.ReadCloser, error) {
	prop := []byte{0}
	if _, err := io.ReadFull(source, prop); err != nil {
		return nil, nil, fmt.Errorf("%w: LZMA2 property: %v", fault.ErrCorrupt, err)
	}
	dict, err := lzma2Dictionary(prop[0])
	if err != nil {
		return nil, nil, err
	}
	if err := checkDictionary(dict, limit); err != nil {
		return nil, nil, err
	}
	// Reader2 has the same byte-reader behavior as Reader. Buffer the
	// restricted chunk source to avoid one ReaderAt call per compressed byte.
	buffered := bufio.NewReaderSize(source, maxReadBuffer)
	reader, err := (lzma.Reader2Config{DictCap: int(dict)}).NewReader2(buffered)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: LZMA2 init: %v", fault.ErrCorrupt, err)
	}
	return reader, nil, nil
}

func lzma2Dictionary(prop byte) (uint32, error) {
	if prop > 40 {
		return 0, fmt.Errorf("%w: invalid LZMA2 property", fault.ErrCorrupt)
	}
	if prop == 40 {
		return math.MaxUint32, nil
	}
	return (2 | uint32(prop&1)) << (uint(prop)/2 + 11), nil
}

func checkDictionary(dict uint32, limit int64) error {
	if uint64(dict) > uint64(maxInt()) || uint64(dict) > uint64(limit) {
		return fmt.Errorf("%w: LZMA dictionary %d", fault.ErrLimitExceeded, dict)
	}
	return nil
}

func decodeFileSegment(chunk []byte, file format.StoredFile, limit int64) ([]byte, error) {
	if file.Offset > uint64(len(chunk)) || file.Size > uint64(len(chunk))-file.Offset {
		return nil, fmt.Errorf("%w: file range", fault.ErrCorrupt)
	}
	raw := chunk[int(file.Offset):int(file.Offset+file.Size)]

	var data []byte
	switch file.Filter {
	case format.NoFilter:
		data = raw
	case format.Instruction4108:
		if err := checkFilterAllocation(uint64(len(raw)), limit); err != nil {
			return nil, err
		}
		data = decodeInstruction4108(raw)
	case format.Instruction5200:
		if err := checkFilterAllocation(uint64(len(raw)), limit); err != nil {
			return nil, err
		}
		data = decodeInstruction5200(raw, false)
	case format.Instruction5309:
		if err := checkFilterAllocation(uint64(len(raw)), limit); err != nil {
			return nil, err
		}
		data = decodeInstruction5200(raw, true)
	case format.ZlibFilter:
		z, err := zlib.NewReader(bytes.NewReader(raw))
		if err != nil {
			return nil, fmt.Errorf("%w: file zlib: %v", fault.ErrCorrupt, err)
		}
		data, err = readAllLimit(z, limit)
		_ = z.Close()
		if err != nil {
			if errors.Is(err, fault.ErrLimitExceeded) {
				return nil, err
			}
			return nil, fmt.Errorf("%w: file zlib: %v", fault.ErrCorrupt, err)
		}
	default:
		return nil, fault.ErrUnsupportedCompression
	}

	if file.Checksum.Type != format.ChecksumNone {
		checksumData := data
		if file.Filter == format.ZlibFilter {
			// The native chain hashes the restricted compressed bytes and
			// inflates them only after the checksum filter has consumed them.
			checksumData = raw
		}
		got, err := crypto.Sum(file.Checksum.Type, checksumData)
		if err != nil {
			return nil, fmt.Errorf("%w: file checksum: %v", fault.ErrCorrupt, err)
		}
		if !crypto.EqualChecksum(file.Checksum.Type, got, file.Checksum.Data) {
			return nil, fault.ErrChecksumMismatch
		}
	}
	return data, nil
}

func checkFilterAllocation(size uint64, limit int64) error {
	if limit < 0 || size > uint64(limit) {
		return fmt.Errorf("%w: file filter needs %d bytes", fault.ErrLimitExceeded, size)
	}
	return nil
}

func decodeInstruction4108(src []byte) []byte {
	dst := make([]byte, len(src))
	var addr uint32
	var left int
	var offset uint32 = 5
	for i, b := range src {
		out := b
		if left == 0 {
			if b == 0xe8 || b == 0xe9 {
				addr = ^offset + 1
				left = 4
			}
		} else {
			addr += uint32(b)
			out = byte(addr)
			addr >>= 8
			left--
		}
		dst[i] = out
		offset++
	}
	return dst
}

func decodeInstruction5200(src []byte, flipHighByte bool) []byte {
	dst := make([]byte, 0, len(src))
	var offset uint32
	for i := 0; i < len(src); {
		b := src[i]
		i++
		dst = append(dst, b)
		offset++
		if b != 0xe8 && b != 0xe9 {
			continue
		}
		left := uint32(0x10000) - ((offset - 1) & 0xffff)
		if left < 5 {
			continue
		}
		if len(src)-i < 4 {
			dst = append(dst, src[i:]...)
			offset += uint32(len(src) - i)
			break
		}
		addr := binary.LittleEndian.Uint32(src[i : i+4])
		i += 4
		offset += 4
		if byte(addr>>24) != 0 && byte(addr>>24) != 0xff {
			var buf [4]byte
			binary.LittleEndian.PutUint32(buf[:], addr)
			dst = append(dst, buf[:]...)
			continue
		}
		rel := (addr & 0x00ffffff) - (offset & 0x00ffffff)
		var buf [4]byte
		binary.LittleEndian.PutUint32(buf[:], rel)
		if flipHighByte && rel&0x00800000 != 0 {
			buf[3] = ^byte(addr >> 24)
		} else {
			buf[3] = byte(addr >> 24)
		}
		dst = append(dst, buf[:]...)
	}
	return dst
}

func markFailure(files []fileAssembly, index int, err error) {
	if index < 0 || index >= len(files) || files[index].failed {
		return
	}
	files[index].failed = true
	files[index].err = err
}

type memoryBudget struct {
	limit int64
	used  int64
}

func (b *memoryBudget) available() int64 {
	if b.limit <= b.used {
		return 0
	}
	return b.limit - b.used
}

func (b *memoryBudget) reserve(n uint64) error {
	if n > uint64(b.available()) {
		return fmt.Errorf("%w: requested %d bytes", fault.ErrLimitExceeded, n)
	}
	b.used += int64(n)
	return nil
}

func (b *memoryBudget) release(n uint64) {
	if n >= uint64(b.used) {
		b.used = 0
		return
	}
	b.used -= int64(n)
}

func readAllLimit(r io.Reader, limit int64) ([]byte, error) {
	if limit < 0 {
		return nil, fault.ErrLimitExceeded
	}
	if limit == 0 {
		var one [1]byte
		n, err := r.Read(one[:])
		if n > 0 {
			return nil, fault.ErrLimitExceeded
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
		return []byte{}, nil
	}
	result := make([]byte, 0, minInt64(limit, 64<<10))
	buffer := make([]byte, maxReadBuffer)
	for {
		n, err := r.Read(buffer)
		if n > 0 {
			if int64(len(result))+int64(n) > limit {
				return nil, fault.ErrLimitExceeded
			}
			result = append(result, buffer[:n]...)
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return result, nil
			}
			return nil, err
		}
		if n == 0 {
			return nil, io.ErrNoProgress
		}
	}
}

func uint64ReaderLimit(n uint64) int64 {
	if n > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(n)
}

func maxInt() int {
	return int(^uint(0) >> 1)
}

func minInt64(a, b int64) int {
	if a < b {
		return int(a)
	}
	return int(b)
}

type xorReader struct {
	src io.Reader
	xor func(dst, src []byte)
}

func (r *xorReader) Read(p []byte) (int, error) {
	n, err := r.src.Read(p)
	if n > 0 {
		r.xor(p[:n], p[:n])
	}
	return n, err
}
