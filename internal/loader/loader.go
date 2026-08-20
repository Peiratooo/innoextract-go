// Package loader locates the Inno Setup payloads embedded in an executable.
package loader

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"math"

	"github.com/Peiratooo/innoextract-go/internal/fault"
	"github.com/Peiratooo/innoextract-go/internal/format"
)

const (
	loaderResourceName = uint32(11111)
	resourceTypeData   = uint32(10)
)

// Locate finds the loader offset table. It accepts a complete PE executable or
// an external setup-0.bin (where the setup header starts at offset zero).
func Locate(r io.ReaderAt) (format.Offsets, error) {
	if r == nil {
		return format.Offsets{}, fmt.Errorf("%w: nil reader", fault.ErrInvalidFormat)
	}
	if o, ok, err := fixedOffsetTable(r); err != nil {
		return format.Offsets{}, err
	} else if ok {
		return o, nil
	}
	if o, ok, err := resourceOffsetTable(r); err != nil {
		return format.Offsets{}, err
	} else if ok {
		return o, nil
	}
	return format.Offsets{}, nil
}

func readAt(r io.ReaderAt, off int64, n int) ([]byte, error) {
	if off < 0 || n < 0 || int64(n) > math.MaxInt64-off {
		return nil, fmt.Errorf("%w: invalid range", fault.ErrCorrupt)
	}
	b := make([]byte, n)
	got, err := r.ReadAt(b, off)
	if got != n {
		if err == nil {
			err = io.ErrUnexpectedEOF
		}
		return nil, fmt.Errorf("%w: read at %#x (%d bytes): %v", fault.ErrCorrupt, off, n, err)
	}
	return b, nil
}

func u16(b []byte, off int) uint16 { return binary.LittleEndian.Uint16(b[off:]) }
func u32(b []byte, off int) uint32 { return binary.LittleEndian.Uint32(b[off:]) }
func u64(b []byte, off int) uint64 { return binary.LittleEndian.Uint64(b[off:]) }

func fixedOffsetTable(r io.ReaderAt) (format.Offsets, bool, error) {
	b, err := readAt(r, 0x30, 12)
	if err != nil {
		// A short setup-0.bin is handled by the caller as an external header.
		return format.Offsets{}, false, nil
	}
	if string(b[:4]) != "Inno" || ^u32(b, 4) != u32(b, 8) {
		return format.Offsets{}, false, nil
	}
	pos := uint64(u32(b, 4))
	return loadOffsetTable(r, pos)
}

func loadOffsetTable(r io.ReaderAt, pos uint64) (format.Offsets, bool, error) {
	if pos > math.MaxInt64 {
		return format.Offsets{}, true, fmt.Errorf("%w: loader offset overflows int64", fault.ErrCorrupt)
	}
	b, err := readAt(r, int64(pos), 12)
	if err != nil {
		return format.Offsets{}, true, err
	}
	magic := b[:12]
	version := loaderMagicVersion(magic)
	if version == 0 {
		return format.Offsets{}, true, fmt.Errorf("%w: unknown loader magic", fault.ErrInvalidFormat)
	}

	var revision uint32
	// All current loader records begin with the 12-byte magic and a revision.
	revBytes, err := readAt(r, int64(pos)+12, 4)
	if err != nil {
		return format.Offsets{}, true, err
	}
	revision = u32(revBytes, 0)

	if revision == 2 {
		data, err := readAt(r, int64(pos)+16, 48)
		if err != nil {
			return format.Offsets{}, true, err
		}
		offExe := int64(binary.LittleEndian.Uint64(data[8:16]))
		offHeader := int64(binary.LittleEndian.Uint64(data[24:32]))
		offData := int64(binary.LittleEndian.Uint64(data[32:40]))
		if offExe < 0 || offHeader < 0 || offData < 0 {
			return format.Offsets{}, true, fmt.Errorf("%w: negative loader offset", fault.ErrCorrupt)
		}
		// The record checksum covers magic, revision and all fields before CRC.
		all, err := readAt(r, int64(pos), 60)
		if err != nil {
			return format.Offsets{}, true, err
		}
		crcBytes, crcErr := readAt(r, int64(pos)+60, 4)
		if crcErr != nil {
			return format.Offsets{}, true, crcErr
		}
		if got, want := crc32.ChecksumIEEE(all), u32(crcBytes, 0); got != want {
			// The C++ implementation only warns. Keep parsing: some modified
			// loaders are known to have stale checksums.
		}
		return format.Offsets{
			FoundMagic:          true,
			Revision:            revision,
			ExeOffset:           uint64(offExe),
			ExeCompressedSize:   0,
			ExeUncompressedSize: uint64(u32(data, 16)),
			ExeChecksum:         format.Checksum{Type: format.ChecksumCRC32, Data: append([]byte(nil), data[20:24]...)},
			HeaderOffset:        uint64(offHeader),
			DataOffset:          uint64(offData),
		}, true, nil
	}

	// Revision 1 is used by Inno Setup 5.1.5 through 6.4.x. The fields are
	// 32-bit even on PE32+ files.
	data, err := readAt(r, int64(pos)+16, 28)
	if err != nil {
		return format.Offsets{}, true, err
	}
	// The first field is the total-size field and is not needed here.
	offExe := u32(data, 4)
	idx := 8
	var exeCompressed uint64
	if version < 0x04010600 {
		exeCompressed = uint64(u32(data, idx))
		idx += 4
	}
	exeUncompressed := uint64(u32(data, idx))
	idx += 4
	checksumType := format.ChecksumCRC32
	checksum := append([]byte(nil), data[idx:idx+4]...)
	idx += 4
	if version < 0x04000300 {
		checksumType = format.ChecksumAdler32
	}
	// Message offset was removed in 4.0.0; all supported modern versions use 0.
	var message uint64
	if version < 0x04000000 {
		message = uint64(u32(data, idx))
		idx += 4
	}
	_ = message
	header := uint64(u32(data, idx))
	dataOffset := uint64(u32(data, idx+4))
	return format.Offsets{
		FoundMagic:          true,
		Revision:            1,
		ExeOffset:           uint64(offExe),
		ExeCompressedSize:   exeCompressed,
		ExeUncompressedSize: exeUncompressed,
		ExeChecksum:         format.Checksum{Type: checksumType, Data: checksum},
		HeaderOffset:        header,
		DataOffset:          dataOffset,
	}, true, nil
}

func loaderMagicVersion(m []byte) uint32 {
	known := map[string]uint32{
		"rDlPtS02\x87eVx":          0x01020A00,
		"rDlPtS04\x87eVx":          0x04000000,
		"rDlPtS05\x87eVx":          0x04000300,
		"rDlPtS06\x87eVx":          0x04000A00,
		"rDlPtS07\x87eVx":          0x04010600,
		"rDlPtS\xcd\xe6\xd7{\x0b*": 0x05010500,
		"nS5W7dT\x83\xaa\x1b\x0fj": 0x05010500,
	}
	return known[string(m)]
}

type section struct {
	va, virtualSize, raw, rawSize uint32
}

func (s section) fileOffset(rva uint32) (uint32, bool) {
	span := s.virtualSize
	if s.rawSize > span {
		span = s.rawSize
	}
	if rva < s.va || rva-s.va >= span {
		return 0, false
	}
	off := uint64(s.raw) + uint64(rva-s.va)
	if off > math.MaxUint32 {
		return 0, false
	}
	return uint32(off), true
}

func resourceOffsetTable(r io.ReaderAt) (format.Offsets, bool, error) {
	dos, err := readAt(r, 0, 64)
	if err != nil || string(dos[:2]) != "MZ" {
		return format.Offsets{}, false, nil
	}
	peOff := uint64(u32(dos, 0x3c))
	if peOff > math.MaxInt64 {
		return format.Offsets{}, false, fmt.Errorf("%w: PE offset overflows", fault.ErrCorrupt)
	}
	pe, err := readAt(r, int64(peOff), 24)
	if err != nil || string(pe[:4]) != "PE\x00\x00" {
		return format.Offsets{}, false, nil
	}
	nsections := int(u16(pe, 6))
	optionalSize := int(u16(pe, 20))
	if nsections <= 0 || nsections > 96 || optionalSize < 96 || optionalSize > 4096 {
		return format.Offsets{}, true, fmt.Errorf("%w: invalid PE headers", fault.ErrCorrupt)
	}
	optOff := peOff + 24
	opt, err := readAt(r, int64(optOff), optionalSize)
	if err != nil {
		return format.Offsets{}, true, err
	}
	magic := u16(opt, 0)
	dirOff := 96
	if magic == 0x20b {
		dirOff = 112
	} else if magic != 0x10b {
		return format.Offsets{}, true, fmt.Errorf("%w: unsupported PE optional header", fault.ErrInvalidFormat)
	}
	if dirOff+24 > len(opt) || u32(opt, dirOff) < 3 {
		return format.Offsets{}, true, fmt.Errorf("%w: missing PE resource directory", fault.ErrCorrupt)
	}
	resourceRVA := u32(opt, dirOff+16)
	if resourceRVA == 0 {
		return format.Offsets{}, true, fmt.Errorf("%w: missing PE resources", fault.ErrInvalidFormat)
	}
	sectionOff := optOff + uint64(optionalSize)
	sectionBytes, err := readAt(r, int64(sectionOff), nsections*40)
	if err != nil {
		return format.Offsets{}, true, err
	}
	sections := make([]section, 0, nsections)
	for i := 0; i < nsections; i++ {
		p := i * 40
		sections = append(sections, section{u32(sectionBytes, p+12), u32(sectionBytes, p+8), u32(sectionBytes, p+20), u32(sectionBytes, p+16)})
	}
	resourceFile, ok := rvaToFile(sections, resourceRVA)
	if !ok {
		return format.Offsets{}, true, fmt.Errorf("%w: resource RVA not mapped", fault.ErrCorrupt)
	}
	resourceLeaf, ok, err := findResource(r, sections, resourceRVA, resourceFile, resourceTypeData, loaderResourceName)
	if err != nil {
		return format.Offsets{}, true, err
	}
	if !ok {
		return format.Offsets{}, true, fmt.Errorf("%w: Inno loader resource not found", fault.ErrInvalidFormat)
	}
	o, found, err := loadOffsetTable(r, uint64(resourceLeaf))
	return o, found, err
}

func rvaToFile(sections []section, rva uint32) (uint32, bool) {
	for _, s := range sections {
		if off, ok := s.fileOffset(rva); ok {
			return off, true
		}
	}
	return 0, false
}

func readResourceDir(r io.ReaderAt, off uint32) ([]byte, error) {
	// Read the fixed header first, then only the number of entries declared in it.
	h, err := readAt(r, int64(off), 16)
	if err != nil {
		return nil, err
	}
	n := int(u16(h, 12)) + int(u16(h, 14))
	if n < 0 || n > 4096 {
		return nil, fmt.Errorf("%w: unreasonable resource entry count", fault.ErrCorrupt)
	}
	return readAt(r, int64(off), 16+n*8)
}

func resourceEntry(dir []byte, id uint32) (uint32, bool) {
	n := int(u16(dir, 12)) + int(u16(dir, 14))
	for i := 0; i < n; i++ {
		p := 16 + i*8
		name := u32(dir, p)
		if name&0x80000000 == 0 && name == id {
			return u32(dir, p+4), true
		}
	}
	return 0, false
}

func findResource(r io.ReaderAt, sections []section, resourceRVA, root uint32, typ, name uint32) (uint32, bool, error) {
	rootDir, err := readResourceDir(r, root)
	if err != nil {
		return 0, false, err
	}
	typeRef, ok := resourceEntry(rootDir, typ)
	if !ok || typeRef&0x80000000 == 0 {
		return 0, false, nil
	}
	typeOff, ok := addRVA(root, typeRef&0x7fffffff)
	if !ok {
		return 0, false, fmt.Errorf("%w: resource table overflow", fault.ErrCorrupt)
	}
	typeDir, err := readResourceDir(r, typeOff)
	if err != nil {
		return 0, false, err
	}
	nameRef, ok := resourceEntry(typeDir, name)
	if !ok || nameRef&0x80000000 == 0 {
		return 0, false, nil
	}
	nameOff, ok := addRVA(root, nameRef&0x7fffffff)
	if !ok {
		return 0, false, fmt.Errorf("%w: resource table overflow", fault.ErrCorrupt)
	}
	nameDir, err := readResourceDir(r, nameOff)
	if err != nil {
		return 0, false, err
	}
	// Default language means the first language entry, matching B. Prefer 409
	// when present because it is the normal PE resource language.
	var langRef uint32
	var found bool
	for i := 0; i < int(u16(nameDir, 12))+int(u16(nameDir, 14)); i++ {
		p := 16 + i*8
		if u32(nameDir, p)&0x7fffffff == 0x409 {
			langRef, found = u32(nameDir, p+4), true
			break
		}
		if !found {
			langRef = u32(nameDir, p+4)
			found = true
		}
	}
	if !found || langRef&0x80000000 != 0 {
		return 0, false, nil
	}
	leafOff, ok := addRVA(root, langRef&0x7fffffff)
	if !ok {
		return 0, false, fmt.Errorf("%w: resource leaf overflow", fault.ErrCorrupt)
	}
	leaf, err := readAt(r, int64(leafOff), 16)
	if err != nil {
		return 0, false, err
	}
	dataRVA, size := u32(leaf, 0), u32(leaf, 4)
	dataFile, ok := rvaToFile(sections, dataRVA)
	if !ok {
		return 0, false, fmt.Errorf("%w: resource data RVA not mapped", fault.ErrCorrupt)
	}
	if size > 0 {
		if _, err := readAt(r, int64(dataFile), int(size)); err != nil {
			return 0, false, err
		}
	}
	return dataFile, true, nil
}

func addRVA(root, rel uint32) (uint32, bool) {
	if uint64(root)+uint64(rel) > math.MaxUint32 {
		return 0, false
	}
	return root + rel, true
}
