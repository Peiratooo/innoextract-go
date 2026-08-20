package stream

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"

	"github.com/Peiratooo/innoextract-go/internal/fault"
	"github.com/Peiratooo/innoextract-go/internal/format"
)

var (
	sliceMagic16 = [8]byte{'i', 'd', 's', 'k', 'a', '1', '6', 0x1a}
	sliceMagic32 = [8]byte{'i', 'd', 's', 'k', 'a', '3', '2', 0x1a}
)

// sliceSource presents either embedded data or a sequence of external slices
// as one forward-only reader.  The underlying providers remain ReaderAt so a
// failed read never leaves an opaque stream in a partially consumed state.
type sliceSource struct {
	embedded  bool
	r         io.ReaderAt
	provider  func(uint32) (io.ReaderAt, error)
	dataStart uint64

	slice uint32
	last  uint32
	pos   uint64

	current io.ReaderAt
	base    uint64
	end     uint64 // max uint64 means the provider is a raw, size-less payload
	opened  bool
}

func newSliceSource(r io.ReaderAt, a *format.Archive, chunk format.Chunk) (*sliceSource, error) {
	if chunk.FirstSlice > chunk.LastSlice {
		return nil, fmt.Errorf("%w: invalid slice range", fault.ErrCorrupt)
	}
	if a.Offsets.DataOffset == 0 && a.Header.BaseFilename != "" {
		return nil, fmt.Errorf("%w: external data requires a slice provider", fault.ErrMissingSlice)
	}
	dataStart := a.Offsets.DataOffset
	// A zero data offset is the external-slice marker in Inno Setup.  Falling
	// back to the supplied ReaderAt is useful for callers that already supplied
	// a payload-only reader and does not affect normal parsed archives.
	if dataStart != 0 || a.Header.BaseFilename == "" {
		if math.MaxUint64-dataStart < chunk.Offset {
			return nil, fmt.Errorf("%w: data offset overflow", fault.ErrCorrupt)
		}
		return &sliceSource{
			embedded:  true,
			r:         r,
			dataStart: dataStart + chunk.Offset,
			slice:     chunk.FirstSlice,
			last:      chunk.LastSlice,
			end:       math.MaxUint64,
		}, nil
	}
	// The actual provider is installed by newSliceSourceWithProvider.  This
	// branch is retained for direct ReaderAt use and is replaced in
	// decodeChunk when Options.Slices is present.
	return &sliceSource{
		embedded:  true,
		r:         r,
		dataStart: chunk.Offset,
		slice:     chunk.FirstSlice,
		last:      chunk.LastSlice,
		end:       math.MaxUint64,
	}, nil
}

func newSliceSourceWithProvider(r io.ReaderAt, a *format.Archive, chunk format.Chunk, provider func(uint32) (io.ReaderAt, error)) (*sliceSource, error) {
	if provider == nil {
		return newSliceSource(r, a, chunk)
	}
	if chunk.FirstSlice > chunk.LastSlice {
		return nil, fmt.Errorf("%w: invalid slice range", fault.ErrCorrupt)
	}
	if a.Offsets.DataOffset != 0 {
		return newSliceSource(r, a, chunk)
	}
	return &sliceSource{
		provider: provider,
		slice:    chunk.FirstSlice,
		last:     chunk.LastSlice,
		pos:      chunk.Offset,
		end:      math.MaxUint64,
	}, nil
}

func (s *sliceSource) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if s.embedded {
		if math.MaxUint64-s.dataStart < s.pos {
			return 0, fmt.Errorf("%w: reader offset overflow", fault.ErrCorrupt)
		}
		offset, err := checkedOffset(s.dataStart, s.pos)
		if err != nil {
			return 0, err
		}
		n, err := s.r.ReadAt(p, offset)
		s.pos += uint64(n)
		if n == len(p) {
			return n, nil
		}
		if err == nil {
			err = io.EOF
		}
		return n, err
	}

	total := 0
	for len(p) > 0 {
		if !s.opened {
			if err := s.open(); err != nil {
				return total, err
			}
		}
		if s.end != math.MaxUint64 && s.pos >= s.end {
			if s.slice == s.last {
				return total, io.EOF
			}
			s.slice++
			s.pos = 0
			s.opened = false
			continue
		}

		want := len(p)
		if s.end != math.MaxUint64 {
			remaining := s.end - s.pos
			if remaining < uint64(want) {
				want = int(remaining)
			}
			if want == 0 {
				continue
			}
		}
		offset, err := checkedOffset(s.base, s.pos)
		if err != nil {
			return total, err
		}
		n, err := s.current.ReadAt(p[:want], offset)
		if n > 0 {
			s.pos += uint64(n)
			total += n
			p = p[n:]
		}
		if n == want {
			continue
		}
		if err == nil {
			return total, io.ErrNoProgress
		}
		if !errors.Is(err, io.EOF) {
			return total, err
		}
		if s.end != math.MaxUint64 && s.pos < s.end {
			return total, io.ErrUnexpectedEOF
		}
		if s.slice == s.last {
			return total, io.EOF
		}
		s.slice++
		s.pos = 0
		s.opened = false
	}
	return total, nil
}

func (s *sliceSource) open() error {
	if s.provider == nil {
		return fmt.Errorf("%w: slice %d", fault.ErrMissingSlice, s.slice)
	}
	r, err := s.provider(s.slice)
	if err != nil || r == nil {
		if err == nil {
			err = errors.New("nil slice reader")
		}
		return fmt.Errorf("%w: slice %d: %v", fault.ErrMissingSlice, s.slice, err)
	}
	s.current = r
	s.base = 0
	s.end = math.MaxUint64

	var header [12]byte
	n, readErr := r.ReadAt(header[:], 0)
	if n >= 8 && (bytesEqual8(header[:8], sliceMagic16[:]) || bytesEqual8(header[:8], sliceMagic32[:])) {
		if n < len(header) {
			return fmt.Errorf("%w: truncated slice header", fault.ErrCorrupt)
		}
		total := binary.LittleEndian.Uint32(header[8:])
		if total < 12 {
			return fmt.Errorf("%w: invalid slice size %d", fault.ErrCorrupt, total)
		}
		s.base = 12
		s.end = uint64(total - 12)
	} else if readErr != nil && n == 0 && !errors.Is(readErr, io.EOF) {
		return fmt.Errorf("%w: slice %d: %v", fault.ErrCorrupt, s.slice, readErr)
	}
	s.opened = true
	return nil
}

func bytesEqual8(a, b []byte) bool {
	if len(a) < 8 || len(b) < 8 {
		return false
	}
	for i := 0; i < 8; i++ {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func checkedOffset(base, pos uint64) (int64, error) {
	if math.MaxUint64-base < pos {
		return 0, fmt.Errorf("%w: reader offset overflow", fault.ErrCorrupt)
	}
	offset := base + pos
	if offset > math.MaxInt64 {
		return 0, fmt.Errorf("%w: reader offset exceeds int64", fault.ErrCorrupt)
	}
	return int64(offset), nil
}
