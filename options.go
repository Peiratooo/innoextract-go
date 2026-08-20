package innoextract

import (
	"fmt"
	"io"
)

const (
	defaultMemoryLimit = int64(1 << 30)
	defaultHeaderLimit = int64(64 << 20)
)

type SliceProvider func(index uint32) (io.ReaderAt, error)

type options struct {
	password    string
	codepage    uint32
	slices      SliceProvider
	memoryLimit int64
	headerLimit int64
}

type Option func(*options) error

func WithPassword(password string) Option {
	return func(o *options) error { o.password = password; return nil }
}

func WithCodepage(codepage uint32) Option {
	return func(o *options) error {
		if codepage == 0 {
			return fmt.Errorf("codepage must be non-zero")
		}
		o.codepage = codepage
		return nil
	}
}

func WithSliceProvider(provider SliceProvider) Option {
	return func(o *options) error {
		if provider == nil {
			return fmt.Errorf("slice provider must not be nil")
		}
		o.slices = provider
		return nil
	}
}

func WithMemoryLimit(bytes int64) Option {
	return func(o *options) error {
		if bytes <= 0 {
			return fmt.Errorf("memory limit must be positive")
		}
		o.memoryLimit = bytes
		return nil
	}
}

func defaultOptions() options {
	return options{memoryLimit: defaultMemoryLimit, headerLimit: defaultHeaderLimit}
}
