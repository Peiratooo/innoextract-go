package innoextract

import (
	"fmt"
	"strings"

	"github.com/Peiratooo/innoextract-go/internal/fault"
)

var (
	ErrInvalidFormat          = fault.ErrInvalidFormat
	ErrUnsupportedVersion     = fault.ErrUnsupportedVersion
	ErrPasswordRequired       = fault.ErrPasswordRequired
	ErrIncorrectPassword      = fault.ErrIncorrectPassword
	ErrUnsupportedEncryption  = fault.ErrUnsupportedEncryption
	ErrUnsupportedCompression = fault.ErrUnsupportedCompression
	ErrMissingSlice           = fault.ErrMissingSlice
	ErrChecksumMismatch       = fault.ErrChecksumMismatch
	ErrCorrupt                = fault.ErrCorrupt
	ErrLimitExceeded          = fault.ErrLimitExceeded
)

type EntryError struct {
	Entry Entry
	Err   error
}

func (e EntryError) Error() string {
	return fmt.Sprintf("%s: %v", e.Entry.Path, e.Err)
}

func (e EntryError) Unwrap() error { return e.Err }

type ExtractError struct {
	Failures []EntryError
}

func (e *ExtractError) Error() string {
	if e == nil || len(e.Failures) == 0 {
		return ""
	}
	parts := make([]string, len(e.Failures))
	for i := range e.Failures {
		parts[i] = e.Failures[i].Error()
	}
	return strings.Join(parts, "; ")
}

func (e *ExtractError) Unwrap() []error {
	if e == nil {
		return nil
	}
	errs := make([]error, len(e.Failures))
	for i := range e.Failures {
		errs[i] = e.Failures[i]
	}
	return errs
}
