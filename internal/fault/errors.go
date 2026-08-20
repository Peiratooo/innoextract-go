package fault

import "errors"

var (
	ErrInvalidFormat          = errors.New("invalid Inno Setup format")
	ErrUnsupportedVersion     = errors.New("unsupported Inno Setup version")
	ErrPasswordRequired       = errors.New("password required")
	ErrIncorrectPassword      = errors.New("incorrect password")
	ErrUnsupportedEncryption  = errors.New("unsupported encryption")
	ErrUnsupportedCompression = errors.New("unsupported compression")
	ErrMissingSlice           = errors.New("missing data slice")
	ErrChecksumMismatch       = errors.New("checksum mismatch")
	ErrCorrupt                = errors.New("corrupt setup data")
	ErrLimitExceeded          = errors.New("resource limit exceeded")
)
