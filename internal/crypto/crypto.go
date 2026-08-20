// Package crypto contains the small set of cryptographic primitives used by
// the Inno Setup data stream.  None of the types in this package are part of
// the public API; they deliberately expose only the operations needed by the
// stream decoder.
package crypto

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"hash"

	stdpbkdf2 "crypto/pbkdf2"
	stdadler32 "hash/adler32"
	stdcrc32 "hash/crc32"

	"golang.org/x/crypto/chacha20"

	"github.com/Peiratooo/innoextract-go/internal/format"
)

var (
	ErrUnsupportedChecksum = errors.New("unsupported checksum")
	ErrInvalidKey          = errors.New("invalid encryption key")
	ErrInvalidSalt         = errors.New("invalid encryption salt")
)

// NewHasher returns the standard streaming hash implementation for an Inno
// checksum type.  ChecksumNone and the password-metadata checksum do not
// describe a stream hash and return a nil hasher.
func NewHasher(t format.ChecksumType) (hash.Hash, error) {
	switch t {
	case format.ChecksumNone, format.ChecksumPBKDF2SHA256XChaCha20:
		return nil, nil
	case format.ChecksumAdler32:
		return stdadler32.New(), nil
	case format.ChecksumCRC32:
		return stdcrc32.NewIEEE(), nil
	case format.ChecksumMD5:
		return md5.New(), nil
	case format.ChecksumSHA1:
		return sha1.New(), nil
	case format.ChecksumSHA256:
		return sha256.New(), nil
	default:
		return nil, ErrUnsupportedChecksum
	}
}

// Sum computes an Inno checksum for data.  Numeric checksums use the byte
// order returned by hash.Hash (big-endian); EqualChecksum accepts both the
// raw on-disk little-endian representation and that representation because
// the parser contract stores checksum bytes rather than a host integer.
func Sum(t format.ChecksumType, data []byte) ([]byte, error) {
	h, err := NewHasher(t)
	if err != nil {
		return nil, err
	}
	if h == nil {
		return nil, nil
	}
	_, _ = h.Write(data)
	return h.Sum(nil), nil
}

// EqualChecksum compares a calculated digest with the checksum stored in an
// archive.  Adler32 and CRC32 are serialized as little-endian uint32 values
// by Inno Setup; accepting the hash.Hash byte order as well keeps this helper
// independent of whether the format reader retained raw bytes or normalized
// the integer.
func EqualChecksum(t format.ChecksumType, got, want []byte) bool {
	if t == format.ChecksumNone {
		return true
	}
	if t == format.ChecksumPBKDF2SHA256XChaCha20 {
		return bytes.Equal(got, want)
	}
	if bytes.Equal(got, want) {
		return true
	}
	if (t == format.ChecksumAdler32 || t == format.ChecksumCRC32) && len(want) == 4 {
		var reversed [4]byte
		for i := range reversed {
			reversed[i] = want[len(want)-1-i]
		}
		return bytes.Equal(got, reversed[:])
	}
	return false
}

// PasswordChecksum calculates the legacy Inno password check, which hashes
// the password salt followed by the password bytes.
func PasswordChecksum(t format.ChecksumType, salt, password []byte) ([]byte, error) {
	h, err := NewHasher(t)
	if err != nil {
		return nil, err
	}
	if h == nil {
		return nil, ErrUnsupportedChecksum
	}
	_, _ = h.Write(salt)
	_, _ = h.Write(password)
	return h.Sum(nil), nil
}

// VerifyPassword verifies either a legacy digest or the 6.4-era
// PBKDF2/XChaCha20 password test.  For XChaCha20, salt must contain the
// 16-byte PBKDF2 salt, LE32 iteration count, and 24-byte base nonce.
func VerifyPassword(t format.ChecksumType, salt, password, expected []byte) (bool, error) {
	if t == format.ChecksumPBKDF2SHA256XChaCha20 {
		keyNonce, err := DeriveXChaChaKey(password, salt)
		if err != nil {
			return false, err
		}
		return VerifyXChaChaPassword(keyNonce, expected), nil
	}
	got, err := PasswordChecksum(t, salt, password)
	if err != nil {
		return false, err
	}
	return EqualChecksum(t, got, expected), nil
}

// DeriveXChaChaKey derives the 32-byte key and appends the 24-byte base nonce
// used by Inno Setup 6.4.x.  The salt layout is exactly:
//
//	16-byte PBKDF2 salt, little-endian uint32 iterations, 24-byte nonce.
func DeriveXChaChaKey(password, salt []byte) ([]byte, error) {
	if len(salt) != 16+4+chacha20.NonceSizeX {
		return nil, ErrInvalidSalt
	}
	iterations := binary.LittleEndian.Uint32(salt[16:20])
	if iterations == 0 {
		return nil, ErrInvalidSalt
	}
	key, err := stdpbkdf2.Key(sha256.New, string(password), salt[:16], int(iterations), chacha20.KeySize)
	if err != nil {
		return nil, err
	}
	result := make([]byte, chacha20.KeySize+chacha20.NonceSizeX)
	copy(result, key)
	copy(result[chacha20.KeySize:], salt[20:])
	return result, nil
}

// VerifyXChaChaPassword performs the password-test operation used by Inno
// Setup.  It intentionally compares the four bytes in constant time only at
// the final call site; the archive format has no authentication beyond this
// check and the subsequent file checksum.
func VerifyXChaChaPassword(keyNonce, expected []byte) bool {
	if len(keyNonce) != chacha20.KeySize+chacha20.NonceSizeX || len(expected) < 4 {
		return false
	}
	nonce := make([]byte, chacha20.NonceSizeX)
	copy(nonce, keyNonce[chacha20.KeySize:])
	for i := 8; i < 12; i++ {
		nonce[i] = ^nonce[i]
	}
	cipher, err := chacha20.NewUnauthenticatedCipher(keyNonce[:chacha20.KeySize], nonce)
	if err != nil {
		return false
	}
	actual := make([]byte, 4)
	cipher.XORKeyStream(actual, actual)
	return subtle.ConstantTimeCompare(actual, expected[:4]) == 1
}

// ChunkNonce applies Inno Setup's per-chunk nonce derivation to a keyNonce
// returned by DeriveXChaChaKey.
func ChunkNonce(keyNonce []byte, offset uint64, firstSlice uint32) ([]byte, error) {
	if len(keyNonce) != chacha20.KeySize+chacha20.NonceSizeX {
		return nil, ErrInvalidKey
	}
	nonce := make([]byte, chacha20.NonceSizeX)
	copy(nonce, keyNonce[chacha20.KeySize:])
	binary.LittleEndian.PutUint64(nonce[:8], binary.LittleEndian.Uint64(nonce[:8])^offset)
	binary.LittleEndian.PutUint32(nonce[8:12], binary.LittleEndian.Uint32(nonce[8:12])^firstSlice)
	return nonce, nil
}

// NewXChaCha returns a stream cipher for one chunk.
func NewXChaCha(keyNonce []byte, offset uint64, firstSlice uint32) (*chacha20.Cipher, error) {
	if len(keyNonce) != chacha20.KeySize+chacha20.NonceSizeX {
		return nil, ErrInvalidKey
	}
	nonce, err := ChunkNonce(keyNonce, offset, firstSlice)
	if err != nil {
		return nil, err
	}
	return chacha20.NewUnauthenticatedCipher(keyNonce[:chacha20.KeySize], nonce)
}

// ARC4 is the legacy stream cipher used by encrypted Inno Setup chunks.
// It is kept private to this package because it is unauthenticated and should
// not be offered as a general-purpose cryptographic API.
type ARC4 struct {
	s    [256]byte
	a, b byte
}

func NewARC4(key []byte) (*ARC4, error) {
	if len(key) == 0 {
		return nil, ErrInvalidKey
	}
	r := &ARC4{}
	for i := range r.s {
		r.s[i] = byte(i)
	}
	var j byte
	for i := 0; i < len(r.s); i++ {
		j += r.s[i] + key[i%len(key)]
		r.s[i], r.s[int(j)] = r.s[int(j)], r.s[i]
	}
	return r, nil
}

func (r *ARC4) next() byte {
	r.a++
	r.b += r.s[r.a]
	r.s[r.a], r.s[r.b] = r.s[r.b], r.s[r.a]
	return r.s[byte(r.s[r.a]+r.s[r.b])]
}

func (r *ARC4) Discard(n int) {
	for i := 0; i < n; i++ {
		_ = r.next()
	}
}

func (r *ARC4) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("crypto: destination buffer too small")
	}
	for i, b := range src {
		dst[i] = b ^ r.next()
	}
}
