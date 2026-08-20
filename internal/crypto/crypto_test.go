package crypto

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/Peiratooo/innoextract-go/internal/format"
)

func TestChecksumVectors(t *testing.T) {
	data := []byte("123456789")
	tests := []struct {
		name  string
		type_ format.ChecksumType
		want  string
	}{
		{"Adler32", format.ChecksumAdler32, "091e01de"},
		{"CRC32", format.ChecksumCRC32, "cbf43926"},
		{"MD5", format.ChecksumMD5, "25f9e794323b453885f5181f1b624d0b"},
		{"SHA1", format.ChecksumSHA1, "f7c3bc1d808e04732adf679965ccc34ca7ae3441"},
		{"SHA256", format.ChecksumSHA256, "15e2b0d3c33891ebb0f1ef609ec419420c20e320ce94c65fbc8c3312448eb225"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := Sum(test.type_, data)
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(got) != test.want {
				t.Fatalf("sum = %x, want %s", got, test.want)
			}
		})
	}
}

func TestARC4Vector(t *testing.T) {
	cipher, err := NewARC4([]byte("Key"))
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("Plaintext")
	got := make([]byte, len(plaintext))
	cipher.XORKeyStream(got, plaintext)
	if hex.EncodeToString(got) != "bbf316e8d940af0ad3" {
		t.Fatalf("ciphertext = %x", got)
	}
}

func TestPBKDF2DerivationVector(t *testing.T) {
	salt := make([]byte, 16+4+24)
	copy(salt, "salt")
	salt[16] = 2
	derived, err := DeriveXChaChaKey([]byte("password"), salt)
	if err != nil {
		t.Fatal(err)
	}
	want := "8db3277ed085e8ab63e4fdd5c11e6c60bd3788ab4164f25d6349786fa6262023"
	if hex.EncodeToString(derived[:32]) != want {
		t.Fatalf("PBKDF2 key = %x, want %s", derived[:32], want)
	}
	if len(derived) != 56 {
		t.Fatalf("derived key+nonce length = %d", len(derived))
	}
}

func TestXChaCha20Vector(t *testing.T) {
	key, _ := hex.DecodeString("9d23bd4149cb979ccf3c5c94dd217e9808cb0e50cd0f67812235eaaf601d6232")
	nonce, _ := hex.DecodeString("c047548266b7c370d33566a2425cbf30d82d1eaf5294109e")
	want, _ := hex.DecodeString("a21209096594de8c5667b1d13ad93f744106d054df210e4782cd396fec692d3515a20bf351eec011a92c367888bc464c32f0807acd6c203a247e0db854148468e9f96bee4cf718d68d5f637cbd5a376457788e6fae90fc31097cfc")
	cipher, err := NewXChaCha(append(key, nonce...), 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(want))
	cipher.XORKeyStream(got, got)
	if !bytes.Equal(got, want) {
		t.Fatalf("XChaCha20 output = %x, want %x", got, want)
	}
}
