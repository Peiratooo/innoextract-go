package format

import "strconv"

type ChecksumType uint8

const (
	ChecksumNone ChecksumType = iota
	ChecksumAdler32
	ChecksumCRC32
	ChecksumMD5
	ChecksumSHA1
	ChecksumSHA256
	ChecksumPBKDF2SHA256XChaCha20
)

type Checksum struct {
	Type ChecksumType
	Data []byte
}

type Compression uint8

const (
	Stored Compression = iota
	Zlib
	BZip2
	LZMA1
	LZMA2
	UnknownCompression
)

type Encryption uint8

const (
	Plaintext Encryption = iota
	ARC4MD5
	ARC4SHA1
	XChaCha20
)

type FileFilter uint8

const (
	NoFilter FileFilter = iota
	Instruction4108
	Instruction5200
	Instruction5309
	ZlibFilter
)

type Offsets struct {
	FoundMagic          bool
	Revision            uint32
	ExeOffset           uint64
	ExeCompressedSize   uint64
	ExeUncompressedSize uint64
	ExeChecksum         Checksum
	HeaderOffset        uint64
	DataOffset          uint64
}

type Version struct {
	Major, Minor, Patch, Revision uint8
	Unicode, Known                bool
}

func (v Version) String() string {
	s := strconv.Itoa(int(v.Major)) + "." + strconv.Itoa(int(v.Minor)) + "." + strconv.Itoa(int(v.Patch))
	if v.Revision != 0 {
		s += "." + strconv.Itoa(int(v.Revision))
	}
	return s
}

type Chunk struct {
	FirstSlice, LastSlice uint32
	SortOffset            uint64
	Offset, Size          uint64
	Compression           Compression
	Encryption            Encryption
}

type StoredFile struct {
	Offset, Size uint64
	Checksum     Checksum
	Filter       FileFilter
}

type DataEntry struct {
	Chunk            Chunk
	File             StoredFile
	UncompressedSize uint64
}

type FileEntry struct {
	Source, Destination                 string
	Languages, Components, Tasks, Check string
	BeforeInstall, AfterInstall         string
	Location                            uint32
	AdditionalLocations                 []uint32
	Size                                uint64
	Checksum                            Checksum
	Temporary, Bits32, Bits64, DontCopy bool
}

type Language struct {
	Name, DisplayName string
	ID, Codepage      uint32
}

type RegistryEntry struct {
	Key, Name, Value string
}

type Header struct {
	AppName, AppVersion, AppID, Publisher string
	BaseFilename                          string
	SlicesPerDisk                         uint32
	Compression                           Compression
	Encrypted                             bool
	UnsupportedEncryption                 bool
	Password                              Checksum
	PasswordSalt                          []byte
}

type Archive struct {
	Offsets     Offsets
	Version     Version
	Header      Header
	Languages   []Language
	Files       []FileEntry
	DataEntries []DataEntry
	Registry    []RegistryEntry
}
