package innoextract

// ChecksumType identifies an installer-provided checksum.
type ChecksumType string

const (
	ChecksumNone    ChecksumType = ""
	ChecksumAdler32 ChecksumType = "adler32"
	ChecksumCRC32   ChecksumType = "crc32"
	ChecksumMD5     ChecksumType = "md5"
	ChecksumSHA1    ChecksumType = "sha1"
	ChecksumSHA256  ChecksumType = "sha256"
)

type Language struct {
	Name        string
	DisplayName string
	ID          uint32
	Codepage    uint32
}

type Info struct {
	DataVersion string
	AppName     string
	AppVersion  string
	AppID       string
	Publisher   string
	Languages   []Language
	GOGGameID   string
	Encrypted   bool
}

type Entry struct {
	Index          int
	Path           string
	Size           uint64
	CompressedSize uint64
	Checksum       string
	ChecksumType   ChecksumType
	Languages      string
	Components     string
	Tasks          string
	Check          string
	Temporary      bool
	Bits32         bool
	Bits64         bool
	Encrypted      bool
}

type File struct {
	Entry
	Data   []byte
	SHA256 string
}
