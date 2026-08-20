# innoextract-go

`innoextract-go` is a Go library for reading the metadata and embedded data
files in modern Inno Setup installers. It is an altered-source Go port of
the [innoextract](https://constexpr.org/innoextract/) extractor core; it does
not run an installer, its wizard, Pascal script, DLLs, or registry actions.

The module path is:

```text
github.com/Peiratooo/innoextract-go
```

Install it with:

```sh
go get github.com/Peiratooo/innoextract-go
```

## Basic use

The input is an `io.ReaderAt`, so the library can seek without taking
ownership of a file. `*os.File` and `*bytes.Reader` are typical inputs. A
separate size argument and `context.Context` are not required.

```go
package main

import (
	"fmt"
	"log"
	"os"

	innoextract "github.com/Peiratooo/innoextract-go"
)

func main() {
	setup, err := os.Open("setup.exe")
	if err != nil {
		log.Fatal(err)
	}
	defer setup.Close()

	archive, err := innoextract.Open(setup)
	if err != nil {
		log.Fatal(err)
	}

	info := archive.Info()
	fmt.Printf("%s %s (%s)\n", info.AppName, info.AppVersion, info.DataVersion)
	for _, entry := range archive.Files() {
		fmt.Printf("%s (%d bytes)\n", entry.Path, entry.Size)
	}

	files, err := archive.Extract()
	if err != nil {
		// `files` may contain entries that were decoded successfully.
		log.Printf("extraction completed with errors: %v", err)
	}
	for _, file := range files {
		fmt.Printf("%s: %d bytes, sha256=%s\n", file.Path, len(file.Data), file.SHA256)
	}
}
```

For callers that do not need to retain the parsed archive, the one-shot form
is equivalent to `Open` followed by `Archive.Extract`:

```go
files, err := innoextract.Extract(setup)
```

`File.Data` is the decoded content and `File.SHA256` is the lowercase SHA-256
digest calculated by the library. Paths are normalized to safe relative
slash-separated paths. Duplicate archive entries are kept as separate
entries; they are not written to disk or silently merged.

## Options

Options are passed to `Open` or the one-shot `Extract` function:

* `WithPassword(password)` supplies a password where the selected encrypted
  format is supported.
* `WithCodepage(codepage)` selects the code page used by legacy ANSI metadata;
  the modern 6.x metadata stream is UTF-16LE.
* `WithSliceProvider(provider)` supplies an `io.ReaderAt` for an external data
  slice when an installer is split across `.bin` files. The provider is only
  called for slices referenced by the archive.
* `WithMemoryLimit(bytes)` bounds extraction/decompression memory. The default
  extraction budget is 1 GiB; the setup metadata header is bounded at 64 MiB.

Extraction is memory-oriented: decoded content is returned in `File.Data` and
the package does not create output directories or write files. The caller
owns and closes the input reader after it has finished with the archive.

## Results and errors

`Archive.Info` returns installer metadata, including the data version,
application fields, languages, encryption flag, and a detected GOG game ID.
`Archive.Files` returns the file manifest. `Archive.Verify` decodes and
checksums the entries without returning file data.

Parsing and archive-wide failures are returned by `Open` (and by the one-shot
`Extract`) as errors such as `ErrInvalidFormat`, `ErrUnsupportedVersion`,
`ErrUnsupportedCompression`, `ErrUnsupportedEncryption`, or
`ErrLimitExceeded`. Use `errors.Is` to test these sentinel errors.

An individual file can fail while other files succeed. In that case
`Archive.Extract` returns the successful `[]File` together with an
`*ExtractError`; its `Failures` field contains an `EntryError` for each failed
entry, and `errors.Is`/`errors.As` can still inspect the underlying cause.
Callers should inspect both return values rather than discarding successful
files whenever `err != nil`.

## Compatibility boundary

The current setup metadata parser accepts Inno Setup data versions from 6.0
through 6.7 (inclusive). Versions outside that range, including future 6.8+
formats and older 1.x–5.x formats, are not promised and normally return
`ErrUnsupportedVersion`. The repository includes a 6.6.1 sample integration
test; applications should still validate the exact installer families they
need.

Encrypted 6.5+ installers use an outer encryption header. The header is
recognized, but encrypted 6.5+ data is currently rejected with
`ErrUnsupportedEncryption`; `WithPassword` does not bypass this limitation.
Unencrypted 6.5+ installers remain within the version boundary. Encrypted
installers in general should be treated as unsupported unless a future release
explicitly documents their format.

## License and source

This repository's `LICENSE` records that the code is an altered source version
of `innoextract`, whose original copyright is held by Daniel Scharrer
(2011–2020), and adds the Go-port contributors' notice. It carries the
original permissive three-condition license: preserve attribution, mark
altered source versions, and retain the notice. Distributions must include
that file. `innoextract-go` is not affiliated with Inno Setup.
