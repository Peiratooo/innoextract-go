// Package innoextract reads files embedded in Inno Setup installers.
package innoextract

import "io"

import "github.com/Peiratooo/innoextract-go/internal/format"

type archiveData = *format.Archive

// Archive is a parsed Inno Setup installer. Its methods do not write to disk.
type Archive struct {
	r    io.ReaderAt
	opts options
	data archiveData
}

// Extract is the one-shot form of Open followed by Archive.Extract.
func Extract(r io.ReaderAt, opts ...Option) ([]File, error) {
	a, err := Open(r, opts...)
	if err != nil {
		return nil, err
	}
	return a.Extract()
}
