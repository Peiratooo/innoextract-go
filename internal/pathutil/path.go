// Package pathutil contains the path rules used when turning an Inno Setup
// destination into a path that is safe to hand to a caller.
package pathutil

import "strings"

// Clean converts an Inno Setup path to a relative, slash-separated path.
//
// Inno destinations commonly contain Windows separators, constants such as
// {app}, drive/root prefixes, and values which are not valid file-name
// characters. Clean deliberately does not consult the local filesystem and
// never returns an absolute path. Unknown constants are reduced to their
// contents (the same useful fallback as innoextract's empty filename map).
func Clean(raw string) string {
	raw = expandConstants(raw, 0)

	// A drive prefix is a root marker, not part of an output path. This also
	// handles drive-relative paths such as C:foo safely.
	if len(raw) >= 2 && isASCIIAlpha(raw[0]) && raw[1] == ':' {
		raw = raw[2:]
	}

	// Treat both slash forms as separators before processing components. Drop
	// all leading separators so that the result cannot be absolute or UNC.
	raw = strings.NewReplacer("\\", "/").Replace(raw)
	raw = strings.TrimLeft(raw, "/")

	parts := make([]string, 0, 4)
	for _, part := range strings.Split(raw, "/") {
		part = cleanPart(part)
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			if len(parts) > 0 {
				parts = parts[:len(parts)-1]
			}
			continue
		}
		parts = append(parts, part)
	}
	return strings.Join(parts, "/")
}

func cleanPart(part string) string {
	var b strings.Builder
	b.Grow(len(part))
	for i := 0; i < len(part); i++ {
		c := part[i]
		if c < 0x20 || strings.ContainsRune(`<>:"|?*`, rune(c)) {
			b.WriteByte('$')
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

func expandConstants(s string, depth int) string {
	// Constants can be nested in malformed/custom installers. A small depth
	// cap prevents a crafted path from causing unbounded recursion.
	if depth >= 8 || !strings.ContainsRune(s, '{') {
		return s
	}

	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		if s[i] != '{' {
			b.WriteByte(s[i])
			i++
			continue
		}

		end := findConstantEnd(s, i+1)
		if end < 0 {
			// An unmatched brace is not useful as a path component. Treat it as
			// an unsafe character instead of preserving a surprising path.
			b.WriteByte('$')
			i++
			continue
		}

		value := s[i+1 : end]
		if value == "" {
			b.WriteByte('$')
		} else {
			b.WriteString(expandConstants(value, depth+1))
		}
		i = end + 1
	}
	return b.String()
}

func findConstantEnd(s string, start int) int {
	depth := 0
	for i := start; i < len(s); i++ {
		switch s[i] {
		case '{':
			depth++
		case '}':
			if depth == 0 {
				return i
			}
			depth--
		}
	}
	return -1
}

func isASCIIAlpha(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}
