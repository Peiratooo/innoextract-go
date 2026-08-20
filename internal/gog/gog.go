// Package gog contains the format-only parts of GOG installer handling.
// It deliberately does not inspect the filesystem or invoke archive tools.
package gog

import (
	"encoding/hex"
	"sort"
	"strconv"
	"strings"

	"github.com/Peiratooo/innoextract-go/internal/format"
)

const gogGamesPrefix = `SOFTWARE\GOG.com\Games\`

// GameID returns the GOG game ID stored in registry entries. A gameID value is
// preferred; if it is absent, the final component of the Games key is used as
// the same fallback as the native innoextract implementation.
func GameID(entries []format.RegistryEntry) string {
	var fallback string
	for _, entry := range entries {
		if !strings.HasPrefix(strings.ToLower(entry.Key), strings.ToLower(gogGamesPrefix)) {
			continue
		}
		id := entry.Key[len(gogGamesPrefix):]
		if strings.Contains(id, `\`) {
			continue
		}
		if strings.EqualFold(entry.Name, "gameID") {
			return entry.Value
		}
		if fallback == "" {
			fallback = id
		}
	}
	return fallback
}

// Apply recovers the pure metadata used by GOG Galaxy multi-part files.
// Malformed markers are ignored because this API has no logging or error
// channel; ordinary Inno files are left unchanged.
func Apply(a *format.Archive) {
	if a == nil {
		return
	}
	if !looksLikeGOG(a) && !hasGalaxyMarkers(a) {
		return
	}

	allLanguages := make(map[string]struct{})
	hasLanguageConstraints := false
	applyGalaxyParts(a, allLanguages, &hasLanguageConstraints)
	applyGalaxyConstraints(a, allLanguages)

	if len(allLanguages) == 0 {
		return
	}
	if !hasLanguageConstraints {
		a.Languages = nil
	}
	names := make([]string, 0, len(allLanguages))
	for name := range allLanguages {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if !hasLanguage(a.Languages, name) {
			a.Languages = append(a.Languages, format.Language{Name: name})
		}
	}
}

func looksLikeGOG(a *format.Archive) bool {
	if GameID(a.Registry) != "" {
		return true
	}
	return strings.Contains(strings.ToLower(a.Header.Publisher), "gog.com")
}

func hasGalaxyMarkers(a *format.Archive) bool {
	for _, file := range a.Files {
		if len(firstFunctionCall(file.BeforeInstall, "before_install", "before_install_dependency")) != 0 ||
			len(firstFunctionCall(file.AfterInstall, "after_install", "after_install_dependency")) != 0 {
			return true
		}
	}
	return false
}

func applyGalaxyParts(a *format.Archive, allLanguages map[string]struct{}, hasLanguageConstraints *bool) {
	activeStart := -1
	var remaining uint64

	for i := range a.Files {
		file := &a.Files[i]
		startInfo := firstFunctionCall(file.BeforeInstall, "before_install", "before_install_dependency")

		if len(startInfo) != 0 {
			// A new start abandons an incomplete previous group.
			activeStart = -1
			remaining = 0

			if len(startInfo) >= 2 && startInfo[1] != "" {
				file.Destination = startInfo[1]
			}
			file.Checksum = format.Checksum{}
			if checksum, ok := parseMD5(startInfo[0]); ok {
				file.Checksum = checksum
			}
			file.Size = 0

			parts := uint64(1)
			if len(startInfo) >= 3 {
				parsed, err := strconv.ParseUint(startInfo[2], 10, 64)
				if err != nil {
					parts = 0
				} else if parsed != 0 {
					parts = parsed
				}
			}
			if parts != 0 {
				activeStart = i
				remaining = parts
			}
		}

		partInfo := firstFunctionCall(file.AfterInstall, "after_install", "after_install_dependency")
		if len(partInfo) != 0 {
			if activeStart < 0 || remaining == 0 || uint64(file.Location) >= uint64(len(a.DataEntries)) || len(partInfo) < 3 {
				activeStart = -1
				remaining = 0
			} else if uncompressed, err := strconv.ParseUint(partInfo[2], 10, 64); err != nil {
				activeStart = -1
				remaining = 0
			} else {
				remaining--
				data := &a.DataEntries[file.Location]
				data.UncompressedSize = uncompressed
				data.File.Filter = format.ZlibFilter

				start := &a.Files[activeStart]
				start.Size += uncompressed
				if i != activeStart {
					file.Destination = ""
					if !containsLocation(start.AdditionalLocations, file.Location) {
						start.AdditionalLocations = append(start.AdditionalLocations, file.Location)
					}
				}
			}
		} else if len(startInfo) != 0 || remaining != 0 {
			// A start marker must be followed immediately by a valid part. This
			// also prevents an unrelated file from being absorbed into a group.
			activeStart = -1
			remaining = 0
		}

		if file.Destination != "" {
			collectLanguages(file.Check, allLanguages)
		}
		*hasLanguageConstraints = *hasLanguageConstraints || file.Languages != ""
	}
}

func applyGalaxyConstraints(a *format.Archive, allLanguages map[string]struct{}) {
	for i := range a.Files {
		file := &a.Files[i]
		if file.Destination == "" {
			continue
		}

		check := firstFunctionCall(file.Check, "check_if_install")
		if len(check) != 0 {
			if check[0] != "" {
				constraints := parseConstraints(check[0])
				if len(constraints) != 0 && !isAllLanguages(constraints, allLanguages) {
					file.Languages = constraintExpression(constraints)
				}
			}
			if len(check) >= 2 && check[1] != "" {
				file.Bits32, file.Bits64 = architectureBits(check[1])
			}
			if file.Components == "" {
				file.Components = "game"
			}
		}

		dependency := firstFunctionCall(file.Check, "check_if_install_dependency")
		if len(dependency) != 0 && file.Components == "" && dependency[0] != "" {
			file.Components = dependency[0]
		}
	}
}

type constraint struct {
	name    string
	negated bool
}

func parseConstraints(input string) []constraint {
	var result []constraint
	for _, token := range strings.Split(input, "#") {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		negated := token[0] == '!'
		if negated {
			token = strings.TrimSpace(token[1:])
		}
		if token != "" {
			result = append(result, constraint{name: token, negated: negated})
		}
	}
	return result
}

func constraintExpression(constraints []constraint) string {
	var b strings.Builder
	for i, item := range constraints {
		if i != 0 {
			b.WriteString(" or ")
		}
		if item.negated {
			// Keep the spacing used by B's create_constraint_expression; these
			// strings are Inno expressions rather than user-facing prose.
			b.WriteString(" not ")
		}
		b.WriteString(item.name)
	}
	return b.String()
}

func isAllLanguages(constraints []constraint, all map[string]struct{}) bool {
	if len(all) <= 1 || len(constraints) < len(all) {
		return false
	}
	seen := make(map[string]struct{}, len(constraints))
	for _, item := range constraints {
		if item.negated {
			continue
		}
		seen[item.name] = struct{}{}
	}
	for name := range all {
		if _, ok := seen[name]; !ok {
			return false
		}
	}
	return true
}

func architectureBits(input string) (bits32, bits64 bool) {
	if input == "32#64#" {
		return false, false
	}
	constraints := parseConstraints(input)
	if len(constraints) == 0 {
		return false, false
	}

	var positive32, positive64 bool
	for _, item := range constraints {
		switch item.name {
		case "32":
			if !item.negated {
				positive32 = true
			} else if len(constraints) <= 1 {
				positive64 = true
			}
		case "64":
			if !item.negated {
				positive64 = true
			} else if len(constraints) <= 1 {
				positive32 = true
			}
		}
	}
	if positive32 && positive64 {
		return false, false
	}
	return positive32, positive64
}

func collectLanguages(code string, all map[string]struct{}) {
	check := firstFunctionCall(code, "check_if_install")
	if len(check) == 0 || check[0] == "" {
		return
	}
	for _, item := range parseConstraints(check[0]) {
		all[item.name] = struct{}{}
	}
}

func parseMD5(value string) (format.Checksum, bool) {
	data, err := hex.DecodeString(value)
	if err != nil || len(data) != 16 {
		return format.Checksum{}, false
	}
	return format.Checksum{Type: format.ChecksumMD5, Data: data}, true
}

func containsLocation(locations []uint32, location uint32) bool {
	for _, item := range locations {
		if item == location {
			return true
		}
	}
	return false
}

func hasLanguage(languages []format.Language, name string) bool {
	for _, language := range languages {
		if language.Name == name {
			return true
		}
	}
	return false
}

func firstFunctionCall(code string, names ...string) []string {
	for _, name := range names {
		if result := parseFunctionCall(code, name); result != nil {
			return result
		}
	}
	return nil
}

func parseFunctionCall(code, name string) []string {
	i := skipSpace(code, 0)
	start := i
	for i < len(code) && !strings.ContainsRune(" \t\r\n(),'", rune(code[i])) {
		i++
	}
	if code[start:i] != name {
		return nil
	}
	i = skipSpace(code, i)
	if i >= len(code) || code[i] != '(' {
		return nil
	}
	i++
	var args []string
	for {
		i = skipSpace(code, i)
		if i >= len(code) {
			return nil
		}

		var value string
		if code[i] == ')' {
			// Empty argument lists are valid and are represented by no args.
			i++
			break
		}
		if code[i] == '\'' {
			var b strings.Builder
			i++
			closed := false
			for i < len(code) {
				end := strings.IndexByte(code[i:], '\'')
				if end < 0 {
					return nil
				}
				b.WriteString(code[i : i+end])
				i += end + 1
				if i < len(code) && code[i] == '\'' {
					b.WriteByte('\'')
					i++
					continue
				}
				closed = true
				break
			}
			if !closed {
				return nil
			}
			value = b.String()
		} else {
			start = i
			for i < len(code) && !strings.ContainsRune(" \t\r\n(),", rune(code[i])) {
				i++
			}
			value = code[start:i]
		}
		args = append(args, value)

		i = skipSpace(code, i)
		if i >= len(code) {
			return nil
		}
		switch code[i] {
		case ',':
			i++
		case ')':
			i++
			goto done
		default:
			return nil
		}
	}

done:
	i = skipSpace(code, i)
	if i < len(code) && code[i] == ';' {
		i = skipSpace(code, i+1)
	}
	if i != len(code) {
		return nil
	}
	return args
}

func skipSpace(s string, i int) int {
	for i < len(s) {
		switch s[i] {
		case ' ', '\t', '\r', '\n':
			i++
		default:
			return i
		}
	}
	return i
}
