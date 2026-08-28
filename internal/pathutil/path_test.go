package pathutil

import "testing"

func TestClean(t *testing.T) {
	tests := map[string]string{
		`{app}\bin\agent.exe`:                   "bin/agent.exe",
		`{APP}/bin/agent.exe`:                   "bin/agent.exe",
		`{application}\bin\agent.exe`:           "application/bin/agent.exe",
		`C:\\Program Files\\Demo\\..\\demo.exe`: "Program Files/demo.exe",
		`\\server\share\folder\\.\\file?.dll`:   "server/share/folder/file$.dll",
		`../../outside/../inside.txt`:           "inside.txt",
		`a//b///c`:                              "a/b/c",
		`{code:GetDir}\x:y|z*.txt`:              "code$GetDir/x$y$z$.txt",
		`/absolute/path`:                        "absolute/path",
		`C:relative.txt`:                        "relative.txt",
	}

	for raw, want := range tests {
		if got := Clean(raw); got != want {
			t.Errorf("Clean(%q) = %q, want %q", raw, got, want)
		}
	}
	if got := Clean("foo\x00bar"); got != "foo$bar" {
		t.Errorf("Clean(control character) = %q, want %q", got, "foo$bar")
	}
}

func TestCleanNeverReturnsAbsoluteOrParentPath(t *testing.T) {
	inputs := []string{
		`/tmp/file`, `\\host\share\file`, `D:\..\..\file`, `..`, `../..`,
		`a/../../../../file`, `C:/Windows/System32`,
	}
	for _, input := range inputs {
		got := Clean(input)
		if got == "" {
			continue
		}
		if got[0] == '/' || got == ".." || len(got) >= 3 && got[:3] == "../" {
			t.Errorf("Clean(%q) returned unsafe path %q", input, got)
		}
	}
}
