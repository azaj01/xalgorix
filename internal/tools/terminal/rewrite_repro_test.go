package terminal

import (
	"testing"
)

// TestRewriteShellSegments_MultiBytePanic reproduces the panic:
//
//	runtime error: slice bounds out of range [414:413]
//
// when a command contains multi-byte UTF-8 characters (e.g. em-dash,
// curly quotes, non-ASCII domain characters) before a shell delimiter.
//
// In `range command`, `i` is the byte offset of each rune. For multi-byte
// runes, the byte offset can jump by 2-4 bytes. But the code uses
// `command[i+1]` (a byte-level peek-ahead of exactly 1) and
// `command[i : i+delimiterLen]` — these assume every rune occupies
// exactly 1 byte. After a multi-byte rune, `i` can overshoot the
// actual byte position, making `i+delimiterLen` exceed `i` by a
// wrong amount, or producing inverted slice bounds.
func TestRewriteShellSegments_MultiBytePanic(t *testing.T) {
	// Simulates the crash scenario: a command with multi-byte characters
	// followed by a pipe or &&.
	cases := []struct {
		name string
		cmd  string
	}{
		{
			name: "em-dash before pipe",
			cmd:  "echo 'testing — value' | grep foo",
		},
		{
			name: "curly quotes before semicolon",
			cmd:  "echo 'it\u2019s a test'; echo done",
		},
		{
			name: "unicode domain before &&",
			cmd:  "curl https://例え.jp/path && echo done",
		},
		{
			name: "mixed multi-byte with double pipe",
			cmd:  "echo 'naïve café résumé' || echo fallback",
		},
		{
			name: "emoji in command before ampersand",
			cmd:  "echo '🔍 scanning' && nuclei -u https://example.test",
		},
		{
			name: "long multi-byte prefix to trigger offset mismatch",
			// Build a string with enough multi-byte chars that i (byte offset)
			// significantly exceeds the character count, reproducing [414:413].
			cmd: buildLongMultiByteCommand(),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Should not panic
			result := rewriteShellSegments(tc.cmd, func(s string) string { return s })
			if result != tc.cmd {
				t.Fatalf("identity rewrite changed command:\n  got:  %q\n  want: %q", result, tc.cmd)
			}
		})
	}
}

func buildLongMultiByteCommand() string {
	// Each '—' is 3 bytes (U+2014). 140 of them = 420 bytes but only 140 runes.
	// After all of them, place a pipe. The rune index `i` at the pipe will be
	// 420 (byte offset), but the previous rune ended at byte 419, so
	// command[start:i] with start=0 works, but the delimiter peek
	// command[i+1] can access byte 421 while len might be 422... the real
	// problem is when the byte offset math for delimiterLen goes wrong.
	s := ""
	for j := 0; j < 140; j++ {
		s += "—"
	}
	return s + " | grep test"
}
