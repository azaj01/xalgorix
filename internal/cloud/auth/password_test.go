package auth

import (
	"errors"
	"strings"
	"testing"
)

func TestEnforcePolicy(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		password string
		want     error
	}{
		{"valid mixed letters and digits", "Abcdefgh1234", nil},
		{"valid letters digits and symbols", "p@ssword-1234", nil},
		{"valid exactly twelve runes", "abcdefghij12", nil},
		{"valid unicode letters with digit", "résuméélève12", nil},
		{"too short", "Ab1cdef", ErrPasswordTooShort},
		{"too short eleven", "abcdefghij1", ErrPasswordTooShort},
		{"missing digit", "abcdefghijklmno", ErrPasswordMissingDigit},
		{"missing letter", "123456789012345", ErrPasswordMissingLetter},
		{"missing both still reports too short for empty", "", ErrPasswordTooShort},
		{"only symbols", "!@#$%^&*()_+-=", ErrPasswordMissingLetter},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := EnforcePolicy(tc.password)
			if !errors.Is(got, tc.want) {
				t.Fatalf("EnforcePolicy(%q) = %v, want %v", tc.password, got, tc.want)
			}
		})
	}
}

func TestHashProducesPHCFormat(t *testing.T) {
	t.Parallel()

	encoded, err := Hash("correct horse battery staple")
	if err != nil {
		t.Fatalf("Hash returned error: %v", err)
	}

	const wantPrefix = "$argon2id$v=19$m=65536,t=2,p=2$"
	if !strings.HasPrefix(encoded, wantPrefix) {
		t.Fatalf("encoded hash %q does not start with %q", encoded, wantPrefix)
	}

	parts := strings.Split(encoded, "$")
	if len(parts) != 6 {
		t.Fatalf("expected 6 PHC segments, got %d in %q", len(parts), encoded)
	}
	if parts[4] == "" || parts[5] == "" {
		t.Fatalf("expected non-empty salt and hash segments, got %q", encoded)
	}
}

func TestHashIsUnique(t *testing.T) {
	t.Parallel()

	const password = "correct horse battery staple"
	first, err := Hash(password)
	if err != nil {
		t.Fatalf("Hash #1 returned error: %v", err)
	}
	second, err := Hash(password)
	if err != nil {
		t.Fatalf("Hash #2 returned error: %v", err)
	}
	if first == second {
		t.Fatalf("expected unique hashes for repeated calls; both were %q", first)
	}

	ok, err := Verify(password, first)
	if err != nil || !ok {
		t.Fatalf("Verify(first) = (%v, %v), want (true, nil)", ok, err)
	}
	ok, err = Verify(password, second)
	if err != nil || !ok {
		t.Fatalf("Verify(second) = (%v, %v), want (true, nil)", ok, err)
	}
}

func TestVerifySuccessAndFailure(t *testing.T) {
	t.Parallel()

	encoded, err := Hash("Abcdefgh1234")
	if err != nil {
		t.Fatalf("Hash returned error: %v", err)
	}

	ok, err := Verify("Abcdefgh1234", encoded)
	if err != nil {
		t.Fatalf("Verify with correct password returned error: %v", err)
	}
	if !ok {
		t.Fatalf("Verify with correct password returned false")
	}

	ok, err = Verify("Abcdefgh1235", encoded)
	if err != nil {
		t.Fatalf("Verify with wrong password returned error: %v", err)
	}
	if ok {
		t.Fatalf("Verify with wrong password returned true")
	}

	ok, err = Verify("", encoded)
	if err != nil {
		t.Fatalf("Verify with empty password returned error: %v", err)
	}
	if ok {
		t.Fatalf("Verify with empty password returned true")
	}
}

func TestVerifyMalformedEncoded(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		encoded string
	}{
		{"empty", ""},
		{"plain text", "not-a-hash"},
		{"missing leading dollar", "argon2id$v=19$m=65536,t=2,p=2$c2FsdA$aGFzaA"},
		{"wrong algorithm", "$argon2i$v=19$m=65536,t=2,p=2$c2FsdHNhbHRzYWx0c2E$aGFzaGhhc2hoYXNoaA"},
		{"unsupported version", "$argon2id$v=18$m=65536,t=2,p=2$c2FsdHNhbHRzYWx0c2E$aGFzaGhhc2hoYXNoaA"},
		{"bad params", "$argon2id$v=19$mem=65536,t=2,p=2$c2FsdHNhbHRzYWx0c2E$aGFzaGhhc2hoYXNoaA"},
		{"zero time", "$argon2id$v=19$m=65536,t=0,p=2$c2FsdHNhbHRzYWx0c2E$aGFzaGhhc2hoYXNoaA"},
		{"corrupt salt base64", "$argon2id$v=19$m=65536,t=2,p=2$!!!notbase64!!!$aGFzaGhhc2hoYXNoaA"},
		{"corrupt hash base64", "$argon2id$v=19$m=65536,t=2,p=2$c2FsdHNhbHRzYWx0c2E$!!!notbase64!!!"},
		{"too few segments", "$argon2id$v=19$m=65536,t=2,p=2"},
		{"empty salt", "$argon2id$v=19$m=65536,t=2,p=2$$aGFzaGhhc2hoYXNoaA"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ok, err := Verify("Abcdefgh1234", tc.encoded)
			if ok {
				t.Fatalf("Verify with malformed encoded returned true")
			}
			if !errors.Is(err, ErrInvalidEncodedHash) {
				t.Fatalf("Verify(malformed) error = %v, want ErrInvalidEncodedHash", err)
			}
		})
	}
}

func TestVerifyTamperedHashFails(t *testing.T) {
	t.Parallel()

	encoded, err := Hash("Abcdefgh1234")
	if err != nil {
		t.Fatalf("Hash returned error: %v", err)
	}

	// Flip the last character of the hash segment to simulate tampering
	// without breaking the PHC structure or base64 validity.
	idx := strings.LastIndex(encoded, "$")
	if idx == -1 || idx == len(encoded)-1 {
		t.Fatalf("unexpected encoded layout: %q", encoded)
	}
	last := encoded[len(encoded)-1]
	var swapped byte
	if last == 'A' {
		swapped = 'B'
	} else {
		swapped = 'A'
	}
	tampered := encoded[:len(encoded)-1] + string(swapped)

	ok, err := Verify("Abcdefgh1234", tampered)
	if err != nil {
		// A tampered but still well-formed PHC string must not error.
		t.Fatalf("Verify(tampered) returned error: %v", err)
	}
	if ok {
		t.Fatalf("Verify(tampered) returned true; expected false")
	}
}
