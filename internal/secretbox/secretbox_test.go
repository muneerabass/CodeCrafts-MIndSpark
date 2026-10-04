package secretbox

import (
	"errors"
	"strings"
	"testing"
)

func TestSealOpen(t *testing.T) {
	t.Setenv("DEPGUARD_SECRET_KEY", strings.Repeat("ab", 32))
	box, err := Seal("https://hooks.slack.com/services/T/B/x", "t1/slack")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(box), "hooks.slack.com") {
		t.Fatal("plaintext in ciphertext")
	}
	if got, err := Open(box, "t1/slack"); err != nil || got != "https://hooks.slack.com/services/T/B/x" {
		t.Fatalf("%q %v", got, err)
	}
	if _, err := Open(box, "t2/slack"); err == nil {
		t.Fatal("opened with another tenant's aad")
	}
	t.Setenv("DEPGUARD_SECRET_KEY", "short")
	if _, err := Seal("x", "a"); !errors.Is(err, ErrNoKey) {
		t.Fatal(err)
	}
}
