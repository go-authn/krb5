package krb5

import (
	"errors"
	"testing"

	"github.com/jcmturner/gokrb5/v8/types"
)

// brokenContext holds a key whose encryption type does not exist, which is
// how the crypto failure paths are reached: with a real key they cannot be.
// A context like this cannot arise from an exchange — [Acceptor.Accept] only
// ever builds one from a key the KDC issued — so these branches would
// otherwise be code nobody has run, in the half of the package that says no.
func brokenContext() *Context {
	return &Context{key: types.EncryptionKey{KeyType: 0, KeyValue: []byte("short")}}
}

func TestSigningFailsLoudlyOnAnImpossibleKey(t *testing.T) {
	c := brokenContext()
	if _, err := c.MIC([]byte("x")); err == nil {
		t.Error("MIC succeeded with an unknown encryption type")
	}
	if _, err := c.Wrap([]byte("x")); err == nil {
		t.Error("Wrap succeeded with an unknown encryption type")
	}
	if _, err := c.Seal([]byte("x")); err == nil {
		t.Error("Seal succeeded with an unknown encryption type")
	}
	if _, err := c.Unseal(make([]byte, 64)); err == nil {
		t.Error("Unseal succeeded with an unknown encryption type")
	}
}

func TestVerifyMICRefusesWhatItShould(t *testing.T) {
	c := testContext(t)
	good, err := c.MIC([]byte("the message"))
	if err != nil {
		t.Fatal(err)
	}
	// Our own signature, presented back to us. The acceptor flag and the key
	// usage differ by direction precisely so this cannot pass.
	if err := c.VerifyMIC([]byte("the message"), good); !errors.Is(err, ErrBadMIC) {
		t.Errorf("an acceptor's own MIC verified: %v", err)
	}
	for _, tc := range []struct {
		name  string
		token []byte
	}{
		{"empty", nil},
		{"not a token", []byte("hello there, this is long enough")},
		{"a truncated one", good[:len(good)-1]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := c.VerifyMIC([]byte("the message"), tc.token); !errors.Is(err, ErrBadMIC) {
				t.Errorf("err = %v, want ErrBadMIC", err)
			}
		})
	}
}

func TestVerifyMICIsAboutTHISMessage(t *testing.T) {
	// The signature covers the message and the token header together, so a
	// token lifted from one message must not verify against another. If it
	// did, every signed call could be re-aimed.
	c := testContext(t)
	tok := initiatorMIC(t, c, []byte("transfer 10"))
	if err := c.VerifyMIC([]byte("transfer 10"), tok); err != nil {
		t.Fatalf("the genuine message was refused: %v", err)
	}
	if err := c.VerifyMIC([]byte("transfer 99"), tok); !errors.Is(err, ErrBadMIC) {
		t.Errorf("a signature verified against another message: %v", err)
	}
}

func TestUnwrapRefusesASealedToken(t *testing.T) {
	// ErrSealed is distinct from ErrBadMIC on purpose: the token is
	// well-formed and correctly signed, and the only thing wrong is that the
	// payload is ciphertext. Reporting a bad signature would send an operator
	// looking at keys and clocks for a missing feature.
	c := testContext(t)
	tok, err := c.Seal([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	// Seal marks the token as the acceptor's; clear that so Unwrap reaches
	// the sealed check rather than the direction check.
	tok[2] = 0x02
	if _, err := c.Unwrap(tok); !errors.Is(err, ErrSealed) {
		t.Errorf("err = %v, want ErrSealed", err)
	}
}

func TestUnwrapRefusesWhatIsNotAWrapToken(t *testing.T) {
	c := testContext(t)
	for _, tc := range [][]byte{nil, []byte("short"), make([]byte, 64)} {
		if _, err := c.Unwrap(tc); err == nil {
			t.Errorf("%x was accepted as a wrap token", tc)
		}
	}
}
