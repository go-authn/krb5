package krb5

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/types"
)

// testContext is a context with a key and nothing else: enough to seal and
// unseal, which is all these tests are about. What a REAL exchange produces
// is checked against MIT in judge_test.go; this file covers the refusals,
// which MIT has no reason to send.
func testContext(t *testing.T) *Context {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return &Context{key: types.EncryptionKey{KeyType: 18, KeyValue: k}}
}

// sealAsInitiator builds what a client sends, which Seal deliberately cannot
// do: Seal is the acceptor half, and the two differ by a flag and a key usage.
func sealAsInitiator(t *testing.T, c *Context, msg []byte, ec uint16) []byte {
	t.Helper()
	h := sealHeader{flags: gssapi.MICTokenFlagSealed, ec: ec}
	plain := append([]byte{}, msg...)
	plain = append(plain, make([]byte, ec)...)
	plain = append(plain, h.marshal(0)...)
	et, err := crypto.GetEtype(c.key.KeyType)
	if err != nil {
		t.Fatal(err)
	}
	_, cipher, err := et.EncryptMessage(c.key.KeyValue, plain, keyusage.GSSAPI_INITIATOR_SEAL)
	if err != nil {
		t.Fatal(err)
	}
	return append(h.marshal(0), cipher...)
}

func TestUnsealOpensWhatAnInitiatorSealed(t *testing.T) {
	c := testContext(t)
	for _, ec := range []uint16{0, 1, 7, 16} {
		got, err := c.Unseal(sealAsInitiator(t, c, []byte("secret"), ec))
		if err != nil {
			t.Fatalf("ec=%d: %v", ec, err)
		}
		if string(got) != "secret" {
			t.Errorf("ec=%d: got %q, want %q", ec, got, "secret")
		}
	}
}

func TestUnsealRefusesAnUnsealedToken(t *testing.T) {
	// A caller asking to unseal is one whose protocol promised
	// confidentiality. Returning the payload of a token that crossed the wire
	// in the clear would keep that promise in name only.
	c := testContext(t)
	tok, err := c.Wrap([]byte("in the clear"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Unseal(tok); !errors.Is(err, ErrNotSealed) {
		t.Errorf("err = %v, want ErrNotSealed", err)
	}
}

func TestUnsealRefusesOurOwnTokenComingBack(t *testing.T) {
	c := testContext(t)
	tok, err := c.Seal([]byte("from the server"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Unseal(tok); !errors.Is(err, ErrBadMIC) {
		t.Errorf("err = %v, want ErrBadMIC", err)
	}
}

func TestUnsealRefusesAnAlteredHeader(t *testing.T) {
	// The header travels in the CLEAR. Only the copy encrypted inside ties it
	// to the ciphertext, so altering the visible one must be caught there.
	c := testContext(t)
	for _, off := range []int{2, 4, 5, 8, 15} {
		tok := sealAsInitiator(t, c, []byte("secret"), 0)
		tok[off] ^= 1
		if _, err := c.Unseal(tok); err == nil {
			t.Errorf("a token with byte %d altered was accepted", off)
		}
	}
}

func TestUnsealRefusesEveryTruncation(t *testing.T) {
	c := testContext(t)
	full := sealAsInitiator(t, c, []byte("secret"), 0)
	for n := range len(full) {
		if _, err := c.Unseal(full[:n]); err == nil {
			t.Errorf("a token cut to %d bytes was accepted", n)
		}
	}
}

func TestUnsealRefusesAForeignTokenId(t *testing.T) {
	c := testContext(t)
	tok := sealAsInitiator(t, c, []byte("secret"), 0)
	tok[0], tok[1] = 0x04, 0x04 // a MIC token's id
	if _, err := c.Unseal(tok); !errors.Is(err, errShortToken) {
		t.Errorf("err = %v, want errShortToken", err)
	}
}

func TestUnsealRefusesAPlaintextTooShortForItsOwnFiller(t *testing.T) {
	// EC says there are more filler octets than the decrypted plaintext can
	// hold. Trusting it would index past the buffer.
	c := testContext(t)
	h := sealHeader{flags: gssapi.MICTokenFlagSealed, ec: 64}
	et, err := crypto.GetEtype(c.key.KeyType)
	if err != nil {
		t.Fatal(err)
	}
	_, cipher, err := et.EncryptMessage(c.key.KeyValue, h.marshal(0), keyusage.GSSAPI_INITIATOR_SEAL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Unseal(append(h.marshal(0), cipher...)); !errors.Is(err, errShortToken) {
		t.Errorf("err = %v, want errShortToken", err)
	}
}

func TestRotationIsItsOwnInverse(t *testing.T) {
	// Not exercised by the judge — MIT sends RRC=0 — so it is pinned here
	// rather than assumed.
	b := []byte("0123456789")
	for _, n := range []uint16{0, 1, 3, 10, 13, 1000} {
		if got := rotateLeft(rotateRight(b, n), n); !bytes.Equal(got, b) {
			t.Errorf("rrc=%d: round trip gave %q", n, got)
		}
	}
	if got := rotateLeft(nil, 3); got != nil {
		t.Errorf("rotating nothing gave %q", got)
	}
	if got := rotateRight(nil, 3); got != nil {
		t.Errorf("rotating nothing gave %q", got)
	}
}

func TestUnsealHonoursARotatedToken(t *testing.T) {
	c := testContext(t)
	tok := sealAsInitiator(t, c, []byte("secret"), 0)
	const rrc = 7
	h, data, err := parseSealHeader(tok)
	if err != nil {
		t.Fatal(err)
	}
	h.rrc = rrc
	rotated := append(h.marshal(rrc), rotateRight(data, rrc)...)
	got, err := c.Unseal(rotated)
	if err != nil {
		t.Fatalf("a rotated token was refused: %v", err)
	}
	if string(got) != "secret" {
		t.Errorf("got %q, want %q", got, "secret")
	}
}

// initiatorMIC signs as a client does: the flag and the key usage are what
// tell the two directions apart.
func initiatorMIC(t *testing.T, c *Context, msg []byte) []byte {
	t.Helper()
	tok, err := gssapi.NewInitiatorMICToken(msg, c.key)
	if err != nil {
		t.Fatal(err)
	}
	b, err := tok.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return b
}
