package krb5

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/asn1tools"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// mutualToken builds a valid AP-REQ for nfs/host@EXAMPLE.ORG from
// alice@EXAMPLE.ORG asking for mutual authentication, framed under mech, with
// subkey in the authenticator when it is set. It returns the token and the
// ticket's session key.
func mutualToken(t *testing.T, kt *keytab.Keytab, mech asn1.ObjectIdentifier, subkey types.EncryptionKey, cusec int) ([]byte, types.EncryptionKey) {
	t.Helper()
	now := time.Now().UTC()
	sname := types.PrincipalName{NameType: 2, NameString: []string{"nfs", "host"}}
	cname := types.PrincipalName{NameType: 1, NameString: []string{"alice"}}
	tkt, sk, err := messages.NewTicket(cname, "EXAMPLE.ORG", sname, "EXAMPLE.ORG",
		asn1.BitString{Bytes: []byte{0, 0, 0, 0}, BitLength: 32}, kt, 18, 1,
		now.Add(-time.Minute), now.Add(-time.Minute), now.Add(time.Hour), time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	auth, err := types.NewAuthenticator("EXAMPLE.ORG", cname)
	if err != nil {
		t.Fatal(err)
	}
	auth.Cusec = cusec // distinct per case: gokrb5 keeps a process-wide replay cache
	auth.SubKey = subkey
	req, err := messages.NewAPReq(tkt, sk, auth)
	if err != nil {
		t.Fatal(err)
	}
	// RFC 4120 §5.5.1: mutual-required is bit 2, counted from the most
	// significant bit of the first byte.
	req.APOptions = asn1.BitString{Bytes: []byte{0x20, 0, 0, 0}, BitLength: 32}
	b, err := req.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	oid, err := asn1.Marshal(mech)
	if err != nil {
		t.Fatal(err)
	}
	return asn1tools.AddASNAppTag(append(append(oid, 0x01, 0x00), b...), 0), sk
}

func mechKeytab(t *testing.T) *keytab.Keytab {
	t.Helper()
	kt := keytab.New()
	if err := kt.AddEntry("nfs/host", "EXAMPLE.ORG", "test-only-service-key", time.Now(), 1, 18); err != nil {
		t.Fatal(err)
	}
	return kt
}

// Windows' SPNEGO frames its krb5 AP-REQ under the Microsoft OID
// 1.2.840.48018.1.2.2. MIT accepts it and frames the AP-REP under the OID the
// client used (accept_sec_context.c: parse_init_token sets mech_used, and the
// reply header is made with mech_used). A reply under the other OID is one a
// strict initiator does not recognise as its own mechanism's.
func TestTheReplyIsFramedUnderTheClientsOID(t *testing.T) {
	kt := mechKeytab(t)
	a := New(kt)
	for i, mech := range []asn1.ObjectIdentifier{
		{1, 2, 840, 113554, 1, 2, 2}, // RFC 1964 / RFC 4121
		{1, 2, 840, 48018, 1, 2, 2},  // Microsoft's
	} {
		t.Run(mech.String(), func(t *testing.T) {
			tok, _ := mutualToken(t, kt, mech, types.EncryptionKey{}, 2000+i)
			ctx, rep, err := a.Accept(tok)
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			if ctx.Principal() != "alice@EXAMPLE.ORG" {
				t.Errorf("principal = %q", ctx.Principal())
			}
			if len(rep) == 0 {
				t.Fatal("no AP-REP for a mutual-required AP-REQ")
			}
			var got asn1.ObjectIdentifier
			rest, err := asn1.UnmarshalWithParams(rep, &got, "application,explicit,tag:0")
			if err != nil {
				t.Fatalf("the AP-REP is not GSS-framed: %v", err)
			}
			if !got.Equal(mech) {
				t.Errorf("AP-REP framed under %s, the client used %s", got, mech)
			}
			if len(rest) < 2 || rest[0] != 0x02 || rest[1] != 0x00 {
				t.Errorf("AP-REP token id = % x, want 02 00", rest[:min(2, len(rest))])
			}
		})
	}
}

// Any other mechanism is still not ours: accepting both krb5 OIDs must not
// have opened the door to every OID.
func TestAnotherMechanismIsStillRefused(t *testing.T) {
	kt := mechKeytab(t)
	for i, mech := range []asn1.ObjectIdentifier{
		{1, 3, 6, 1, 5, 5, 2},        // SPNEGO itself
		{1, 2, 840, 48018, 1, 2, 3},  // one arc off Microsoft's
		{1, 2, 840, 113554, 1, 2, 3}, // one arc off the standard
	} {
		t.Run(mech.String(), func(t *testing.T) {
			tok, _ := mutualToken(t, kt, mech, types.EncryptionKey{}, 2100+i)
			if _, _, err := New(kt).Accept(tok); !errors.Is(err, ErrNotAToken) {
				t.Errorf("err = %v, want ErrNotAToken", err)
			}
		})
	}
}

// SessionKey is the context key of RFC 4121 §4.3: the authenticator's subkey
// when the client sent one, else the ticket's session key. SMB derives its
// signing and encryption keys from it ([MS-SMB2] 3.3.5.5.3), so the other
// choice would produce a session that sets up and then fails every signature.
func TestSessionKeyIsTheContextKey(t *testing.T) {
	kt := mechKeytab(t)
	a := New(kt)
	sub := types.EncryptionKey{KeyType: 17, KeyValue: bytes.Repeat([]byte{0x5a}, 16)}

	t.Run("with a subkey", func(t *testing.T) {
		tok, sk := mutualToken(t, kt, mechMSKRB5, sub, 2200)
		ctx, _, err := a.Accept(tok)
		if err != nil {
			t.Fatalf("refused: %v", err)
		}
		if got := ctx.SessionKey(); !bytes.Equal(got, sub.KeyValue) {
			t.Errorf("SessionKey = %x, want the subkey %x (the ticket key is %x)", got, sub.KeyValue, sk.KeyValue)
		}
		if got := ctx.SessionKeyType(); got != 17 {
			t.Errorf("SessionKeyType = %d, want 17", got)
		}
	})

	t.Run("without a subkey", func(t *testing.T) {
		tok, sk := mutualToken(t, kt, mechKRB5, types.EncryptionKey{}, 2201)
		ctx, _, err := a.Accept(tok)
		if err != nil {
			t.Fatalf("refused: %v", err)
		}
		if got := ctx.SessionKey(); len(got) == 0 || !bytes.Equal(got, sk.KeyValue) {
			t.Errorf("SessionKey = %x, want the ticket's session key %x", got, sk.KeyValue)
		}
		if got := ctx.SessionKeyType(); got != sk.KeyType {
			t.Errorf("SessionKeyType = %d, want %d", got, sk.KeyType)
		}
	})

	// The caller gets a copy: zeroing it once used, as a careful caller does,
	// must not break the context's own MIC and Wrap.
	t.Run("a copy", func(t *testing.T) {
		tok, _ := mutualToken(t, kt, mechKRB5, sub, 2202)
		ctx, _, err := a.Accept(tok)
		if err != nil {
			t.Fatalf("refused: %v", err)
		}
		k := ctx.SessionKey()
		clear(k)
		if got := ctx.SessionKey(); !bytes.Equal(got, sub.KeyValue) {
			t.Errorf("clearing the returned key changed the context's: now %x", got)
		}
	})
}
