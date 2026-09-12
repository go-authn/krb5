package krb5

import (
	"testing"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/asn1tools"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana/asnAppTag"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// A SYNTACTICALLY VALID AP-REQ whose ticket carries a three-byte cipher.
// Truncating the token would have been caught by the ASN.1 parse; this gets
// past it and reaches the decryption underneath.
func TestAcceptSurvivesAWellFormedAPReqWithAShortCipher(t *testing.T) {
	kt := keytab.New()
	if err := kt.AddEntry("nfs/host", "EXAMPLE.ORG", "pw", timeNow(), 1, 18); err != nil {
		t.Fatal(err)
	}
	tkt := messages.Ticket{
		TktVNO: 5,
		Realm:  "EXAMPLE.ORG",
		SName:  types.PrincipalName{NameType: 2, NameString: []string{"nfs", "host"}},
		EncPart: types.EncryptedData{
			EType:  18,
			KVNO:   1,
			Cipher: []byte{1, 2, 3},
		},
	}
	tb, err := tkt.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	req := marshalledAPReq(t, tb)

	oid, err := asn1.Marshal(gssapi.OIDKRB5.OID())
	if err != nil {
		t.Fatal(err)
	}
	token := asn1tools.AddASNAppTag(append(append(oid, 0x01, 0x00), req...), 0)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("a three-byte cipher inside a well-formed AP-REQ PANICKED: %v", r)
		}
	}()
	if _, _, err := New(kt).Accept(token); err == nil {
		t.Error("a ticket with a three-byte cipher was accepted")
	} else {
		t.Logf("refused, as it must be: %v", err)
	}
}

type marshalAPReqShim struct {
	PVNO                   int                 `asn1:"explicit,tag:0"`
	MsgType                int                 `asn1:"explicit,tag:1"`
	APOptions              asn1.BitString      `asn1:"explicit,tag:2"`
	Ticket                 asn1.RawValue       `asn1:"explicit,tag:3"`
	EncryptedAuthenticator types.EncryptedData `asn1:"explicit,tag:4"`
}

func marshalledAPReq(t *testing.T, ticket []byte) []byte {
	t.Helper()
	m := marshalAPReqShim{
		PVNO:      5,
		MsgType:   14,
		APOptions: asn1.BitString{Bytes: []byte{0, 0, 0, 0}, BitLength: 32},
		Ticket: asn1.RawValue{
			Class: asn1.ClassContextSpecific, IsCompound: true, Tag: 3, Bytes: ticket,
		},
		EncryptedAuthenticator: types.EncryptedData{EType: 18, KVNO: 1, Cipher: []byte{4, 5, 6}},
	}
	b, err := asn1.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return asn1tools.AddASNAppTag(b, asnAppTag.APREQ)
}

func timeNow() time.Time { return time.Now() }

// TestAcceptRefusesEveryShortCipher walks the lengths and the fields.
//
// The earlier robustness sweep truncated VALID tokens, and that only ever
// tested the ASN.1 parse: it refuses a cut token long before anything tries
// to decrypt. What reaches the decryption is a token that is well-formed all
// the way down and simply lies about a length.
func TestAcceptRefusesEveryShortCipher(t *testing.T) {
	kt := keytab.New()
	if err := kt.AddEntry("nfs/host", "EXAMPLE.ORG", "pw", timeNow(), 1, 18); err != nil {
		t.Fatal(err)
	}
	a := New(kt)

	for _, etype := range []int32{17, 18, 19, 20, 23} {
		for n := 0; n <= 28; n++ {
			for _, field := range []string{"ticket", "authenticator"} {
				token := apReqWith(t, etype, n, field)
				func() {
					defer func() {
						if r := recover(); r != nil {
							t.Fatalf("etype %d, %s, %d cipher bytes: PANIC %v", etype, field, n, r)
						}
					}()
					if _, _, err := a.Accept(token); err == nil {
						t.Errorf("etype %d, %s, %d cipher bytes was accepted", etype, field, n)
					}
				}()
			}
		}
	}
}

func TestAcceptRefusesAnEncryptionTypeItCannotDo(t *testing.T) {
	// Refusing by name beats letting the decryption fail somewhere less
	// legible — and beats indexing into a table that has no entry.
	kt := keytab.New()
	if err := kt.AddEntry("nfs/host", "EXAMPLE.ORG", "pw", timeNow(), 1, 18); err != nil {
		t.Fatal(err)
	}
	if _, _, err := New(kt).Accept(apReqWith(t, 9999, 64, "ticket")); err == nil {
		t.Error("an unknown encryption type was accepted")
	}
}

// apReqWith builds a well-formed AP-REQ whose named field carries n cipher
// bytes of the given encryption type.
func apReqWith(t *testing.T, etype int32, n int, field string) []byte {
	t.Helper()
	short := types.EncryptedData{EType: etype, KVNO: 1, Cipher: make([]byte, n)}
	full := types.EncryptedData{EType: 18, KVNO: 1, Cipher: make([]byte, 64)}
	tktEnc, authEnc := full, full
	switch field {
	case "ticket":
		tktEnc = short
	case "authenticator":
		authEnc = short
	}
	tkt := messages.Ticket{
		TktVNO:  5,
		Realm:   "EXAMPLE.ORG",
		SName:   types.PrincipalName{NameType: 2, NameString: []string{"nfs", "host"}},
		EncPart: tktEnc,
	}
	tb, err := tkt.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	m := marshalAPReqShim{
		PVNO:      5,
		MsgType:   14,
		APOptions: asn1.BitString{Bytes: []byte{0, 0, 0, 0}, BitLength: 32},
		Ticket: asn1.RawValue{
			Class: asn1.ClassContextSpecific, IsCompound: true, Tag: 3, Bytes: tb,
		},
		EncryptedAuthenticator: authEnc,
	}
	b, err := asn1.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	req := asn1tools.AddASNAppTag(b, asnAppTag.APREQ)
	oid, err := asn1.Marshal(gssapi.OIDKRB5.OID())
	if err != nil {
		t.Fatal(err)
	}
	return asn1tools.AddASNAppTag(append(append(oid, 0x01, 0x00), req...), 0)
}
