package krb5

import (
	"errors"
	"testing"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/asn1tools"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// A valid ticket for the service, whose CLEARTEXT sname is rewritten. With the
// Principal option the keytab lookup used to ignore the ticket's sname, the
// ticket decrypted, and gokrb5 then indexed NameString[0] of an empty name.
func snameToken(t *testing.T, sname []string) []byte {
	t.Helper()
	kt := mechKeytab(t)
	now := time.Now().UTC()
	sn := types.PrincipalName{NameType: 2, NameString: []string{"nfs", "host"}}
	cn := types.PrincipalName{NameType: 1, NameString: []string{"alice"}}
	tkt, sk, err := messages.NewTicket(cn, "EXAMPLE.ORG", sn, "EXAMPLE.ORG",
		asn1.BitString{Bytes: []byte{0, 0, 0, 0}, BitLength: 32}, kt, 18, 1,
		now.Add(-time.Minute), now.Add(-time.Minute), now.Add(time.Hour), time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	auth, err := types.NewAuthenticator("EXAMPLE.ORG", cn)
	if err != nil {
		t.Fatal(err)
	}
	req, err := messages.NewAPReq(tkt, sk, auth)
	if err != nil {
		t.Fatal(err)
	}
	// The attacker's only edit: the sname outside the encrypted part.
	req.Ticket.SName.NameString = sname
	b, err := req.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	oid, err := asn1.Marshal(mechKRB5)
	if err != nil {
		t.Fatal(err)
	}
	return asn1tools.AddASNAppTag(append(append(oid, 0x01, 0x00), b...), 0)
}

func TestPrincipalRefusesEmptyCleartextSName(t *testing.T) {
	tok := snameToken(t, nil)
	a := New(mechKeytab(t), Principal("nfs/host"))
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Accept PANICKED on a ticket with an empty cleartext sname: %v", r)
		}
	}()
	_, _, err := a.Accept(tok)
	if !errors.Is(err, ErrRejected) {
		t.Fatalf("err = %v, want ErrRejected", err)
	}
}

// A ticket whose cleartext sname names another service is refused too.
func TestPrincipalRefusesOtherCleartextSName(t *testing.T) {
	tok := snameToken(t, []string{"cifs", "host"})
	_, _, err := New(mechKeytab(t), Principal("nfs/host")).Accept(tok)
	if !errors.Is(err, ErrRejected) {
		t.Fatalf("err = %v, want ErrRejected", err)
	}
}

// The recover is defence in depth: a keytab-less acceptor makes gokrb5 panic,
// and Accept must refuse rather than crash.
func TestAcceptRecoversFromAPanic(t *testing.T) {
	tok := snameToken(t, []string{"nfs", "host"})
	_, _, err := New(nil).Accept(tok)
	if !errors.Is(err, ErrRejected) {
		t.Fatalf("err = %v, want ErrRejected", err)
	}
}

// Witness: without the Principal option the same token is refused cleanly.
func TestEmptyCleartextSNameWithoutPrincipalOption(t *testing.T) {
	tok := snameToken(t, nil)
	a := New(mechKeytab(t))
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Accept PANICKED: %v", r)
		}
	}()
	_, _, err := a.Accept(tok)
	if err == nil {
		t.Fatal("accepted")
	}
	t.Logf("refused: %v", err)
}

// Witness: the unmodified token is accepted, so the builder is sound.
func TestPrincipalAcceptsUnmodifiedToken(t *testing.T) {
	tok := snameToken(t, []string{"nfs", "host"})
	if _, _, err := New(mechKeytab(t), Principal("nfs/host")).Accept(tok); err != nil {
		t.Fatal(err)
	}
}
