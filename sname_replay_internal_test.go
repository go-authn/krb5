package krb5

import (
	"testing"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/asn1tools"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// ONE AP-REQ (one ticket, one encrypted authenticator), framed several times
// with only the ticket's cleartext sname differing. gokrb5's replay cache
// compares that cleartext sname, so a rewritten one defeated it.
func TestPrincipalReplayWithRewrittenSNameRefused(t *testing.T) {
	kt := mechKeytab(t)
	now := time.Now().UTC()
	sn := types.PrincipalName{NameType: 2, NameString: []string{"nfs", "host"}}
	cn := types.PrincipalName{NameType: 1, NameString: []string{"secaudit5-replay"}}
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
	frame := func(sname ...string) []byte {
		r := req
		r.Ticket.SName.NameString = sname
		b, err := r.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		oid, err := asn1.Marshal(mechKRB5)
		if err != nil {
			t.Fatal(err)
		}
		return asn1tools.AddASNAppTag(append(append(oid, 0x01, 0x00), b...), 0)
	}
	a := New(kt, Principal("nfs/host"))

	if _, _, err := a.Accept(frame("nfs", "host")); err != nil {
		t.Fatalf("the genuine token: %v", err)
	}
	// Witness: the byte-identical replay IS refused.
	if _, _, err := a.Accept(frame("nfs", "host")); err == nil {
		t.Fatal("witness broken: the identical replay was accepted")
	}
	// The same ticket and authenticator, cleartext sname rewritten, and then
	// the original again (the rewritten entry overwrote the first).
	for i, s := range [][]string{{"x"}, {"nfs", "host"}, {"x"}, {"nfs", "host"}} {
		ctx, _, err := a.Accept(frame(s...))
		if err == nil {
			t.Errorf("replay %d (cleartext sname %v) ACCEPTED as %s", i+1, s, ctx.Principal())
		}
	}
}
