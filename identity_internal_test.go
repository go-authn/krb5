package krb5

import (
	"errors"
	"testing"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/asn1tools"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// apReqToken builds a complete, valid GSS Kerberos token: a ticket for
// nfs/host@EXAMPLE.ORG issued to ticketName@ticketRealm and sealed with the
// service key, and an authenticator, sealed with the ticket's session key,
// naming authName@authRealm. The client controls the authenticator, never
// the ticket.
func apReqToken(t *testing.T, kt *keytab.Keytab, ticketName, ticketRealm, authName, authRealm string, cusec int) []byte {
	t.Helper()
	now := time.Now().UTC()
	sname := types.PrincipalName{NameType: 2, NameString: []string{"nfs", "host"}}
	cname := types.PrincipalName{NameType: 1, NameString: []string{ticketName}}
	tkt, sk, err := messages.NewTicket(cname, ticketRealm, sname, "EXAMPLE.ORG",
		asn1.BitString{Bytes: []byte{0, 0, 0, 0}, BitLength: 32}, kt, 18, 1,
		now.Add(-time.Minute), now.Add(-time.Minute), now.Add(time.Hour), time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	auth, err := types.NewAuthenticator(authRealm, types.PrincipalName{NameType: 1, NameString: []string{authName}})
	if err != nil {
		t.Fatal(err)
	}
	auth.Cusec = cusec // distinct per case: gokrb5 keeps a process-wide replay cache
	req, err := messages.NewAPReq(tkt, sk, auth)
	if err != nil {
		t.Fatal(err)
	}
	b, err := req.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	oid, err := asn1.Marshal(gssapi.OIDKRB5.OID())
	if err != nil {
		t.Fatal(err)
	}
	return asn1tools.AddASNAppTag(append(append(oid, 0x01, 0x00), b...), 0)
}

// The client's identity is the one the KDC sealed in the ticket. The
// authenticator is written by the client: under a cross-realm trust, a
// partner realm's alice holds a genuine ticket for our service and could name
// our realm in her authenticator. gokrb5 v8.4.4 compares the authenticator's
// name with the ticket's but not its realm (messages/APReq.go Verify), and
// builds the credentials from the authenticator (service/APExchange.go).
// RFC 4120 3.2.3: name AND realm are compared, KRB_AP_ERR_BADMATCH otherwise.
func TestTheIdentityComesFromTheTicketNotTheAuthenticator(t *testing.T) {
	kt := keytab.New()
	if err := kt.AddEntry("nfs/host", "EXAMPLE.ORG", "test-only-service-key", time.Now(), 1, 18); err != nil {
		t.Fatal(err)
	}
	a := New(kt)
	for i, tc := range []struct {
		name                     string
		tName, tRealm            string
		aName, aRealm            string
		wantPrincipal, wantRealm string // "" = refused
	}{
		{"the control: our realm's alice", "alice", "EXAMPLE.ORG", "alice", "EXAMPLE.ORG", "alice@EXAMPLE.ORG", "EXAMPLE.ORG"},
		{"the control: a partner realm's alice, honest", "alice", "PARTNER.ORG", "alice", "PARTNER.ORG", "alice@PARTNER.ORG", "PARTNER.ORG"},
		{"a partner realm's alice claiming our realm", "alice", "PARTNER.ORG", "alice", "EXAMPLE.ORG", "", ""},
		{"our alice claiming a partner realm", "alice", "EXAMPLE.ORG", "alice", "PARTNER.ORG", "", ""},
		{"another name (gokrb5 already refuses)", "alice", "EXAMPLE.ORG", "bob", "EXAMPLE.ORG", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, _, err := a.Accept(apReqToken(t, kt, tc.tName, tc.tRealm, tc.aName, tc.aRealm, 1000+i))
			if tc.wantPrincipal == "" {
				if err == nil {
					t.Fatalf("ACCEPTED as %s (realm %s): the authenticator chose the identity", ctx.Principal(), ctx.Realm())
				}
				if !errors.Is(err, ErrRejected) {
					t.Errorf("err = %v, want ErrRejected", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			if ctx.Principal() != tc.wantPrincipal || ctx.Realm() != tc.wantRealm || ctx.User() != tc.tName {
				t.Errorf("got %q / %q / %q, want %q / %q / %q",
					ctx.Principal(), ctx.User(), ctx.Realm(), tc.wantPrincipal, tc.tName, tc.wantRealm)
			}
		})
	}
}
