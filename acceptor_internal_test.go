package krb5

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/keytab"
)

func TestLoadReportsAKeytabItCannotRead(t *testing.T) {
	// A keytab is the service's identity. Starting without one and finding
	// out on the first client is far worse than refusing here.
	if _, err := Load(filepath.Join(t.TempDir(), "absent.keytab")); !errors.Is(err, ErrNoKeytab) {
		t.Errorf("err = %v, want ErrNoKeytab", err)
	}
	empty := filepath.Join(t.TempDir(), "empty.keytab")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(empty); !errors.Is(err, ErrNoKeytab) {
		t.Errorf("an empty keytab gave %v, want ErrNoKeytab", err)
	}
}

func TestOptionsReachTheAcceptor(t *testing.T) {
	a := New(keytab.New(), Principal("nfs/host.example.org"), ClockSkew(30))
	if a.principal != "nfs/host.example.org" {
		t.Errorf("principal = %q", a.principal)
	}
	if a.skew != 30 {
		t.Errorf("skew = %d, want 30", a.skew)
	}
	if d := New(keytab.New()); d.principal != "" || d.skew != 0 {
		t.Errorf("the default acceptor is not plain: %+v", d)
	}
}

func TestAcceptRefusesWhatIsNotATokenForUs(t *testing.T) {
	a := New(keytab.New())
	otherOID, err := asn1.Marshal(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 2}) // SPNEGO
	if err != nil {
		t.Fatal(err)
	}
	spnego := wrapRaw(otherOID)

	ourOID, err := asn1.Marshal(gssapi.OIDKRB5.OID())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		token []byte
		want  error
	}{
		{"nothing at all", nil, ErrNotAToken},
		{"not ASN.1", []byte("hello there"), ErrNotAToken},
		{"another mechanism", spnego, ErrNotAToken},
		{"no token id", wrapRaw(ourOID), ErrNotAToken},
		{"one byte of token id", wrapRaw(append(ourOID, 0x01)), ErrNotAToken},
		{"an AP-REP, not an AP-REQ", wrapRaw(append(ourOID, 0x02, 0x00)), ErrNotAPReq},
		{"an AP-REQ that does not decode", wrapRaw(append(ourOID, 0x01, 0x00, 0x30, 0x00)), ErrNotAToken},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, out, err := a.Accept(tc.token)
			if !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
			// ⛔ A refusal must hand back nothing to send. A caller that
			// wrote out anyway would answer a stranger with bytes derived
			// from a token this package just refused.
			if ctx != nil || out != nil {
				t.Errorf("a refusal returned ctx=%v out=%x", ctx, out)
			}
		})
	}
}

// wrapRaw puts bytes inside the APPLICATION 0 envelope a GSS token wears.
func wrapRaw(b []byte) []byte {
	out := make([]byte, len(b))
	copy(out, b)
	return appTag0(out)
}

func TestContextReportsWhatItKnows(t *testing.T) {
	exp := time.Now().Add(time.Hour).Truncate(time.Second)
	c := &Context{
		principal: "alice@EXAMPLE.ORG",
		user:      "alice",
		realm:     "EXAMPLE.ORG",
		peerSeq:   42,
		expires:   exp,
	}
	if c.Principal() != "alice@EXAMPLE.ORG" || c.User() != "alice" || c.Realm() != "EXAMPLE.ORG" {
		t.Errorf("names: %q %q %q", c.Principal(), c.User(), c.Realm())
	}
	if c.PeerSequence() != 42 {
		t.Errorf("PeerSequence = %d", c.PeerSequence())
	}
	if !c.Expires().Equal(exp) {
		t.Errorf("Expires = %v, want %v", c.Expires(), exp)
	}
}
