package krb5

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/asn1tools"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// A client's request, built with every field the replay cache keys on chosen
// by the test.
type spec struct {
	realm string
	user  string
	sname []string
	when  time.Time
	cusec int
}

func (s spec) token(t *testing.T, kt *keytab.Keytab) []byte {
	t.Helper()
	if s.realm == "" {
		s.realm = "EXAMPLE.ORG"
	}
	if s.sname == nil {
		s.sname = []string{"nfs", "host"}
	}
	now := time.Now().UTC()
	sn := types.PrincipalName{NameType: 2, NameString: s.sname}
	cn := types.PrincipalName{NameType: 1, NameString: []string{s.user}}
	tkt, sk, err := messages.NewTicket(cn, s.realm, sn, "EXAMPLE.ORG",
		asn1.BitString{Bytes: []byte{0, 0, 0, 0}, BitLength: 32}, kt, 18, 1,
		now.Add(-time.Minute), now.Add(-time.Minute), now.Add(time.Hour), time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	auth, err := types.NewAuthenticator(s.realm, cn)
	if err != nil {
		t.Fatal(err)
	}
	if !s.when.IsZero() {
		auth.CTime = s.when
	}
	auth.Cusec = s.cusec
	req, err := messages.NewAPReq(tkt, sk, auth)
	if err != nil {
		t.Fatal(err)
	}
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

// Suspicion 1a. gokrb5's replay cache keys on the client name WITHOUT its
// realm, so alice@A and alice@B whose authenticators carry the same
// microsecond collide: the second, genuine, client is refused as a replay.
func TestTwoRealmsSameNameSameInstantAreNotReplays(t *testing.T) {
	kt := mechKeytab(t)
	a := New(kt)
	at := time.Now().UTC().Truncate(time.Second)
	for _, realm := range []string{"A.EXAMPLE", "B.EXAMPLE"} {
		tok := spec{realm: realm, user: "alice", when: at, cusec: 7001}.token(t, kt)
		if _, _, err := a.Accept(tok); err != nil {
			t.Fatalf("alice@%s: %v", realm, err)
		}
	}
}

// Suspicion 1b. gokrb5 checks the cache and then adds to it in two separate
// locked steps, so concurrent copies of one AP-REQ can all pass the check.
func TestConcurrentCopiesOfOneTokenAreAcceptedOnce(t *testing.T) {
	kt := mechKeytab(t)
	a := New(kt)
	const rounds, copies = 150, 24
	for r := 0; r < rounds; r++ {
		tok := spec{user: "bob", cusec: r}.token(t, kt)
		var ok int
		var done, ready, start sync.WaitGroup
		var m sync.Mutex
		ready.Add(copies)
		start.Add(1)
		for i := 0; i < copies; i++ {
			done.Add(1)
			go func() {
				defer done.Done()
				ready.Done()
				start.Wait()
				if _, _, err := a.Accept(tok); err == nil {
					m.Lock()
					ok++
					m.Unlock()
				}
			}()
		}
		ready.Wait()
		start.Done()
		done.Wait()
		if ok != 1 {
			t.Fatalf("round %d: %d of %d concurrent copies accepted, want exactly 1", r, ok, copies)
		}
	}
}

// Suspicion 1c. One entry per authenticator, no bound: a client holding a
// valid ticket can mint authenticators (it knows the session key) and each is
// remembered. The cache is capped, per client and in total.
func TestReplayCacheIsBounded(t *testing.T) {
	kt := mechKeytab(t)
	a := New(kt, ReplayCacheSize(64)) // 4 per client
	at := time.Now().UTC().Truncate(time.Second)
	var refused int
	for i := 0; i < 40; i++ {
		_, _, err := a.Accept(spec{user: "mallory", when: at, cusec: i}.token(t, kt))
		if err != nil {
			if !errors.Is(err, ErrRejected) {
				t.Fatalf("refusal is not ErrRejected: %v", err)
			}
			refused++
		}
	}
	if refused != 36 {
		t.Fatalf("one client got %d of 40 distinct authenticators remembered; want 4", 40-refused)
	}
	// Another client is not starved by mallory.
	if _, _, err := a.Accept(spec{user: "carol", when: at, cusec: 1}.token(t, kt)); err != nil {
		t.Fatalf("a second client was starved: %v", err)
	}
	// The total is capped too.
	var accepted int
	for i := 0; i < 40; i++ {
		if _, _, err := a.Accept(spec{user: fmt.Sprintf("u%d", i), when: at, cusec: 500 + i}.token(t, kt)); err == nil {
			accepted++
		}
	}
	if accepted > 64-5 {
		t.Fatalf("%d more clients accepted past the total cap of 64", accepted)
	}
}

// Entries expire with the clock-skew window: after it a slot is free again.
func TestReplayCacheForgetsAfterTheWindow(t *testing.T) {
	now := time.Now().UTC()
	c := newReplayCache(64, 60*time.Second)
	c.clock = func() time.Time { return now }
	k := func(cusec int) replayKey {
		return replayKey{realm: "R", cname: "dave", sname: "nfs/host", at: now.Add(time.Duration(cusec) * time.Microsecond)}
	}
	if err := c.admit(k(1)); err != nil {
		t.Fatal(err)
	}
	if err := c.admit(k(1)); !errors.Is(err, errReplay) {
		t.Fatalf("replay inside the window: %v", err)
	}
	now = now.Add(121 * time.Second) // 2 x the skew: nothing can still be replayed
	if err := c.admit(k(2)); err != nil {
		t.Fatal(err)
	}
	if n := c.size(); n != 1 {
		t.Fatalf("size after the window = %d, want 1 (expired entry pruned)", n)
	}
	if err := c.admit(k(1)); err != nil {
		t.Fatalf("an expired entry still blocks: %v", err)
	}
}

// The key carries every field: changing any one of them is a different
// authenticator.
func TestReplayKeyFieldsAllCount(t *testing.T) {
	now := time.Now().UTC()
	base := replayKey{realm: "R", cname: "dave", sname: "nfs/host", at: now}
	c := newReplayCache(64, time.Minute)
	if err := c.admit(base); err != nil {
		t.Fatal(err)
	}
	for name, k := range map[string]replayKey{
		"realm": {realm: "R2", cname: "dave", sname: "nfs/host", at: now},
		"cname": {realm: "R", cname: "dave2", sname: "nfs/host", at: now},
		"sname": {realm: "R", cname: "dave", sname: "nfs/other", at: now},
		"time":  {realm: "R", cname: "dave", sname: "nfs/host", at: now.Add(time.Microsecond)},
	} {
		if err := c.admit(k); err != nil {
			t.Errorf("differing %s treated as a replay: %v", name, err)
		}
	}
}

// Suspicion 2 (the library half). A keytab shared with the KDC holds the
// krbtgt key. An acceptor without Principal looks the key up by the ticket's
// cleartext sname, so a TGT would be accepted as a service ticket.
func TestATicketGrantingTicketIsNotAServiceTicket(t *testing.T) {
	kt := keytab.New()
	if err := kt.AddEntry("krbtgt/EXAMPLE.ORG", "EXAMPLE.ORG", "tgs-key", time.Now(), 1, 18); err != nil {
		t.Fatal(err)
	}
	a := New(kt)
	tok := spec{user: "erin", sname: []string{"krbtgt", "EXAMPLE.ORG"}, cusec: 9}.token(t, kt)
	if _, _, err := a.Accept(tok); err == nil {
		t.Fatal("a TGT was accepted as a service ticket")
	}
}
