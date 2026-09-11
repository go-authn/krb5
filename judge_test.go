package krb5_test

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/go-authn/krb5"
)

// This file runs the package against MIT Kerberos itself: a real KDC issues
// the ticket and MIT's own gss-client presents it. A stand-in built from my
// reading of RFC 4121 could only ever confirm that reading.
//
// The fixture is three environment variables, set by test/kdc.sh:
//
//	KRB5_CONFIG        the realm's krb5.conf
//	KRB5_TEST_KEYTAB   a keytab holding the service principal
//	KRB5_TEST_SERVICE  the service name gss-client is asked for ("nfs")
//
// KRB5_REQUIRE_JUDGE=1 turns "the fixture is missing" from a skip into a
// failure. Every lane that runs these tests sets it: a differential test that
// can quietly not run is not a control, and the way you find out is that the
// whole file finishes in 80 milliseconds.

func fixture(t *testing.T) (keytab, service string) {
	t.Helper()
	keytab, service = os.Getenv("KRB5_TEST_KEYTAB"), os.Getenv("KRB5_TEST_SERVICE")
	if keytab == "" || service == "" || os.Getenv("KRB5_CONFIG") == "" {
		if os.Getenv("KRB5_REQUIRE_JUDGE") != "" {
			t.Fatal("KRB5_REQUIRE_JUDGE is set but the KDC fixture is not: " +
				"KRB5_CONFIG, KRB5_TEST_KEYTAB and KRB5_TEST_SERVICE must all be set")
		}
		t.Skip("no KDC fixture; run test/kdc.sh and export what it prints")
	}
	return keytab, service
}

// Sample-protocol framing, measured by putting a recording proxy between the
// real gss-client and the real gss-server rather than read out of the sample's
// source: one flags byte, a big-endian length, then the token.
const (
	tokNoop     = 0x01
	tokContext  = 0x02
	tokData     = 0x04
	tokMIC      = 0x08
	tokWrapped  = 0x20
	tokSendMIC  = 0x80
	maxTokenLen = 1 << 20
)

func sendToken(w io.Writer, flags byte, tok []byte) error {
	hdr := make([]byte, 5)
	hdr[0] = flags
	binary.BigEndian.PutUint32(hdr[1:], uint32(len(tok)))
	if _, err := w.Write(append(hdr, tok...)); err != nil {
		return err
	}
	return nil
}

func recvToken(r io.Reader) (byte, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(hdr[1:])
	if n > maxTokenLen {
		return 0, nil, errors.New("token too large")
	}
	tok := make([]byte, n)
	if _, err := io.ReadFull(r, tok); err != nil {
		return 0, nil, err
	}
	return hdr[0], tok, nil
}

// serve answers one gss-client conversation and reports what it learned.
type outcome struct {
	principal string
	payload   string
	err       error
}

func serve(ln net.Listener, a *krb5.Acceptor, out chan<- outcome) {
	var res outcome
	c, err := ln.Accept()
	if err != nil {
		res.err = err
		out <- res
		return
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))

	var ctx *krb5.Context
	fail := func(err error) {
		res.err = err
		out <- res
	}
	for {
		flags, tok, err := recvToken(c)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				res.err = err
			}
			out <- res
			return
		}
		switch {
		case flags&tokContext != 0 && len(tok) > 0:
			newCtx, rep, err := a.Accept(tok)
			if err != nil {
				fail(err)
				return
			}
			ctx = newCtx
			res.principal = ctx.Principal()
			if len(rep) > 0 {
				if err := sendToken(c, tokContext, rep); err != nil {
					fail(err)
					return
				}
			}
		case flags&tokData != 0:
			if ctx == nil {
				fail(errors.New("data before a context"))
				return
			}
			msg := tok
			if flags&tokWrapped != 0 {
				if msg, err = ctx.Unwrap(tok); err != nil {
					fail(err)
					return
				}
			}
			res.payload = string(msg)
			if flags&tokSendMIC != 0 {
				mic, err := ctx.MIC(msg)
				if err != nil {
					fail(err)
					return
				}
				if err := sendToken(c, tokMIC, mic); err != nil {
					fail(err)
					return
				}
			}
		}
	}
}

func TestMITClientAgainstThisAcceptor(t *testing.T) {
	keytab, service := fixture(t)

	a, err := krb5.Load(keytab)
	if err != nil {
		t.Fatalf("loading the keytab: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	out := make(chan outcome, 1)
	go serve(ln, a, out)

	// -nx asks gss_wrap for integrity without confidentiality, which is what
	// this package implements; -nm makes gss-client verify the MIC we return.
	cmd := exec.Command("pkgx", "+kerberos.org", "--", "gss-client",
		"-port", itoa(port), "-nx", "localhost", service, "bonjour la flotte")
	cmd.Env = os.Environ()
	clientOut, clientErr := cmd.CombinedOutput()
	// The acceptor's own error is read FIRST: when it refuses something, the
	// client only ever reports that the connection went away, which names the
	// symptom and hides the cause.
	var res outcome
	select {
	case res = <-out:
	case <-time.After(30 * time.Second):
		t.Fatal("acceptor never finished")
	}
	if res.err != nil {
		t.Fatalf("acceptor: %v\n--- gss-client said:\n%s", res.err, clientOut)
	}
	if clientErr != nil {
		t.Fatalf("gss-client failed: %v\n%s", clientErr, clientOut)
	}
	if !strings.Contains(string(clientOut), "Signature verified") {
		t.Errorf("gss-client did not verify our signature:\n%s", clientOut)
	}

	if res.payload != "bonjour la flotte" {
		t.Errorf("payload = %q, want %q", res.payload, "bonjour la flotte")
	}
	if !strings.HasPrefix(res.principal, "alice@") {
		t.Errorf("principal = %q, want alice@REALM", res.principal)
	}
	t.Logf("MIT gss-client authenticated as %s", res.principal)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
