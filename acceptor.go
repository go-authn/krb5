package krb5

import (
	"errors"
	"fmt"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/service"
	"github.com/jcmturner/gokrb5/v8/types"
)

// Acceptor verifies tickets presented for one service.
//
// It is safe for concurrent use: the keytab is read-only after loading, and
// each accepted ticket produces its own [Context].
type Acceptor struct {
	kt        *keytab.Keytab
	principal string
	skew      int
}

// Option configures an [Acceptor].
type Option func(*Acceptor)

// Principal restricts the acceptor to one service principal, named without
// its realm ("nfs/host.example.org").
//
// Without it, any principal in the keytab may be addressed. A keytab that
// holds exactly one service does not need this; one that holds several, and
// wants a port to answer for only one of them, does.
func Principal(name string) Option { return func(a *Acceptor) { a.principal = name } }

// ClockSkew is how far the client's clock may be from this one, in seconds.
// Zero means gokrb5's default of five minutes, which is also MIT's.
func ClockSkew(seconds int) Option { return func(a *Acceptor) { a.skew = seconds } }

// ErrNoKeytab reports a keytab that could not be read.
var ErrNoKeytab = errors.New("krb5: keytab")

// Load reads a keytab from disk and returns an acceptor for it.
//
// A keytab is a secret at rest. Its path may come from a configuration file
// or from KRB5_KTNAME; the KEY inside it must never be logged, printed, or
// carried in an environment variable.
func Load(path string, opts ...Option) (*Acceptor, error) {
	kt, err := keytab.Load(path)
	if err != nil {
		return nil, fmt.Errorf("%w %q: %w", ErrNoKeytab, path, err)
	}
	return New(kt, opts...), nil
}

// New returns an acceptor over an already-loaded keytab.
func New(kt *keytab.Keytab, opts ...Option) *Acceptor {
	a := &Acceptor{kt: kt}
	for _, o := range opts {
		o(a)
	}
	return a
}

// GSS-API krb5 mechanism token ids (RFC 4121 §4.1).
//
// They are bytes rather than the hex strings gokrb5 uses. A string would have
// to be decoded at every use, and decoding a constant is a failure path that
// can never be taken — untestable code in a package where every other refusal
// is tested.
var (
	tokIDAPReq = [2]byte{0x01, 0x00}
	tokIDAPRep = [2]byte{0x02, 0x00}
)

// Errors an acceptor returns. They are deliberately coarse: a client learns
// that its ticket was refused, never which of the many checks refused it.
var (
	// ErrNotAToken reports bytes that are not a GSS-API krb5 token at all.
	ErrNotAToken = errors.New("krb5: not a GSS-API krb5 token")
	// ErrNotAPReq reports a well-formed token that is not an AP-REQ — a
	// client sending its own AP-REP, or a KRB-ERROR.
	ErrNotAPReq = errors.New("krb5: token is not an AP-REQ")
	// ErrRejected reports a ticket this service will not accept: wrong
	// service, wrong key, expired, replayed, or a clock too far out.
	ErrRejected = errors.New("krb5: ticket rejected")
)

// Accept verifies one AP-REQ and returns the context it establishes.
//
// The second result is the token to send back to the client. It is non-empty
// whenever the client asked for mutual authentication, which in practice is
// always; sending it is not optional, because the client will not consider
// the context open until it has verified the AP-REP.
//
// An error means no context: the returned token is then empty, and the caller
// should refuse the operation rather than fall back to something weaker.
func (a *Acceptor) Accept(token []byte) (*Context, []byte, error) {
	tokID, body, err := splitToken(token)
	if err != nil {
		return nil, nil, err
	}
	if tokID != tokIDAPReq {
		return nil, nil, fmt.Errorf("%w (token id %02x%02x)", ErrNotAPReq, tokID[0], tokID[1])
	}
	var req messages.APReq
	if err := req.Unmarshal(body); err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrNotAToken, err)
	}

	opts := []func(*service.Settings){service.DecodePAC(false)}
	if a.principal != "" {
		opts = append(opts, service.KeytabPrincipal(a.principal))
	}
	if a.skew > 0 {
		opts = append(opts, service.MaxClockSkew(time.Duration(a.skew)*time.Second))
	}
	ok, creds, err := service.VerifyAPREQ(&req, service.NewSettings(a.kt, opts...))
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrRejected, err)
	}
	if !ok {
		return nil, nil, ErrRejected
	}

	// RFC 4121 §4.3: the context key is the subkey the initiator asserted in
	// its authenticator, and the ticket's session key only when it asserted
	// none. Getting this backwards produces a context that establishes and
	// then fails on the first MIC, which is a far harder failure to read.
	key := req.Ticket.DecryptedEncPart.Key
	if isSet(req.Authenticator.SubKey) {
		key = req.Authenticator.SubKey
	}
	ctx := &Context{
		principal: creds.UserName() + "@" + creds.Domain(),
		user:      creds.UserName(),
		realm:     creds.Domain(),
		key:       key,
		peerSeq:   uint64(req.Authenticator.SeqNumber),
		expires:   req.Ticket.DecryptedEncPart.EndTime,
	}

	if !mutualRequired(req.APOptions) {
		return ctx, nil, nil
	}
	rep, err := a.apRep(&req)
	if err != nil {
		return nil, nil, err
	}
	return ctx, rep, nil
}

// isSet reports whether an encryption key was actually present. Go's zero
// value for types.EncryptionKey is a valid-looking struct with an empty key,
// so "did the client send a subkey" has to be asked of the bytes.
func isSet(k types.EncryptionKey) bool { return k.KeyType != 0 && len(k.KeyValue) > 0 }

// mutualRequired reads the AP-REQ option bit (RFC 4120 §5.5.1: reserved(0),
// use-session-key(1), mutual-required(2)).
func mutualRequired(o asn1.BitString) bool { return o.At(2) == 1 }

// splitToken peels the GSS-API InitialContextToken framing (RFC 2743 §3.1):
// an APPLICATION 0 wrapper around the mechanism OID and then, for the krb5
// mechanism, a two-byte token id and the Kerberos message.
func splitToken(b []byte) (tokID [2]byte, body []byte, err error) {
	var oid asn1.ObjectIdentifier
	rest, err := asn1.UnmarshalWithParams(b, &oid, "application,explicit,tag:0")
	if err != nil {
		return tokID, nil, fmt.Errorf("%w: %w", ErrNotAToken, err)
	}
	if !oid.Equal(gssapi.OIDKRB5.OID()) {
		return tokID, nil, fmt.Errorf("%w: mechanism is %s, want %s",
			ErrNotAToken, oid, gssapi.OIDKRB5.OID())
	}
	if len(rest) < 2 {
		return tokID, nil, fmt.Errorf("%w: no token id", ErrNotAToken)
	}
	return [2]byte(rest[:2]), rest[2:], nil
}
