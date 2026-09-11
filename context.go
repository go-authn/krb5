package krb5

import (
	"errors"
	"fmt"
	"time"

	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/types"
)

// Context is one authenticated conversation with one client.
//
// It is created by [Acceptor.Accept] and holds the key that exchange
// established. Everything it signs or verifies is bound to that key, so a
// context is exactly as long-lived as the ticket behind it — see [Context.Expires].
//
// A Context is NOT safe for concurrent use.
type Context struct {
	principal string
	user      string
	realm     string
	key       types.EncryptionKey
	peerSeq   uint64
	expires   time.Time
}

// Principal is who the client proved itself to be, in full Kerberos spelling
// ("alice@EXAMPLE.ORG").
//
// This is an authenticated answer, which is the whole point of the exchange:
// unlike an AUTH_UNIX uid or an SMB username, the client could not have
// produced it without holding the key.
func (c *Context) Principal() string { return c.principal }

// User is the principal without its realm, and Realm is the realm alone.
//
// Mapping a principal onto a local account is the CALLER's decision and a
// policy question, not a string operation: alice@EXAMPLE.ORG and
// alice@PARTNER.ORG are different people who both answer to "alice".
func (c *Context) User() string  { return c.user }
func (c *Context) Realm() string { return c.realm }

// Expires is when the ticket behind this context stops being valid. A server
// holding long-lived connections should stop honouring a context past it.
func (c *Context) Expires() time.Time { return c.expires }

// PeerSequence is the sequence number the client started at, from its
// authenticator. Protocols that carry their own sequence — RPCSEC_GSS does —
// check messages against it.
func (c *Context) PeerSequence() uint64 { return c.peerSeq }

// ErrBadMIC reports a message whose signature does not match. It is the only
// answer a verifier gives: which of the length, the header, the sequence or
// the checksum disagreed is not a client's business.
var ErrBadMIC = errors.New("krb5: bad message signature")

// VerifyMIC checks that msg was signed by the client on this context.
//
// The signature is over msg and the token header together, so a token lifted
// from one message will not verify against another.
func (c *Context) VerifyMIC(msg, token []byte) error {
	var mt gssapi.MICToken
	if err := mt.Unmarshal(token, false); err != nil {
		return fmt.Errorf("%w: %w", ErrBadMIC, err)
	}
	mt.Payload = msg
	ok, err := mt.Verify(c.key, keyusage.GSSAPI_INITIATOR_SIGN)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrBadMIC, err)
	}
	if !ok {
		return ErrBadMIC
	}
	return nil
}

// MIC signs msg as the acceptor and returns the token to send back.
//
// The key usage differs from the one [Context.VerifyMIC] checks — 23 here,
// 25 there. That asymmetry is what stops a token this server produced from
// being replayed back at it as though the client had signed it.
func (c *Context) MIC(msg []byte) ([]byte, error) {
	mt := gssapi.MICToken{
		Flags:     gssapi.MICTokenFlagSentByAcceptor,
		SndSeqNum: 0,
		Payload:   msg,
	}
	if err := mt.SetChecksum(c.key, keyusage.GSSAPI_ACCEPTOR_SIGN); err != nil {
		return nil, fmt.Errorf("krb5: signing: %w", err)
	}
	return mt.Marshal()
}

// ErrSealed reports a wrap token carrying confidentiality, which this package
// does not implement. It is a DISTINCT error from [ErrBadMIC] on purpose: a
// sealed token is well-formed and correctly signed, and the only thing wrong
// is that the payload is ciphertext. Returning it as a bad signature would
// send an operator looking at keys and clocks for a missing feature.
var ErrSealed = errors.New("krb5: wrap token is sealed (sec=krb5p is not implemented)")

// Unwrap reads a wrap token the client sent and returns its payload.
func (c *Context) Unwrap(token []byte) ([]byte, error) {
	var wt gssapi.WrapToken
	if err := wt.Unmarshal(token, false); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBadMIC, err)
	}
	if wt.Flags&gssapi.MICTokenFlagSealed != 0 {
		return nil, ErrSealed
	}
	ok, err := wt.Verify(c.key, keyusage.GSSAPI_INITIATOR_SEAL)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBadMIC, err)
	}
	if !ok {
		return nil, ErrBadMIC
	}
	return wt.Payload, nil
}

// Wrap packages msg as the acceptor, signed but not encrypted.
func (c *Context) Wrap(msg []byte) ([]byte, error) {
	wt := gssapi.WrapToken{
		Flags:     gssapi.MICTokenFlagSentByAcceptor,
		EC:        12,
		RRC:       0,
		SndSeqNum: 0,
		Payload:   msg,
	}
	if err := wt.SetCheckSum(c.key, keyusage.GSSAPI_ACCEPTOR_SEAL); err != nil {
		return nil, fmt.Errorf("krb5: wrapping: %w", err)
	}
	return wt.Marshal()
}
