// Package krb5 accepts Kerberos tickets.
//
// It is the ACCEPTOR half of Kerberos, and only that half: it holds a keytab,
// verifies the AP-REQ a client presents, and then signs and verifies messages
// under the session key that exchange established. It never talks to a KDC
// and never issues a ticket. Whose tickets it accepts is therefore somebody
// else's decision — MIT, Heimdal, Active Directory and FreeIPA all produce
// tickets this package verifies, because verification only needs the service
// key, which the keytab already holds.
//
// # Why this exists
//
// github.com/jcmturner/gokrb5 is a CLIENT library. It verifies an AP-REQ
// (service.VerifyAPREQ) but it cannot build the AP-REP that answers one, and
// says so itself:
//
//	case TOK_ID_KRB_AP_REP:
//		return []byte{}, errors.New("marshal of AP_REP GSSAPI MechToken not supported by gokrb5")
//
// Every GSS-API client asks for mutual authentication — MIT's own gss-client
// sets GSS_C_MUTUAL_FLAG with no option to turn it off — so a service that
// cannot produce an AP-REP cannot complete a single context. Building it is
// most of what this package adds.
//
// # What it does not do
//
// Anything a KDC does: no AS-REQ, no TGS-REQ, no principal database.
//
// [Context.Unwrap] still refuses a SEALED token, with a distinct error. A
// caller reading an integrity-only token must not be handed ciphertext that
// reads like a message; confidentiality goes through [Context.Seal] and
// [Context.Unseal], which together are sec=krb5p.
//
// It also asserts no acceptor subkey. The context key is the subkey the
// initiator put in its authenticator, or the ticket's session key when it
// sent none, which is what RFC 4121 §4.3 allows and what keeps the key usage
// numbers on both sides unambiguous.
package krb5
