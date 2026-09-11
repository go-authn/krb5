# krb5

[![Go Reference](https://pkg.go.dev/badge/github.com/go-authn/krb5.svg)](https://pkg.go.dev/github.com/go-authn/krb5)
[![License](https://img.shields.io/badge/license-BSD--3--Clause-0A6E96?style=flat-square)](LICENSE)
[![CI](https://github.com/go-authn/krb5/actions/workflows/ci.yml/badge.svg)](https://github.com/go-authn/krb5/actions/workflows/ci.yml)

**Accept Kerberos tickets in Go, with no cgo.** Pure Go, `CGO_ENABLED=0`, over
[gokrb5](https://github.com/jcmturner/gokrb5) for the ticket decryption.

```go
a, err := krb5.Load("/etc/krb5.keytab")
ctx, apRep, err := a.Accept(token)   // apRep goes back to the client
fmt.Println(ctx.Principal())         // alice@EXAMPLE.ORG — an authenticated answer
```

This is the **acceptor** half of Kerberos and only that half. It holds a
keytab, verifies the AP-REQ a client presents, answers with the AP-REP that
proves the service is genuine, and then signs and verifies messages under the
session key. It never talks to a KDC and never issues a ticket, so whose
tickets it accepts is somebody else's decision: MIT, Heimdal, Active Directory
and FreeIPA all produce tickets it verifies.

## Why it exists

[gokrb5](https://github.com/jcmturner/gokrb5) is a client library. It verifies
an AP-REQ and then cannot answer one:

```go
case TOK_ID_KRB_AP_REP:
    return []byte{}, errors.New("marshal of AP_REP GSSAPI MechToken not supported by gokrb5")
```

Every GSS-API client asks for mutual authentication — MIT's own `gss-client`
sets `GSS_C_MUTUAL_FLAG` and offers no way to turn it off — so a service that
cannot produce an AP-REP completes no context at all. Building it is most of
what this package adds; gokrb5 does the ticket decryption underneath.

## What it does not do

**Confidentiality.** `Unwrap` reads a wrap token whose payload is in the clear
and whose checksum is authenticated, and it *refuses* a sealed one rather than
handing back ciphertext that reads like a message. In NFS terms that is
`sec=krb5` and `sec=krb5i`, and not `sec=krb5p`.

**Acceptor subkeys.** It asserts none, so the context key is the subkey the
initiator put in its authenticator — RFC 4121 §4.3 — which keeps the key usage
numbers unambiguous on both sides.

**Anything a KDC does.** No AS-REQ, no TGS-REQ, no principal database.

## The judge

The tests are not run against a stand-in. A real MIT KDC issues a ticket and
MIT's own `gss-client` presents it, against this package standing in for
`gss-server`. A fake built from one's own reading of RFC 4121 can only confirm
that reading.

```sh
test/kdc.sh /tmp/krbtest
set -a; . /tmp/krbtest/env; set +a
go test ./...
```

`test/kdc.sh` builds a throwaway realm on loopback, unprivileged, and touches
nothing the machine already has. Setting `KRB5_REQUIRE_JUDGE=1` turns "the
fixture is missing" from a skip into a failure — every lane that runs the
tests sets it, because a differential test that can quietly not run is not a
control.

The sample protocol's framing was measured by putting a recording proxy
between the real client and the real server, not read out of its source.

## Licence

BSD-3-Clause.
