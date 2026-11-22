# Changelog

## v0.5.0

Security audit 2026-11-21 (suspicions, go-authn/krb5). Breaking: behaviour
that was accepted is now refused.

- The replay cache is this package's own, per acceptor, replacing gokrb5's
  process-wide `service.Cache`. gokrb5's keyed on the client name without its
  realm (alice@A and alice@B in the same microsecond collided and the genuine
  second one was refused), checked and added in two separately locked steps
  (concurrent copies of one AP-REQ were all accepted: 2 of 24 measured), and
  kept one entry per authenticator without bound. The new cache decides in one
  critical section, keys on realm, client, service and time, is capped (total
  and per client, a full cache refuses) and forgets after twice the skew.
  New option `ReplayCacheSize(n)`, default 65536.
- A ticket-granting ticket (cleartext sname `krbtgt/...`) is refused as a
  service ticket. A keytab shared with the KDC holds the krbtgt key, and an
  acceptor without `Principal` looks the key up by the ticket's sname.

## v0.4.1

Security fixes for acceptors built with the `Principal` option.

- A ticket whose cleartext service name is empty made `Accept` panic inside
  gokrb5. `Accept` now refuses any ticket whose cleartext sname differs from
  the configured principal, before gokrb5 sees it, and recovers from a panic
  in gokrb5 as a refusal.
- Rewriting the cleartext sname defeated gokrb5's replay cache, so a captured
  AP-REQ could be replayed. The same sname check closes it.

Acceptors without `Principal` are unchanged.
