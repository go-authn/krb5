# Changelog

## v0.4.1

Security fixes for acceptors built with the `Principal` option.

- A ticket whose cleartext service name is empty made `Accept` panic inside
  gokrb5. `Accept` now refuses any ticket whose cleartext sname differs from
  the configured principal, before gokrb5 sees it, and recovers from a panic
  in gokrb5 as a refusal.
- Rewriting the cleartext sname defeated gokrb5's replay cache, so a captured
  AP-REQ could be replayed. The same sname check closes it.

Acceptors without `Principal` are unchanged.
