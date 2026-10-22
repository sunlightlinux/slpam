---
name: Feature Request
about: Propose a capability for pam_slinit.so
title: "[FEATURE] "
labels: enhancement
assignees: ''
---

## What is missing

What the module does not do today, and what breaks because of it.

## Does elogind do it?

`../elogind/src/login/pam_elogind.c` is the reference implementation.
If `pam_elogind.so` handles this, say how — matching its observable
behaviour is usually the right answer, and divergence needs a reason.

If this is something elogind does *not* do, say so plainly; that is a
stronger case to argue but a legitimate one.

## Does it belong here?

This module is a login hook: it calls `CreateSession` on the way in and
`ReleaseSession` on the way out. Session semantics themselves belong to
`slinit-logind`.

- [ ] This is about the PAM side (what gets gathered, what gets exported
      to the environment, what the stack is told)
- [ ] This needs a change in `slinit-logind` too — if so, say which
- [ ] This is really a `slinit-logind` request and should be filed
      against [slinit](https://github.com/sunlightlinux/slinit)

## Already recorded?

`TODO.md` lists the remaining work in order, including one open decision
about which component owns session lifetime. Check whether this is
already there before filing.

## Cost

This code runs inside `sshd` and `gdm`. A feature that adds a blocking
call, global state that survives a fork, or an allocation on an error
path is more expensive here than its size suggests. Say what the
proposal needs.
