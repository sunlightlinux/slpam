---
name: Bug Report
about: Report a problem with pam_slinit.so — a session that does not open, close or carry the right environment
title: "[BUG] "
labels: bug
assignees: ''
---

> **Not for security issues.** If the problem lets a session be created
> that should not have been, or makes a machine unloggable, see
> `SECURITY.md` and email instead of filing here.

## Description

What happened. Useful shapes: a login that succeeds but has no session,
a logout that leaves a stale session behind, a greeter that cannot start
because the previous session was never released, missing `XDG_*`
variables.

## PAM service and stack

Which service — `sshd`, `gdm`, `login`, `su`, something else — and the
relevant `/etc/pam.d/` file:

```
# contents of /etc/pam.d/<service>, or at least the session lines
```

Order matters in PAM, so please include the whole session stack rather
than only the `pam_slinit.so` line.

## Versions

- `pam_slinit.so` — commit or package version:
- `slinit-logind` — `slinitctl --version`:
- Distribution:

## What slinit-logind thinks

The module's job is to make these agree with reality:

```
busctl --system call org.freedesktop.login1 /org/freedesktop/login1 \
  org.freedesktop.login1.Manager ListSessions
ls /run/systemd/sessions/
```

Note that `slinit-logind` **does not log session events**, so
`journalctl` will usually be empty on this path — state is the evidence,
not logs.

## Expected Behavior

## Actual Behavior

## Reproduction

Steps, and whether it happens every time or intermittently. If it is
intermittent, say roughly how often.
