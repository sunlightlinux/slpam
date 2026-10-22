# Contributing to slpam

Thank you for your interest in `pam_slinit.so`, the PAM module that
opens and closes [slinit-logind](https://github.com/sunlightlinux/slinit)
sessions.

Read `README.md` for the decisions already settled — C rather than Go,
`libdbus-1` rather than `sd-bus` — and `TODO.md` for what remains and in
what order. Both record the evidence, so a change that reverses one of
them needs to engage with that evidence rather than restate the
preference.

## Before you start: this one can lock you out

A PAM module is `dlopen`ed into `login`, `sshd`, `gdm` and `su`. A bug
here does not produce a failing test, it produces a machine nobody can
log into — possibly a remote one where SSH was the only way in.

So:

1. **Develop against a local VM with console access.** Not a remote
   host, not your workstation's live PAM stack.
2. **Keep a working module in the stack** until yours is proven. This is
   why unfinished entry points return `PAM_IGNORE` and not an error: a
   module that declines lets the stack continue.
3. **Open a second session before editing `/etc/pam.d/`** on anything
   you care about.

## Building

```sh
make          # builds src/pam_slinit.so
make check    # asserts the module exports exactly two symbols
```

Needs `libpam` and `libdbus-1` headers — `pam-devel` and `dbus-devel` on
Sunlight and Void.

`make check` is not decoration. `-fvisibility=hidden` with `PAM_EXTERN`,
which carries no visibility of its own, produces an object that links
and loads and exports nothing at all: `dlopen` succeeds and PAM then
finds no entry point, with no complaint at build time. If you add an
entry point, add it to `src/pam_slinit.sym` and to the check.

## Submitting Changes

1. Fork the repository
2. Create a branch (`git checkout -b pam/open-session`)
3. Make the change
4. `make && make check` must pass
5. Say in the PR **how you tested it** — which PAM service, on what, and
   whether the machine stayed reachable
6. Push and open a Pull Request

## Conventions

- **C, and conservative C.** This code runs inside other people's
  privileged processes. No global state that survives a fork, no
  unbounded waits, no allocation that is not freed on every path.
- **A PAM failure must degrade, not block.** If `slinit-logind` is slow
  or absent, the module returns and lets the stack decide. An entry
  point that can hang is a lockout waiting to happen.
- **Two exported symbols.** Everything else stays `static` or hidden.
- **Never return `PAM_SUCCESS` for work that did not happen.** Success
  from an `open_session` that created no session is a lie the stack
  cannot detect; the user logs in and the failure appears later as a
  desktop with no seat.
- **Match elogind's observable behaviour** unless there is a reason not
  to, and write the reason down. `../elogind/src/login/pam_elogind.c` is
  the reference.

## Reporting Issues

Use the issue tracker for bugs and requests — **except** anything that
could let a session be created that should not have been, or that locks
a machine out. Those go to `SECURITY.md`.
