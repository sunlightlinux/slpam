# slpam

`pam_slinit.so` — the PAM module that opens and closes **slinit-logind**
sessions, so a Sunlight Linux system can log users in without
`pam_elogind.so`.

Part of [Sunlight Linux](https://github.com/sunlightlinux). Apache-2.0.

## Why this repository exists

`slinit-logind` already owns `org.freedesktop.login1` — sessions, seats,
users, inhibitors and sleep. What is missing is the *login hook*: the
thing that calls `CreateSession` when a user logs in. Today that is
`pam_elogind.so`, which ships in the **elogind package**, and
`gnome-shell` and `xfce4` depend on that package. So the elogind *daemon*
is already switched off while the *package* stays mandatory.

**Shipping this module does not by itself remove elogind.** The
dependency has to change distro-side in `slpkgs` as well. Two pieces of
work, not one.

## Decisions, and the evidence behind them

### C, not Go

Every other Sunlight component is Go. This one is not, and the reason is
not taste.

A PAM module is a shared object `dlopen`ed into `login`, `sshd`, `gdm`
and `su`. Building it with Go's `-buildmode=c-shared` would put the Go
runtime — and its scheduler threads and garbage collector — inside every
process that authenticates anybody. Those processes fork.

slinit already measured this in `lib/slinit-mlock`, where the same
question came up for an `LD_PRELOAD`: the Go shared object was **1.9 MB
against 17 kB** for the C one, and preloading it took a trivial process
from 2.8 MB and one thread to **78 MB and two**. A PAM module is loaded
far more often than a preload, into processes that are far more
sensitive.

### libdbus-1, not sd-bus

elogind's module uses `sd-bus`, which comes from libsystemd or
libelogind. Linking against either would reintroduce exactly what this
module exists to remove.

`libdbus-1` is already present at runtime on a Sunlight system, because
`dbus-daemon` links it — so `pam_slinit.so` adds no new runtime
dependency.

Verified against the installed rootfs rather than assumed. The built
module's direct `NEEDED` entries are exactly three — `libdbus-1.so.3`,
`libpam.so.0`, `libc.so.6` — and in the Sunlight rootfs
`libdbus-1.so.3` itself needs only `libc.so.6`. `libsystemd` is not in
that rootfs at all.

On a systemd distribution the same object does load `libsystemd`
transitively, because `libdbus-1` is built with systemd support there.
That is a property of the host's dbus, not of this module, and it is
worth knowing before someone reads an `ldd` on a development machine and
concludes the opposite.

### `CreateSessionWithPIDFD`, falling back to `CreateSession`

The module names the session leader by a pidfd, so a pid recycled between
the module reading it and slinit-logind acting on it cannot make another
process the leader. slinit-logind has the call from 3.16; against an
older one the call fails with `UnknownMethod` and the module retries with
`CreateSession` and the pid, as `pam_systemd` does against an older
logind. Both carry systemd's signatures exactly.

## The session lifetime contract

A session ends when its leader process exits, which slinit-logind watches
through a pidfd, or when `pam_sm_close_session` calls `ReleaseSession`.
That is systemd's contract since v258.

The file descriptor `CreateSession` returns is not part of it. Before v258
it was a FIFO whose closing ended the session; systemd now returns a
placeholder, and so does slinit-logind from 3.16 (earlier versions
returned a FIFO they never watched). The module closes it at once.

`ReleaseSession` still matters: it ends the session when the login does,
not when the leader exits, which differs for a display manager's worker
or a session that left a process behind. The module releases only a
session it created; for an `existing` one it does nothing at close, since
that session belongs to whoever created it.

## What the module sends

The rules `pam_systemd` applies before `CreateSession`, so a session
looks the same to slinit-logind whichever module registered it
(`src/context.c`, tested by `make test`):

- type, class, desktop, seat and VT come from `XDG_SESSION_TYPE`,
  `XDG_SESSION_CLASS`, `XDG_SESSION_DESKTOP`, `XDG_SEAT` and `XDG_VTNR` in
  the PAM environment, then the process environment, then the module's
  `type=`, `class=` and `desktop=` arguments;
- a tty containing `:` is an X display; `cron` and `ssh` are not ttys;
  a `/dev/` prefix is dropped;
- type defaults to `x11`, `tty` or `unspecified`; class to `background`
  for `unspecified`, else `user`;
- seat and VT number are left to slinit-logind, which derives them from a
  virtual-console tty as systemd-logind does.

It then exports `XDG_SESSION_ID`, `XDG_SESSION_TYPE`, `XDG_SESSION_CLASS`,
`XDG_SESSION_DESKTOP`, `XDG_SEAT`, `XDG_VTNR`, and, for a new session whose
runtime directory exists and belongs to the user, `XDG_RUNTIME_DIR`.

Options: `debug`, `class=`, `type=`, `desktop=`.

## Building

```sh
make                 # builds src/pam_slinit.so
make check           # asserts the module exports exactly two symbols
make test            # the session-parameter rules, without PAM or a bus
```

Requires `libpam` and `libdbus-1` development headers (`pam-devel`,
`dbus-devel` on Sunlight/Void).

## Status

Opens and releases sessions. Not yet in any `/etc/pam.d` file on Sunlight,
and elogind is still installed: `TODO.md` lists what remains.
