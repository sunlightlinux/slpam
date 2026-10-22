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

### `CreateSession`, not `CreateSessionWithPIDFD`

elogind prefers the pidfd variant when it can get one.
`slinit-logind` implements `CreateSession` and **not**
`CreateSessionWithPIDFD`, so this module calls the former. The
signatures line up exactly — elogind sends `uusssssussbss` and
slinit-logind's handler takes those parameters in that order, returning
the same eight values.

## The session lifetime contract, as it actually stands

`CreateSession` returns a FIFO file descriptor. In systemd and elogind
that fd *is* the session's lifetime: logind watches the read end, and
when every copy of the write end is closed the session ends.

**slinit-logind ships the fd but does not watch it yet** — its own
comment calls that Phase C. Cleanup currently depends on:

1. the explicit `ReleaseSession` call from `pam_sm_close_session`, and
2. a watch on the session leader's death, as a safety net for a greeter
   that crashes or is killed before PAM can close the session.

So for this module, **`ReleaseSession` is not optional** — it is the
cleanup path, not a courtesy. What to do with the FIFO fd is an open
decision recorded in `TODO.md`, because holding it open achieves nothing
today but matches where slinit-logind is going.

## Building

```sh
make                 # builds src/pam_slinit.so
make check           # asserts the module exports exactly two symbols
```

Requires `libpam` and `libdbus-1` development headers (`pam-devel`,
`dbus-devel` on Sunlight/Void).

## Status

Skeleton. The build, the exported symbol set and the decisions above are
settled; the session logic is not yet written. `TODO.md` lists what
remains, in the order it should be done.
