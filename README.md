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
- for a tty, seat and VT number are left to slinit-logind, which derives
  them from a virtual-console tty as systemd-logind does;
- for an X display with no `XDG_VTNR`, the module asks the X server: it
  connects to the display's socket, takes the peer's pid and reads that
  process's controlling tty. A VT there puts the session on `seat0`. A
  display manager that sets `XDG_SEAT` and `XDG_VTNR` skips this; `xdm`
  and its kind set neither and would otherwise get a session with no seat.
  The peer must be root or the user being logged in, because any user can
  bind the abstract socket name of a display nobody is serving; and the
  connect gives up after two seconds, so a server that has stopped
  accepting does not hold the login.

It then exports `XDG_SESSION_ID`, `XDG_SESSION_TYPE`, `XDG_SESSION_CLASS`,
`XDG_SESSION_DESKTOP`, `XDG_SEAT`, `XDG_VTNR`, and, when the session
belongs to the user being logged in and its runtime directory exists and
is theirs, `XDG_RUNTIME_DIR` — plus `DBUS_SESSION_BUS_ADDRESS` if a user
bus is listening at `$XDG_RUNTIME_DIR/bus`. A variable with no value is
removed rather than left as an earlier module set it.

A `SessionBusy` answer is success with no session variables exported:
there is nothing to open. systemd-logind sends it for a caller already in
a session, `su` and `sudo` above all. slinit-logind sends it from the
version that refuses nested sessions, for the same case and for a VT on
`seat0` that a non-greeter session already holds; a login on such a VT
therefore goes through with no session, and none of what "active on the
console" grants. Earlier slinit-logind versions open a nested session
instead.

If the login fails after the session was created, the module releases the
session, drops the inhibitor lock and removes `XDG_SESSION_ID`,
`XDG_SEAT`, `XDG_VTNR`, `XDG_RUNTIME_DIR` and `DBUS_SESSION_BUS_ADDRESS`
from the PAM environment before returning the error: nothing is left
naming a session that no longer exists. Type, class and desktop stay,
since they describe what was asked for and a display manager sets them
before the module runs.

Class `none`, from `class=none` or `XDG_SESSION_CLASS=none`, registers
nothing and succeeds.

## What else it does, as `pam_systemd` does

Checked against systemd v262 (`src/login/pam_systemd.c`). All of it also
happens when no session was registered.

- **`HOME`** is set from the user's passwd entry.
- **Inhibitor lock.** `inhibit=shutdown:sleep` (or `XDG_SESSION_INHIBIT`),
  with `inhibit-why=` (or `XDG_SESSION_INHIBIT_WHY`), takes a block-mode
  lock through `Inhibit` and holds it until the session closes. Failing
  to get it is logged and the login goes on.
- **Areas.** `area=work` (or `XDG_AREA`) logs the user into
  `~/Areas/work`: `HOME` points there, `XDG_AREA` is set, and
  `XDG_RUNTIME_DIR` becomes `<runtime>/Areas/work`, created if missing.
  The area must be a directory the user owns; if not, they are told and
  get their ordinary home. `src/area.c`: the runtime directory belongs to
  the user, so each level is opened without following symlinks and a new
  directory is renamed into place only once its ownership is right.
- **Session markers.** For a `tty` session with a terminal on stdout and
  `TERM` not `dumb`, the OSC 3008 `start` sequence is written at open and
  its `end` at close (`src/osc.c`).
- **Shell credentials.** `shell.prompt.prefix`, `shell.prompt.suffix` and
  `shell.welcome` from `$CREDENTIALS_DIRECTORY`, if the service has one,
  become `SHELL_PROMPT_PREFIX`, `SHELL_PROMPT_SUFFIX` and `SHELL_WELCOME`.
- **`XDG_SESSION_EXTRA_DEVICE_ACCESS`** is carried into the session.

Options: `debug` (also `debug=yes|no`), `class=`, `type=`, `desktop=`,
`area=`, `inhibit=`, `inhibit-why=`.

## The environment is input, so guard it

`XDG_SESSION_CLASS`, `XDG_SESSION_TYPE`, `XDG_SEAT`, `XDG_VTNR`,
`XDG_AREA` and `XDG_SESSION_INHIBIT` are read from the PAM environment
and then from the process's own, exactly as `pam_systemd` reads them.
That is what lets a display manager describe its session, and it is safe
only while the user being logged in cannot set them:

- `XDG_SESSION_CLASS=greeter` is allowed to share a VT that another
  session holds, which slinit-logind otherwise refuses;
- `XDG_SEAT` and `XDG_VTNR` say which console the session is on, and
  being active on a console is what polkit's `allow_active` rules reward;
- `XDG_SESSION_INHIBIT=shutdown` blocks the machine from powering off for
  as long as the session lasts.

So, in the stack that loads this module:

- no `pam_env.so user_readenv=1`, and nothing else that copies
  user-controlled files into the PAM environment, before `pam_slinit.so`;
- `sshd_config` must not `AcceptEnv XDG_*`, nor `PermitUserEnvironment`;
- a service that calls PAM with these already in its own environment
  passes them on: that is the feature, so it must be the service's
  intent.

This has to be checked in Sunlight's `/etc/pam.d` and `sshd_config` when
the module is wired in; the module cannot tell a display manager's
variable from a user's.

## What the module does not trust

- **The bus address.** The system bus address is compiled in
  (`SYSTEM_BUS_ADDRESS`, by default what `dbus-1.pc` says) and
  `DBUS_SYSTEM_BUS_ADDRESS` is never read. libdbus would read it, and an
  address can be `unixexec:path=...`, a program to run. libdbus ignores
  the variable in a setuid process, but tells one by comparing the real,
  effective and saved ids, so a setuid program that has made all three
  root and still has its caller's environment when it opens the session
  would run the caller's program as root. Override `SYSTEM_BUS_ADDRESS`
  only to point a test build at a private bus.
- **Strings that are not UTF-8.** D-Bus strings must be UTF-8, and libdbus
  answers one that is not by calling `abort()` in the process that loaded
  the module. A remote host name, an X display or an `XDG_*` value that
  is not valid UTF-8 is logged and left out; `remote` stays set for a
  host name that could not be sent.
- **`$XDG_RUNTIME_DIR/bus`.** `DBUS_SESSION_BUS_ADDRESS` is exported only
  when that name is itself a socket, not a symlink to something.

### Where it still differs from `pam_systemd`

- **A failed marker.** `pam_systemd` fails the login when it cannot write
  the OSC `start` sequence. This module logs it and carries on: a marker
  for the terminal's benefit is not worth a refused login.

- **Session classes.** No `user-early`, `user-light`, `background-light`
  or `user-incomplete`. In systemd they decide whether a user service
  manager is started; Sunlight has none, and slinit-logind stores the
  class as given without acting on it.
- **Release.** `pam_systemd` no longer reads `existing` and releases
  whatever `XDG_SESSION_ID` names. This module releases only a session it
  created: slinit-logind lets root release any session, and matches an
  existing one by leader pid.
- **Varlink.** `pam_systemd` tries `io.systemd.Login` first; slinit-logind
  speaks D-Bus only, so the list in `XDG_SESSION_EXTRA_DEVICE_ACCESS`,
  which travels only over Varlink, is exported but not sent.
- **User records.** No umask, nice level, rlimits, capability sets, `TZ`,
  `LANG` or default area from systemd's JSON user records.
- **Resource limits.** `systemd.memory_max` and its siblings are not sent
  as session properties.

Against `pam_elogind` there is one more: `PAM_TTY=cron` and `PAM_TTY=ssh`
set the class only when none was given, as `pam_systemd` does, where
`pam_elogind` overwrites it.

## Building

```sh
make                 # builds src/pam_slinit.so
make check           # asserts the module exports exactly two symbols
make test            # session rules, OSC sequences, area directories: no PAM, no bus
```

Requires `libpam` and `libdbus-1` development headers (`pam-devel`,
`dbus-devel` on Sunlight/Void).

## Status

Opens and releases sessions. Not yet in any `/etc/pam.d` file on Sunlight,
and elogind is still installed: `TODO.md` lists what remains.
