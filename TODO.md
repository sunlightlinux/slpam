# slpam — remaining work, in order

The build, the exported symbol set and the design decisions in
`README.md` are settled. The session logic is not written. This is the
order to write it in, and why.

## 1. `pam_sm_open_session` → `CreateSession`

Gather what the call needs from the PAM handle — `PAM_USER` (then
`getpwnam` for the uid), `PAM_SERVICE`, `PAM_TTY`, `PAM_XDISPLAY`,
`PAM_RUSER`, `PAM_RHOST` — derive type, class, seat and vtnr, and call
`CreateSession` on `org.freedesktop.login1.Manager`.

The signature is `uusssssussbss` followed by an `a(sv)` of properties,
in that order: uid, pid, service, type, class, desktop, seat, vtnr, tty,
display, remote, remote_user, remote_host. Send an empty property array
to begin with; the `MemoryMax` handling elogind does is step 5.

Returns, in order: session id, object path, runtime path, FIFO fd, uid,
seat, vtnr, and an `existing` flag. **Honour `existing`** — a second
`CreateSession` for a session that already exists is not an error, and
treating it as one is how a display manager ends up unable to reuse a
seat.

## 2. Export the session to the environment

`pam_putenv` for `XDG_SESSION_ID`, `XDG_RUNTIME_DIR`, `XDG_SESSION_TYPE`,
`XDG_SESSION_CLASS`, `XDG_SEAT` and `XDG_VTNR`. Without these a desktop
session comes up unable to find its own runtime directory, which looks
like a dozen unrelated failures.

Only set `XDG_RUNTIME_DIR` when the session is not `existing`, matching
elogind: a second session for the same user must not re-point it.

## 3. `pam_sm_close_session` → `ReleaseSession`

Not optional, and the reason is specific to slinit-logind: it ships the
session FIFO fd but **does not watch it yet** (its own comment calls
that Phase C). So cleanup rests on this call, with a watch on the
session leader's death as the only safety net. A session that is never
released leaves a record that blocks a replacement greeter.

## 4. Decide what to do with the FIFO fd — OPEN

In systemd and elogind the fd *is* the session lifetime: logind watches
the read end and the session ends when the last write end closes. The
module deliberately leaks it into the session leader for exactly that
reason.

slinit-logind does not watch it yet, so today holding it open achieves
nothing and closing it costs nothing. The decision matters because it
changes which component owns session lifetime, and because a module that
closes the fd will need revisiting the moment Phase C lands.

Three options, in order of preference:

1. **Hold it open and leak it deliberately**, as systemd does, so the
   module is already correct when Phase C arrives. Costs one fd per
   session and needs care that it is not closed by a `close_range` in
   some other module.
2. Close it immediately and rely on `ReleaseSession`. Simplest, correct
   today, wrong later.
3. Implement Phase C in slinit-logind first, then write the module
   against a contract that is actually enforced.

Option 3 is the honest one if the two can be sequenced; option 1
otherwise. **Do not pick silently** — this is the one decision here that
is about where a responsibility lives, not about code.

## 5. The rest of elogind parity

`MemoryMax` / `MemoryMaxScale` properties, `pam_slinit.8`, and the
`class=background` / `type=unspecified` edge cases. None of it blocks a
working login.

## 6. Distro side — a separate piece of work

Shipping this module does not remove elogind. `gnome-shell` and `xfce4`
depend on the elogind *package*, so the dependency has to change in
`slpkgs` as well, and `/etc/pam.d/*` has to reference `pam_slinit.so`.

Plan both halves or elogind stays installed regardless of how good the
module is.

## Testing notes

- `make check` asserts the module exports exactly two symbols. It exists
  because `-fvisibility=hidden` plus `PAM_EXTERN` — which carries no
  visibility of its own — produces an object that `dlopen` loads happily
  and that PAM then cannot call. That failure is silent at build time.
- A `dlopen` + `dlsym` probe is the cheapest real check that the module
  is loadable; `ldd` alone does not prove the entry points resolve.
- Read `ldd` output on a development machine with suspicion: on a
  systemd host `libdbus-1` drags in `libsystemd`, which says nothing
  about the target.
