# slpam — remaining work, in order

The build, the exported symbol set and the design decisions in
`README.md` are settled. The session logic is not written. This is the
order to write it in, and why.

## 1–4. Done

`pam_sm_open_session` calls `CreateSessionWithPIDFD` (falling back to
`CreateSession`), exports the `XDG_*` variables and remembers the session
it created; `pam_sm_close_session` releases it. The FIFO question is
closed: since systemd v258 a session ends with its leader's pidfd, and
slinit-logind 3.16 does the same and returns a placeholder fd, which the
module closes. README.md records the contract.

Still to do for these steps: run them on a real login (console, sshd, a
display manager) on Sunlight, not only through a test PAM service.

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
