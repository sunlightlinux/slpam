## Description

What this changes and why.

## Type of Change

- [ ] Session logic (`pam_sm_open_session` / `pam_sm_close_session`)
- [ ] Build or packaging
- [ ] Documentation
- [ ] Bug fix
- [ ] Security fix — **coordinate via `SECURITY.md` first, do not open a
      public PR for an unreleased vulnerability**

## How this was tested

A PAM module that is wrong locks machines out, so "it compiles" is not a
test. Please say what you actually did.

- [ ] `make && make check` pass
- [ ] Tested on a VM with console access, not a remote-only machine
- [ ] PAM service(s) exercised: <!-- sshd / gdm / login / su -->
- [ ] A second session stayed usable while testing
- [ ] Logged in **and** out, and confirmed the session was released:
      `ListSessions` and `/run/systemd/sessions/` both clear afterwards

Remember `slinit-logind` does not log session events — check state, not
`journalctl`.

## Checklist

- [ ] Only two symbols exported; new entry points added to
      `src/pam_slinit.sym` and to `make check`
- [ ] No `PAM_SUCCESS` returned for work that did not happen
- [ ] No unbounded wait — a slow or absent `slinit-logind` degrades
      rather than blocks
- [ ] Nothing allocated that is not freed on every path, including error
      paths
- [ ] No global state that survives the fork `sshd` performs after PAM
- [ ] A divergence from `pam_elogind.so`'s observable behaviour is
      explained in a comment, not just in this PR
- [ ] `README.md` / `TODO.md` updated if a settled decision changed
