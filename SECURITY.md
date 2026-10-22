# Security Policy

## Why this repository is different

`pam_slinit.so` is a shared object that `dlopen`s into **every process
that authenticates anybody** — `login`, `sshd`, `gdm`, `su`, `sudo`.
Those processes are privileged, and several of them fork.

That gives this small amount of code two failure modes that are not
ordinary bugs:

- **Authentication bypass.** A module that returns the wrong code, or
  that mishandles a `CreateSession` failure, can let a session be
  established that should not have been.
- **Lockout.** A module that crashes, hangs, or returns an error where
  it should decline can make a machine unloggable — including over SSH,
  which may be the only route in.

Both are security issues. The second one is still a security issue even
though nothing was "broken into": availability of the administrative
path is part of the system's security.

## Reporting a Vulnerability

**Do NOT open a public GitHub issue for a security vulnerability.**

Email: ionut_n2001@yahoo.com

Include:

- The failure mode — bypass, lockout, privilege or information leak
- Which PAM service (`sshd`, `gdm`, `login`, `su`, …) and the relevant
  `/etc/pam.d/` stack
- The module version or commit, and the `slinit-logind` version
- Steps to reproduce, and whether the machine stayed reachable
- Potential impact and a suggested fix, if you have one

You should get a response within 48 hours. We will coordinate a fix
before public disclosure.

## What is in scope

- Returning `PAM_SUCCESS` for a session that was not created
- Anything that lets one user's session be created, released, killed or
  read as another user's
- Crashes, hangs or unbounded waits inside a PAM entry point —
  `slinit-logind` being slow or absent must degrade, not block
- Leaking file descriptors, memory or the D-Bus connection across the
  fork that follows PAM in `sshd`
- Trusting unvalidated input from the login1 bus

## What is not in scope

- `slinit-logind`'s own D-Bus surface — report those against
  [slinit](https://github.com/sunlightlinux/slinit)
- A misconfigured `/etc/pam.d/` stack. Order matters in PAM; a module
  placed wrongly is an operator error, though if our documentation
  invited it, that is a documentation bug worth reporting publicly
- `libpam` and `libdbus-1` themselves

## Testing guidance, because getting this wrong costs access

A broken PAM module is tested in the worst possible place. If you are
developing against this repository:

- **Test in a local VM with console access first**, never on a remote
  machine whose only route in is SSH
- **Keep a working module in the stack** until yours is proven —
  entry points that are not finished return `PAM_IGNORE` precisely so
  the stack can continue
- **Hold an already-open session** before you touch `/etc/pam.d/` on any
  machine you care about, so you have a way back if the next login fails
