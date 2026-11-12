/* SPDX-License-Identifier: Apache-2.0 */

#ifndef SLPAM_CONTEXT_H
#define SLPAM_CONTEXT_H

#include <stdbool.h>
#include <stdint.h>

/*
 * What a session is registered as. Filled from the PAM items, then the
 * module arguments and the XDG_* environment, then completed by
 * slpam_context_settle(), which is pure so it can be tested without PAM
 * or a bus.
 *
 * Strings point into storage owned by the caller (the PAM handle, argv,
 * the environment, or literals); the struct owns nothing.
 */
struct slpam_context {
        const char *service;
        const char *type;
        const char *session_class;
        const char *desktop;
        const char *seat;
        uint32_t vtnr;
        const char *tty;
        const char *display;
        const char *remote_user;
        const char *remote_host;
        bool remote;
};

/*
 * Applies the rules pam_systemd applies before CreateSession, so that a
 * session looks the same to slinit-logind whichever module registered it:
 *
 *   - a tty containing ':' is an X display put there for utmp: it moves
 *     to display and the tty is dropped;
 *   - cron sets PAM_TTY to "cron" without a terminal: no tty, type
 *     unspecified, class background unless given;
 *   - sshd sets PAM_TTY to "ssh" before it knows whether it will allocate
 *     a pty: no tty, type tty, class user unless given;
 *   - a "/dev/" prefix is dropped;
 *   - a VT number only means something on seat0;
 *   - type defaults to x11 with a display, tty with a tty, else
 *     unspecified; class to background for unspecified, else user;
 *   - remote means a remote host was given and it is not this machine.
 *
 * Seat and VT are not derived from the tty here: slinit-logind does that
 * on CreateSession, as systemd-logind does.
 */
void slpam_context_settle(struct slpam_context *c);

/* True for the names a remote host takes when it is in fact this machine. */
bool slpam_is_localhost(const char *host);

#endif
