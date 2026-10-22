/* SPDX-License-Identifier: Apache-2.0 */

/*
 * pam_slinit.so — opens and closes slinit-logind sessions.
 *
 * Replaces pam_elogind.so on a Sunlight Linux system. slinit-logind
 * already owns org.freedesktop.login1; this module is the login hook
 * that calls CreateSession on the way in and ReleaseSession on the way
 * out.
 *
 * C, not Go, and libdbus-1, not sd-bus. README.md records why, with the
 * measurements behind both.
 *
 * Only two symbols leave this object; see pam_slinit.sym.
 */

#include <syslog.h>

#include <security/pam_modules.h>
#include <security/pam_ext.h>

#include <dbus/dbus.h>

#define LOGIN1_DEST "org.freedesktop.login1"
#define LOGIN1_PATH "/org/freedesktop/login1"
#define LOGIN1_IFACE "org.freedesktop.login1.Manager"

/*
 * The module is built -fvisibility=hidden so nothing internal escapes,
 * and PAM_EXTERN is only `extern` — it carries no visibility of its
 * own. Without this attribute the two service functions are compiled
 * STV_HIDDEN and the version script cannot un-hide them: the object
 * loads and exports nothing, so dlopen succeeds and PAM then cannot
 * find a single entry point. `make check` exists because that failure
 * is silent at build time. systemd and elogind carry the same
 * attribute as their `_public_` macro.
 */
#define SLPAM_PUBLIC __attribute__((visibility("default")))

/*
 * Why PAM_IGNORE and not PAM_SUCCESS while the logic is unwritten.
 *
 * PAM_SUCCESS from an open_session that created no session would be a
 * lie the stack cannot detect: the user logs in, nothing registers the
 * session, and the failure surfaces much later as a desktop with no
 * seat. PAM_IGNORE says "this module has no opinion", the stack
 * continues, and an administrator who has also kept pam_elogind.so in
 * place still gets a working session.
 *
 * This is deliberately the safe direction for a module that is not
 * finished, and it must become PAM_SUCCESS / an error once the calls
 * below are real.
 */

SLPAM_PUBLIC PAM_EXTERN int pam_sm_open_session(pam_handle_t *handle, int flags,
                                   int argc, const char **argv)
{
        (void) flags;
        (void) argc;
        (void) argv;

        pam_syslog(handle, LOG_NOTICE,
                   "pam_slinit: session logic not implemented yet; "
                   "declining so the PAM stack can continue");
        return PAM_IGNORE;
}

SLPAM_PUBLIC PAM_EXTERN int pam_sm_close_session(pam_handle_t *handle, int flags,
                                    int argc, const char **argv)
{
        (void) flags;
        (void) argc;
        (void) argv;

        /*
         * ReleaseSession is not a courtesy here. slinit-logind ships the
         * session FIFO fd but does not yet watch it, so an unreleased
         * session is cleaned up only by its leader-death watch — see
         * README.md. Once open_session is real, this one must be too, or
         * stale records block a display manager from starting a
         * replacement.
         */
        pam_syslog(handle, LOG_NOTICE,
                   "pam_slinit: nothing to release; session logic not "
                   "implemented yet");
        return PAM_IGNORE;
}
