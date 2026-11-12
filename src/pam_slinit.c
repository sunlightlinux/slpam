/* SPDX-License-Identifier: Apache-2.0 */

/*
 * pam_slinit.so — opens and closes slinit-logind sessions.
 *
 * Replaces pam_elogind.so on a Sunlight Linux system. slinit-logind owns
 * org.freedesktop.login1; this module is the login hook that registers a
 * session on the way in and releases it on the way out.
 *
 * C, not Go, and libdbus-1, not sd-bus. README.md records why, with the
 * measurements behind both.
 *
 * Only two symbols leave this object; see pam_slinit.sym.
 */

#define _GNU_SOURCE

#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/syscall.h>

#include <security/pam_modules.h>
#include <security/pam_ext.h>

#include <dbus/dbus.h>

#include "context.h"

#define LOGIN1_DEST "org.freedesktop.login1"
#define LOGIN1_PATH "/org/freedesktop/login1"
#define LOGIN1_IFACE "org.freedesktop.login1.Manager"

/* The session this handle registered, for close_session to release. */
#define DATA_SESSION_ID "slinit.session-id"

/* How long a login waits for slinit-logind before giving up. */
#define CALL_TIMEOUT_MS 25000

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

struct options {
        bool debug;
        const char *session_class;
        const char *type;
        const char *desktop;
};

static void parse_args(pam_handle_t *handle, int argc, const char **argv, struct options *o)
{
        for (int i = 0; i < argc; i++) {
                if (strcmp(argv[i], "debug") == 0)
                        o->debug = true;
                else if (strncmp(argv[i], "class=", 6) == 0)
                        o->session_class = argv[i] + 6;
                else if (strncmp(argv[i], "type=", 5) == 0)
                        o->type = argv[i] + 5;
                else if (strncmp(argv[i], "desktop=", 8) == 0)
                        o->desktop = argv[i] + 8;
                else
                        pam_syslog(handle, LOG_WARNING, "unknown option: %s", argv[i]);
        }
}

/*
 * The PAM environment first, then the process's own. A service started
 * with XDG_SESSION_CLASS=greeter in its environment gets a greeter session
 * without its PAM stack being rewritten; secure_getenv because the module
 * runs inside su and sudo.
 */
static const char *env(pam_handle_t *handle, const char *key, const char *fallback)
{
        const char *v = pam_getenv(handle, key);

        if (v != NULL && *v != '\0')
                return v;
        v = secure_getenv(key);
        if (v != NULL && *v != '\0')
                return v;
        return fallback;
}

static const char *item(pam_handle_t *handle, int type)
{
        const void *v = NULL;

        if (pam_get_item(handle, type, &v) != PAM_SUCCESS)
                return NULL;
        return v;
}

static const char *nz(const char *s)
{
        return s != NULL ? s : "";
}

static int put(pam_handle_t *handle, const char *key, const char *value)
{
        char *kv;
        int r;

        if (asprintf(&kv, "%s=%s", key, value) < 0)
                return PAM_BUF_ERR;
        r = pam_putenv(handle, kv);
        free(kv);
        if (r != PAM_SUCCESS)
                pam_syslog(handle, LOG_ERR, "cannot set %s: %s", key, pam_strerror(handle, r));
        return r;
}

static DBusConnection *bus_open(pam_handle_t *handle)
{
        DBusError err;
        DBusConnection *conn;

        dbus_error_init(&err);
        /*
         * Private, not shared: the login process may use the bus for
         * something else, and closing a shared connection here would
         * close it under them.
         */
        conn = dbus_bus_get_private(DBUS_BUS_SYSTEM, &err);
        if (conn == NULL) {
                pam_syslog(handle, LOG_ERR, "cannot connect to the system bus: %s", err.message);
                dbus_error_free(&err);
                return NULL;
        }
        /* libdbus's default is to _exit() the process on disconnect. */
        dbus_connection_set_exit_on_disconnect(conn, FALSE);
        return conn;
}

static void bus_close(DBusConnection *conn)
{
        dbus_connection_close(conn);
        dbus_connection_unref(conn);
}

static bool append_create_args(DBusMessage *m, const struct slpam_context *c, uid_t uid,
                               bool with_pidfd, int pidfd)
{
        DBusMessageIter it, props;
        dbus_uint32_t u32 = uid, vt = c->vtnr, pid = (dbus_uint32_t) getpid();
        dbus_bool_t remote = c->remote;
        dbus_uint64_t flags = 0;
        const char *strs1[] = { nz(c->service), nz(c->type), nz(c->session_class),
                                nz(c->desktop), nz(c->seat) };
        const char *strs2[] = { nz(c->tty), nz(c->display) };
        const char *strs3[] = { nz(c->remote_user), nz(c->remote_host) };

        dbus_message_iter_init_append(m, &it);
        if (!dbus_message_iter_append_basic(&it, DBUS_TYPE_UINT32, &u32))
                return false;
        if (with_pidfd ? !dbus_message_iter_append_basic(&it, DBUS_TYPE_UNIX_FD, &pidfd)
                       : !dbus_message_iter_append_basic(&it, DBUS_TYPE_UINT32, &pid))
                return false;
        for (size_t i = 0; i < 5; i++)
                if (!dbus_message_iter_append_basic(&it, DBUS_TYPE_STRING, &strs1[i]))
                        return false;
        if (!dbus_message_iter_append_basic(&it, DBUS_TYPE_UINT32, &vt))
                return false;
        for (size_t i = 0; i < 2; i++)
                if (!dbus_message_iter_append_basic(&it, DBUS_TYPE_STRING, &strs2[i]))
                        return false;
        if (!dbus_message_iter_append_basic(&it, DBUS_TYPE_BOOLEAN, &remote))
                return false;
        for (size_t i = 0; i < 2; i++)
                if (!dbus_message_iter_append_basic(&it, DBUS_TYPE_STRING, &strs3[i]))
                        return false;
        if (with_pidfd && !dbus_message_iter_append_basic(&it, DBUS_TYPE_UINT64, &flags))
                return false;
        /* No properties yet; MemoryMax and friends are TODO.md step 5. */
        if (!dbus_message_iter_open_container(&it, DBUS_TYPE_ARRAY, "(sv)", &props))
                return false;
        return dbus_message_iter_close_container(&it, &props);
}

/*
 * CreateSessionWithPIDFD names the leader by a pidfd, so a pid recycled
 * between here and slinit-logind cannot make another process the leader.
 * slinit-logind before 3.16 does not have it; the call then falls back to
 * CreateSession with the pid, as pam_systemd does against an older logind.
 */
static DBusMessage *create_session(pam_handle_t *handle, DBusConnection *conn,
                                   const struct slpam_context *c, uid_t uid)
{
        int pidfd = (int) syscall(SYS_pidfd_open, getpid(), 0);
        bool with_pidfd = pidfd >= 0 && dbus_connection_can_send_type(conn, DBUS_TYPE_UNIX_FD);
        DBusMessage *reply = NULL;

        for (int attempt = 0; attempt < 2; attempt++) {
                DBusError err;
                DBusMessage *m = dbus_message_new_method_call(LOGIN1_DEST, LOGIN1_PATH, LOGIN1_IFACE,
                                                              with_pidfd ? "CreateSessionWithPIDFD"
                                                                         : "CreateSession");

                if (m == NULL || !append_create_args(m, c, uid, with_pidfd, pidfd)) {
                        if (m != NULL)
                                dbus_message_unref(m);
                        pam_syslog(handle, LOG_ERR, "out of memory building CreateSession");
                        break;
                }
                dbus_error_init(&err);
                reply = dbus_connection_send_with_reply_and_block(conn, m, CALL_TIMEOUT_MS, &err);
                dbus_message_unref(m);
                if (reply != NULL)
                        break;
                if (with_pidfd && dbus_error_has_name(&err, DBUS_ERROR_UNKNOWN_METHOD)) {
                        dbus_error_free(&err);
                        with_pidfd = false;
                        continue;
                }
                pam_syslog(handle, LOG_ERR, "CreateSession failed: %s", err.message);
                dbus_error_free(&err);
                break;
        }
        if (pidfd >= 0)
                close(pidfd);
        return reply;
}

/*
 * XDG_RUNTIME_DIR only when it is a directory the user owns: a session
 * pointed at somebody else's runtime directory hands their sockets to the
 * wrong user.
 */
static bool runtime_dir_ok(const char *path, uid_t uid)
{
        struct stat st;

        return path != NULL && *path == '/' && lstat(path, &st) == 0 &&
               S_ISDIR(st.st_mode) && st.st_uid == uid;
}

static void free_data(pam_handle_t *handle, void *data, int status)
{
        (void) handle;
        (void) status;
        free(data);
}

SLPAM_PUBLIC PAM_EXTERN int pam_sm_open_session(pam_handle_t *handle, int flags,
                                                 int argc, const char **argv)
{
        struct options o = { 0 };
        struct slpam_context c = { 0 };
        const char *user = NULL;
        struct passwd pw, *pwp = NULL;
        char pwbuf[4096];
        DBusConnection *conn;
        DBusMessage *reply;
        DBusError err;
        const char *id, *path, *runtime, *seat;
        int fd = -1;
        dbus_uint32_t uid_out, vtnr;
        dbus_bool_t existing;
        char vtbuf[16];
        int r;

        (void) flags;
        parse_args(handle, argc, argv, &o);

        if (pam_get_user(handle, &user, NULL) != PAM_SUCCESS || user == NULL || *user == '\0') {
                pam_syslog(handle, LOG_ERR, "no user name");
                return PAM_SESSION_ERR;
        }
        if (getpwnam_r(user, &pw, pwbuf, sizeof(pwbuf), &pwp) != 0 || pwp == NULL) {
                pam_syslog(handle, LOG_ERR, "no such user: %s", user);
                return PAM_USER_UNKNOWN;
        }

        c.service = item(handle, PAM_SERVICE);
        c.tty = item(handle, PAM_TTY);
        c.display = item(handle, PAM_XDISPLAY);
        c.remote_user = item(handle, PAM_RUSER);
        c.remote_host = item(handle, PAM_RHOST);
        c.seat = env(handle, "XDG_SEAT", NULL);
        c.vtnr = (uint32_t) strtoul(nz(env(handle, "XDG_VTNR", NULL)), NULL, 10);
        c.type = env(handle, "XDG_SESSION_TYPE", o.type);
        c.session_class = env(handle, "XDG_SESSION_CLASS", o.session_class);
        c.desktop = env(handle, "XDG_SESSION_DESKTOP", o.desktop);
        slpam_context_settle(&c);

        if (o.debug)
                pam_syslog(handle, LOG_DEBUG,
                           "CreateSession uid=%u service=%s type=%s class=%s desktop=%s seat=%s "
                           "vtnr=%u tty=%s display=%s remote=%s ruser=%s rhost=%s",
                           (unsigned) pw.pw_uid, nz(c.service), c.type, c.session_class,
                           nz(c.desktop), nz(c.seat), (unsigned) c.vtnr, nz(c.tty),
                           nz(c.display), c.remote ? "yes" : "no", nz(c.remote_user),
                           nz(c.remote_host));

        conn = bus_open(handle);
        if (conn == NULL)
                return PAM_SESSION_ERR;
        reply = create_session(handle, conn, &c, pw.pw_uid);
        if (reply == NULL) {
                bus_close(conn);
                return PAM_SESSION_ERR;
        }

        dbus_error_init(&err);
        if (!dbus_message_get_args(reply, &err,
                                   DBUS_TYPE_STRING, &id,
                                   DBUS_TYPE_OBJECT_PATH, &path,
                                   DBUS_TYPE_STRING, &runtime,
                                   DBUS_TYPE_UNIX_FD, &fd,
                                   DBUS_TYPE_UINT32, &uid_out,
                                   DBUS_TYPE_STRING, &seat,
                                   DBUS_TYPE_UINT32, &vtnr,
                                   DBUS_TYPE_BOOLEAN, &existing,
                                   DBUS_TYPE_INVALID)) {
                pam_syslog(handle, LOG_ERR, "cannot parse the CreateSession reply: %s", err.message);
                dbus_error_free(&err);
                dbus_message_unref(reply);
                bus_close(conn);
                return PAM_SESSION_ERR;
        }
        /*
         * The fd is a placeholder (slinit-logind 3.16, systemd since v258)
         * or the read end of a FIFO nothing watches (earlier slinit-logind).
         * Either way a session does not end with it, so it is not kept.
         */
        if (fd >= 0)
                close(fd);

        if (o.debug)
                pam_syslog(handle, LOG_DEBUG, "session %s path=%s runtime=%s seat=%s vtnr=%u existing=%s",
                           id, path, runtime, seat, (unsigned) vtnr, existing ? "yes" : "no");

        r = put(handle, "XDG_SESSION_ID", id);
        if (r == PAM_SUCCESS)
                r = put(handle, "XDG_SESSION_TYPE", c.type);
        if (r == PAM_SUCCESS)
                r = put(handle, "XDG_SESSION_CLASS", c.session_class);
        if (r == PAM_SUCCESS && c.desktop != NULL && *c.desktop != '\0')
                r = put(handle, "XDG_SESSION_DESKTOP", c.desktop);
        if (r == PAM_SUCCESS && *seat != '\0')
                r = put(handle, "XDG_SEAT", seat);
        if (r == PAM_SUCCESS && vtnr > 0) {
                snprintf(vtbuf, sizeof(vtbuf), "%u", (unsigned) vtnr);
                r = put(handle, "XDG_VTNR", vtbuf);
        }
        /*
         * Only for a new session: a second one for the same leader must
         * not re-point it (elogind does the same).
         */
        if (r == PAM_SUCCESS && !existing) {
                if (runtime_dir_ok(runtime, pw.pw_uid))
                        r = put(handle, "XDG_RUNTIME_DIR", runtime);
                else
                        pam_syslog(handle, LOG_WARNING,
                                   "not setting XDG_RUNTIME_DIR: %s is not a directory owned by uid %u",
                                   runtime, (unsigned) pw.pw_uid);
        }

        /*
         * Only a session this handle created is released by it. An
         * existing one belongs to whoever created it; releasing it at
         * this handle's close would end their session.
         */
        if (r == PAM_SUCCESS && !existing) {
                char *copy = strdup(id);

                if (copy == NULL)
                        r = PAM_BUF_ERR;
                else
                        r = pam_set_data(handle, DATA_SESSION_ID, copy, free_data);
        }

        dbus_message_unref(reply);
        bus_close(conn);
        return r == PAM_SUCCESS ? PAM_SUCCESS : PAM_SESSION_ERR;
}

/*
 * ReleaseSession ends the session now rather than when its leader exits,
 * which matters when the leader outlives the login: a display manager's
 * worker, or a session that left a process running. slinit-logind accepts
 * it from inside the session (this process is its leader) or from root.
 */
SLPAM_PUBLIC PAM_EXTERN int pam_sm_close_session(pam_handle_t *handle, int flags,
                                                  int argc, const char **argv)
{
        struct options o = { 0 };
        const void *data = NULL;
        const char *id;
        DBusConnection *conn;
        DBusMessage *m, *reply;
        DBusError err;

        (void) flags;
        parse_args(handle, argc, argv, &o);

        if (pam_get_data(handle, DATA_SESSION_ID, &data) != PAM_SUCCESS || data == NULL)
                return PAM_SUCCESS; /* nothing this handle created */
        id = data;

        conn = bus_open(handle);
        if (conn == NULL)
                return PAM_SESSION_ERR;
        m = dbus_message_new_method_call(LOGIN1_DEST, LOGIN1_PATH, LOGIN1_IFACE, "ReleaseSession");
        if (m == NULL || !dbus_message_append_args(m, DBUS_TYPE_STRING, &id, DBUS_TYPE_INVALID)) {
                if (m != NULL)
                        dbus_message_unref(m);
                bus_close(conn);
                return PAM_BUF_ERR;
        }
        dbus_error_init(&err);
        reply = dbus_connection_send_with_reply_and_block(conn, m, CALL_TIMEOUT_MS, &err);
        dbus_message_unref(m);
        bus_close(conn);
        if (reply == NULL) {
                pam_syslog(handle, LOG_ERR, "ReleaseSession %s failed: %s", id, err.message);
                dbus_error_free(&err);
                return PAM_SESSION_ERR;
        }
        dbus_message_unref(reply);
        if (o.debug)
                pam_syslog(handle, LOG_DEBUG, "released session %s", id);
        return PAM_SUCCESS;
}
