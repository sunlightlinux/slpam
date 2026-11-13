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

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pwd.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/vfs.h>

#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <security/pam_modutil.h>

#include <dbus/dbus.h>

#include "area.h"
#include "context.h"
#include "osc.h"

#define LOGIN1_DEST "org.freedesktop.login1"
#define LOGIN1_PATH "/org/freedesktop/login1"
#define LOGIN1_IFACE "org.freedesktop.login1.Manager"
#define LOGIN1_SESSION_BUSY "org.freedesktop.login1.SessionBusy"

/* The session this handle registered, for close_session to release. */
#define DATA_SESSION_ID "slinit.session-id"
/* The inhibitor lock held while the session is open. */
#define DATA_INHIBIT_FD "slinit.inhibit-fd"
/* The terminal the session-start sequence went to, and the id it carried. */
#define DATA_OSC_FD "slinit.osc-context-fd"
#define DATA_OSC_ID "slinit.osc-context-id"

/* pam_set_data takes a pointer; an fd is stored off by one so 0 is not NULL. */
#define FD_TO_PTR(fd) ((void *) (intptr_t) ((fd) + 1))
#define PTR_TO_FD(p) ((int) (intptr_t) (p) - 1)

/* A credential is a line of prompt, not a file to slurp. */
#define CREDENTIAL_MAX 65536

/* How long a login waits for slinit-logind before giving up. */
#define CALL_TIMEOUT_MS 25000

/* How long a login waits for an X server to accept a connection. */
#define DISPLAY_TIMEOUT_SEC 2

/* Linux 6.5; older libc headers do not have it. */
#ifndef SO_PEERPIDFD
#define SO_PEERPIDFD 77
#endif

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
        const char *area;
        const char *inhibit;
        const char *inhibit_why;
};

/* debug=yes and debug=0, as pam_elogind takes them: a pam.d line carries over. */
static int parse_bool(const char *v)
{
        static const char *const yes[] = { "1", "yes", "y", "true", "t", "on" };
        static const char *const no[] = { "0", "no", "n", "false", "f", "off" };

        for (size_t i = 0; i < sizeof(yes) / sizeof(yes[0]); i++)
                if (strcasecmp(v, yes[i]) == 0)
                        return 1;
        for (size_t i = 0; i < sizeof(no) / sizeof(no[0]); i++)
                if (strcasecmp(v, no[i]) == 0)
                        return 0;
        return -1;
}

static void parse_args(pam_handle_t *handle, int argc, const char **argv, struct options *o)
{
        for (int i = 0; i < argc; i++) {
                if (strcmp(argv[i], "debug") == 0)
                        o->debug = true;
                else if (strncmp(argv[i], "debug=", 6) == 0) {
                        int b = parse_bool(argv[i] + 6);

                        if (b < 0)
                                pam_syslog(handle, LOG_WARNING, "cannot parse %s, ignoring", argv[i]);
                        else
                                o->debug = b;
                }
                else if (strncmp(argv[i], "class=", 6) == 0)
                        o->session_class = argv[i] + 6;
                else if (strncmp(argv[i], "type=", 5) == 0)
                        o->type = argv[i] + 5;
                else if (strncmp(argv[i], "desktop=", 8) == 0)
                        o->desktop = argv[i] + 8;
                else if (strncmp(argv[i], "area=", 5) == 0)
                        o->area = argv[i] + 5;
                else if (strncmp(argv[i], "inhibit=", 8) == 0)
                        o->inhibit = argv[i] + 8;
                else if (strncmp(argv[i], "inhibit-why=", 12) == 0)
                        o->inhibit_why = argv[i] + 12;
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

/*
 * Sets key, or with no value removes it: a variable left over from an
 * earlier module must not describe a session this one did not give it.
 */
static int put(pam_handle_t *handle, const char *key, const char *value)
{
        char *kv;
        int r;

        if (value == NULL || *value == '\0') {
                /* pam_putenv logs when asked to remove what is not there. */
                if (pam_getenv(handle, key) == NULL)
                        return PAM_SUCCESS;
                r = pam_putenv(handle, key);
                return r == PAM_BAD_ITEM ? PAM_SUCCESS : r;
        }
        if (asprintf(&kv, "%s=%s", key, value) < 0)
                return PAM_BUF_ERR;
        r = pam_putenv(handle, kv);
        free(kv);
        if (r != PAM_SUCCESS)
                pam_syslog(handle, LOG_ERR, "cannot set %s: %s", key, pam_strerror(handle, r));
        return r;
}

/*
 * The VT an X display runs on: connect to its socket, ask the kernel who
 * is on the other end, and read that process's controlling tty. A display
 * manager that sets XDG_SEAT and XDG_VTNR never gets here; xdm and its
 * kind set neither, and slinit-logind derives a seat from a tty only, so
 * without this their sessions have no seat and are never the active one.
 * pam_elogind does the same (get_seat_from_display). 0 when unknown.
 *
 * Two things it does not take on trust. The abstract socket name is free
 * for any user to bind when no X server holds it, so the peer must be
 * root or the user being logged in: nobody else gets to say which VT this
 * session is on. And the connect is bounded, since a server that has
 * stopped accepting would otherwise hold the login for good.
 *
 * The peer is named by a pid, and a pid can be reused between learning
 * it and reading /proc. Where the kernel hands out a pidfd for the peer
 * (6.5 on), the answer counts only if that process is still alive after
 * the read: then the pid was its own throughout. On an older kernel the
 * window stays, as it does in pam_systemd.
 */
static uint32_t vtnr_from_display(const char *display, uid_t uid)
{
        const struct timeval patience = { .tv_sec = DISPLAY_TIMEOUT_SEC };
        struct sockaddr_un sa = { .sun_family = AF_UNIX };
        const socklen_t base = offsetof(struct sockaddr_un, sun_path);
        struct ucred cred;
        socklen_t len = sizeof(cred);
        char path[64], stat[512];
        uint32_t vtnr = 0;
        ssize_t got;
        int n, fd, peer = -1;
        socklen_t peer_len = sizeof(peer);

        if (display == NULL || display[0] != ':' || !isdigit((unsigned char) display[1]))
                return 0;
        /* sun_path[0] stays 0: the abstract socket first, then the file. */
        n = snprintf(sa.sun_path + 1, sizeof(sa.sun_path) - 1, "/tmp/.X11-unix/X%.*s",
                     (int) strspn(display + 1, "0123456789"), display + 1);
        if (n < 0 || (size_t) n >= sizeof(sa.sun_path) - 1)
                return 0;
        fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fd < 0)
                return 0;
        /* A unix connect() waits for room in the backlog for the send timeout. */
        if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &patience, sizeof(patience)) < 0)
                goto out;
        if (connect(fd, (struct sockaddr *) &sa, base + 1 + (socklen_t) n) < 0) {
                if (errno != ECONNREFUSED)
                        goto out;
                memmove(sa.sun_path, sa.sun_path + 1, (size_t) n + 1);
                if (connect(fd, (struct sockaddr *) &sa, base + (socklen_t) n + 1) < 0)
                        goto out;
        }
        if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) < 0 || cred.pid <= 0)
                goto out;
        if (cred.uid != 0 && cred.uid != uid)
                goto out;
        if (getsockopt(fd, SOL_SOCKET, SO_PEERPIDFD, &peer, &peer_len) < 0)
                peer = -1; /* an older kernel */
        close(fd);

        snprintf(path, sizeof(path), "/proc/%ld/stat", (long) cred.pid);
        fd = open(path, O_RDONLY | O_CLOEXEC | O_NOCTTY);
        if (fd < 0)
                goto out;
        got = read(fd, stat, sizeof(stat) - 1);
        if (got > 0) {
                stat[got] = '\0';
                vtnr = slpam_vtnr_from_stat(stat);
        }
        /* A pidfd turns readable when its process exits. */
        if (peer >= 0) {
                struct pollfd gone = { .fd = peer, .events = POLLIN };

                if (poll(&gone, 1, 0) != 0)
                        vtnr = 0;
        }
out:
        if (fd >= 0)
                close(fd);
        if (peer >= 0)
                close(peer);
        return vtnr;
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
                                   const struct slpam_context *c, uid_t uid, bool *busy)
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
                /*
                 * "Already in a session": what systemd-logind answers when
                 * the caller sits inside one, su and sudo above all. Not a
                 * failure; there is simply nothing to open. Logged without
                 * debug, with the daemon's reason: a login on a VT someone
                 * else holds goes through this way, and should be visible.
                 */
                if (dbus_error_has_name(&err, LOGIN1_SESSION_BUSY)) {
                        *busy = true;
                        pam_syslog(handle, LOG_NOTICE, "not creating a session: %s", err.message);
                } else
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

/*
 * DBUS_SESSION_BUS_ADDRESS, only when a user bus is in fact listening in
 * the runtime directory. Clients that do not look there by themselves
 * otherwise autolaunch a second bus. pam_elogind sets the same value.
 */
static int put_user_bus(pam_handle_t *handle, const char *runtime)
{
        char *sock, *addr;
        int r = PAM_SUCCESS;

        if (asprintf(&sock, "%s/bus", runtime) < 0)
                return PAM_BUF_ERR;
        if (access(sock, F_OK) == 0) {
                if (asprintf(&addr, "unix:path=%s", sock) < 0)
                        r = PAM_BUF_ERR;
                else {
                        r = put(handle, "DBUS_SESSION_BUS_ADDRESS", addr);
                        free(addr);
                }
        }
        free(sock);
        return r;
}

static void free_data(pam_handle_t *handle, void *data, int status)
{
        (void) handle;
        (void) status;
        free(data);
}

static void close_data(pam_handle_t *handle, void *data, int status)
{
        (void) handle;
        (void) status;
        if (PTR_TO_FD(data) >= 0)
                close(PTR_TO_FD(data));
}

/* Stores a copy of fd above stdio in the handle; the caller keeps its own. */
static int keep_fd(pam_handle_t *handle, const char *name, int fd)
{
        int copy = fcntl(fd, F_DUPFD_CLOEXEC, 3);
        int r;

        if (copy < 0)
                return PAM_SYSTEM_ERR;
        r = pam_set_data(handle, name, FD_TO_PTR(copy), close_data);
        if (r != PAM_SUCCESS)
                close(copy);
        return r;
}

static int call_release(pam_handle_t *handle, DBusConnection *conn, const char *id)
{
        DBusMessage *m, *reply;
        DBusError err;

        m = dbus_message_new_method_call(LOGIN1_DEST, LOGIN1_PATH, LOGIN1_IFACE, "ReleaseSession");
        if (m == NULL || !dbus_message_append_args(m, DBUS_TYPE_STRING, &id, DBUS_TYPE_INVALID)) {
                if (m != NULL)
                        dbus_message_unref(m);
                return PAM_BUF_ERR;
        }
        dbus_error_init(&err);
        reply = dbus_connection_send_with_reply_and_block(conn, m, CALL_TIMEOUT_MS, &err);
        dbus_message_unref(m);
        if (reply == NULL) {
                pam_syslog(handle, LOG_ERR, "ReleaseSession %s failed: %s", id, err.message);
                dbus_error_free(&err);
                return PAM_SESSION_ERR;
        }
        dbus_message_unref(reply);
        return PAM_SUCCESS;
}

/*
 * Releases the session this handle created, if it created one, and
 * forgets it. Used at close, and at open when the login fails after the
 * session exists: left alone it would stay registered, with its seat and
 * VT, for as long as the process that failed to log anyone in lives.
 */
static int release_created(pam_handle_t *handle, const struct options *o)
{
        const void *data = NULL;
        DBusConnection *conn;
        int r;

        if (pam_get_data(handle, DATA_SESSION_ID, &data) != PAM_SUCCESS || data == NULL)
                return PAM_SUCCESS; /* nothing this handle created */
        conn = bus_open(handle);
        if (conn == NULL)
                return PAM_SESSION_ERR;
        r = call_release(handle, conn, data);
        bus_close(conn);
        if (r == PAM_SUCCESS && o->debug)
                pam_syslog(handle, LOG_DEBUG, "released session %s", (const char *) data);
        /* Replacing the entry frees the id; a second close finds nothing. */
        (void) pam_set_data(handle, DATA_SESSION_ID, NULL, NULL);
        return r;
}

/*
 * Registers the session and exports what describes it. *runtime comes back
 * malloc'd when the session has a runtime directory this user may be
 * pointed at, NULL otherwise; *session_id likewise when a session was
 * opened or joined. Not registering at all is a success: class none, or
 * slinit-logind answering that the caller is in a session already.
 */
static int register_session(pam_handle_t *handle, const struct options *o,
                            const struct slpam_context *c, const struct passwd *pw,
                            char **runtime_out, char **session_id)
{
        DBusConnection *conn;
        DBusMessage *reply;
        DBusError err;
        const char *id, *path, *runtime, *seat;
        int fd = -1;
        dbus_uint32_t uid_out, vtnr;
        dbus_bool_t existing;
        bool busy = false;
        char vtbuf[16];
        int r;

        /*
         * class=none is pam_systemd's way to say "do not register this
         * one": a PAM stack shared by a service that must stay out of
         * logind.
         */
        if (strcmp(c->session_class, "none") == 0) {
                if (o->debug)
                        pam_syslog(handle, LOG_DEBUG, "session class none, not registering");
                return PAM_SUCCESS;
        }

        if (o->debug)
                pam_syslog(handle, LOG_DEBUG,
                           "CreateSession uid=%u service=%s type=%s class=%s desktop=%s seat=%s "
                           "vtnr=%u tty=%s display=%s remote=%s ruser=%s rhost=%s",
                           (unsigned) pw->pw_uid, nz(c->service), c->type, c->session_class,
                           nz(c->desktop), nz(c->seat), (unsigned) c->vtnr, nz(c->tty),
                           nz(c->display), c->remote ? "yes" : "no", nz(c->remote_user),
                           nz(c->remote_host));

        conn = bus_open(handle);
        if (conn == NULL)
                return PAM_SESSION_ERR;
        reply = create_session(handle, conn, c, pw->pw_uid, &busy);
        if (reply == NULL) {
                bus_close(conn);
                return busy ? PAM_SUCCESS : PAM_SESSION_ERR;
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

        if (o->debug)
                pam_syslog(handle, LOG_DEBUG, "session %s path=%s runtime=%s seat=%s vtnr=%u existing=%s",
                           id, path, runtime, seat, (unsigned) vtnr, existing ? "yes" : "no");

        /*
         * Remembered before anything else can fail, so that whatever does
         * fail from here on, the caller can release what was just created.
         * Only a session this handle created: an existing one belongs to
         * whoever created it, and releasing it would end their session.
         */
        if (!existing) {
                char *copy = strdup(id);

                r = copy != NULL ? pam_set_data(handle, DATA_SESSION_ID, copy, free_data) : PAM_BUF_ERR;
                if (r != PAM_SUCCESS) {
                        free(copy); /* PAM took no ownership */
                        (void) call_release(handle, conn, id);
                        dbus_message_unref(reply);
                        bus_close(conn);
                        return PAM_SESSION_ERR;
                }
        }

        r = put(handle, "XDG_SESSION_ID", id);
        if (r == PAM_SUCCESS)
                r = put(handle, "XDG_SESSION_TYPE", c->type);
        if (r == PAM_SUCCESS)
                r = put(handle, "XDG_SESSION_CLASS", c->session_class);
        if (r == PAM_SUCCESS)
                r = put(handle, "XDG_SESSION_DESKTOP", c->desktop);
        if (r == PAM_SUCCESS)
                r = put(handle, "XDG_SEAT", seat);
        if (r == PAM_SUCCESS && vtnr > 0) {
                snprintf(vtbuf, sizeof(vtbuf), "%u", (unsigned) vtnr);
                r = put(handle, "XDG_VTNR", vtbuf);
        }

        /*
         * Only when the session belongs to the user being logged in. An
         * existing session comes back with its original owner's uid, and
         * pointing another user at that runtime directory would have them
         * clobber it; pam_systemd draws the line at the same place.
         */
        if (r == PAM_SUCCESS && uid_out == pw->pw_uid) {
                if (!runtime_dir_ok(runtime, pw->pw_uid))
                        pam_syslog(handle, LOG_WARNING,
                                   "not setting XDG_RUNTIME_DIR: %s is not a directory owned by uid %u",
                                   runtime, (unsigned) pw->pw_uid);
                else if ((*runtime_out = strdup(runtime)) == NULL)
                        r = PAM_BUF_ERR;
        }
        if (r == PAM_SUCCESS && (*session_id = strdup(id)) == NULL)
                r = PAM_BUF_ERR;

        dbus_message_unref(reply);
        bus_close(conn);
        return r == PAM_SUCCESS ? PAM_SUCCESS : PAM_SESSION_ERR;
}

/*
 * inhibit=shutdown:sleep, or XDG_SESSION_INHIBIT: a block-mode inhibitor
 * held for as long as the session is open, for a login that must not be
 * cut short by a suspend. The lock is the fd; it is dropped at close, or
 * with the process. A failure is logged and the login goes on.
 */
static void acquire_inhibit_lock(pam_handle_t *handle, const struct options *o,
                                 const char *what, const char *why, const char *service)
{
        const char *who = service != NULL && *service != '\0' ? service : "pam_slinit";
        const char *mode = "block";
        DBusConnection *conn;
        DBusMessage *m, *reply = NULL;
        DBusError err;
        int fd = -1;

        if (why == NULL || *why == '\0')
                why = "Active PAM session";
        conn = bus_open(handle);
        if (conn == NULL)
                return;
        dbus_error_init(&err);
        m = dbus_message_new_method_call(LOGIN1_DEST, LOGIN1_PATH, LOGIN1_IFACE, "Inhibit");
        if (m != NULL && dbus_message_append_args(m, DBUS_TYPE_STRING, &what, DBUS_TYPE_STRING, &who,
                                                  DBUS_TYPE_STRING, &why, DBUS_TYPE_STRING, &mode,
                                                  DBUS_TYPE_INVALID))
                reply = dbus_connection_send_with_reply_and_block(conn, m, CALL_TIMEOUT_MS, &err);
        if (m != NULL)
                dbus_message_unref(m);
        if (reply == NULL) {
                pam_syslog(handle, LOG_WARNING, "cannot acquire inhibit lock for '%s': %s", what,
                           dbus_error_is_set(&err) ? err.message : "out of memory");
                dbus_error_free(&err);
                bus_close(conn);
                return;
        }
        if (!dbus_message_get_args(reply, &err, DBUS_TYPE_UNIX_FD, &fd, DBUS_TYPE_INVALID)) {
                pam_syslog(handle, LOG_WARNING, "cannot parse the Inhibit reply: %s", err.message);
                dbus_error_free(&err);
        } else {
                if (keep_fd(handle, DATA_INHIBIT_FD, fd) != PAM_SUCCESS)
                        pam_syslog(handle, LOG_WARNING, "cannot keep the inhibit lock");
                else if (o->debug)
                        pam_syslog(handle, LOG_DEBUG, "acquired inhibit lock for '%s'", what);
                close(fd);
        }
        dbus_message_unref(reply);
        bus_close(conn);
}

/*
 * shell.prompt.prefix, shell.prompt.suffix and shell.welcome, when the
 * service was started with credentials: how a container manager or a unit
 * file labels the shells opened inside it. No credentials directory, the
 * usual case, and this does nothing.
 */
static int import_shell_credentials(pam_handle_t *handle, const struct options *o)
{
        static const char *const names[][2] = {
                { "shell.prompt.prefix", "SHELL_PROMPT_PREFIX" },
                { "shell.prompt.suffix", "SHELL_PROMPT_SUFFIX" },
                { "shell.welcome", "SHELL_WELCOME" },
        };
        const char *dir = secure_getenv("CREDENTIALS_DIRECTORY");
        int dirfd, r = PAM_SUCCESS;

        if (dir == NULL || dir[0] != '/')
                return PAM_SUCCESS;
        dirfd = open(dir, O_PATH | O_DIRECTORY | O_CLOEXEC);
        if (dirfd < 0)
                return PAM_SUCCESS;
        for (size_t i = 0; r == PAM_SUCCESS && i < sizeof(names) / sizeof(names[0]); i++) {
                int fd = openat(dirfd, names[i][0], O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NOCTTY);
                char *value;
                ssize_t n = 0, got;

                if (fd < 0)
                        continue;
                value = malloc(CREDENTIAL_MAX + 1);
                if (value == NULL) {
                        close(fd);
                        r = PAM_BUF_ERR;
                        break;
                }
                while (n < CREDENTIAL_MAX && (got = read(fd, value + n, (size_t) (CREDENTIAL_MAX - n))) > 0)
                        n += got;
                close(fd);
                value[n] = '\0';
                /* An environment variable cannot carry a NUL; nor an empty one a prompt. */
                if (n == 0 || strlen(value) != (size_t) n) {
                        if (o->debug)
                                pam_syslog(handle, LOG_DEBUG, "ignoring credential %s", names[i][0]);
                } else
                        r = put(handle, names[i][1], value);
                free(value);
        }
        close(dirfd);
        return r;
}

/*
 * HOME, XDG_AREA and the runtime directory. An area the user cannot be
 * given — missing, or not theirs — is not an error: they are told, and get
 * their ordinary home.
 */
static int setup_environment(pam_handle_t *handle, const struct options *o, const struct passwd *pw,
                             const char *runtime, const char *area)
{
        const char *home = pw->pw_dir;
        char *area_home = NULL, *area_runtime = NULL;
        int r, e;

        if (area != NULL && *area == '\0')
                area = NULL;
        if (area != NULL) {
                e = slpam_area_home(home, area, pw->pw_uid, &area_home);
                if (e < 0) {
                        const char *why = e == -EPERM ? "is not owned by the user" : "is not accessible";

                        pam_syslog(handle, LOG_WARNING, "area '%s' under %s %s (%s), using the home directory",
                                   area, home, why, strerror(-e));
                        pam_info(handle, "Area '%s' %s, reverting to regular home directory.", area, why);
                        area = NULL;
                } else {
                        if (o->debug)
                                pam_syslog(handle, LOG_DEBUG, "area '%s' selected, HOME is %s", area, area_home);
                        home = area_home;
                }
        }

        r = put(handle, "XDG_AREA", area);
        if (r == PAM_SUCCESS && home != NULL && *home != '\0')
                r = put(handle, "HOME", home);
        if (r != PAM_SUCCESS)
                goto out;

        if (runtime == NULL) {
                /* An area without a runtime directory must not inherit the main one. */
                if (area != NULL)
                        r = put(handle, "XDG_RUNTIME_DIR", NULL);
                goto out;
        }
        if (area != NULL) {
                e = slpam_area_runtime(runtime, area, pw->pw_uid, pw->pw_gid, &area_runtime);
                if (e < 0) {
                        pam_syslog(handle, LOG_ERR, "cannot create %s/Areas/%s: %s", runtime, area,
                                   strerror(-e));
                        r = PAM_SESSION_ERR;
                        goto out;
                }
                runtime = area_runtime;
        }
        r = put(handle, "XDG_RUNTIME_DIR", runtime);
        if (r == PAM_SUCCESS)
                r = put_user_bus(handle, runtime);
out:
        free(area_home);
        free(area_runtime);
        return r;
}

static char *read_line(const char *path, char *buf, size_t size)
{
        int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOCTTY);
        ssize_t n;

        if (fd < 0)
                return NULL;
        n = read(fd, buf, size - 1);
        close(fd);
        if (n <= 0)
                return NULL;
        buf[n] = '\0';
        buf[strcspn(buf, "\n")] = '\0';
        return buf;
}

static int write_all(int fd, const char *s)
{
        size_t left = strlen(s);

        while (left > 0) {
                ssize_t n = write(fd, s, left);

                if (n < 0 && errno == EINTR)
                        continue;
                if (n <= 0)
                        return -1;
                s += n;
                left -= (size_t) n;
        }
        return 0;
}

/*
 * For a tty session, the sequence that tells the terminal a session
 * starts here, as pam_systemd writes it. Straight to stdout: the PAM
 * conversation would add a newline to what is not a message. The terminal
 * is remembered by an O_PATH fd, which does not hold it open, so the end
 * sequence can still be sent at close after login has shut 0, 1 and 2.
 *
 * Nothing here fails the login. pam_systemd does fail it when the write
 * does; a marker for the terminal's benefit is not worth a refused login.
 */
static void open_osc_context(pam_handle_t *handle, const struct options *o, const struct passwd *pw,
                            const char *session_id)
{
        struct slpam_osc_identity who = { .pid = (long) getpid(), .target_user = pw->pw_name,
                                          .session_id = session_id };
        char host[256], machine[64], boot[64], link[64];
        const struct passwd *self;
        const char *term;
        uint8_t *id;
        char *seq;
        int pidfd, tty;

        term = pam_getenv(handle, "TERM");
        if (term == NULL)
                term = getenv("TERM");
        if (term != NULL && strcmp(term, "dumb") == 0)
                return;
        if (!isatty(STDOUT_FILENO))
                return;

        id = malloc(16);
        if (id == NULL)
                return;
        if (getrandom(id, 16, 0) != 16) {
                free(id);
                return;
        }

        self = pam_modutil_getpwuid(handle, getuid());
        if (self != NULL)
                who.user = self->pw_name;
        if (gethostname(host, sizeof(host)) == 0) {
                host[sizeof(host) - 1] = '\0';
                who.hostname = host;
        }
        who.machine_id = read_line("/etc/machine-id", machine, sizeof(machine));
        who.boot_id = read_line("/proc/sys/kernel/random/boot_id", boot, sizeof(boot));
        who.comm = program_invocation_short_name;
        /* A pidfd's inode identifies the process only where pidfds live on pidfs. */
        pidfd = (int) syscall(SYS_pidfd_open, getpid(), 0);
        if (pidfd >= 0) {
                struct statfs sfs;
                struct stat st;

                if (fstatfs(pidfd, &sfs) == 0 && sfs.f_type == 0x50494446 && fstat(pidfd, &st) == 0) {
                        who.has_pidfd_id = true;
                        who.pidfd_id = st.st_ino;
                }
                close(pidfd);
        }

        seq = slpam_osc_open(id, &who);
        if (seq == NULL) {
                free(id);
                return;
        }
        snprintf(link, sizeof(link), "/proc/self/fd/%d", STDOUT_FILENO);
        tty = open(link, O_PATH | O_CLOEXEC);
        if (write_all(STDOUT_FILENO, seq) < 0) {
                pam_syslog(handle, LOG_WARNING, "cannot write the session-start sequence: %s", strerror(errno));
                free(seq);
                free(id);
                if (tty >= 0)
                        close(tty);
                return;
        }
        free(seq);

        /* Without both the id and the terminal there is no end to write later. */
        if (pam_set_data(handle, DATA_OSC_ID, id, free_data) != PAM_SUCCESS)
                free(id);
        else if (tty < 0 || keep_fd(handle, DATA_OSC_FD, tty) != PAM_SUCCESS) {
                if (o->debug)
                        pam_syslog(handle, LOG_DEBUG, "cannot pin the terminal, no session-end sequence");
        }
        if (tty >= 0)
                close(tty);
}

static void close_osc_context(pam_handle_t *handle, const struct options *o)
{
        const void *p = NULL;
        const uint8_t *id;
        char link[64];
        char *seq;
        int fd;

        if (pam_get_data(handle, DATA_OSC_FD, &p) != PAM_SUCCESS || PTR_TO_FD(p) < 0)
                return;
        snprintf(link, sizeof(link), "/proc/self/fd/%d", PTR_TO_FD(p));
        p = NULL;
        if (pam_get_data(handle, DATA_OSC_ID, &p) != PAM_SUCCESS || p == NULL)
                return;
        id = p;

        /* Non-blocking: a terminal that has gone away must not hang a logout. */
        fd = open(link, O_WRONLY | O_CLOEXEC | O_NONBLOCK | O_NOCTTY);
        if (fd < 0) {
                if (o->debug)
                        pam_syslog(handle, LOG_DEBUG, "cannot reopen the terminal: %s", strerror(errno));
                return;
        }
        if (isatty(fd)) {
                seq = slpam_osc_close(id);
                if (seq != NULL) {
                        if (write_all(fd, seq) < 0 && o->debug)
                                pam_syslog(handle, LOG_DEBUG, "cannot write the session-end sequence: %s",
                                           strerror(errno));
                        free(seq);
                }
        }
        close(fd);
}

SLPAM_PUBLIC PAM_EXTERN int pam_sm_open_session(pam_handle_t *handle, int flags,
                                                 int argc, const char **argv)
{
        struct options o = { 0 };
        struct slpam_context c = { 0 };
        const char *user = NULL, *inhibit, *inhibit_why, *extra;
        const struct passwd *pw;
        char *area = NULL, *runtime = NULL, *session_id = NULL;
        bool on_tty;
        int r;

        (void) flags;
        parse_args(handle, argc, argv, &o);

        if (pam_get_user(handle, &user, NULL) != PAM_SUCCESS || user == NULL || *user == '\0') {
                pam_syslog(handle, LOG_ERR, "no user name");
                return PAM_SESSION_ERR;
        }
        /* libpam sizes the buffer and keeps the entry for the handle's life. */
        pw = pam_modutil_getpwnam(handle, user);
        if (pw == NULL) {
                pam_syslog(handle, LOG_ERR, "no such user: %s", user);
                return PAM_USER_UNKNOWN;
        }

        c.service = item(handle, PAM_SERVICE);
        c.tty = item(handle, PAM_TTY);
        c.display = item(handle, PAM_XDISPLAY);
        c.remote_user = item(handle, PAM_RUSER);
        c.remote_host = item(handle, PAM_RHOST);
        c.seat = env(handle, "XDG_SEAT", NULL);
        c.vtnr = slpam_parse_vtnr(env(handle, "XDG_VTNR", NULL));
        c.type = env(handle, "XDG_SESSION_TYPE", o.type);
        c.session_class = env(handle, "XDG_SESSION_CLASS", o.session_class);
        c.desktop = env(handle, "XDG_SESSION_DESKTOP", o.desktop);
        inhibit = env(handle, "XDG_SESSION_INHIBIT", o.inhibit);
        inhibit_why = env(handle, "XDG_SESSION_INHIBIT_WHY", o.inhibit_why);
        slpam_context_settle(&c);

        /* An X display with no VT given: ask the X server which one it is on. */
        if (c.display != NULL && *c.display != '\0' && c.vtnr == 0 &&
            (c.seat == NULL || *c.seat == '\0' || strcmp(c.seat, "seat0") == 0)) {
                c.vtnr = vtnr_from_display(c.display, pw->pw_uid);
                if (c.vtnr > 0)
                        c.seat = "seat0";
        }

        /*
         * What is needed past this point is copied or decided now: these
         * strings may live in the PAM environment, which the exports
         * below rewrite under them.
         */
        on_tty = strcmp(c.type, "tty") == 0;
        if (env(handle, "XDG_AREA", o.area) != NULL) {
                area = strdup(env(handle, "XDG_AREA", o.area));
                if (area == NULL)
                        return PAM_BUF_ERR;
                if (!slpam_area_name_ok(area)) {
                        pam_syslog(handle, LOG_WARNING, "area '%s' is not a valid file name, ignoring", area);
                        free(area);
                        area = NULL;
                }
        }

        r = register_session(handle, &o, &c, pw, &runtime, &session_id);
        if (r != PAM_SUCCESS)
                goto out;

        if (inhibit != NULL)
                acquire_inhibit_lock(handle, &o, inhibit, inhibit_why, item(handle, PAM_SERVICE));

        /*
         * Carried into the session as it was given. Only systemd-logind's
         * Varlink interface takes the list itself; the variable is what
         * reaches a compositor either way.
         */
        extra = env(handle, "XDG_SESSION_EXTRA_DEVICE_ACCESS", NULL);
        if (extra != NULL && pam_getenv(handle, "XDG_SESSION_EXTRA_DEVICE_ACCESS") == NULL)
                r = put(handle, "XDG_SESSION_EXTRA_DEVICE_ACCESS", extra);
        if (r == PAM_SUCCESS)
                r = import_shell_credentials(handle, &o);
        if (r == PAM_SUCCESS)
                r = setup_environment(handle, &o, pw, runtime, area);
        if (r == PAM_SUCCESS && on_tty)
                open_osc_context(handle, &o, pw, session_id);
out:
        if (r != PAM_SUCCESS) {
                /* A login that fails leaves nothing behind: no session, no lock. */
                (void) release_created(handle, &o);
                (void) pam_set_data(handle, DATA_INHIBIT_FD, NULL, NULL);
        }
        free(area);
        free(runtime);
        free(session_id);
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

        (void) flags;
        parse_args(handle, argc, argv, &o);

        close_osc_context(handle, &o);
        /* Replacing the entry runs its cleanup, which closes the lock. */
        (void) pam_set_data(handle, DATA_INHIBIT_FD, NULL, NULL);
        return release_created(handle, &o);
}
