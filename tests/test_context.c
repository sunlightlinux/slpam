/* SPDX-License-Identifier: Apache-2.0 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "area.h"
#include "context.h"
#include "osc.h"

static int failures;

static const char *show(const char *s)
{
        return s != NULL ? s : "(null)";
}

static void expect_str(const char *name, const char *field, const char *got, const char *want)
{
        if ((got == NULL) != (want == NULL) || (got != NULL && strcmp(got, want) != 0)) {
                printf("FAIL %s: %s = %s, want %s\n", name, field, show(got), show(want));
                failures++;
        }
}

struct tcase {
        const char *name;
        struct slpam_context in;
        const char *type, *session_class, *tty, *display;
        unsigned vtnr;
        int remote;
};

static void expect_seq(const char *name, char *got, const char *want)
{
        if (got == NULL || strcmp(got, want) != 0) {
                printf("FAIL %s:\n  got  ", name);
                for (const char *p = got != NULL ? got : "(null)"; *p != '\0'; p++)
                        printf(*p == '\033' ? "<ESC>" : "%c", *p);
                printf("\n");
                failures++;
        }
        free(got);
}

static void expect_int(const char *name, long got, long want)
{
        if (got != want) {
                printf("FAIL %s: %ld, want %ld\n", name, got, want);
                failures++;
        }
}

static void test_osc(void)
{
        static const uint8_t id[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0xff };
        struct slpam_osc_identity who = {
                .user = "root", .hostname = "sun;light", .pid = 42,
                .machine_id = "0123456789abcdef0123456789abcdef\n",
                .boot_id = "01234567-89ab-cdef-0123-456789abcdef",
                .has_pidfd_id = true, .pidfd_id = 7, .comm = "login",
                .target_user = "io\\nut", .session_id = "c3",
        };
        struct slpam_osc_identity bare = { .pid = 1, .machine_id = "not-an-id", .boot_id = "" };

        expect_seq("osc open", slpam_osc_open(id, &who),
                   "\033]3008;start=000102030405060708090a0b0c0d0eff;user=root;hostname=sun\\x3blight"
                   ";machineid=0123456789abcdef0123456789abcdef"
                   ";bootid=0123456789abcdef0123456789abcdef;pid=42;pidfdid=7;comm=login"
                   ";targetuser=io\\x5cnut;sessionid=c3;type=session\033\\");
        expect_seq("osc open, nothing known", slpam_osc_open(id, &bare),
                   "\033]3008;start=000102030405060708090a0b0c0d0eff;pid=1;type=session\033\\");
        expect_seq("osc close", slpam_osc_close(id),
                   "\033]3008;end=000102030405060708090a0b0c0d0eff\033\\");

        /* An escape in a name must not reach the terminal as one. */
        who = (struct slpam_osc_identity) { .pid = 1, .hostname = "a\033\\b\a\x7f" };
        expect_seq("osc control characters", slpam_osc_open(id, &who),
                   "\033]3008;start=000102030405060708090a0b0c0d0eff;hostname=a\\x1b\\x5cb\\x07\\x7f"
                   ";pid=1;type=session\033\\");
}

static void test_area(void)
{
        static const struct { const char *in; bool want; } names[] = {
                { "work", true }, { "a b", true }, { ".hidden", true }, { "", false },
                { NULL, false }, { ".", false }, { "..", false }, { "a/b", false }, { "/", false },
        };
        char tmpl[] = "/tmp/slpam-test-XXXXXX", path[512], *got = NULL;
        struct stat st;
        char longname[300];

        memset(longname, 'a', sizeof(longname) - 1);
        longname[sizeof(longname) - 1] = '\0';
        expect_int("area name longer than NAME_MAX", slpam_area_name_ok(longname), false);
        for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++)
                expect_int(names[i].in != NULL ? names[i].in : "area name (null)",
                           slpam_area_name_ok(names[i].in), names[i].want);

        if (mkdtemp(tmpl) == NULL) {
                printf("FAIL mkdtemp\n");
                failures++;
                return;
        }
        /* home/Areas/work is real, home/Areas/link points at it, home/Areas/file is a file. */
        snprintf(path, sizeof(path), "mkdir -p %s/home/Areas/work %s/run && ln -s work %s/home/Areas/link"
                 " && touch %s/home/Areas/file && ln -s /nonexistent %s/run/Areas", tmpl, tmpl, tmpl, tmpl, tmpl);
        expect_int("fixture", system(path), 0);

        snprintf(path, sizeof(path), "%s/home", tmpl);
        expect_int("area home", slpam_area_home(path, "work", getuid(), &got), 0);
        if (got != NULL && strstr(got, "/home/Areas/work") == NULL) {
                printf("FAIL area home resolved to %s\n", got);
                failures++;
        }
        free(got);
        got = NULL;
        expect_int("area home through a symlink", slpam_area_home(path, "link", getuid(), &got), 0);
        if (got != NULL && strstr(got, "/home/Areas/work") == NULL) {
                printf("FAIL area symlink resolved to %s\n", got);
                failures++;
        }
        free(got);
        got = NULL;
        expect_int("area home owned by someone else", slpam_area_home(path, "work", getuid() + 1, &got), -1 /* EPERM */);
        expect_int("area home missing", slpam_area_home(path, "nope", getuid(), &got) < 0, 1);
        expect_int("area home that is a file", slpam_area_home(path, "file", getuid(), &got) < 0, 1);

        /* run/Areas is a symlink planted by the user: it must not be followed. */
        snprintf(path, sizeof(path), "%s/run", tmpl);
        expect_int("runtime Areas is a symlink", slpam_area_runtime(path, "work", getuid(), getgid(), &got) < 0, 1);
        snprintf(path, sizeof(path), "%s/run/Areas", tmpl);
        expect_int("unlink", unlink(path), 0);
        snprintf(path, sizeof(path), "%s/run", tmpl);
        expect_int("area runtime", slpam_area_runtime(path, "work", getuid(), getgid(), &got), 0);
        if (got == NULL || stat(got, &st) < 0 || !S_ISDIR(st.st_mode) || (st.st_mode & 07777) != 0755 ||
            st.st_uid != getuid()) {
                printf("FAIL area runtime directory %s is not a 0755 directory of ours\n", got != NULL ? got : "(null)");
                failures++;
        }
        free(got);
        got = NULL;
        expect_int("area runtime, already there", slpam_area_runtime(path, "work", getuid(), getgid(), &got), 0);
        free(got);
        /* Nothing temporary left behind. */
        snprintf(path, sizeof(path), "test -z \"$(find %s/run -name '.#*')\" && rm -rf %s", tmpl, tmpl);
        expect_int("no temporary directories left", system(path), 0);
}

int main(void)
{
        static const struct tcase cases[] = {
                { "console login on tty1", { .tty = "tty1" },
                  "tty", "user", "tty1", NULL, 0, 0 },
                { "/dev/ prefix dropped", { .tty = "/dev/tty2" },
                  "tty", "user", "tty2", NULL, 0, 0 },
                { "X display in PAM_TTY", { .tty = ":0" },
                  "x11", "user", NULL, ":0", 0, 0 },
                { "X display item wins", { .tty = ":1", .display = ":0" },
                  "x11", "user", NULL, ":0", 0, 0 },
                { "cron", { .tty = "cron" },
                  "unspecified", "background", NULL, NULL, 0, 0 },
                { "cron keeps a given class", { .tty = "cron", .session_class = "user" },
                  "unspecified", "user", NULL, NULL, 0, 0 },
                { "sshd before its pty", { .tty = "ssh", .remote_host = "10.0.0.5" },
                  "tty", "user", NULL, NULL, 0, 1 },
                { "nothing at all", { 0 },
                  "unspecified", "background", NULL, NULL, 0, 0 },
                { "greeter by environment", { .tty = "tty7", .session_class = "greeter" },
                  "tty", "greeter", "tty7", NULL, 0, 0 },
                { "wayland type kept", { .tty = "tty2", .type = "wayland" },
                  "wayland", "user", "tty2", NULL, 0, 0 },
                { "vtnr dropped off seat0", { .seat = "seat1", .vtnr = 3 },
                  "unspecified", "background", NULL, NULL, 0, 0 },
                { "vtnr kept on seat0", { .seat = "seat0", .vtnr = 3, .tty = "tty3" },
                  "tty", "user", "tty3", NULL, 3, 0 },
                { "localhost is not remote", { .tty = "pts/0", .remote_host = "LOCALHOST" },
                  "tty", "user", "pts/0", NULL, 0, 0 },
                { "::1 is not remote", { .remote_host = "::1" },
                  "unspecified", "background", NULL, NULL, 0, 0 },
        };

        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
                const struct tcase *t = &cases[i];
                struct slpam_context c = t->in;

                slpam_context_settle(&c);
                expect_str(t->name, "type", c.type, t->type);
                expect_str(t->name, "class", c.session_class, t->session_class);
                expect_str(t->name, "tty", c.tty, t->tty);
                expect_str(t->name, "display", c.display, t->display);
                if (c.vtnr != t->vtnr) {
                        printf("FAIL %s: vtnr = %u, want %u\n", t->name, (unsigned) c.vtnr, t->vtnr);
                        failures++;
                }
                if ((int) c.remote != t->remote) {
                        printf("FAIL %s: remote = %d, want %d\n", t->name, c.remote, t->remote);
                        failures++;
                }
        }

        static const struct { const char *in; uint32_t want; } vtnrs[] = {
                { "1", 1 }, { "63", 63 }, { "", 0 }, { NULL, 0 }, { "3abc", 0 },
                { "-1", 0 }, { " 2", 0 }, { "4294967295", 4294967295u }, { "4294967296", 0 },
        };
        for (size_t i = 0; i < sizeof(vtnrs) / sizeof(vtnrs[0]); i++)
                if (slpam_parse_vtnr(vtnrs[i].in) != vtnrs[i].want) {
                        printf("FAIL parse_vtnr(%s) = %u, want %u\n", show(vtnrs[i].in),
                               (unsigned) slpam_parse_vtnr(vtnrs[i].in), (unsigned) vtnrs[i].want);
                        failures++;
                }

        static const struct { const char *name, *in; uint32_t want; } stats[] = {
                { "Xorg on tty7", "812 (Xorg) S 790 812 812 1031 812 4194560 1 0", 7 },
                { "comm with ') '", "9 (a) b) c) S 1 9 9 1026 9 0", 2 },
                { "no controlling tty", "5 (Xorg) S 1 5 5 0 -1 0", 0 },
                { "a pty is not a VT", "5 (Xvnc) S 1 5 5 34816 5 0", 0 },
                { "tty0 is not a VT number", "5 (X) S 1 5 5 1024 5 0", 0 },
                { "ttyS0 is not a VT", "5 (X) S 1 5 5 1088 5 0", 0 },
                { "truncated", "5 (X) S 1", 0 },
                { "empty", "", 0 },
                { "null", NULL, 0 },
        };
        for (size_t i = 0; i < sizeof(stats) / sizeof(stats[0]); i++)
                if (slpam_vtnr_from_stat(stats[i].in) != stats[i].want) {
                        printf("FAIL vtnr_from_stat %s = %u, want %u\n", stats[i].name,
                               (unsigned) slpam_vtnr_from_stat(stats[i].in), (unsigned) stats[i].want);
                        failures++;
                }

        test_osc();
        test_area();

        if (failures == 0)
                printf("ok: %zu table cases, osc and area\n", sizeof(cases) / sizeof(cases[0]) +
                       sizeof(vtnrs) / sizeof(vtnrs[0]) + sizeof(stats) / sizeof(stats[0]));
        return failures != 0;
}
