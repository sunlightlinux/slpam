/* SPDX-License-Identifier: Apache-2.0 */

#include <stdio.h>
#include <string.h>

#include "context.h"

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
        if (failures == 0)
                printf("ok: %zu cases\n", sizeof(cases) / sizeof(cases[0]));
        return failures != 0;
}
