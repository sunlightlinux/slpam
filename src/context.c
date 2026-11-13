/* SPDX-License-Identifier: Apache-2.0 */

#include <stdio.h>
#include <string.h>
#include <strings.h>

#include "context.h"

static bool empty(const char *s)
{
        return s == NULL || *s == '\0';
}

bool slpam_is_localhost(const char *host)
{
        static const char *const names[] = {
                "localhost", "localhost.localdomain", "localhost6",
                "localhost6.localdomain6", "127.0.0.1", "::1",
        };

        if (empty(host))
                return false;
        for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++)
                if (strcasecmp(host, names[i]) == 0)
                        return true;
        return false;
}

uint32_t slpam_parse_vtnr(const char *s)
{
        uint64_t v = 0;

        if (empty(s))
                return 0;
        for (; *s != '\0'; s++) {
                if (*s < '0' || *s > '9')
                        return 0;
                v = v * 10 + (uint64_t) (*s - '0');
                if (v > UINT32_MAX)
                        return 0;
        }
        return (uint32_t) v;
}

uint32_t slpam_vtnr_from_stat(const char *stat)
{
        const char *p;
        unsigned tty_nr, major, minor;

        /* The command name may itself contain ')' and spaces: skip to the last. */
        p = stat != NULL ? strrchr(stat, ')') : NULL;
        if (p == NULL)
                return 0;
        /* state ppid pgrp session tty_nr */
        if (sscanf(p + 1, " %*c %*d %*d %*d %u", &tty_nr) != 1)
                return 0;
        major = (tty_nr >> 8) & 0xfff;
        minor = (tty_nr & 0xff) | ((tty_nr >> 12) & 0xfff00);
        /* Major 4, minors 1-63 are tty1-tty63; minor 0 is "the current VT". */
        return major == 4 && minor >= 1 && minor <= 63 ? minor : 0;
}

void slpam_context_settle(struct slpam_context *c)
{
        if (!empty(c->tty) && strchr(c->tty, ':') != NULL) {
                if (empty(c->display))
                        c->display = c->tty;
                c->tty = NULL;
        } else if (c->tty != NULL && strcmp(c->tty, "cron") == 0) {
                c->type = "unspecified";
                if (empty(c->session_class))
                        c->session_class = "background";
                c->tty = NULL;
        } else if (c->tty != NULL && strcmp(c->tty, "ssh") == 0) {
                c->type = "tty";
                if (empty(c->session_class))
                        c->session_class = "user";
                c->tty = NULL;
        } else if (c->tty != NULL && strncmp(c->tty, "/dev/", 5) == 0) {
                c->tty += 5;
        }

        if (!empty(c->seat) && strcmp(c->seat, "seat0") != 0)
                c->vtnr = 0;

        if (empty(c->type))
                c->type = !empty(c->display) ? "x11" :
                          !empty(c->tty) ? "tty" : "unspecified";
        if (empty(c->session_class))
                c->session_class = strcmp(c->type, "unspecified") == 0 ? "background" : "user";

        c->remote = !empty(c->remote_host) && !slpam_is_localhost(c->remote_host);
}
