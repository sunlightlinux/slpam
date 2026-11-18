/* SPDX-License-Identifier: Apache-2.0 */

/*
 * A PAM application for the end-to-end tests: the part login, sshd or a
 * display manager plays. It opens a session and closes it, and writes what
 * it saw to a report file — not to stdout, which belongs to the module's
 * terminal sequences when the test gives it a pty.
 *
 *   pamapp USER CONFDIR REPORT [--tty T] [--rhost H] [--ruser U]
 *          [--display D] [--env K=V]... [--cycles N]
 *
 * Arguments are passed through byte for byte, so a test can hand the
 * module a string that is not UTF-8.
 */

#define _GNU_SOURCE

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <security/pam_appl.h>

#ifdef __GLIBC__
#include <malloc.h>
#endif

static FILE *report;

static int conv(int n, const struct pam_message **msg, struct pam_response **resp, void *data)
{
        (void) data;
        for (int i = 0; i < n; i++)
                fprintf(report, "conv %s\n", msg[i]->msg);
        *resp = calloc((size_t) n, sizeof(**resp));
        return *resp != NULL ? PAM_SUCCESS : PAM_BUF_ERR;
}

static int open_fds(void)
{
        DIR *d = opendir("/proc/self/fd");
        int n = 0;

        if (d == NULL)
                return -1;
        while (readdir(d) != NULL)
                n++;
        closedir(d);
        return n;
}

struct args {
        const char *user, *confdir, *tty, *rhost, *ruser, *display;
        const char *env[32];
        int n_env, cycles;
};

static int one_login(const struct args *a, int verbose)
{
        struct pam_conv c = { conv, NULL };
        pam_handle_t *h;
        int r, before, opened;

        r = pam_start_confdir("svc", a->user, &c, a->confdir, &h);
        if (r != PAM_SUCCESS) {
                fprintf(report, "start %d\n", r);
                return r;
        }
        if (a->tty != NULL)
                pam_set_item(h, PAM_TTY, a->tty);
        if (a->rhost != NULL)
                pam_set_item(h, PAM_RHOST, a->rhost);
        if (a->ruser != NULL)
                pam_set_item(h, PAM_RUSER, a->ruser);
        if (a->display != NULL)
                pam_set_item(h, PAM_XDISPLAY, a->display);
        for (int i = 0; i < a->n_env; i++)
                pam_putenv(h, a->env[i]);

        before = open_fds();
        r = pam_open_session(h, 0);
        opened = open_fds();
        if (verbose) {
                char **env = pam_getenvlist(h);

                fprintf(report, "open %d\n", r);
                for (char **p = env; p != NULL && *p != NULL; p++) {
                        fprintf(report, "env %s\n", *p);
                        free(*p);
                }
                free(env);
        }
        /* An application does not close a session it failed to open. */
        if (r == PAM_SUCCESS) {
                int rc = pam_close_session(h, 0);

                if (verbose)
                        fprintf(report, "close %d\n", rc);
                if (rc != PAM_SUCCESS)
                        r = rc;
        }
        if (verbose)
                fprintf(report, "fds %d %d %d\n", before, opened, open_fds());
        pam_end(h, r);
        return r;
}

int main(int argc, char **argv)
{
        struct args a = { .cycles = 0 };
        int r = 0;

        if (argc < 4)
                return 2;
        a.user = argv[1];
        a.confdir = argv[2];
        report = fopen(argv[3], "w");
        if (report == NULL)
                return 2;
        for (int i = 4; i + 1 < argc; i += 2) {
                if (strcmp(argv[i], "--tty") == 0)
                        a.tty = argv[i + 1];
                else if (strcmp(argv[i], "--rhost") == 0)
                        a.rhost = argv[i + 1];
                else if (strcmp(argv[i], "--ruser") == 0)
                        a.ruser = argv[i + 1];
                else if (strcmp(argv[i], "--display") == 0)
                        a.display = argv[i + 1];
                else if (strcmp(argv[i], "--env") == 0 && a.n_env < 32)
                        a.env[a.n_env++] = argv[i + 1];
                else if (strcmp(argv[i], "--cycles") == 0)
                        a.cycles = atoi(argv[i + 1]);
                else
                        return 2;
        }

        if (a.cycles == 0)
                r = one_login(&a, 1);
        for (int i = 0; i <= a.cycles && a.cycles > 0; i++) {
                r = one_login(&a, 0);
                if (r != PAM_SUCCESS) {
                        fprintf(report, "cycle %d failed %d\n", i, r);
                        break;
                }
#ifdef __GLIBC__
                if (i % 100 == 0) {
                        struct mallinfo2 mi = mallinfo2();

                        fprintf(report, "heap %d %zu\n", i, mi.uordblks);
                }
#endif
        }
        fclose(report);
        /* Reaching here at all is part of the result: the module must not end the process. */
        return 0;
}
