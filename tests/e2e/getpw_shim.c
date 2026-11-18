/* SPDX-License-Identifier: Apache-2.0 */

/*
 * Test only, loaded with LD_PRELOAD: the user's home directory is wherever
 * FAKE_HOME says. The area tests need a home they can put ~/Areas in, and
 * must not touch the real one of whoever runs them.
 */

#define _GNU_SOURCE

#include <dlfcn.h>
#include <pwd.h>
#include <stdlib.h>

int getpwnam_r(const char *name, struct passwd *pw, char *buf, size_t len, struct passwd **res)
{
        static int (*real)(const char *, struct passwd *, char *, size_t, struct passwd **);
        const char *home = getenv("FAKE_HOME");
        int r;

        if (real == NULL)
                real = dlsym(RTLD_NEXT, "getpwnam_r");
        r = real(name, pw, buf, len, res);
        if (r == 0 && *res != NULL && home != NULL)
                pw->pw_dir = (char *) home;
        return r;
}
