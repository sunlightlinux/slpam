/* SPDX-License-Identifier: Apache-2.0 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/random.h>
#include <sys/stat.h>

#include "area.h"

bool slpam_area_name_ok(const char *area)
{
        if (area == NULL || *area == '\0')
                return false;
        if (strcmp(area, ".") == 0 || strcmp(area, "..") == 0)
                return false;
        if (strchr(area, '/') != NULL)
                return false;
        return strlen(area) <= NAME_MAX;
}

int slpam_area_home(const char *home, const char *area, uid_t uid, char **resolved)
{
        char *path, link[64], real[PATH_MAX];
        struct stat st;
        ssize_t n;
        int fd, r = 0;

        if (asprintf(&path, "%s/Areas/%s", home, area) < 0)
                return -ENOMEM;
        fd = open(path, O_PATH | O_DIRECTORY | O_CLOEXEC);
        free(path);
        if (fd < 0)
                return -errno;
        if (fstat(fd, &st) < 0)
                r = -errno;
        else if (st.st_uid != uid)
                r = -EPERM;
        else {
                /* Where the open landed, not where the name pointed a moment ago. */
                snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
                n = readlink(link, real, sizeof(real) - 1);
                if (n < 0)
                        r = -errno;
                else if (n == 0 || real[0] != '/')
                        r = -ENOENT;
                else {
                        real[n] = '\0';
                        *resolved = strdup(real);
                        if (*resolved == NULL)
                                r = -ENOMEM;
                }
        }
        close(fd);
        return r;
}

/* Opens parent/name, creating it owned by uid:gid with the given mode. */
static int mkdir_chown_open(int parent, const char *name, uid_t uid, gid_t gid, mode_t mode)
{
        char tmp[NAME_MAX + 1];
        int r;

        for (unsigned attempt = 0;; attempt++) {
                unsigned long long rnd = 0;
                int fd = openat(parent, name, O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);

                if (fd >= 0)
                        return fd;
                if (errno != ENOENT)
                        return -errno;

                /*
                 * Under a temporary name first, so that the directory never
                 * exists under the real one with the wrong owner.
                 */
                if (getrandom(&rnd, sizeof(rnd), 0) != (ssize_t) sizeof(rnd))
                        return -errno;
                if (snprintf(tmp, sizeof(tmp), ".#%.200s%016llx", name, rnd) >= (int) sizeof(tmp))
                        return -ENAMETOOLONG;
                if (mkdirat(parent, tmp, 0700) < 0)
                        return -errno;
                fd = openat(parent, tmp, O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
                if (fd < 0) {
                        r = -errno;
                        goto fail;
                }
                if (fchown(fd, uid, gid) < 0 || fchmod(fd, mode) < 0) {
                        r = -errno;
                        close(fd);
                        goto fail;
                }
                if (renameat2(parent, tmp, parent, name, RENAME_NOREPLACE) == 0)
                        return fd;
                r = -errno;
                close(fd);
                /* Another login may have made it at the same moment: look again. */
                if (r != -EEXIST || attempt >= 5)
                        goto fail;
                (void) unlinkat(parent, tmp, AT_REMOVEDIR);
        }
fail:
        (void) unlinkat(parent, tmp, AT_REMOVEDIR);
        return r;
}

int slpam_area_runtime(const char *runtime, const char *area, uid_t uid, gid_t gid, char **path)
{
        int fd, areas, one, r = 0;

        fd = open(runtime, O_PATH | O_DIRECTORY | O_CLOEXEC);
        if (fd < 0)
                return -errno;
        areas = mkdir_chown_open(fd, "Areas", uid, gid, 0755);
        close(fd);
        if (areas < 0)
                return areas;
        one = mkdir_chown_open(areas, area, uid, gid, 0755);
        close(areas);
        if (one < 0)
                return one;
        close(one);
        if (asprintf(path, "%s/Areas/%s", runtime, area) < 0)
                r = -ENOMEM;
        return r;
}
