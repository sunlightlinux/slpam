/* SPDX-License-Identifier: Apache-2.0 */

#ifndef SLPAM_AREA_H
#define SLPAM_AREA_H

#include <stdbool.h>
#include <sys/types.h>

/*
 * Areas, as pam_systemd has them: a login into ~/Areas/<area> instead of
 * the home directory, with a runtime directory of its own, chosen by
 * area= or XDG_AREA. No PAM here; the functions return -errno and the
 * caller does the logging.
 */

/* One path component: not empty, not "." or "..", no '/', no longer than NAME_MAX. */
bool slpam_area_name_ok(const char *area);

/*
 * The area's home, <home>/Areas/<area>, with symlinks resolved. It must be
 * a directory and belong to uid, checked on the opened directory rather
 * than the name. *resolved is malloc'd. -EPERM when it belongs to someone
 * else.
 */
int slpam_area_home(const char *home, const char *area, uid_t uid, char **resolved);

/*
 * <runtime>/Areas/<area>, created if missing and owned by uid:gid. The
 * runtime directory is the user's, so nothing is done by name: each level
 * is opened without following symlinks, and a new directory is made under
 * a temporary name and renamed into place once its ownership is right.
 * *path is malloc'd.
 */
int slpam_area_runtime(const char *runtime, const char *area, uid_t uid, gid_t gid, char **path);

#endif
