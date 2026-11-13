/* SPDX-License-Identifier: Apache-2.0 */

#ifndef SLPAM_OSC_H
#define SLPAM_OSC_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

/*
 * The OSC 3008 "context" sequences pam_systemd writes to a terminal when a
 * tty session starts and ends, so a terminal emulator can tell where one
 * login stops and the next begins. Built here as plain strings, with no
 * terminal involved, so the format can be tested.
 *
 * Every string is optional; a NULL or empty one leaves its field out.
 */
struct slpam_osc_identity {
        const char *user;        /* who the process runs as */
        const char *hostname;
        const char *machine_id;  /* 32 hex digits; dashes are dropped */
        const char *boot_id;     /* likewise */
        long pid;
        bool has_pidfd_id;
        uint64_t pidfd_id;
        const char *comm;
        const char *target_user; /* who is logging in */
        const char *session_id;
};

/* ESC ] 3008;start=<id>;...;type=session ESC \  — malloc'd, NULL on OOM. */
char *slpam_osc_open(const uint8_t id[16], const struct slpam_osc_identity *who);

/* ESC ] 3008;end=<id> ESC \  — malloc'd, NULL on OOM. */
char *slpam_osc_close(const uint8_t id[16]);

/*
 * A value as it goes into a sequence: control characters, DEL and above,
 * ';' and '\' become \xNN, so a hostname or user name cannot end the field
 * or the sequence.
 */
void slpam_osc_escape(FILE *f, const char *value);

#endif
