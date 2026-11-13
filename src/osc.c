/* SPDX-License-Identifier: Apache-2.0 */

#include <stdlib.h>
#include <string.h>

#include "osc.h"

#define OSC "\033]"
#define ST "\033\\"

void slpam_osc_escape(FILE *f, const char *value)
{
        for (const unsigned char *p = (const unsigned char *) value; *p != '\0'; p++) {
                if (*p < ' ' || *p >= 127 || *p == ';' || *p == '\\')
                        fprintf(f, "\\x%02x", *p);
                else
                        fputc(*p, f);
        }
}

static void put_id(FILE *f, const uint8_t id[16])
{
        for (int i = 0; i < 16; i++)
                fprintf(f, "%02x", id[i]);
}

static void field(FILE *f, const char *key, const char *value)
{
        if (value == NULL || *value == '\0')
                return;
        fprintf(f, ";%s=", key);
        slpam_osc_escape(f, value);
}

/* An id as the kernel prints it has dashes; the sequence carries none. */
static void id_field(FILE *f, const char *key, const char *value)
{
        size_t n = 0;

        if (value == NULL)
                return;
        for (const char *p = value; *p != '\0'; p++) {
                if (*p == '-' || *p == '\n')
                        continue;
                if (!((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f')))
                        return;
                n++;
        }
        if (n != 32)
                return;
        fprintf(f, ";%s=", key);
        for (const char *p = value; *p != '\0'; p++)
                if (*p != '-' && *p != '\n')
                        fputc(*p, f);
}

static char *finish(FILE *f, char **buf)
{
        bool bad = ferror(f) != 0;

        if (fclose(f) != 0 || bad) {
                free(*buf);
                return NULL;
        }
        return *buf;
}

char *slpam_osc_open(const uint8_t id[16], const struct slpam_osc_identity *who)
{
        char *buf = NULL;
        size_t len = 0;
        FILE *f = open_memstream(&buf, &len);

        if (f == NULL)
                return NULL;
        fputs(OSC "3008;start=", f);
        put_id(f, id);
        field(f, "user", who->user);
        field(f, "hostname", who->hostname);
        id_field(f, "machineid", who->machine_id);
        id_field(f, "bootid", who->boot_id);
        fprintf(f, ";pid=%ld", who->pid);
        if (who->has_pidfd_id)
                fprintf(f, ";pidfdid=%llu", (unsigned long long) who->pidfd_id);
        field(f, "comm", who->comm);
        field(f, "targetuser", who->target_user);
        field(f, "sessionid", who->session_id);
        fputs(";type=session" ST, f);
        return finish(f, &buf);
}

char *slpam_osc_close(const uint8_t id[16])
{
        char *buf = NULL;
        size_t len = 0;
        FILE *f = open_memstream(&buf, &len);

        if (f == NULL)
                return NULL;
        fputs(OSC "3008;end=", f);
        put_id(f, id);
        fputs(ST, f);
        return finish(f, &buf);
}
