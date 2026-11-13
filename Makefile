# slpam — pam_slinit.so
#
# Deliberately plain. A PAM module is one shared object with two exported
# symbols; a generator would be more machinery than the thing it builds.

CC      ?= cc
PKGCONF ?= pkg-config

CFLAGS  ?= -O2 -g -Wall -Wextra -Wformat=2 -Wshadow -Wstrict-prototypes
# override: a packager passes CFLAGS and LDFLAGS on make's command line
# (xbps-src does), and a command-line variable silently discards a plain
# `+=`. These are not preferences to be replaced: without -fPIC and
# -shared there is no module, and without the version script and
# -fvisibility=hidden it exports whatever it likes.
override CFLAGS  += -fPIC -fvisibility=hidden
override CFLAGS  += $(shell $(PKGCONF) --cflags dbus-1)

# -z defs so an undefined symbol fails the link here rather than at
# dlopen time, inside sshd, on somebody's only route into the machine.
override LDFLAGS += -shared -Wl,-z,defs,-z,relro,-z,now
override LDFLAGS += -Wl,--version-script=src/pam_slinit.sym
# nodelete: libdbus keeps process-wide state (its message cache, its locks,
# the bus addresses) that only dbus_shutdown() frees, and that call is not
# ours to make inside somebody else's process. If pam_end() unloaded this
# module, libdbus would go with it and all of that would be lost each time,
# a few kilobytes per login in a daemon that does not fork for each one.
override LDFLAGS += -Wl,-z,nodelete
override LDLIBS  += $(shell $(PKGCONF) --libs dbus-1) -lpam

DESTDIR    ?=
PREFIX     ?= /usr
SECURITYDIR ?= $(PREFIX)/lib/security

MODULE = src/pam_slinit.so
SRCS   = src/pam_slinit.c src/context.c src/osc.c src/area.c
HDRS   = src/context.h src/osc.h src/area.h

all: $(MODULE)

# The Makefile too: a changed link flag must not leave the old object in place.
$(MODULE): $(SRCS) $(HDRS) src/pam_slinit.sym Makefile
	$(CC) $(CFLAGS) $(SRCS) -o $@ $(LDFLAGS) $(LDLIBS)

# The rules that decide what a session is registered as, without PAM or a
# bus: they are the part most easily got subtly wrong.
TEST = tests/test_context

TEST_SRCS = tests/test_context.c src/context.c src/osc.c src/area.c

$(TEST): $(TEST_SRCS) $(HDRS)
	$(CC) -O0 -g -Wall -Wextra -Isrc $(TEST_SRCS) -o $@

test: $(TEST)
	./$(TEST)

# The symbol set is part of the contract, so it is checked, not assumed.
check: $(MODULE)
	@got=$$(nm -D --defined-only $(MODULE) | awk '$$2=="T"{print $$3}' | sort | tr '\n' ' '); \
	want="pam_sm_close_session pam_sm_open_session "; \
	if [ "$$got" != "$$want" ]; then \
		echo "exported symbols are '$$got', want '$$want'" >&2; exit 1; \
	fi; \
	echo "exports exactly: $$got"

install: $(MODULE)
	install -Dm755 $(MODULE) $(DESTDIR)$(SECURITYDIR)/pam_slinit.so

clean:
	rm -f $(MODULE) $(TEST)

.PHONY: all check test install clean
