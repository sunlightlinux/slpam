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

# The system bus address is compiled in, from what dbus was built with,
# and never taken from the environment at run time: an address can name a
# program to run (src/pam_slinit.c, bus_open). Override it only to point a
# test build at a private bus.
SYSTEM_BUS_ADDRESS ?= $(shell $(PKGCONF) --variable=system_bus_default_address dbus-1)
ifeq ($(strip $(SYSTEM_BUS_ADDRESS)),)
SYSTEM_BUS_ADDRESS = unix:path=/run/dbus/system_bus_socket
endif
override CFLAGS  += -DSLPAM_SYSTEM_BUS_ADDRESS='"$(SYSTEM_BUS_ADDRESS)"'

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

# The same tests with the sanitizers watching: the area code makes and
# renames directories as root in a directory the user owns, and the OSC
# builder formats strings the user chose. Neither is where a stray byte
# should go unnoticed.
TEST_SAN = tests/test_context_san

$(TEST_SAN): $(TEST_SRCS) $(HDRS)
	$(CC) -O1 -g -Wall -Wextra -fsanitize=address,undefined -fno-sanitize-recover=all \
		-fno-omit-frame-pointer -Isrc $(TEST_SRCS) -o $@

test-san: $(TEST_SAN)
	./$(TEST_SAN)

# The module inside a real PAM application, against a mock slinit-logind on
# a private bus. Needs dbus-daemon and python3 with dbus and gi; see
# tests/e2e/run.py for what it does and does not show.
PYTHON ?= python3

e2e:
	MAKE='$(MAKE)' CC='$(CC)' $(PYTHON) tests/e2e/run.py

# What the built object must be, checked rather than assumed. Each line is
# here because getting it wrong is silent:
#  - the exported symbols: with -fvisibility=hidden and no attribute the
#    module loads and PAM finds no entry point;
#  - NODELETE and BIND_NOW: a packager's LDFLAGS once replaced the
#    module's own, and nothing complained;
#  - the three libraries: the module exists so that libsystemd and
#    libelogind are not among them. musl's libc is libc.musl-<arch>.so.1.
check: $(MODULE)
	@got=$$(nm -D --defined-only $(MODULE) | awk '$$2=="T"{print $$3}' | sort | tr '\n' ' '); \
	want="pam_sm_close_session pam_sm_open_session "; \
	if [ "$$got" != "$$want" ]; then \
		echo "exported symbols are '$$got', want '$$want'" >&2; exit 1; \
	fi; \
	echo "exports exactly: $$got"
	@flags=$$(readelf -d $(MODULE) | awk '/FLAGS/{$$1=$$2=""; print}' | tr '\n' ' '); \
	for f in NODELETE NOW; do \
		case " $$flags " in *" $$f "*) ;; \
		*) echo "$(MODULE) is not linked $$f (flags:$$flags)" >&2; exit 1 ;; esac; \
	done; \
	echo "linked: NODELETE NOW"
	@got=$$(readelf -d $(MODULE) | sed -n 's/.*(NEEDED).*\[\(.*\)\]/\1/p' \
		| sed -e 's/\.so.*//' -e 's/^libc\.musl-.*/libc/' | sort | tr '\n' ' '); \
	want="libc libdbus-1 libpam "; \
	if [ "$$got" != "$$want" ]; then \
		echo "needs '$$got', want '$$want'" >&2; exit 1; \
	fi; \
	echo "needs exactly: $$got"

install: $(MODULE)
	install -Dm755 $(MODULE) $(DESTDIR)$(SECURITYDIR)/pam_slinit.so

clean:
	rm -f $(MODULE) $(TEST) $(TEST_SAN)
	rm -rf tests/e2e/_build

.PHONY: all check test test-san e2e install clean
