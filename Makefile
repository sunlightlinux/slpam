# slpam — pam_slinit.so
#
# Deliberately plain. A PAM module is one shared object with two exported
# symbols; a generator would be more machinery than the thing it builds.

CC      ?= cc
PKGCONF ?= pkg-config

CFLAGS  ?= -O2 -g -Wall -Wextra -Wformat=2 -Wshadow -Wstrict-prototypes
CFLAGS  += -fPIC -fvisibility=hidden
CFLAGS  += $(shell $(PKGCONF) --cflags dbus-1)

# -z defs so an undefined symbol fails the link here rather than at
# dlopen time, inside sshd, on somebody's only route into the machine.
LDFLAGS += -shared -Wl,-z,defs,-z,relro,-z,now
LDFLAGS += -Wl,--version-script=src/pam_slinit.sym
LDLIBS  += $(shell $(PKGCONF) --libs dbus-1) -lpam

DESTDIR    ?=
PREFIX     ?= /usr
SECURITYDIR ?= $(PREFIX)/lib/security

MODULE = src/pam_slinit.so

all: $(MODULE)

$(MODULE): src/pam_slinit.c src/pam_slinit.sym
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS) $(LDLIBS)

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
	rm -f $(MODULE)

.PHONY: all check install clean
