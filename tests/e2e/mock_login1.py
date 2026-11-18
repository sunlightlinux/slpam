#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""A stand-in for slinit-logind, for the end-to-end tests.

Owns org.freedesktop.login1 on a private bus and answers the three calls
pam_slinit.so makes, recording each as a line of JSON. It checks nothing
and holds no state: what it is for is letting a test say "the daemon
answered this" and then look at what the module did about it.

    mock_login1.py BUS_ADDRESS LOG RUNTIME_DIR MODE

MODE is how CreateSession answers:
    ok          a new session, c7
    seat        the same, on seat0 and VT 3
    old         CreateSessionWithPIDFD is an unknown method; CreateSession works
    busy        org.freedesktop.login1.SessionBusy
    denied      org.freedesktop.DBus.Error.AccessDenied
    otheruid    a session that belongs to another user
    noruntime   a runtime directory that does not exist
"""

import json
import os
import sys

import dbus
import dbus.bus
import dbus.mainloop.glib
import dbus.service
from gi.repository import GLib

ADDRESS, LOG, RUNTIME, MODE = sys.argv[1:5]
IFACE = "org.freedesktop.login1.Manager"

log = open(LOG, "a", buffering=1)


def record(call, **fields):
    log.write(json.dumps(dict(call=call, **fields)) + "\n")


def placeholder_fd():
    r, w = os.pipe()
    os.close(w)
    return dbus.types.UnixFd(r)


def pid_of(pidfd):
    fd = pidfd.take()
    try:
        with open("/proc/self/fdinfo/%d" % fd) as f:
            for line in f:
                if line.startswith("Pid:"):
                    return int(line.split()[1])
    finally:
        os.close(fd)
    return -1


class Error(dbus.DBusException):
    def __init__(self, name, message):
        super().__init__(message)
        self._dbus_error_name = name


class Manager(dbus.service.Object):
    def reply(self, uid, tty):
        on_seat = MODE == "seat" and tty.startswith("tty")
        return ("c7", dbus.ObjectPath("/org/freedesktop/login1/session/c7"),
                "/nonexistent/slpam" if MODE == "noruntime" else RUNTIME,
                placeholder_fd(),
                dbus.UInt32(uid + 1 if MODE == "otheruid" else uid),
                "seat0" if on_seat else "", dbus.UInt32(3 if on_seat else 0), False)

    def refuse(self):
        if MODE == "busy":
            raise Error("org.freedesktop.login1.SessionBusy", "Already running in a session")
        if MODE == "denied":
            raise Error("org.freedesktop.DBus.Error.AccessDenied", "no")

    @dbus.service.method(IFACE, in_signature="uhsssssussbssta(sv)", out_signature="soshusub")
    def CreateSessionWithPIDFD(self, uid, pidfd, service, typ, cls, desktop, seat, vtnr, tty,
                               display, remote, ruser, rhost, flags, props):
        record("CreateSessionWithPIDFD", uid=int(uid), leader=pid_of(pidfd), service=str(service),
               type=str(typ), **{"class": str(cls)}, desktop=str(desktop), seat=str(seat),
               vtnr=int(vtnr), tty=str(tty), display=str(display), remote=bool(remote),
               ruser=str(ruser), rhost=str(rhost), flags=int(flags))
        if MODE == "old":
            raise Error("org.freedesktop.DBus.Error.UnknownMethod", "no such method")
        self.refuse()
        return self.reply(int(uid), str(tty))

    @dbus.service.method(IFACE, in_signature="uusssssussbssa(sv)", out_signature="soshusub")
    def CreateSession(self, uid, pid, service, typ, cls, desktop, seat, vtnr, tty, display,
                      remote, ruser, rhost, props):
        record("CreateSession", uid=int(uid), leader=int(pid), type=str(typ), tty=str(tty))
        self.refuse()
        return self.reply(int(uid), str(tty))

    @dbus.service.method(IFACE, in_signature="s", out_signature="")
    def ReleaseSession(self, session_id):
        record("ReleaseSession", id=str(session_id))

    @dbus.service.method(IFACE, in_signature="ssss", out_signature="h")
    def Inhibit(self, what, who, why, mode):
        record("Inhibit", what=str(what), who=str(who), why=str(why), mode=str(mode))
        return placeholder_fd()


dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
bus = dbus.bus.BusConnection(ADDRESS)
name = dbus.service.BusName("org.freedesktop.login1", bus)
manager = Manager(bus, "/org/freedesktop/login1")
print("ready", flush=True)
GLib.MainLoop().run()
