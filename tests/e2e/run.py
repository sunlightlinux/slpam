#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""End-to-end tests for pam_slinit.so.

`make test` covers the rules that need neither PAM nor a bus. These cover
the rest: the module loaded by libpam into a real process, talking D-Bus to
something that answers as slinit-logind would.

What runs here:
  - a private dbus-daemon, on an abstract socket nobody else knows;
  - tests/e2e/mock_login1.py owning org.freedesktop.login1 on it;
  - tests/e2e/pamapp, a PAM application, with a PAM configuration
    directory of its own, so /etc/pam.d is never read or written.

Nothing needs root and nothing touches the machine's own bus or logind.

The module is built specially for this run. Its bus address is compiled
in and never read from the environment (README.md, "What the module does
not trust"), so the copy under test is one built with the private bus's
address. It is otherwise the same code, compiled with the same flags.

What this cannot show: that the real slinit-logind answers as the mock
does, and that a real login works. Those need a machine; see TODO.md.
"""

import json
import os
import pty
import re
import select
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
BUILD = os.path.join(HERE, "_build")
USER = __import__("pwd").getpwuid(os.getuid()).pw_name

PAM_SUCCESS = 0
OSC = re.compile(rb"\x1b\]3008;(start|end)=([0-9a-f]{32})([^\x1b]*)\x1b\\")


def run(*cmd, **kw):
    return subprocess.run(cmd, check=True, **kw)


class Bus:
    """The private bus, and the build of the module that talks to it."""

    def __init__(self):
        # Abstract, so there is no path to outgrow sun_path or to leave
        # behind; unique, so two runs on one machine do not meet.
        self.address = "unix:abstract=slpam-e2e-%d-%s" % (os.getpid(), os.urandom(4).hex())
        os.makedirs(BUILD, exist_ok=True)
        self.module = os.path.join(BUILD, "pam_slinit.so")
        make = os.environ.get("MAKE", "make")
        # -B: the address is baked in, and a module left from an earlier
        # run was built for a bus that no longer exists.
        run(make, "-B", "-s", "-C", ROOT, "MODULE=" + self.module,
            "SYSTEM_BUS_ADDRESS=" + self.address, self.module)
        cc = os.environ.get("CC", "cc")
        run(cc, "-O1", "-g", "-Wall", "-Wextra", os.path.join(HERE, "pamapp.c"),
            "-o", os.path.join(BUILD, "pamapp"), "-lpam")
        run(cc, "-shared", "-fPIC", "-O1", "-Wall", "-Wextra", os.path.join(HERE, "getpw_shim.c"),
            "-o", os.path.join(BUILD, "getpw_shim.so"), "-ldl")
        self.daemon = subprocess.Popen(
            ["dbus-daemon", "--session", "--nofork", "--address=" + self.address, "--print-address"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        if not self.daemon.stdout.readline():
            raise RuntimeError("dbus-daemon did not start")

    def stop(self):
        self.daemon.terminate()
        self.daemon.wait()
        self.daemon.stdout.close()


BUS = None


def setUpModule():
    global BUS
    BUS = Bus()


def tearDownModule():
    BUS.stop()


class Login:
    """What one run of pamapp produced."""

    def __init__(self, status, report, calls, terminal, seconds):
        self.status = status          # the process's exit status; negative is a signal
        self.calls = calls            # what the daemon was asked, in order
        self.terminal = terminal      # bytes the terminal received, if there was one
        self.seconds = seconds
        self.opened = self.closed = None
        self.env, self.conv, self.fds, self.heap = {}, [], None, {}
        for line in report.splitlines():
            word, _, rest = line.partition(" ")
            if word == "open":
                self.opened = int(rest)
            elif word == "close":
                self.closed = int(rest)
            elif word == "env":
                key, _, value = rest.partition("=")
                self.env[key] = value
            elif word == "conv":
                self.conv.append(rest)
            elif word == "fds":
                self.fds = [int(n) for n in rest.split()]
            elif word == "heap":
                cycle, used = rest.split()
                self.heap[int(cycle)] = int(used)

    def called(self, name):
        return [c for c in self.calls if c["call"] == name]


class Case(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="slpam-e2e-")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.runtime = os.path.join(self.dir, "run")
        self.home = os.path.join(self.dir, "home")
        os.makedirs(self.runtime)
        os.makedirs(self.home)
        os.makedirs(os.path.join(self.dir, "pam.d"))

    def login(self, mode="ok", options="", tty="tty3", pamenv=(), environ=None, args=(),
              fake_home=False, on_pty=False):
        with open(os.path.join(self.dir, "pam.d", "svc"), "w") as f:
            f.write("session required %s %s\n" % (BUS.module, options))
        log = os.path.join(self.dir, "calls")
        report = os.path.join(self.dir, "report")
        for path in (log, report):
            open(path, "w").close()

        mock = subprocess.Popen(
            [sys.executable, os.path.join(HERE, "mock_login1.py"), BUS.address, log, self.runtime, mode],
            stdout=subprocess.PIPE)
        self.addCleanup(mock.stdout.close)
        self.addCleanup(mock.wait)
        self.addCleanup(mock.terminate)
        self.assertEqual(mock.stdout.readline().strip(), b"ready", "the mock daemon did not start")

        # A clean environment: the module reads XDG_* from the process's
        # own, and whoever runs the tests is usually inside a session.
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "TERM": "xterm"}
        if fake_home:
            env["FAKE_HOME"] = self.home
            env["LD_PRELOAD"] = os.path.join(BUILD, "getpw_shim.so")
        env.update(environ or {})

        cmd = [os.path.join(BUILD, "pamapp"), USER, os.path.join(self.dir, "pam.d"), report]
        if tty is not None:
            cmd += ["--tty", tty]
        for kv in pamenv:
            cmd += ["--env", kv]
        cmd += list(args)

        terminal = b""
        started = time.monotonic()
        if on_pty:
            master, slave = pty.openpty()
            proc = subprocess.Popen(cmd, env=env, stdin=slave, stdout=slave, stderr=subprocess.DEVNULL)
            os.close(slave)
            proc.wait(timeout=120)
            while select.select([master], [], [], 0.2)[0]:
                try:
                    chunk = os.read(master, 4096)
                except OSError:
                    break
                if not chunk:
                    break
                terminal += chunk
            os.close(master)
        else:
            # stderr is libdbus's, when it is about to abort: worth seeing.
            proc = subprocess.run(cmd, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                  stderr=subprocess.PIPE, timeout=120)
            if proc.returncode != 0:
                sys.stderr.write(proc.stderr.decode("utf-8", "replace"))
        seconds = time.monotonic() - started

        mock.terminate()
        mock.wait()
        with open(log) as f:
            calls = [json.loads(line) for line in f]
        with open(report, "rb") as f:
            text = f.read().decode("utf-8", "surrogateescape")
        return Login(proc.returncode, text, calls, terminal, seconds)


class Registration(Case):
    def test_console_login(self):
        r = self.login(mode="seat")
        self.assertEqual((r.status, r.opened, r.closed), (0, PAM_SUCCESS, PAM_SUCCESS))
        create, = r.called("CreateSessionWithPIDFD")
        self.assertEqual((create["uid"], create["type"], create["class"], create["tty"]),
                         (os.getuid(), "tty", "user", "tty3"))
        self.assertEqual(create["flags"], 0)
        self.assertFalse(create["remote"])
        self.assertEqual(r.called("CreateSession"), [], "the pid fallback was used for no reason")
        self.assertEqual(r.env["XDG_SESSION_ID"], "c7")
        self.assertEqual((r.env["XDG_SEAT"], r.env["XDG_VTNR"]), ("seat0", "3"))
        self.assertEqual((r.env["XDG_SESSION_TYPE"], r.env["XDG_SESSION_CLASS"]), ("tty", "user"))
        self.assertEqual(r.env["XDG_RUNTIME_DIR"], self.runtime)
        self.assertEqual([c["id"] for c in r.called("ReleaseSession")], ["c7"])

    def test_the_leader_is_named_by_a_pidfd_of_the_login_process(self):
        # The pid the daemon reads off the pidfd must be the process that
        # opened the session, and the report file is that process's own.
        r = self.login()
        leader = r.called("CreateSessionWithPIDFD")[0]["leader"]
        self.assertGreater(leader, 1)
        self.assertNotEqual(leader, os.getpid())

    def test_falls_back_to_create_session_on_an_older_daemon(self):
        r = self.login(mode="old")
        self.assertEqual((r.status, r.opened), (0, PAM_SUCCESS))
        self.assertEqual([c["call"] for c in r.calls],
                         ["CreateSessionWithPIDFD", "CreateSession", "ReleaseSession"])
        self.assertEqual(r.env["XDG_SESSION_ID"], "c7")

    def test_session_busy_is_success_with_nothing_opened(self):
        r = self.login(mode="busy")
        self.assertEqual((r.status, r.opened, r.closed), (0, PAM_SUCCESS, PAM_SUCCESS))
        self.assertNotIn("XDG_SESSION_ID", r.env)
        self.assertNotIn("XDG_RUNTIME_DIR", r.env)
        self.assertEqual(r.called("ReleaseSession"), [], "released a session it never opened")

    def test_a_refusal_from_the_daemon_fails_the_login(self):
        # The control for every test above: if this one passes too, the
        # harness has stopped being able to tell a login that worked from
        # one that did not.
        r = self.login(mode="denied")
        self.assertEqual(r.status, 0)
        self.assertNotEqual(r.opened, PAM_SUCCESS)
        self.assertNotIn("XDG_SESSION_ID", r.env)
        self.assertEqual(r.called("ReleaseSession"), [])

    def test_class_none_registers_nothing(self):
        r = self.login(options="class=none")
        self.assertEqual((r.status, r.opened, r.closed), (0, PAM_SUCCESS, PAM_SUCCESS))
        self.assertEqual(r.calls, [])
        self.assertNotIn("XDG_SESSION_ID", r.env)

    def test_the_pam_environment_wins_over_the_module_arguments(self):
        r = self.login(options="class=user type=tty desktop=none",
                       pamenv=["XDG_SESSION_CLASS=greeter", "XDG_SESSION_TYPE=wayland",
                               "XDG_SESSION_DESKTOP=gnome"])
        create, = r.called("CreateSessionWithPIDFD")
        self.assertEqual((create["class"], create["type"], create["desktop"]),
                         ("greeter", "wayland", "gnome"))

    def test_ssh_is_remote_and_has_no_tty(self):
        r = self.login(tty="ssh", args=["--rhost", "10.0.0.5", "--ruser", "ana"])
        create, = r.called("CreateSessionWithPIDFD")
        self.assertEqual((create["type"], create["tty"], create["rhost"], create["ruser"]),
                         ("tty", "", "10.0.0.5", "ana"))
        self.assertTrue(create["remote"])

    def test_no_file_descriptor_is_left_open(self):
        r = self.login(options="inhibit=sleep")
        before, opened, closed = r.fds
        self.assertEqual(opened, before + 1, "only the inhibitor lock should stay open during the session")
        self.assertEqual(closed, before)

    def test_three_hundred_logins_do_not_grow_the_heap(self):
        # -z nodelete is what this guards. Without it every pam_end()
        # unloaded libdbus and orphaned its process-wide state: about
        # 4.8 kB a login.
        r = self.login(args=["--cycles", "300"])
        self.assertEqual(r.status, 0)
        if not r.heap:
            self.skipTest("no mallinfo2 on this libc")
        self.assertEqual(sorted(r.heap), [0, 100, 200, 300])
        self.assertLess(r.heap[300] - r.heap[100], 16 * 1024,
                        "heap grew from %d to %d bytes over 200 logins" % (r.heap[100], r.heap[300]))


class RuntimeDirectory(Case):
    def test_not_exported_for_another_users_session(self):
        r = self.login(mode="otheruid")
        self.assertEqual(r.opened, PAM_SUCCESS)
        self.assertEqual(r.env["XDG_SESSION_ID"], "c7")
        self.assertNotIn("XDG_RUNTIME_DIR", r.env)

    def test_not_exported_when_it_is_not_there(self):
        r = self.login(mode="noruntime")
        self.assertEqual(r.opened, PAM_SUCCESS)
        self.assertNotIn("XDG_RUNTIME_DIR", r.env)

    def test_user_bus_address_only_for_a_real_socket(self):
        r = self.login()
        self.assertNotIn("DBUS_SESSION_BUS_ADDRESS", r.env)

        # A symlink the user planted: root must not report what it points at.
        os.symlink("/etc/passwd", os.path.join(self.runtime, "bus"))
        r = self.login()
        self.assertNotIn("DBUS_SESSION_BUS_ADDRESS", r.env)
        os.unlink(os.path.join(self.runtime, "bus"))

        s = socket.socket(socket.AF_UNIX)
        here = os.getcwd()
        os.chdir(self.runtime)   # the path may be longer than sun_path
        try:
            s.bind("bus")
        finally:
            os.chdir(here)
        self.addCleanup(s.close)
        r = self.login()
        self.assertEqual(r.env["DBUS_SESSION_BUS_ADDRESS"], "unix:path=%s/bus" % self.runtime)


class Inhibit(Case):
    def test_lock_taken_with_the_service_as_holder(self):
        r = self.login(options="inhibit=shutdown:sleep inhibit-why=backup")
        call, = r.called("Inhibit")
        self.assertEqual(call, dict(call="Inhibit", what="shutdown:sleep", who="svc", why="backup",
                                    mode="block"))

    def test_from_the_environment_with_the_default_reason(self):
        r = self.login(pamenv=["XDG_SESSION_INHIBIT=sleep"])
        call, = r.called("Inhibit")
        self.assertEqual((call["what"], call["why"]), ("sleep", "Active PAM session"))

    def test_no_lock_unless_asked(self):
        self.assertEqual(self.login().called("Inhibit"), [])


class Areas(Case):
    def test_login_into_an_area(self):
        os.makedirs(os.path.join(self.home, "Areas", "work"))
        r = self.login(options="area=work", fake_home=True)
        self.assertEqual((r.status, r.opened, r.closed), (0, PAM_SUCCESS, PAM_SUCCESS))
        self.assertEqual(r.env["XDG_AREA"], "work")
        self.assertEqual(r.env["HOME"], os.path.realpath(os.path.join(self.home, "Areas", "work")))
        area_runtime = os.path.join(self.runtime, "Areas", "work")
        self.assertEqual(r.env["XDG_RUNTIME_DIR"], area_runtime)
        st = os.stat(area_runtime)
        self.assertEqual((st.st_mode & 0o7777, st.st_uid), (0o755, os.getuid()))
        self.assertEqual([n for n in os.listdir(self.runtime) if n.startswith(".#")], [])

    def test_a_missing_area_falls_back_to_the_home_directory(self):
        r = self.login(options="area=work", fake_home=True)
        self.assertEqual(r.opened, PAM_SUCCESS)
        self.assertNotIn("XDG_AREA", r.env)
        self.assertEqual(r.env["HOME"], self.home)
        self.assertEqual(r.env["XDG_RUNTIME_DIR"], self.runtime)
        self.assertTrue(any("work" in line for line in r.conv), "the user was not told")

    def test_an_area_name_that_is_a_path_is_ignored(self):
        r = self.login(pamenv=["XDG_AREA=../../etc"], fake_home=True)
        self.assertEqual(r.opened, PAM_SUCCESS)
        self.assertEqual(r.env["HOME"], self.home)
        self.assertFalse(os.path.exists(os.path.join(self.runtime, "Areas")))

    def test_a_login_that_fails_after_the_session_exists_leaves_nothing(self):
        os.makedirs(os.path.join(self.home, "Areas", "work"))
        # The runtime directory is the user's: they plant a symlink where
        # the module is about to create a directory.
        os.symlink("/nonexistent", os.path.join(self.runtime, "Areas"))
        r = self.login(mode="seat", options="area=work inhibit=sleep", fake_home=True)
        self.assertEqual(r.status, 0)
        self.assertNotEqual(r.opened, PAM_SUCCESS)
        self.assertEqual([c["call"] for c in r.calls],
                         ["CreateSessionWithPIDFD", "Inhibit", "ReleaseSession"])
        for name in ("XDG_SESSION_ID", "XDG_SEAT", "XDG_VTNR", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"):
            self.assertNotIn(name, r.env)
        before, opened, _ = r.fds
        self.assertEqual(opened, before, "the inhibitor lock outlived the failed login")
        self.assertFalse(os.path.exists("/nonexistent"))


class NotTrusted(Case):
    """README.md, "What the module does not trust"."""

    BAD = b"evil\xffhost"

    def test_a_remote_host_that_is_not_utf8(self):
        r = self.login(tty="ssh", args=["--rhost", self.BAD])
        self.assertEqual(r.status, 0, "the process was ended by signal %d" % -r.status)
        self.assertEqual(r.opened, PAM_SUCCESS)
        create, = r.called("CreateSessionWithPIDFD")
        self.assertEqual(create["rhost"], "")
        self.assertTrue(create["remote"], "a login from elsewhere was registered as local")

    def test_session_variables_that_are_not_utf8(self):
        r = self.login(pamenv=[b"XDG_SESSION_DESKTOP=K\xc0DE", b"XDG_SESSION_TYPE=\xff",
                               b"XDG_SESSION_CLASS=\xfe", b"XDG_SEAT=seat\xff"])
        self.assertEqual(r.status, 0, "the process was ended by signal %d" % -r.status)
        create, = r.called("CreateSessionWithPIDFD")
        self.assertEqual((create["type"], create["class"], create["desktop"], create["seat"]),
                         ("tty", "user", "", ""))

    def test_a_tty_and_a_display_that_are_not_utf8(self):
        r = self.login(tty=b"tty\xff", args=["--display", b":\xff", "--ruser", b"\xff"])
        self.assertEqual(r.status, 0, "the process was ended by signal %d" % -r.status)
        create, = r.called("CreateSessionWithPIDFD")
        self.assertEqual((create["tty"], create["display"], create["ruser"]), ("", "", ""))

    def test_inhibit_strings_that_are_not_utf8(self):
        r = self.login(pamenv=["XDG_SESSION_INHIBIT=sleep", b"XDG_SESSION_INHIBIT_WHY=\xff"])
        self.assertEqual(r.status, 0, "the process was ended by signal %d" % -r.status)
        self.assertEqual(r.called("Inhibit")[0]["why"], "Active PAM session")

        r = self.login(pamenv=[b"XDG_SESSION_INHIBIT=\xff"])
        self.assertEqual(r.status, 0, "the process was ended by signal %d" % -r.status)
        self.assertEqual(r.called("Inhibit"), [])

    def test_a_bus_address_in_the_environment_is_not_used(self):
        proof = os.path.join(self.dir, "proof")
        touch = shutil.which("touch")
        r = self.login(environ={"DBUS_SYSTEM_BUS_ADDRESS": "unixexec:path=%s,argv1=%s" % (touch, proof)})
        self.assertFalse(os.path.exists(proof), "a program named in the environment was run")
        # And the login went to the bus the module was built for.
        self.assertEqual(r.opened, PAM_SUCCESS)
        self.assertEqual(len(r.called("CreateSessionWithPIDFD")), 1)

    def test_an_x_server_that_does_not_answer_holds_the_login_two_seconds(self):
        display = 7391
        name = "\0/tmp/.X11-unix/X%d" % display
        listener = socket.socket(socket.AF_UNIX)
        try:
            listener.bind(name)
        except OSError:
            self.skipTest("display :%d is taken" % display)
        self.addCleanup(listener.close)
        listener.listen(0)
        waiting = []
        for _ in range(2):   # fill the backlog, so the next connect has to wait
            s = socket.socket(socket.AF_UNIX)
            s.setblocking(False)
            try:
                s.connect(name)
            except OSError:
                pass
            waiting.append(s)
            self.addCleanup(s.close)

        r = self.login(tty=":%d" % display)
        self.assertEqual(r.opened, PAM_SUCCESS)
        self.assertGreater(r.seconds, 1.5, "the connect did not wait at all: the test set nothing up")
        self.assertLess(r.seconds, 10, "the login waited %.1f s for an X server" % r.seconds)
        create, = r.called("CreateSessionWithPIDFD")
        self.assertEqual((create["type"], create["display"], create["vtnr"], create["seat"]),
                         ("x11", ":%d" % display, 0, ""))

    def test_an_x_peer_with_no_vt_gives_no_seat(self):
        # The peer is this very process: the right uid, and a controlling
        # tty, if it has one, that is not a virtual console the tests own.
        display = 7392
        listener = socket.socket(socket.AF_UNIX)
        try:
            listener.bind("\0/tmp/.X11-unix/X%d" % display)
        except OSError:
            self.skipTest("display :%d is taken" % display)
        self.addCleanup(listener.close)
        listener.listen(4)
        with open("/proc/self/stat") as f:
            tty_nr = int(f.read().rsplit(")", 1)[1].split()[4])
        if (tty_nr >> 8) & 0xfff == 4 and 1 <= (tty_nr & 0xff) <= 63:
            self.skipTest("the tests are running on a virtual console")
        r = self.login(tty=":%d" % display)
        create, = r.called("CreateSessionWithPIDFD")
        self.assertEqual((create["vtnr"], create["seat"]), (0, ""))


class Terminal(Case):
    def test_session_markers_on_a_tty(self):
        r = self.login(on_pty=True)
        self.assertEqual((r.status, r.opened, r.closed), (0, PAM_SUCCESS, PAM_SUCCESS))
        marks = OSC.findall(r.terminal)
        self.assertEqual([m[0] for m in marks], [b"start", b"end"], r.terminal)
        self.assertEqual(marks[0][1], marks[1][1], "the end names a different context than the start")
        fields = dict(f.split(b"=", 1) for f in marks[0][2].split(b";") if b"=" in f)
        self.assertEqual(fields[b"sessionid"], b"c7")
        self.assertEqual(fields[b"targetuser"], USER.encode())
        self.assertEqual(fields[b"type"], b"session")
        self.assertEqual(fields[b"comm"], b"pamapp")

    def test_no_markers_for_a_dumb_terminal(self):
        r = self.login(on_pty=True, environ={"TERM": "dumb"})
        self.assertEqual(r.opened, PAM_SUCCESS)
        self.assertEqual(OSC.findall(r.terminal), [])

    def test_no_markers_for_a_session_that_is_not_a_tty(self):
        r = self.login(on_pty=True, pamenv=["XDG_SESSION_TYPE=wayland"])
        self.assertEqual(OSC.findall(r.terminal), [])

    def test_nothing_written_when_stdout_is_not_a_terminal(self):
        # sshd's case. The login must simply work.
        r = self.login()
        self.assertEqual((r.opened, r.closed), (PAM_SUCCESS, PAM_SUCCESS))


class Credentials(Case):
    def test_shell_credentials_become_variables(self):
        creds = os.path.join(self.dir, "creds")
        os.makedirs(creds)
        with open(os.path.join(creds, "shell.prompt.prefix"), "w") as f:
            f.write("[box] ")
        with open(os.path.join(creds, "shell.welcome"), "wb") as f:
            f.write(b"hello\0there")      # cannot be a variable: left out
        os.symlink("/etc/passwd", os.path.join(creds, "shell.prompt.suffix"))
        r = self.login(environ={"CREDENTIALS_DIRECTORY": creds})
        self.assertEqual(r.opened, PAM_SUCCESS)
        self.assertEqual(r.env["SHELL_PROMPT_PREFIX"], "[box] ")
        self.assertNotIn("SHELL_WELCOME", r.env)
        self.assertNotIn("SHELL_PROMPT_SUFFIX", r.env, "a symlink in the credentials directory was followed")

    def test_no_credentials_directory(self):
        r = self.login()
        self.assertNotIn("SHELL_PROMPT_PREFIX", r.env)


if __name__ == "__main__":
    unittest.main(verbosity=2)
