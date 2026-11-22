#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Offline tests for cilctl against tests/stub-cil.py. Run on Linux,
macOS or Windows: python3 tests/test_cilctl.py (py -3 on Windows).

Every cilctl run is checked for the stub's SENTINEL key on stdout and
stderr. ssh and scp are replaced by tests/fake-ssh.py (CILCTL_SSH,
CILCTL_SCP), which records its argv and stdin; the jump tunnel test uses
it as a real TCP forwarder."""
import importlib.machinery
import importlib.util
import hashlib
import json
import os
import shutil
import socket
import ssl
import stat
import subprocess
import signal
import sys
import tarfile
import tempfile
import time
import unittest

sys.dont_write_bytecode = True
T = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(T)
CILCTL = os.path.join(ROOT, "cilctl")
SHIM = os.path.join(ROOT, "cilctl.cmd")
EXAMPLE = os.path.join(ROOT, "docs", "config.example.toml")
WINDOWS = os.name == "nt"
BASH = None if WINDOWS else shutil.which("bash")
try:
    import tomllib
except ImportError:
    tomllib = None

SHA0 = "0" * 64
RECIPE = """
[setup.tiny]
model_url = "http://models.example.com/m/tiny-q4.gguf"
model_sha256 = "%s"
alias = "tiny"
title = "Tiny Q4 (test)"
context = 4096
reasoning = true
server_args = "-ngl 99 -t 4 -dev A,B"
env_script = "/etc/profile.d/llama.sh"
free_mb = 100
npus = 2
cpu = 6
ram = 8192
disk = 40
ttl = 90
precheck = '''
[ -r /x ] || { echo "it's not there"; exit 1; }
'''
""" % SHA0


def gnu_sed():
    try:
        return b"GNU" in subprocess.run(["sed", "--version"], stdout=subprocess.PIPE,
                                        stderr=subprocess.DEVNULL).stdout
    except OSError:
        return False


def gnu_stat():
    try:
        return subprocess.run(["stat", "-c", "%s", os.sep], stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL).returncode == 0
    except OSError:
        return False


def load():
    ld = importlib.machinery.SourceFileLoader("cilctl_mod", CILCTL)
    spec = importlib.util.spec_from_loader("cilctl_mod", ld)
    m = importlib.util.module_from_spec(spec)
    ld.exec_module(m)
    return m


def closed_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.w = tempfile.mkdtemp(prefix="cilctl-test-")
        cls.posts = os.path.join(cls.w, "posts")
        e = dict(os.environ, STUB_POSTS=cls.posts)
        cls.stub = subprocess.Popen([sys.executable, "-I", os.path.join(T, "stub-cil.py")],
                                    stdout=subprocess.PIPE, env=e)
        cls.port = int(cls.stub.stdout.readline())
        cls.url = "http://127.0.0.1:%d" % cls.port
        cls.fake = cls.fake_ssh()

    @classmethod
    def tearDownClass(cls):
        cls.stub.terminate()
        cls.stub.wait(5)
        cls.stub.stdout.close()
        shutil.rmtree(cls.w, ignore_errors=True)

    @classmethod
    def fake_ssh(cls):
        src = os.path.join(T, "fake-ssh.py")
        if WINDOWS:
            p = os.path.join(cls.w, "fake-ssh.cmd")
            with open(p, "w") as f:
                f.write('@"%s" "%s" %%*\r\n' % (sys.executable, src))
            return p
        p = os.path.join(cls.w, "fake-ssh")
        with open(p, "w") as f:
            f.write("#!%s\nimport runpy, sys\nsys.argv[0] = %r\nrunpy.run_path(%r, run_name='__main__')\n"
                    % (sys.executable, src, src))
        os.chmod(p, 0o755)
        return p

    def setUp(self):
        self.home = tempfile.mkdtemp(dir=self.w)
        self.state = os.path.join(self.home, "state")
        self.rec = os.path.join(self.home, "rec")
        self.env = {k: v for k, v in os.environ.items() if not k.startswith(("CILCTL_", "XDG_"))}
        self.env.update(CILCTL_URL=self.url, CILCTL_STATE=self.state, HOME=self.home,
                        USERPROFILE=self.home, CILCTL_SSH=self.fake, CILCTL_SCP=self.fake,
                        FAKE_REC=self.rec, PYTHONIOENCODING="utf-8")
        # the state dir of a bare URL
        self.bare = os.path.join(self.state, "url_127.0.0.1_%d" % self.port)

    def run_cli(self, *args, env=None, prog=CILCTL, stdin=""):
        e = dict(self.env)
        for k, v in (env or {}).items():
            if v is None:
                e.pop(k, None)
            else:
                e[k] = v
        r = subprocess.run([sys.executable, prog] + list(args), env=e, input=stdin.encode(),
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
        out, err = r.stdout.decode(), r.stderr.decode()
        self.assertNotIn("SENTINEL", out, "key on stdout: %s" % (args,))
        self.assertNotIn("SENTINEL", err, "key on stderr: %s" % (args,))
        self.assertNotIn("Traceback", err, args)
        return r.returncode, out, err

    def config(self, text):
        p = os.path.join(self.home, "config.toml")
        with open(p, "w", encoding="utf-8") as f:
            f.write(text)
        return {"CILCTL_CONFIG": p}

    def nposts(self):
        try:
            with open(self.posts) as f:
                return len(f.readlines())
        except OSError:
            return 0

    def last_post(self):
        with open(self.posts) as f:
            return json.loads(f.readlines()[-1])

    def recorded(self):
        with open(self.rec) as f:
            return json.load(f)

    def ready(self, i=7, env=None):
        rc, out, err = self.run_cli("wait", str(i), env=env)
        self.assertEqual(rc, 0, out + err)


class Api(Base):
    def test_health(self):
        rc, out, _ = self.run_cli("health")
        self.assertEqual(rc, 0)
        self.assertRegex(out, r'"version": *"0.11.0"')

    def test_lists(self):
        self.assertIn("id=7 status=ready", self.run_cli("leases")[1])

    def test_leases_lists_only_live_leases(self):
        for url in (self.url, self.url + "/images"):  # /images ignores the filter
            out = self.run_cli("leases", env={"CILCTL_URL": url})[1]
            self.assertEqual([l.split()[0] for l in out.splitlines()], ["id=9", "id=7"])
        out = self.run_cli("leases", "--all")[1]
        self.assertIn("id=8 status=failed", out)
        self.assertIn("id=4 status=released", out)
        rc, _, err = self.run_cli("leases", "bogus")
        self.assertNotEqual(rc, 0)
        self.assertIn("usage: leases [--all]", err)
        self.assertRegex(self.run_cli("pools")[1],
                         r"name=arm64 .*env_keys=\['http_proxy', 'https_proxy', 'no_proxy'\]")
        self.assertIn("name=host-1 state=ready", self.run_cli("hosts")[1])
        self.assertIn("name=ubuntu-24.04-arm64 enabled=True", self.run_cli("images")[1])

    def test_request(self):
        # pool and image come from the CIL's only pool
        rc, out, _ = self.run_cli("request", "t-test")
        self.assertEqual(rc, 0)
        self.assertIn("id=7 status=queued", out)
        self.assertEqual(self.last_post(), {"pool": "arm64", "requester": "t-test", "image": "ubuntu-24.04-arm64",
                                            "cpu": 2, "ram_mb": 2048, "disk_gb": 20, "ttl_min": 120})

    def test_pool_and_image_choice(self):
        c = self.nposts()
        rc, _, err = self.run_cli("request", "t-x", env={"CILCTL_URL": self.url + "/multi"})
        self.assertNotEqual(rc, 0)
        self.assertIn("the CIL has pools arm64, x86: set pool in the profile or CILCTL_POOL", err)
        rc, _, err = self.run_cli("up", "--name", "t-x", env={"CILCTL_URL": self.url + "/images"})
        self.assertNotEqual(rc, 0)
        self.assertIn("pool arm64 allows ubuntu-24.04-arm64, debian-13-arm64: pick one with --image", err)
        self.assertEqual(self.nposts(), c)
        rc, _, err = self.run_cli("request", "t-x", env={"CILCTL_URL": self.url + "/multi", "CILCTL_POOL": "x86"})
        self.assertEqual(rc, 0, err)
        self.assertEqual((self.last_post()["pool"], self.last_post()["image"]), ("x86", "ubuntu-24.04"))
        self.run_cli("up", "--name", "t-x", "--image", "debian-13-arm64", env={"CILCTL_URL": self.url + "/images"})
        self.assertEqual(self.last_post()["image"], "debian-13-arm64")
        self.assertNotEqual(self.run_cli("request", "t-x", env={"CILCTL_POOL": "Bad Pool"})[0], 0)

    def test_request_refuses_bad_input_before_posting(self):
        for args in (["Bad Slug"], ["t-test", 'img","host_id":"2'], ["t-test", "ubuntu-24.04-arm64", "two"],
                     ["t-test", "ubuntu-24.04-arm64", "08"],
                     ["t-npu", "ubuntu-24.04-arm64", "12", "20480", "100", "150", "four"],
                     ["t", "i", "1", "1", "1", "1", "1", "extra"], []):
            c = self.nposts()
            rc, out, err = self.run_cli("request", *args)
            self.assertNotEqual(rc, 0, args)
            self.assertEqual(self.nposts(), c, "posted for %s" % args)

    def test_request_npus(self):
        self.run_cli("request", "t-npu", "ubuntu-24.04-arm64", "2", "2048", "20", "120", "0")
        self.assertNotIn("npus", self.last_post())
        rc, out, _ = self.run_cli("request", "t-npu", "ubuntu-24.04-arm64", "12", "20480", "100", "150", "4")
        self.assertIn("npus=4", out)
        self.assertEqual(self.last_post()["npus"], 4)
        # the CIL enforces its own limits; its error is shown
        rc, out, err = self.run_cli("request", "t-npu", "ubuntu-24.04-arm64", "12", "20480", "100", "150", "5")
        self.assertNotEqual(rc, 0)
        self.assertIn('error: "npus: 1 to 4 when given"', err)

    def test_wait_stores_key(self):
        rc, out, _ = self.run_cli("wait", "7")
        self.assertEqual(rc, 0)
        self.assertRegex(out, r"^\d\d:\d\d:\d\d ready host_id=1 expires_at=")
        key = os.path.join(self.bare, "7", "key")
        with open(key) as f:
            self.assertIn("SENTINEL", f.read())
        with open(os.path.join(self.bare, "7", "conn")) as f:
            self.assertEqual(f.read().split(), ["ubuntu", "127.0.0.1", "1"])
        if WINDOWS:
            acl = subprocess.run(["icacls", key], stdout=subprocess.PIPE).stdout.decode(errors="replace")
            aces = [l.strip() for l in acl.splitlines() if "(" in l]
            self.assertEqual(len(aces), 1, acl)
            self.assertIn(os.environ["USERNAME"].lower(), aces[0].lower())
            self.assertIn("(F)", aces[0])
            self.assertNotIn("(I)", aces[0])
        else:
            self.assertEqual(stat.S_IMODE(os.stat(key).st_mode), 0o600)
        # a second wait rewrites the key in place
        self.assertEqual(self.run_cli("wait", "7")[0], 0)

    def test_bad_connection(self):
        # the reply's user, host and port go into ssh argv: an option there
        # would run a command here
        for i in (5, 6, 10, 11):
            rc, out, err = self.run_cli("wait", str(i))
            self.assertEqual(rc, 1, i)
            self.assertIn("lease %d: the CIL sent a bad ssh user, host or port; key not kept (cilctl release %d)"
                          % (i, i), err)
            self.assertFalse(os.path.exists(os.path.join(self.bare, str(i))), i)
            self.assertNotEqual(self.run_cli("ssh", str(i), "true")[0], 0)

    def test_wait_failed_unknown(self):
        os.makedirs(os.path.join(self.bare, "8"))
        open(os.path.join(self.bare, "8", "key"), "w").close()
        rc, out, _ = self.run_cli("wait", "8")
        self.assertEqual(rc, 1)
        self.assertIn("failed", out)
        self.assertIn("last_error=boot timeout", out)
        self.assertFalse(os.path.exists(os.path.join(self.bare, "8")))
        self.assertEqual(self.run_cli("wait", "9")[0], 1)
        self.assertNotEqual(self.run_cli("wait", "x")[0], 0)

    def test_extend_events(self):
        rc, out, _ = self.run_cli("extend", "7", "30")
        self.assertEqual(rc, 0)
        self.assertIn("id=7 status=ready expires_at=", out)
        self.assertIn("kind=ready", self.run_cli("events", "7")[1])
        self.assertNotEqual(self.run_cli("extend", "7", "x")[0], 0)

    def test_release(self):
        self.ready()
        rc, out, _ = self.run_cli("release", "7")
        self.assertEqual((rc, out.strip()), (0, "status=released"))
        self.assertFalse(os.path.exists(os.path.join(self.bare, "7")))
        os.makedirs(os.path.join(self.bare, "8"))
        rc, out, _ = self.run_cli("release", "8")
        self.assertEqual((rc, out.strip()), (0, "status=failed"))
        self.assertFalse(os.path.exists(os.path.join(self.bare, "8")))
        rc, out, err = self.run_cli("release", "9")
        self.assertNotEqual(rc, 0)
        self.assertIn("not found", err)

    def test_release_gateway_timeout(self):
        # regression: a 504 from a slow teardown left the lease up behind
        # "non-JSON reply"; release now rechecks and retries
        for i in ("2", "3", "4"):
            os.makedirs(os.path.join(self.bare, i))
        rc, out, err = self.run_cli("release", "2")
        self.assertEqual((rc, out.strip()), (0, "status=released"))
        self.assertIn("DELETE lease 2: HTTP 504, lease ready", err)
        self.assertFalse(os.path.exists(os.path.join(self.bare, "2")))
        rc, out, err = self.run_cli("release", "4")
        self.assertEqual((rc, out.strip()), (0, "status=released"))
        self.assertFalse(os.path.exists(os.path.join(self.bare, "4")))
        rc, out, err = self.run_cli("release", "3")
        self.assertNotEqual(rc, 0)
        self.assertEqual(err.count("HTTP 504, lease ready"), 3)
        self.assertIn("lease 3 is still ready", err)
        self.assertTrue(os.path.exists(os.path.join(self.bare, "3")))

    def test_bad_url_and_non_json(self):
        rc, _, err = self.run_cli("health", env={"CILCTL_URL": "http://x/'#"})
        self.assertNotEqual(rc, 0)
        self.assertIn("CILCTL_URL must be", err)
        rc, _, err = self.run_cli("--url", "ftp://x", "health")
        self.assertIn("--url must be", err)
        rc, _, err = self.run_cli("leases", env={"CILCTL_URL": self.url + "/html"})
        self.assertNotEqual(rc, 0)
        self.assertIn("non-JSON reply from CIL (HTTP 502)", err)

    def test_no_cil(self):
        rc, _, err = self.run_cli("leases", env={"CILCTL_URL": None})
        self.assertNotEqual(rc, 0)
        self.assertIn("no CIL: pass --url, set CILCTL_URL, or add a [cil.NAME] profile to", err)
        self.assertIn(os.path.join(self.home, ".config", "cilctl", "config.toml"), err)
        rc, out, _ = self.run_cli("cils", env={"CILCTL_URL": None})
        self.assertEqual(rc, 0)
        self.assertIn("no profiles in", out)
        rc, out, _ = self.run_cli("setups", env={"CILCTL_URL": None})
        self.assertEqual(rc, 0)
        self.assertIn("no setup recipes in", out)
        xdg = os.path.join(self.home, "xdg")
        self.assertIn(os.path.join(xdg, "cilctl", "config.toml"),
                      self.run_cli("cils", env={"CILCTL_URL": None, "XDG_CONFIG_HOME": xdg})[1])
        rc, _, err = self.run_cli("cils", env={"CILCTL_CONFIG": os.path.join(self.home, "missing.toml")})
        self.assertNotEqual(rc, 0)
        self.assertIn("no such file (CILCTL_CONFIG)", err)

    def test_ignores_http_proxy(self):
        # regression: urllib sent every call to the environment's proxy
        dead = "http://127.0.0.1:%d" % closed_port()
        rc, out, err = self.run_cli("leases", env={"http_proxy": dead, "HTTP_PROXY": dead})
        self.assertEqual(rc, 0, err)
        self.assertIn("id=7 status=ready", out)

    def test_unreachable_names_the_jump(self):
        rc, _, err = self.run_cli("leases", env={"CILCTL_URL": "http://127.0.0.1:%d" % closed_port()})
        self.assertNotEqual(rc, 0)
        self.assertIn("set --jump, CILCTL_JUMP or the profile's jump", err)

    def test_usage(self):
        rc, out, _ = self.run_cli()
        self.assertEqual(rc, 0)
        self.assertIn("up [--name SLUG]", out)
        self.assertEqual(self.run_cli("bogus")[0], 2)
        self.assertEqual(self.run_cli("--bogus", "x", "health")[0], 2)
        self.assertNotEqual(self.run_cli("--url=", "health")[0], 0)

    @unittest.skipUnless(WINDOWS, "cilctl.cmd is the Windows entry point")
    def test_windows_shim(self):
        def shim(*args, rc=None):
            e = dict(self.env, FAKE_RC=rc) if rc else self.env
            r = subprocess.run([SHIM] + list(args), env=e, input=b"", stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, timeout=120)
            out, err = r.stdout.decode(), r.stderr.decode()
            self.assertNotIn("SENTINEL", out + err)
            return r.returncode, out, err
        rc, out, _ = shim("health")
        self.assertEqual(rc, 0)
        self.assertIn("0.11.0", out)
        self.assertNotEqual(shim("release", "9")[0], 0)
        self.ready()
        self.assertEqual(shim("ssh", "7", "false", rc="3")[0], 3)
        self.assertEqual(shim("ssh", "7", "opencode", "run", "fix the bug")[0], 0)
        self.assertEqual(self.recorded()["argv"][-1],
                         "export PATH=$HOME/.opencode/bin:$HOME/.local/bin:$PATH; opencode run 'fix the bug'")

    @unittest.skipUnless(WINDOWS and shutil.which("powershell") and shutil.which("py"), "PowerShell and py")
    def test_powershell_function(self):
        # the README's PowerShell function: cmd's parser never sees the
        # arguments, so | & ^ % reach the lease as typed (through
        # cilctl.cmd an unquoted ls|wc becomes a cmd pipe)
        self.ready()
        ps = ("function cilctl { py -3 '%s' @args }; "
              "cilctl ssh 7 printf '%%s|' 'a b' 'ls|wc' '100%%&x^y'; exit $LASTEXITCODE" % CILCTL)
        r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps], env=self.env,
                           input=b"", stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
        self.assertEqual(r.returncode, 0, r.stderr.decode())
        self.assertNotIn(b"SENTINEL", r.stdout + r.stderr)
        self.assertEqual(self.recorded()["argv"][-1],
                         "export PATH=$HOME/.opencode/bin:$HOME/.local/bin:$PATH; printf '%s|' 'a b' 'ls|wc' '100%&x^y'")
        ps = "function cilctl { py -3 '%s' @args }; cilctl ssh 7 false; exit $LASTEXITCODE" % CILCTL
        r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                           env=dict(self.env, FAKE_RC="3"), input=b"", stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, timeout=120)
        self.assertEqual(r.returncode, 3)


class Up(Base):
    def test_up_defaults(self):
        rc, out, err = self.run_cli("up", env={"USER": "Some.User", "USERNAME": "Some.User"})
        self.assertEqual(rc, 0, out + err)
        self.assertEqual(self.last_post(), {"pool": "arm64", "requester": "cilctl-some-user",
                                            "image": "ubuntu-24.04-arm64", "cpu": 2, "ram_mb": 2048,
                                            "disk_gb": 20, "ttl_min": 120})
        self.assertIn("lease 7 ready: ubuntu@127.0.0.1 port 1", out)
        self.assertIn("cilctl release 7", out)
        self.assertIn("no profile: pass the same --url or CILCTL_URL", out)
        self.assertNotIn("opencode", out)
        self.assertFalse(os.path.exists(self.rec), "up without --setup ran ssh")

    def test_up_options(self):
        rc, out, err = self.run_cli("up", "--name", "t-up", "--cpu=4", "--ram", "4096", "--disk", "30",
                                    "--ttl", "60", "--npus", "1", "--image", "debian-13-arm64")
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.last_post(), {"pool": "arm64", "requester": "t-up", "image": "debian-13-arm64",
                                            "cpu": 4, "ram_mb": 4096, "disk_gb": 30, "ttl_min": 60, "npus": 1})

    def test_up_setup(self):
        e = self.config(RECIPE)
        rc, out, err = self.run_cli("up", "--name", "t-tiny", "--setup", "tiny", "--ttl", "30", env=e)
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.last_post(), {"pool": "arm64", "requester": "t-tiny", "image": "ubuntu-24.04-arm64",
                                            "cpu": 6, "ram_mb": 8192, "disk_gb": 40, "ttl_min": 30, "npus": 2})
        r = self.recorded()
        self.assertEqual(r["argv"][-1], "bash -s")
        self.assertIn("MODEL_URL=http://models.example.com/m/tiny-q4.gguf\n", r["stdin"])
        self.assertIn("MODEL_SHA256=%s\n" % SHA0, r["stdin"])
        # the model comes through the guest's proxy unless the recipe says direct
        self.assertIn("NOPROXY=''\n", r["stdin"])
        e = self.config(RECIPE + "model_direct = true\n")
        self.assertEqual(self.run_cli("up", "--setup", "tiny", env=e)[0], 0)
        self.assertIn("NOPROXY=models.example.com\n", self.recorded()["stdin"])
        self.assertTrue(r["stdin"].endswith(load().SETUP_SH))
        self.assertIn("cilctl opencode 7", out)

    def test_up_setup_failure_keeps_lease(self):
        rc, out, err = self.run_cli("up", "--setup", "tiny", env=dict(self.config(RECIPE), FAKE_RC="1"))
        self.assertEqual(rc, 1)
        self.assertIn("setup failed; the lease is kept", err)
        self.assertTrue(os.path.exists(os.path.join(self.bare, "7", "key")))

    def test_up_refuses_before_posting(self):
        e = self.config(RECIPE)
        for args in (["--setup", "bogus"], ["--cpu", "x"], ["--name", "Bad"], ["--wat", "1"],
                     ["--cpu"], ["stray"], ["--image", "Bad Image"]):
            c = self.nposts()
            rc, _, err = self.run_cli("up", *args, env=e)
            self.assertNotEqual(rc, 0, args)
            self.assertEqual(self.nposts(), c, args)
        self.assertIn("unknown setup recipe 'bogus' (recipes in %s: tiny)" % e["CILCTL_CONFIG"],
                      self.run_cli("up", "--setup", "bogus", env=e)[2])

    def test_setup_command(self):
        e = self.config(RECIPE)
        self.ready()
        rc, out, _ = self.run_cli("setup", "7", "tiny", env=e)
        self.assertEqual(rc, 0)
        m = load()
        os.environ["CILCTL_CONFIG"] = e["CILCTL_CONFIG"]
        try:
            want = m.setup_script(m.load_config()[2]["tiny"])
        finally:
            del os.environ["CILCTL_CONFIG"]
        self.assertEqual(self.recorded()["stdin"], want)
        self.assertIn("cilctl opencode 7", out)
        self.assertNotEqual(self.run_cli("setup", "7", "huge", env=e)[0], 0)
        self.assertNotEqual(self.run_cli("setup", "7", env=e)[0], 0)
        rc, _, err = self.run_cli("setup", "6", "tiny", env=e)
        self.assertNotEqual(rc, 0)
        self.assertIn("no key for lease 6", err)

    def test_setups_list(self):
        rc, out, _ = self.run_cli("setups", env=self.config(RECIPE))
        self.assertEqual(rc, 0)
        self.assertEqual(out.strip(), "tiny model=tiny-q4.gguf alias=tiny context=4096 npus=2 cpu=6 ram=8192 "
                                      "disk=40 ttl=90")


@unittest.skipUnless(BASH, "the guest script is bash; checked on Linux and macOS")
class SetupScript(Base):
    def recipe(self, text=RECIPE):
        m = load()
        os.environ["CILCTL_CONFIG"] = self.config(text)["CILCTL_CONFIG"]
        try:
            return m, m.load_config()[2]["tiny"]
        finally:
            del os.environ["CILCTL_CONFIG"]

    def fakes(self, curl_rc=None, body=None, install_fails=""):
        """fake curl (appends its argv to $HOME/curl.args, copies the file
        body to its -o path, exits curl_rc)
        and sudo (install fails for paths containing install_fails, else
        copies into $HOME/root)."""
        b = os.path.join(self.home, "bin")
        os.makedirs(b, exist_ok=True)
        with open(os.path.join(b, "curl"), "w") as f:
            f.write('#!/bin/sh\necho "$@" >> "$HOME/curl.args"\nwhile [ $# -gt 0 ]; do [ "$1" = -o ] && o=$2; shift; done\n'
                    '[ -z "%s" ] || cp "%s" "$o"\nexit %d\n' % (body or "", body or "", curl_rc or 0))
        with open(os.path.join(b, "sudo"), "w") as f:
            # sudo install -m MODE SRC DST; sudo cmp -s NEW DST
            f.write('#!/bin/sh\nif [ "$1" = install ]; then\n' +
                    ('  case "$5" in *"%s"*) exit 1 ;; esac\n' % install_fails if install_fails else "") +
                    '  mkdir -p "$HOME/root$(dirname "$5")" && cp "$4" "$HOME/root$5" && chmod "$3" "$HOME/root$5"; exit\n'
                    'fi\nif [ "$1" = cmp ]; then exec cmp -s "$3" "$HOME/root$4"; fi\nexec "$@"\n')
        for x in ("curl", "sudo"):
            os.chmod(os.path.join(b, x), 0o755)
        return dict(self.env, PATH=b + os.pathsep + os.environ["PATH"])

    def fn(self, *args, stdin="", **kw):
        """Run one SETUP_SH function after the tiny recipe's settings."""
        m, r = self.recipe()
        e = self.fakes(**kw)
        r = subprocess.run([BASH, "-c", m.setup_script(r) + "\n", "setup", "--fn"] + list(args), env=e,
                           input=stdin.encode(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60)
        return r.returncode, r.stdout.decode()

    def main(self, text=RECIPE, **kw):
        """The whole script, as setup runs it (bash -s)."""
        m, r = self.recipe(text)
        r = subprocess.run([BASH, "-s"], env=self.fakes(**kw), input=m.setup_script(r).encode(),
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60)
        return r.returncode, r.stdout.decode()

    def test_settings_round_trip(self):
        m, r = self.recipe()
        p = subprocess.run([BASH, "-c", m.setup_script(r), "setup", "--fn", "eval",
                            'printf "%s\\n--\\n" "$PRECHECK" "$OC_JSON" "$TITLE" "$ARGS"'], stdout=subprocess.PIPE)
        self.assertEqual(p.stdout.decode().split("\n--\n")[:4],
                         [r["precheck"], m.opencode_json(r), "Tiny Q4 (test)", "-ngl 99 -t 4 -dev A,B"])
        oc = json.loads(m.opencode_json(r))
        self.assertEqual(oc["model"], "llamacpp/tiny")
        self.assertEqual(oc["provider"]["llamacpp"]["models"]["tiny"],
                         {"name": "Tiny Q4 (test)", "tool_call": True, "reasoning": True,
                          "limit": {"context": 4096, "output": 8192}})

    def test_precheck_refuses(self):
        rc, out = self.main()
        self.assertNotEqual(rc, 0)
        self.assertIn("setup: FAIL: precheck: it's not there", out)

    def test_no_llama_server(self):
        ok = RECIPE.replace('[ -r /x ] || { echo "it\'s not there"; exit 1; }', "echo fine")
        rc, out = self.main(ok)
        self.assertNotEqual(rc, 0)
        self.assertIn("setup: precheck: fine", out)
        self.assertIn("setup: FAIL: no llama-server on PATH after /etc/profile.d/llama.sh", out)

    def test_put_failure_stops_setup(self):
        rc, out = self.fn("put", "/etc/x.conf", stdin="a=1\n", install_fails="x.conf")
        self.assertNotEqual(rc, 0)
        self.assertIn("setup: FAIL: cannot write /etc/x.conf", out)
        self.assertEqual(self.fn("put", "/etc/x.conf", stdin="a=1\n")[0], 0)
        self.assertEqual(self.fn("put", "/etc/x.conf", stdin="a=1\n")[0], 1, "unchanged file rewritten")

    def test_write_service(self):
        rc, out = self.fn("write_service", "/m/q.gguf", "alice")
        self.assertEqual(rc, 0, out)
        root = os.path.join(self.home, "root")
        with open(os.path.join(root, "etc", "systemd", "system", "cilctl-llama.service")) as f:
            unit = f.read()
        self.assertIn("\nUser=alice\n", unit)
        self.assertIn("Description=llama-server: Tiny Q4 (test) (127.0.0.1:8080)\n", unit)
        self.assertIn("\nExecStart=/usr/local/bin/cilctl-llama\n", unit)
        self.assertTrue(unit.endswith("WantedBy=multi-user.target\n"))
        with open(os.path.join(root, "etc", "default", "cilctl-llama")) as f:
            d = f.read()
        self.assertIn("\nMODEL=/m/q.gguf\nCTX=4096\nALIAS=tiny\nARGS=-ngl 99 -t 4 -dev A,B\n"
                      "ENV_SCRIPT=/etc/profile.d/llama.sh\n", d)
        runner = os.path.join(root, "usr", "local", "bin", "cilctl-llama")
        self.assertEqual(stat.S_IMODE(os.stat(runner).st_mode), 0o755)
        # the runner as systemd starts it: the settings in the environment
        b = os.path.join(self.home, "bin")
        with open(os.path.join(b, "llama-server"), "w") as f:
            f.write('#!/bin/sh\nfor a; do printf "[%s]" "$a"; done\necho "$FROM_ENV_SCRIPT"\n')
        os.chmod(os.path.join(b, "llama-server"), 0o755)
        envs = os.path.join(self.home, "env.sh")
        with open(envs, "w") as f:
            f.write("export FROM_ENV_SCRIPT=sourced\n")
        e = dict(self.env, PATH=b + os.pathsep + os.environ["PATH"], MODEL="/m/my model.gguf", CTX="4096",
                 ALIAS="tiny", ARGS="-ngl 99 -t 4", ENV_SCRIPT=envs)
        r = subprocess.run([runner], env=e, stdout=subprocess.PIPE)
        self.assertEqual(r.stdout.decode(), "[-m][/m/my model.gguf][-c][4096][--alias][tiny][--jinja][--host]"
                                            "[127.0.0.1][--port][8080][-ngl][99][-t][4]sourced\n")
        self.assertEqual(self.fn("write_service", "/m/q.gguf", "alice")[0], 1, "unchanged service rewritten")
        # regression: a failed unit write was lost in a pipeline subshell
        shutil.rmtree(root)
        rc, out = self.fn("write_service", "/m/q.gguf", "alice", install_fails="cilctl-llama.service")
        self.assertNotEqual(rc, 0)
        self.assertIn("cannot write /etc/systemd/system/cilctl-llama.service", out)

    def test_model_download_failure(self):
        m = os.path.join(self.home, "models", "q.gguf")
        os.makedirs(os.path.dirname(m))
        for rc_curl, kept in ((7, True), (33, False)):
            with open(m + ".part", "w") as f:
                f.write("partial")
            rc, out = self.fn("fetch_model", "http://h/q.gguf", SHA0, "h", m, "1", curl_rc=rc_curl)
            self.assertNotEqual(rc, 0)
            self.assertIn("setup: FAIL: model download failed", out)
            # curl 33 (no range support) would fail every resume
            self.assertEqual(os.path.exists(m + ".part"), kept, rc_curl)

    def test_model_free_space(self):
        m = os.path.join(self.home, "models", "q.gguf")
        rc, out = self.fn("fetch_model", "http://h/q.gguf", SHA0, "h", m, str(10 ** 12))
        self.assertNotEqual(rc, 0)
        self.assertIn("the recipe needs %d MB" % 10 ** 12, out)

    def test_model_proxy(self):
        args = os.path.join(self.home, "curl.args")
        m = os.path.join(self.home, "models", "q.gguf")
        for noproxy, want in (("", "-fL --retry 3 -C - -sS -o"), ("h", "-fL --retry 3 -C - --noproxy h -sS -o")):
            if os.path.exists(args):
                os.unlink(args)
            self.fn("fetch_model", "http://h/q.gguf", SHA0, noproxy, m, "1")
            with open(args) as f:
                self.assertTrue(f.read().startswith(want + " " + m + ".part http://h/q.gguf"), noproxy)

    @unittest.skipUnless(gnu_stat(), "the model stamp uses GNU stat (the guest's)")
    def test_model_sha(self):
        # the sha is the only integrity check on a model fetched over http
        m = os.path.join(self.home, "models", "q.gguf")
        body = os.path.join(self.home, "body")
        with open(body, "w") as f:
            f.write("weights")
        good = hashlib.sha256(b"weights").hexdigest()
        rc, out = self.fn("fetch_model", "http://h/q.gguf", SHA0, "h", m, "1", body=body)
        self.assertNotEqual(rc, 0)
        self.assertIn("setup: FAIL: model sha256 %s, expected %s" % (good, SHA0), out)
        self.assertFalse(os.path.exists(m) or os.path.exists(m + ".part"))
        rc, out = self.fn("fetch_model", "http://h/q.gguf", good, "h", m, "1", body=body)
        self.assertEqual(rc, 0, out)
        self.assertIn("sha256 ok", out)
        self.assertFalse(os.path.exists(m + ".part"), ".part left behind")
        with open(m + ".ok") as f:
            self.assertTrue(f.read().startswith(good + " "))
        self.assertIn("model present", self.fn("fetch_model", "http://h/q.gguf", good, "h", m, "1")[1])
        # a changed file is hashed again and refetched
        with open(m, "a") as f:
            f.write("x")
        rc, out = self.fn("fetch_model", "http://h/q.gguf", good, "h", m, "1", body=body)
        self.assertIn("sha mismatch, fetching again", out)
        self.assertEqual(rc, 0, out)

    def test_oc_install(self):
        oc = os.path.join(self.home, "oc")
        with open(oc, "w") as f:
            f.write("#!/bin/sh\necho 9.9\n")
        os.chmod(oc, 0o755)
        tgz = os.path.join(self.home, "oc.tar.gz")
        with tarfile.open(tgz, "w:gz") as t:
            t.add(oc, arcname="opencode")
        with open(oc, "rb") as f:
            good = hashlib.sha256(f.read()).hexdigest()
        dst = os.path.join(self.home, ".opencode", "bin", "opencode")
        rc, out = self.fn("oc_install", "http://h/oc.tgz", SHA0, body=tgz)
        self.assertNotEqual(rc, 0)
        self.assertIn("setup: FAIL: opencode sha256 mismatch", out)
        self.assertFalse(os.path.exists(dst))
        rc, out = self.fn("oc_install", "http://h/oc.tgz", good, body=tgz)
        self.assertEqual(rc, 0, out)
        self.assertIn("opencode 9.9 installed", out)
        self.assertIn("opencode present (9.9)", self.fn("oc_install", "http://h/oc.tgz", good)[1])
        with open(dst, "a") as f:
            f.write("# changed\n")
        self.assertIn("opencode 9.9 installed", self.fn("oc_install", "http://h/oc.tgz", good, body=tgz)[1])
        with open(dst, "rb") as f:
            self.assertEqual(hashlib.sha256(f.read()).hexdigest(), good)

    def test_tool_check_curl_failure(self):
        rc, out = self.fn("tool_check", curl_rc=28)
        self.assertNotEqual(rc, 0)
        self.assertIn("setup: FAIL: no get_weather tool call in the reply", out)

    def test_oc_config(self):
        c = os.path.join(self.home, ".config", "opencode", "opencode.json")
        rc, out = self.fn("oc_config")
        self.assertIn("wrote", out)
        with open(c) as f:
            ours = f.read()
        self.assertIn('"baseURL": "http://127.0.0.1:8080/v1"', ours)
        self.assertEqual(json.loads(ours)["model"], "llamacpp/tiny")
        self.assertNotIn("wrote", self.fn("oc_config")[1])
        with open(c, "w") as f:
            f.write(ours.replace('"autoupdate": false', '"autoupdate": false, "share": "disabled"'))
        rc, out = self.fn("oc_config")
        self.assertIn("kept your edited", out)
        with open(c) as f:
            self.assertIn("share", f.read())
        with open(c + ".cilctl-new") as f:
            self.assertEqual(f.read(), ours)
        # from before cilctl: backed up and replaced
        for x in (".cilctl-last", ".cilctl-new"):
            os.unlink(c + x)
        with open(c, "w") as f:
            f.write("{}")
        self.assertIn("wrote", self.fn("oc_config")[1])
        with open(c + ".cilctl-bak") as f:
            self.assertEqual(f.read(), "{}")
        # equal to ours but never recorded (an older setup), then edited
        os.unlink(c + ".cilctl-last")
        self.fn("oc_config")
        with open(c, "w") as f:
            f.write(ours + " ")
        self.assertIn("kept your edited", self.fn("oc_config")[1])


class SshArgv(Base):
    def setUp(self):
        super().setUp()
        self.ready()

    def test_ssh_forms(self):
        self.run_cli("ssh", "7")
        a = self.recorded()["argv"]
        self.assertEqual(a[-1], "ubuntu@127.0.0.1")
        self.assertIn("IdentitiesOnly=yes", a)
        self.assertEqual(a[a.index("-p") + 1], "1")
        self.assertEqual(a[a.index("-i") + 1], os.path.join(self.bare, "7", "key"))
        self.assertFalse(any(x.startswith("ProxyJump") for x in a))
        self.run_cli("ssh", "7", "cd x && opencode")
        a = self.recorded()["argv"]
        self.assertEqual(a[-1], "export PATH=$HOME/.opencode/bin:$HOME/.local/bin:$PATH; cd x && opencode")
        self.assertNotIn("-t", a, "-t without a terminal")
        self.run_cli("ssh", "7", "opencode", "run", "fix it's bug")
        self.assertEqual(self.recorded()["argv"][-1],
                         "export PATH=$HOME/.opencode/bin:$HOME/.local/bin:$PATH; opencode run 'fix it'\"'\"'s bug'")

    def test_ssh_exit_code(self):
        self.assertEqual(self.run_cli("ssh", "7", "false", env={"FAKE_RC": "3"})[0], 3)

    def test_jump(self):
        self.run_cli("--jump", "me@a.example,you@b.example:2222", "ssh", "7", "true")
        self.assertIn("ProxyJump=me@a.example,you@b.example:2222", self.recorded()["argv"])
        self.run_cli("ssh", "7", "true", env={"CILCTL_JUMP": "x@y"})
        self.assertIn("ProxyJump=x@y", self.recorded()["argv"])
        self.run_cli("--jump", "none", "ssh", "7", "true", env={"CILCTL_JUMP": "x@y"})
        self.assertFalse(any(x.startswith("ProxyJump") for x in self.recorded()["argv"]))
        for bad in ("-oProxyCommand=x", "a b", "a@b;c"):
            rc, _, err = self.run_cli("--jump", bad, "ssh", "7", "true")
            self.assertNotEqual(rc, 0, bad)
            self.assertIn("bad hop", err)

    def test_known_hosts_quoted(self):
        self.run_cli("ssh", "7", "true")
        a = self.recorded()["argv"]
        kh = [x for x in a if x.startswith("UserKnownHostsFile=")][0]
        self.assertEqual(kh, 'UserKnownHostsFile="%s"' % os.path.join(self.bare, "7", "known_hosts").replace("\\", "/"))

    def test_copy(self):
        self.run_cli("copy", "7", "a.txt", "b dir", ":up/")
        a = self.recorded()["argv"]
        self.assertEqual(a[:1], ["-r"])
        self.assertEqual(a[a.index("-P") + 1], "1")
        self.assertEqual(a[-3:], ["a.txt", "b dir", "ubuntu@127.0.0.1:up/"])
        # scp would read a relative "run-10:00.log" as host run-10
        self.run_cli("copy", "7", "run-10:00.log", "d/x:y", ":")
        self.assertEqual(self.recorded()["argv"][-3:-1], ["./run-10:00.log", "d/x:y"])
        self.run_cli("copy", "7", ":a", "out:1")
        self.assertEqual(self.recorded()["argv"][-1], "./out:1")
        self.run_cli("scp", "7", ":out.log", ":~/x", ".")
        self.assertEqual(self.recorded()["argv"][-3:], ["ubuntu@127.0.0.1:out.log", "ubuntu@127.0.0.1:~/x", "."])
        self.run_cli("copy", "7", "f", ":")
        self.assertEqual(self.recorded()["argv"][-1], "ubuntu@127.0.0.1:")
        for bad in (["a", "b"], [":a", ":b"], [":a", "b", "c"], ["a"], ["-oProxyCommand=x", ":"], ["a", ":-x"]):
            os.path.exists(self.rec) and os.unlink(self.rec)
            rc, _, _ = self.run_cli("copy", "7", *bad)
            self.assertNotEqual(rc, 0, bad)
            self.assertFalse(os.path.exists(self.rec), "scp ran for %s" % bad)

    def test_forward(self):
        self.run_cli("forward", "7")
        a = self.recorded()["argv"]
        self.assertIn("-N", a)
        self.assertEqual(a[a.index("-L") + 1], "127.0.0.1:8080:127.0.0.1:8080")
        self.run_cli("forward", "7", "18080", "9000")
        a = self.recorded()["argv"]
        self.assertEqual(a[a.index("-L") + 1], "127.0.0.1:18080:127.0.0.1:9000")
        for bad in (["0"], ["70000"], ["x"], ["1", "2", "3"]):
            self.assertNotEqual(self.run_cli("forward", "7", *bad)[0], 0, bad)

    def test_opencode_needs_terminal(self):
        os.path.exists(self.rec) and os.unlink(self.rec)
        rc, _, err = self.run_cli("opencode", "7")
        self.assertNotEqual(rc, 0)
        self.assertIn("needs a terminal", err)
        self.assertFalse(os.path.exists(self.rec))

    def test_opencode_line(self):
        m = load()
        self.assertEqual(m.remote_dir("~"), "$HOME")
        self.assertEqual(m.remote_dir("~/src/my app"), "$HOME/'src/my app'")
        self.assertEqual(m.remote_dir("/srv/x;rm"), "'/srv/x;rm'")

    def test_no_key(self):
        rc, _, err = self.run_cli("ssh", "6")
        self.assertNotEqual(rc, 0)
        self.assertIn("no key for lease 6", err)

    @unittest.skipUnless(BASH and gnu_sed(), "the apt line runs in a Linux guest (bash, GNU sed)")
    def test_apt(self):
        apt = os.path.join(self.home, "apt")

        def aptrun(update_out):
            os.makedirs(os.path.join(apt, "sources.list.d"), exist_ok=True)
            os.makedirs(os.path.join(apt, "mirrors"), exist_ok=True)
            with open(os.path.join(apt, "sources.list.d", "ubuntu.sources"), "w") as f:
                f.write("Types: deb\nURIs: http://ports.ubuntu.com/ubuntu-ports/ http://security.ubuntu.com/ubuntu/\n")
            with open(os.path.join(apt, "mirrors", "debian.list"), "w") as f:
                f.write("https://deb.debian.org/debian\nhttps://deb.debian.org/debian-security\n")
            self.run_cli("apt", "7")
            c = self.recorded()["argv"][-1]
            c = c.replace("/etc/apt", apt).replace("sudo ", "").replace("/tmp/cilctl-apt.log",
                                                                       os.path.join(self.home, "apt.log"))
            c = c.replace("apt-get update", "printf '%s'" % update_out)
            r = subprocess.run([BASH, "-c", c], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            return r.returncode, r.stdout.decode(), c

        rc, out, _ = aptrun("Hit:1 x\\n")
        self.assertEqual(rc, 0, out)
        self.assertIn("apt-ok", out)
        with open(os.path.join(apt, "sources.list.d", "ubuntu.sources")) as f:
            self.assertEqual(f.read(), "Types: deb\nURIs: %s/ubuntu-ports/ %s/ubuntu/\n" % (self.url, self.url))
        with open(os.path.join(apt, "mirrors", "debian.list")) as f:
            self.assertEqual(f.read().split(), [self.url + "/debian", self.url + "/debian-security"])
        self.assertEqual([n for _, _, ns in os.walk(apt) for n in ns if n.endswith(".cilctl-bak")], [])
        for e in ("W: Failed to fetch x\\n", "Err:1 http://x\\n"):
            rc, out, _ = aptrun(e)
            self.assertNotEqual(rc, 0, e)
            self.assertNotIn("apt-ok", out)
            # a failed update puts the sources back
            with open(os.path.join(apt, "sources.list.d", "ubuntu.sources")) as f:
                self.assertIn("http://ports.ubuntu.com/ubuntu-ports/", f.read())
            self.assertFalse(os.path.exists(os.path.join(apt, "mirrors", "debian.list.cilctl-bak")))
        rc, out, c = aptrun("x")
        for d in ("sources.list.d", "mirrors"):
            shutil.rmtree(os.path.join(apt, d))
        r = subprocess.run([BASH, "-c", c], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("no-apt-sources", r.stdout.decode())


class Jump(Base):
    def test_tunnel_argv(self):
        saved = dict(os.environ)
        os.environ.update(CILCTL_URL="http://cil.example:8086", XDG_CONFIG_HOME=self.home)
        for k in ("CILCTL_JUMP", "CILCTL_CONFIG", "CILCTL_CIL"):
            os.environ.pop(k, None)
        try:
            m = load()
            c = m.Cfg(None, "me@a.example,you@b.example:2222", None)
            c.ssh = "ssh"
            a = m.Api(c).tunnel_argv(5555)
        finally:
            os.environ.clear()
            os.environ.update(saved)
        self.assertEqual(a[a.index("-L") + 1], "127.0.0.1:5555:cil.example:8086")
        self.assertEqual(a[-5:], ["-J", "me@a.example", "-p", "2222", "you@b.example"])
        self.assertIn("BatchMode=yes", a)

    @unittest.skipIf(WINDOWS, "terminating the .cmd fake leaves its python child running")
    def test_api_through_tunnel(self):
        dead = closed_port()
        e = {"CILCTL_URL": "http://127.0.0.1:%d" % dead, "CILCTL_JUMP": "me@jump.example",
             "FAKE_FWD": str(self.port)}
        dead_proxy = "http://127.0.0.1:%d" % closed_port()
        rc, out, err = self.run_cli("leases", env=dict(e, http_proxy=dead_proxy, HTTP_PROXY=dead_proxy))
        self.assertEqual(rc, 0, err)
        self.assertIn("id=7 status=ready", out)
        self.assertTunnelGone()
        a = self.recorded()["argv"]
        self.assertEqual(a[a.index("-L") + 1].split(":", 2)[2], "127.0.0.1:%d" % dead)
        self.assertEqual(a[-1], "me@jump.example")
        rc, out, _ = self.run_cli("doctor", env=e)
        self.assertEqual(rc, 0, out)
        self.assertIn("api direct http://127.0.0.1:%d: unreachable" % dead, out)
        self.assertIn("api via jump: ok", out)
        self.assertIn("version 0.11.0 (route jump)", out)

    @unittest.skipIf(WINDOWS, "terminating the .cmd fake leaves its python child running")
    @unittest.skipIf(ssl.OPENSSL_VERSION.startswith("LibreSSL"), "LibreSSL ignores SSL_CERT_FILE")
    def test_https_through_tunnel(self):
        tls = tempfile.mkdtemp(dir=self.home)
        stub = subprocess.Popen([sys.executable, "-I", os.path.join(T, "stub-cil.py")], stdout=subprocess.PIPE,
                                env=dict(os.environ, STUB_POSTS=self.posts, STUB_TLS=tls))
        try:
            port = int(stub.stdout.readline())
            ca = {"SSL_CERT_FILE": os.path.join(tls, "ca.pem")}
            rc, out, err = self.run_cli("--url", "https://localhost:%d" % port, "leases", env=ca)
            self.assertEqual(rc, 0, err)
            self.assertIn("id=7 status=ready", out)
            # through the tunnel the certificate is still checked for the
            # URL's name, not for the tunnel's 127.0.0.1
            e = dict(ca, CILCTL_URL="https://localhost:%d" % closed_port(), CILCTL_JUMP="me@jump.example",
                     FAKE_FWD=str(port))
            rc, out, err = self.run_cli("leases", env=e)
            self.assertEqual(rc, 0, err)
            self.assertIn("id=7 status=ready", out)
            self.assertTunnelGone()
            rc, out, err = self.run_cli("leases", env=dict(e, SSL_CERT_FILE=os.path.join(T, "fake-ssh.py")))
            self.assertEqual(rc, 1)
            self.assertIn("CERTIFICATE_VERIFY_FAILED", err)
        finally:
            stub.terminate()
            stub.wait(5)
            stub.stdout.close()

    def assertTunnelGone(self):
        with open(self.rec + ".pid") as f:
            pid = int(f.read())
        try:
            os.kill(pid, 0)
        except OSError:
            return
        os.kill(pid, signal.SIGKILL)
        self.fail("jump tunnel %d still running" % pid)

    @unittest.skipIf(WINDOWS, "POSIX signals")
    def test_sigterm_stops_tunnel(self):
        # release 3 keeps retrying a 504; SIGTERM mid-retry must not
        # leave the tunnel ssh behind
        e = dict(self.env, CILCTL_URL="http://127.0.0.1:%d" % closed_port(), CILCTL_JUMP="me@jump.example",
                 FAKE_FWD=str(self.port))
        p = subprocess.Popen([sys.executable, CILCTL, "release", "3"], env=e, stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        for _ in range(100):
            if os.path.exists(self.rec + ".pid") and p.poll() is None:
                break
            time.sleep(0.1)
        time.sleep(1)
        p.send_signal(signal.SIGTERM)
        out, err = p.communicate(timeout=30)
        self.assertTunnelGone()
        self.assertEqual(p.returncode, 128 + signal.SIGTERM, err)
        self.assertNotIn(b"SENTINEL", out + err)

    @unittest.skipIf(WINDOWS, "terminating the .cmd fake leaves its python child running")
    def test_tunnel_failure(self):
        e = {"CILCTL_URL": "http://127.0.0.1:%d" % closed_port(), "CILCTL_JUMP": "me@jump.example",
             "FAKE_RC": "255"}
        rc, _, err = self.run_cli("leases", env=e)
        self.assertNotEqual(rc, 0)
        self.assertIn("ssh tunnel via me@jump.example exited", err)
        rc, out, _ = self.run_cli("doctor", env=e)
        self.assertNotEqual(rc, 0)
        self.assertIn("api via jump: ssh tunnel via me@jump.example exited", out)
        self.assertIn("api: no route\n", out)

    @unittest.skipIf(WINDOWS, "POSIX signals")
    def test_ctrl_c(self):
        p = subprocess.Popen([sys.executable, CILCTL, "release", "3"], env=self.env, stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(1.5)
        p.send_signal(signal.SIGINT)
        out, err = p.communicate(timeout=30)
        self.assertEqual(p.returncode, 130, err)
        self.assertNotIn(b"Traceback", err)


class Profiles(Base):
    def two(self, default="a", extra=""):
        return self.config(('default = "%s"\n' % default if default else "") +
                           '[cil.a]\nurl = "%s/"\n\n[cil.b] # the same stub\nurl = "%s"\npool = "x86"\n'
                           'image = "ubuntu-24.04"\njump = "me@hop.example"\n%s' % (self.url, self.url, extra))

    def test_list_and_select(self):
        e = dict(self.two(), CILCTL_URL=None)
        rc, out, _ = self.run_cli("cils", env=e)
        self.assertEqual(rc, 0)
        self.assertEqual(out.splitlines(), [
            "*a url=%s pool=auto image=auto jump=none" % self.url,
            " b url=%s pool=x86 image=ubuntu-24.04 jump=me@hop.example" % self.url])
        self.assertIn("*b url=", self.run_cli("--cil", "b", "cils", env=e)[1])
        self.assertIn("*b url=", self.run_cli("cils", env=dict(e, CILCTL_CIL="b"))[1])
        rc, _, err = self.run_cli("--cil", "nope", "leases", env=e)
        self.assertNotEqual(rc, 0)
        self.assertIn("unknown cil 'nope' (profiles in %s: a, b)" % e["CILCTL_CONFIG"], err)
        self.assertNotEqual(self.run_cli("--cil=", "leases", env=e)[0], 0)

    def test_profile_lease_and_keys(self):
        # each profile posts its own pool and keeps its keys in its own dir
        e = dict(self.two(), CILCTL_URL=None)
        rc, out, err = self.run_cli("up", "--name", "t-a", env=e)
        self.assertEqual(rc, 0, err)
        self.assertEqual((self.last_post()["pool"], self.last_post()["image"]), ("arm64", "ubuntu-24.04-arm64"))
        self.assertNotIn("no profile", out)
        self.assertIn("  cilctl release 7 ", out)
        self.assertTrue(os.path.isfile(os.path.join(self.state, "a", "7", "key")))
        rc, out, err = self.run_cli("--cil", "b", "up", "--name", "t-b", env=e)
        # a pasted hint must reach the same CIL, not the default one
        self.assertIn("  cilctl --cil b release 7 ", out)
        self.assertIn("  cilctl --cil b ssh 7 ", out)
        self.assertEqual((self.last_post()["pool"], self.last_post()["image"]), ("x86", "ubuntu-24.04"))
        self.assertTrue(os.path.isfile(os.path.join(self.state, "b", "7", "key")))
        self.run_cli("--cil", "b", "ssh", "7", "true", env=e)
        a = self.recorded()["argv"]
        self.assertEqual(a[a.index("-i") + 1], os.path.join(self.state, "b", "7", "key"))
        self.assertIn("ProxyJump=me@hop.example", a)
        rc, out, _ = self.run_cli("release", "7", env=e)
        self.assertEqual((rc, out.strip()), (0, "status=released"))
        self.assertFalse(os.path.exists(os.path.join(self.state, "a", "7")))
        self.assertTrue(os.path.isdir(os.path.join(self.state, "b", "7")))
        rc, _, err = self.run_cli("--cil", "a", "ssh", "7", "true", env=e)
        self.assertIn("no key for lease 7 on a", err)
        rc, out, err = self.run_cli("--url", self.url, "--jump", "none", "up", env=e)
        self.assertIn("  cilctl --url %s --jump none release 7 " % self.url, out)

    def test_url_and_jump_precedence(self):
        e = self.two()
        # CILCTL_URL alone: no profile, not the default one
        self.run_cli("wait", "7", env=e)
        self.assertTrue(os.path.isdir(os.path.join(self.bare, "7")))
        self.assertFalse(os.path.exists(os.path.join(self.state, "a")))
        out = self.run_cli("cils", env=e)[1]
        self.assertIn("*(no profile) url=%s" % self.url, out)
        self.assertIn(" a url=", out)
        # an explicit profile keeps its pool, jump and state; --url wins
        dead = "http://127.0.0.1:%d" % closed_port()
        self.run_cli("--cil", "b", "--url", self.url, "up", "--name", "t-b", env=dict(e, CILCTL_URL=dead))
        self.assertEqual(self.last_post()["pool"], "x86")
        self.assertTrue(os.path.isdir(os.path.join(self.state, "b", "7")))
        self.run_cli("--cil", "b", "ssh", "7", "true", env=dict(e, CILCTL_JUMP="x@y"))
        self.assertIn("ProxyJump=x@y", self.recorded()["argv"])
        self.run_cli("--cil", "b", "--jump", "none", "ssh", "7", "true", env=e)
        self.assertFalse(any(x.startswith("ProxyJump") for x in self.recorded()["argv"]))
        rc, _, err = self.run_cli("--cil", "b", "leases", env=dict(e, CILCTL_URL="ftp://x"))
        self.assertIn("CILCTL_URL must be", err)
        rc, _, err = self.run_cli("leases", env=dict(self.config('[cil.a]\nurl = "ftp://x"\n'), CILCTL_URL=None,
                                                     CILCTL_CIL="a"))
        self.assertIn("cil.a: url must be http(s)://", err)

    def test_bad_config(self):
        u = 'url = "http://a"\n'
        for c, msg in (("[cil.a\n", "line 1: bad table header"),
                       ('[cil.x]\npool = "p"\n', "cil.x needs url"),
                       ('[cil.Bad]\n' + u, "starts with a letter"),
                       ('[cil.7]\n' + u, "starts with a letter"),
                       ('[cil.nul]\n' + u, "not a Windows device"),
                       ('[cil.x]\nurl = 1\n', "unknown key 'url' or wrong type"),
                       ('[cil.x]\n' + u + 'token = "t"\n', "unknown key 'token'"),
                       ('defualt = "a"\n', "top-level keys are default"),
                       ('default = "nope"\n', "default 'nope' is not a [cil.NAME] profile"),
                       ('[cil.x]\n' + u + u, "line 3: key url defined twice"),
                       ('[cil.x]\n' + u + '[cil.x]\n', "table [cil.x] defined twice"),
                       ('[cil.x]\nurl = "http://a" junk\n', "line 2: text after the value"),
                       ('[cil.x]\nurl = """x"""\n', "not supported"),
                       ('[cil.x]\nurl = [1]\n', "unsupported value"),
                       ('[cil.x]\nurl = "a\\qb"\n', "bad escape"),
                       ("[setup.s]\nprecheck = '''\nx\n", "unterminated '''"),
                       ('[cil.x]\n' + u + 'pool = "Bad Pool"\n', "bad pool or image name"),
                       ('[setup.s]\nalias = "a"\n', "setup.s needs model_url"),
                       (RECIPE.replace(SHA0, "abc"), "model_sha256 is 64 lower-case hex digits"),
                       (RECIPE.replace('"-ngl 99 -t 4 -dev A,B"', '"-x \\"q\\""'), "bad server_args"),
                       (RECIPE.replace("context = 4096", "context = true"), "unknown key 'context' or wrong type"),
                       (RECIPE.replace("reasoning = true", "reasoning = 1"), "unknown key 'reasoning'"),
                       (RECIPE.replace("tiny-q4.gguf", "tiny q4.gguf"), "bad model_url"),
                       (RECIPE.replace("cpu = 6", "cpu = -6"), "cpu must not be negative"),
                       (RECIPE + 'opencode_url = "https://example.com/oc.tgz"\n', "go together"),
                       ("[cil]\nx = 1\n", "cil.x must be a table"),
                       (RECIPE.replace("[setup.tiny]", "[setup.Tiny]"), "setup 'Tiny': a name is lower case")):
            rc, _, err = self.run_cli("cils", env=self.config(c))
            self.assertNotEqual(rc, 0, c)
            self.assertIn(msg, err, c)

    def test_recipe_name_may_start_with_a_digit(self):
        rc, out, err = self.run_cli("setups", env=self.config(RECIPE.replace("[setup.tiny]", "[setup.4b]")))
        self.assertEqual(rc, 0, err)
        self.assertTrue(out.startswith("4b model=tiny-q4.gguf"), out)

    def test_config_bom(self):
        # PowerShell 5.1 Set-Content -Encoding UTF8 writes a BOM
        rc, out, err = self.run_cli("cils", env=dict(self.config('\ufeffdefault = "a"\n[cil.a]\nurl = "%s"\n' % self.url),
                                                     CILCTL_URL=None))
        self.assertEqual(rc, 0, err)
        self.assertIn("*a url=", out)

    def test_hint_names_the_profile_jump(self):
        e = dict(self.config('[cil.a]\nurl = "http://127.0.0.1:%d"\n' % closed_port()), CILCTL_URL=None)
        rc, _, err = self.run_cli("--cil", "a", "leases", env=e)
        self.assertIn("set --jump, CILCTL_JUMP or the profile's jump", err)
        rc, out, _ = self.run_cli("--cil", "a", "doctor", env=e)
        self.assertIn("api: no route (set --jump, CILCTL_JUMP or the profile's jump)", out)
        self.assertIn("cil: a (pool auto)", out)

    def test_example_config(self):
        e = {"CILCTL_CONFIG": EXAMPLE, "CILCTL_URL": None}
        rc, out, err = self.run_cli("cils", env=e)
        self.assertEqual(rc, 0, err)
        self.assertEqual(out.splitlines(), [
            "*lab url=http://cil.example.com:8086 pool=arm64 image=ubuntu-24.04-arm64 jump=none",
            " remote url=http://192.0.2.10:8086 pool=auto image=auto jump=me@bastion.example.com:2222"])
        rc, out, _ = self.run_cli("setups", env=e)
        self.assertEqual(out.strip(), "small model=Qwen3-4B-Q4_K_M.gguf alias=qwen3-4b context=32768 npus=0 cpu=8 "
                                      "ram=16384 disk=40 ttl=240")


class Hints(Base):
    """Every command cilctl suggests repeats the flags that chose the CIL,
    so pasting one cannot reach the default profile's CIL instead."""

    def test_flags_repeated(self):
        u = "--url"
        c = "cilctl --url %s" % self.url
        rc, _, err = self.run_cli(u, self.url, "wait", "5")
        self.assertIn("key not kept (%s release 5)" % c, err)
        rc, _, err = self.run_cli(u, self.url, "ssh", "9", "true")
        self.assertIn("(run: %s wait 9)" % c, err)
        self.ready()
        rc, _, err = self.run_cli(u, self.url, "opencode", "7")
        self.assertIn("for a batch task: %s ssh 7 opencode run 'task'" % c, err)
        os.makedirs(os.path.join(self.bare, "3"))
        rc, _, err = self.run_cli(u, self.url, "release", "3")
        self.assertIn("lease 3 is still ready; %s release 3 again later" % c, err)
        rc, _, err = self.run_cli(u, self.url + "/fail", "up")
        self.assertIn("lease 8 is not ready; cilctl --url %s/fail events 8, then cilctl --url %s/fail release 8"
                      % (self.url, self.url), err)
        e = self.config(RECIPE)
        rc, out, _ = self.run_cli(u, self.url, "setup", "7", "tiny", env=e)
        self.assertIn("lease 7: %s opencode 7 | %s ssh 7 opencode run 'task' | %s forward 7" % (c, c, c), out)
        rc, _, err = self.run_cli(u, self.url, "up", "--setup", "tiny", env=dict(e, FAKE_RC="1"))
        self.assertIn("the lease is kept: %s ssh 7, or %s release 7" % (c, c), err)
        dead = "http://127.0.0.1:%d" % closed_port()
        rc, _, err = self.run_cli(u, dead, "leases")
        self.assertIn("see cilctl --url %s doctor)" % dead, err)

    def test_up_list(self):
        rc, out, _ = self.run_cli("--url", self.url, "--jump", "", "up")
        # --jump "" is direct, the same as none
        c = "cilctl --url %s --jump none " % self.url
        want = [(c + "ssh 7", "shell"), (c + "ssh 7 'cmd'", "one command"),
                (c + "copy 7 FILE :", "upload to ~ (:path downloads)"), (c + "extend 7 MIN", "before it expires"),
                (c + "release 7", "when done")]
        # one column for the descriptions, two spaces after the longest command
        w = max(len(x) for x, _ in want)
        self.assertEqual([l for l in out.splitlines() if l.startswith("  cilctl")],
                         ["  %s  %s" % (x.ljust(w), y) for x, y in want])

    def test_wait_timeout(self):
        m = load()
        m.POLL_N, m.POLL_S = 1, 0

        class Down:
            def raw(self, *a):
                raise m.ApiDown("down")

        class C:
            cmd = "cilctl --cil b"
            hint = m.Cfg.hint
        saved = sys.stderr
        sys.stderr = f = __import__("io").StringIO()
        try:
            self.assertEqual(m.wait(C(), Down(), 7), 1)
        finally:
            sys.stderr = saved
        self.assertIn("lease 7 not ready after 0 min (cilctl --cil b events 7)", f.getvalue())


class Toml(unittest.TestCase):
    CASES = [
        'a = "x"\nb = \'y\\n\'\nc = 12\nd = -3\ne = true\nf = false\ng = 1_000\n',
        '# c\n[t]  # c\nk = "q\\"\\\\\\t\\u00e9\\U0001F600" # c\n[t.u]\nk2 = \'\'\'\nl1\n  l2 "\'\n\'\'\'\n',
        "[ a . b ]\nk = '''one line'''\nm = '''\n'''\n",
        "x = ''''''\n",
    ]

    def test_against_tomllib(self):
        m = load()
        for c in self.CASES:
            got = m.parse_toml(c)
            if tomllib:
                self.assertEqual(got, tomllib.loads(c), c)
        self.assertEqual(m.parse_toml(self.CASES[1])["t"]["u"]["k2"], 'l1\n  l2 "\'\n')
        with open(EXAMPLE, encoding="utf-8") as f:
            text = f.read()
        if tomllib:
            self.assertEqual(m.parse_toml(text), tomllib.loads(text))
        self.assertEqual(m.parse_toml(RECIPE)["setup"]["tiny"]["precheck"],
                         '[ -r /x ] || { echo "it\'s not there"; exit 1; }\n')

    def test_errors(self):
        m = load()
        for c in ("a = 1.5", "a.b = 1", "a = [1]", "a = {b = 1}"):  # TOML, but not the subset
            with self.assertRaises(m.TomlError, msg=c):
                m.parse_toml(c)
        for c in ('a = "x', "a = 'x", "a = 01", "a = x", "= 1", "[a]\n[a]", "a = 1\na = 2",
                  "a = 1\n[a]", "a = \"\\x\"", 'a = "x" y'):
            with self.assertRaises(m.TomlError, msg=c):
                m.parse_toml(c)
            if tomllib:
                with self.assertRaises(Exception, msg=c):
                    tomllib.loads(c)


class Doctor(Base):
    def test_direct(self):
        self.ready()
        rc, out, _ = self.run_cli("doctor", "7")
        self.assertEqual(rc, 0, out)
        self.assertIn("api direct %s: ok" % self.url, out)
        self.assertIn("version 0.11.0 (route direct)", out)
        self.assertIn("lease 7 ssh direct: ok", out)
        self.assertIn("lease 7 route: direct", out)
        self.assertIn("cil: no profile (pool auto)", out)

    def test_no_route(self):
        e = dict(self.config('[cil.a]\nurl = "http://127.0.0.1:%d"\n' % closed_port()), CILCTL_URL=None)
        self.run_cli("--cil", "a", "--url", self.url, "wait", "7", env=e)
        rc, out, _ = self.run_cli("--cil", "a", "doctor", "7", env=dict(e, FAKE_RC="255"))
        self.assertEqual(rc, 1)
        self.assertIn("api: no route", out)
        self.assertIn("lease 7 route: none", out)


class License(unittest.TestCase):
    def test_spdx_headers(self):
        names = ["cilctl", "cilctl.cmd"]
        for d in ("tests", "tools"):
            if os.path.isdir(os.path.join(ROOT, d)):
                names += [os.path.join(d, n) for n in sorted(os.listdir(os.path.join(ROOT, d)))
                          if n.endswith((".py", ".sh"))]
        self.assertGreaterEqual(len(names), 5)
        for n in names:
            with open(os.path.join(ROOT, n), encoding="utf-8") as f:
                head = [f.readline().rstrip("\r\n") for _ in range(2)]
            self.assertTrue(any(h.endswith("SPDX-License-Identifier: BSD-2-Clause") for h in head), n)

    def test_license_file(self):
        with open(os.path.join(ROOT, "LICENSE"), "rb") as f:
            text = f.read().replace(b"\r\n", b"\n")
        self.assertTrue(text.startswith(b"BSD 2-Clause License\n\nCopyright (c) 2026, Tyler Baker\n"))
        # the whole text, so a dropped clause shows
        self.assertEqual(hashlib.sha256(text).hexdigest(), "62202d807008dd88e4140baf7155990a4c5f29666fe2f31d392aad8368d5cc87")


@unittest.skipUnless(BASH and shutil.which("git"), "tools/scrub.sh is a POSIX shell script")
class Scrub(unittest.TestCase):
    # built at run time, or the scrub of this repository would find them
    A, B, C = (".".join(map(str, o)) for o in ((10, 1, 2, 3), (10, 8, 8, 8), (192, 168, 7, 7)))

    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="cilctl-scrub-")
        self.r = os.path.join(self.d, "r")
        os.makedirs(os.path.join(self.r, "tools"))
        shutil.copy(os.path.join(ROOT, "tools", "scrub.sh"), os.path.join(self.r, "tools"))
        self.git("init", "-q")
        self.commit("README", "docs at 192.0.2.1\n", "add a readme")

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def git(self, *a):
        subprocess.run(["git", "-C", self.r, "-c", "user.name=T", "-c", "user.email=t@example.com"] + list(a),
                       check=True, stdout=subprocess.DEVNULL)

    def commit(self, name, text, msg):
        with open(os.path.join(self.r, name), "a") as f:
            f.write(text)
        self.git("add", "-A")
        self.git("commit", "-q", "-m", msg)

    def scrub(self, d=None, extra=""):
        r = subprocess.run(["sh", os.path.join(self.r, "tools", "scrub.sh")] + ([d] if d else []),
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=dict(os.environ, SCRUB_EXTRA=extra))
        return r.returncode, r.stdout.decode()

    def test_clean(self):
        self.assertEqual(self.scrub(), (0, "scrub: clean (2 files)\n"))

    def test_history(self):
        # an address added and removed again is still in the history
        self.commit("README", "host %s\n" % self.A, "add a host")
        with open(os.path.join(self.r, "README"), "w") as f:
            f.write("docs\n")
        self.git("commit", "-q", "-am", "drop the host")
        rc, out = self.scrub()
        self.assertEqual(rc, 1)
        self.assertIn("history:+host " + self.A, out)

    def test_message_of_scrub_only_commit(self):
        self.commit("tools/scrub.sh", "\n", "tools: tested on " + self.B)
        rc, out = self.scrub()
        self.assertEqual(rc, 1)
        self.assertIn("history:tools: tested on " + self.B, out)

    def test_tree_and_worktree(self):
        self.commit("notes", "ssh admin@%s\n" % self.C, "add notes")
        rc, out = self.scrub()
        self.assertEqual(rc, 1)
        self.assertIn("/notes:1:ssh admin@" + self.C, out)
        os.unlink(os.path.join(self.r, "notes"))
        self.git("commit", "-q", "-am", "drop notes")
        self.git("reset", "-q", "--hard", "HEAD~2")
        self.git("reflog", "expire", "--expire=now", "--all")
        self.git("gc", "-q", "--prune=now")
        # .git is a file in a worktree, naming the main tree's path
        w = os.path.join(self.d, "w")
        self.git("worktree", "add", "-q", w)
        extra = os.path.join(self.d, "extra.txt")
        with open(extra, "w") as f:
            f.write("cilctl-scrub-\n")
        self.assertEqual(self.scrub(w, extra), (0, "scrub: clean (2 files)\n"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
