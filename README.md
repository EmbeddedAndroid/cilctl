# cilctl

`cilctl` is a command line client for a CIL instance, a REST service
that leases short-lived Linux VMs. It requests a lease, waits for it,
keeps the VM's ssh key, and then gets you into the VM: a shell, one
command, file copies, a port forward, or an OpenCode session backed by a
model served with llama-server in the lease. It is one Python file
(standard library only) and runs on Linux, macOS and Windows.

```
cilctl up --name my-task          # request, wait, print how to connect
cilctl ssh 7                      # shell; cilctl ssh 7 'make -j8' runs one command
cilctl copy 7 build.log :         # upload to ~; cilctl copy 7 :out.tar.gz . downloads
cilctl release 7
```

## Install

Requirements: Python 3.9 or later and the OpenSSH client (`ssh`, `scp`).

Linux and macOS:

```
git clone <this repository> cilctl
mkdir -p ~/.local/bin
ln -s "$PWD/cilctl/cilctl" ~/.local/bin/cilctl
cilctl --url http://cil.example.com:8086 doctor
```

macOS ships python3 with the Xcode command line tools
(`xcode-select --install`), and OpenSSH.

Windows (PowerShell): install Python from python.org (it adds the `py`
launcher) and the OpenSSH client (Settings, System, Optional features,
"OpenSSH Client"; present by default on current Windows 10 and 11), then
define a `cilctl` function in your PowerShell profile:

```
$d = "$PWD\cilctl"
if (!(Test-Path $PROFILE)) { New-Item -ItemType File -Force $PROFILE | Out-Null }
Add-Content $PROFILE "function cilctl { py -3 '$d\cilctl' @args }"
. $PROFILE
cilctl --url http://cil.example.com:8086 doctor
```

The profile only loads under an execution policy that allows local
scripts (`Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`); without
it, run `py -3 $d\cilctl ...` directly. From PowerShell, do not call
`cilctl.cmd`: cmd reparses the arguments PowerShell hands it, so an
argument like `'ls|wc'` turns into a cmd pipe. `cilctl.cmd` is for
cmd.exe (put the repository directory on PATH), where quoted arguments
such as `cilctl ssh 7 "ls | wc -l"` reach the lease as typed.

## Choosing a CIL

The CIL is `--url URL`, else `$CILCTL_URL`, else the `url` of the
selected profile. Profiles live in `~/.config/cilctl/config.toml`
(`$XDG_CONFIG_HOME/cilctl/config.toml` when that is set, or the file
named by `$CILCTL_CONFIG`):

```
default = "lab"

[cil.lab]
url = "http://cil.example.com:8086"
pool = "arm64"                       # optional
image = "ubuntu-24.04-arm64"         # optional

[cil.remote]
url = "http://192.0.2.10:8086"
jump = "me@bastion.example.com:2222" # ssh ProxyJump chain, comma separated
```

`--cil NAME` (or `$CILCTL_CIL`) picks a profile; without one, the
`default` profile is used unless a URL was given on the command line or
in `$CILCTL_URL`, which then stands alone. `cilctl cils` lists the
profiles and marks the one selected. Without a `pool`, cilctl uses the
CIL's only pool (`$CILCTL_POOL` names one otherwise), and without an
`image`, that pool's only allowed image.

Lease keys are kept per profile (a bare URL gets its own directory), so
lease 7 on one CIL and lease 7 on another never share a key. Use the same
`--cil` or `--url` for every command on a lease.

`docs/config.example.toml` documents every key. The file is read as a
TOML subset: tables, strings (`"basic"`, `'literal'`, `'''multi-line
literal'''`), integers, booleans and comments.

## Reaching the CIL

cilctl first connects to the API directly. If that fails and jump hosts
are set (`--jump user@host[:port],...`, `$CILCTL_JUMP`, or the profile's
`jump`, in that order; `none` turns them off), API calls go through an
`ssh -L` tunnel to the last hop, and lease ssh and scp use the chain as
`ProxyJump`. An https API keeps its certificate check for the URL's host
name through the tunnel; for a private CA set `SSL_CERT_FILE` (Apple's
/usr/bin/python3 ignores it). Jump hosts are reached with your own ssh
keys and config (`BatchMode` for the tunnel, so an agent or key without
a passphrase is needed). `cilctl doctor [id]` reports which route
reaches the API and, given a lease id, the lease.

## Commands

```
cils | setups                 configured profiles and setup recipes
health | pools | hosts | images
leases [--all]                live leases; --all also lists released and failed ones
request <requester> [image] [cpu] [ram_mb] [disk_gb] [ttl_min] [npus]
wait <id>                     poll until ready and store the key
up [--name SLUG] [--image I] [--cpu N] [--ram MB] [--disk GB] [--ttl MIN]
   [--npus N] [--setup RECIPE]
setup <id> RECIPE
ssh <id> [cmd...]             one argument is a shell line; several are a
                              command and its arguments, quoted for you
opencode <id> [dir]           OpenCode TUI (needs a terminal)
forward <id> [local] [remote] 127.0.0.1:local to the lease's 127.0.0.1:remote
copy|scp <id> SRC... DST      lease paths start with ':'
apt <id>                      point the guest's apt sources at the CIL's mirror
extend <id> <min>
events <id>
release <id>
doctor [id]
```

`apt` rewrites the Ubuntu and Debian archive URLs to the CIL URL's
`/ubuntu`, `/ubuntu-ports`, `/debian` and `/debian-security` and runs
`apt-get update`; when that reports an error the old sources are put back.

`up` defaults to 2 CPUs, 2048 MB, 20 GB and 120 minutes, and names the
lease `cilctl-<user>`. Remote commands run with `~/.opencode/bin` and
`~/.local/bin` on PATH. On POSIX systems cilctl replaces itself with ssh
or scp, so the exit code, terminal and signals are ssh's; on Windows it
waits and passes the exit code on.

## Setup recipes

A `[setup.NAME]` table in the config describes a model to serve in a
lease:

```
[setup.small]
model_url = "https://models.example.com/qwen3-4b/Qwen3-4B-Q4_K_M.gguf"
model_sha256 = "<64 hex digits>"
alias = "qwen3-4b"
context = 32768
server_args = "-ngl 99 -t 8"
cpu = 8
ram = 16384
disk = 40
```

`cilctl up --setup small` leases a VM of the recipe's size (options given
to `up` win) and runs `cilctl setup <id> small`, which, in the guest:

1. runs the recipe's `precheck` shell snippet, if any, and stops with its
   output when it fails;
2. downloads the model to `~/models` (resuming a partial download, through
   the guest's proxy unless `model_direct = true`) and checks its sha256;
3. installs `cilctl-llama.service`, which runs `llama-server` on
   127.0.0.1:8080 with the model, `context`, `alias` and `server_args`
   (after sourcing `env_script`, if set); llama-server must be in the image;
4. installs OpenCode in `~/.opencode/bin` (a pinned linux-arm64 release,
   sha256 checked; `opencode_url` and `opencode_sha256` choose another
   build) and writes `~/.config/opencode/opencode.json` for the model. A
   config you edited is kept and the new one is written next to it as
   `opencode.json.cilctl-new`;
5. waits for `/health` and checks that the model answers a tool call.

Every step checks what is already there, so running setup again is safe.
Then `cilctl opencode <id>` opens OpenCode, `cilctl ssh <id> opencode run
'task'` runs a task in batch, and `cilctl forward <id>` puts the model's
OpenAI-compatible API on http://127.0.0.1:8080/v1 on your machine.

## Keys

A lease response carries the VM's private ssh key. cilctl parses the
responses and prints allowlisted fields only; it never prints key
material or raw lease JSON. The connection's user, host and port must be
plain names and a port number, or the key is not kept. The key is
written to `~/.cache/cilctl/<profile>/<id>/key` (`$CILCTL_STATE` moves
the root) with mode 0600, or with an ACL that grants only the current
user on Windows, and is deleted when the lease is released or found
failed.
Each lease has its own `known_hosts` next to its key.

## Environment

`CILCTL_URL`, `CILCTL_CIL`, `CILCTL_JUMP`, `CILCTL_POOL`, `CILCTL_CONFIG`,
`CILCTL_STATE`, and `CILCTL_SSH` / `CILCTL_SCP` (the ssh and scp binaries).
Command line options win over the environment, which wins over the
profile.

## Tests

Offline, against a stub API (no network), on any of the three OSes:

```
python3 tests/test_cilctl.py      # py -3 tests\test_cilctl.py on Windows
tools/scrub.sh                    # no internal hosts, addresses or keys
```

## License

BSD-2-Clause; see LICENSE.
