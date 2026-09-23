# AGENTS.md

This is a deployment repository, not a build project. It contains a systemd
service (Python 3 daemon), a network-readiness oneshot, their unit files,
and their sysconfig templates. There is no build, test suite, linter, or CI.
"Working in this repo" means editing the daemon/scripts or the unit and
sysconfig files; correctness is verified on a real Oracle Linux host with
`journalctl` and `systemctl`.

## Branch model

- `main` (this branch, primary) — Oracle Linux 8/9, Python 3 daemon at
  `libexec/oracle-systemd-service.py3`
- `python2` (legacy) — Oracle Linux 7 only, Python 2 daemon at
  `libexec/oracle-systemd-service`

Do all new work on `main`. If a fix clearly applies to both, consider
backporting to `python2`, but keep it strictly Python 2 compatible there
(`from io import open`, no `with` on `Popen`, no f-strings). When in doubt,
treat `main` as the canonical implementation.

## Repository layout and install mapping

Repo files map 1:1 to target locations on the host:

| Repo path                          | Install location              |
| ---------------------------------- | ----------------------------- |
| `libexec/oracle-systemd-service.py3` | `/usr/libexec/oracle-systemd-service` (**renamed**) |
| `libexec/network-reachable`        | `/usr/libexec/network-reachable` |
| `sysconfig/oracle`                 | `/etc/sysconfig/oracle`       |
| `sysconfig/network-reachable`      | `/etc/sysconfig/network-reachable` |
| `systemd/oracle.service`           | `/etc/systemd/system/`        |
| `systemd/network-reachable.service`| `/etc/systemd/system/`        |

Gotchas:
- `oracle.service` hardcodes `ExecStart=/usr/libexec/oracle-systemd-service`
  (no extension), but the repo file on `main` is named
  `oracle-systemd-service.py3`. The rename happens at install time (see
  INSTALL.md). If you rename the file in the repo, the unit must be updated
  to match.
- The libexec files must be `chmod 755` and `restorecon`'d after install
  (SELinux) or systemd/SELinux will refuse to exec them.

## Architecture and control flow

`oracle.service` (`Type=notify`, runs as **root**):

1. Parses `/etc/oratab` into a `multiprocessing.Manager` namespace
   (`oracle_ns` — shared state across processes; use it, don't add globals).
2. Starts the listener via `lsnrctl` in the ORACLE_HOME given by the
   `LISTENER_ORACLE_HOME` env var, then starts every oratab database via
   `sqlplus` (`startup`, or `startup mount` when the oratab flag is `S`;
   anything other than `Y`/`S` is skipped).
3. Spawns a `cgroups-checker` child that, every `CGROUP_CHECK_INTERVAL`
   seconds, finds PIDs of running `oracle`/`tnslsnr` binaries via `pidof`
   and appends missing PIDs to the service's `cgroup.procs` file.
4. Sends `READY=1` to systemd, then idles in a sleep loop until signalled.

Why step 3 exists (the whole point of the project): if a DB is (re)started
outside systemd, systemd loses track of its processes and will unmount the
filesystems during shutdown. Re-adding the PIDs to the cgroup — while the
daemon keeps the cgroup alive — lets systemd stop the DB cleanly.

Signal handling (the unit wires all of these):
- `SIGUSR2` = `KillSignal` in the unit: stop all DBs + listener, then exit.
- `SIGTERM`: stop the daemon only (DBs keep running).
- `SIGHUP` = `ExecReload`: re-parse `/etc/oratab` only.

`network-reachable.service` (`Type=oneshot`, `RemainAfterExit=yes`): pings
`TEST_HOST` (default `www.google.com`) up to `REPEAT` times (1s apart) via
`fping`, and is pulled in by `network-online.target` before
`oracle.service` (which is `After=`/`Requires=` it).

**Non-obvious:** the script *always exits 0* — success and exhausted
retries both `echo 0`. So it never fails the unit or blocks
`network-online.target`; it only *delays* boot by up to `REPEAT` seconds
while the network comes up. If you change the exit behavior, remember that
a failed unit in the chain would also affect `oracle.service`.

## Non-obvious constraints

- **Privilege model is load-bearing.** The parent process stays root
  deliberately: writing to `cgroup.procs` requires root. Privileges are
  dropped only inside each start/stop child via `setugid(SERVICE_USER)`
  (default user `oracle`, env `ORACLE_DATABASE_USER`). Do not move the
  privilege drop to the parent/main process — the cgroup sync would break.
- **`LISTENER_ORACLE_HOME` is checked at module level.** The daemon logs an
  error, sends `notify('ERRNO=1')`, and `sys.exit(1)` during import if it
  is unset. It is the only required config option; everything else has
  defaults.
- Config comes exclusively from `EnvironmentFile=/etc/sysconfig/oracle`
  (and `.../network-reachable`): `LISTENER_ORACLE_HOME` (required),
  `ORACLE_DATABASE_USER`, `CGROUP_CHECK_INTERVAL`, `TEST_HOST`, `REPEAT`.
  Adding a new option means touching the daemon, the sysconfig template,
  and INSTALL.md.
- `network-reachable` depends on **`fping`**, which is a separate package
  (`dnf install fping`) and easy to forget.
- The py3 daemon relies on the `python3-systemd` package
  (`from systemd import journal, daemon`).
- oratab lines need at least two colons; parsing strips `#` comments and
  skips blank/malformed lines silently.
- **Journal identifiers differ by design:** the unit sets
  `SyslogIdentifier=oracle-service`, but the daemon's `JournalHandler` uses
  `os.path.basename(__file__)` (→ `oracle-systemd-service` after install).
  When debugging, filter by unit (`journalctl -u oracle`), not by
  identifier.
- SQL/lsnrctl output is only captured and forwarded to the journal; the
  daemon does not assert on database state (it trusts sqlplus exiting).
- `run_sqlplus` and `lsnrctl` look up ORACLE_BASE by exec'ing
  `$ORACLE_HOME/bin/orabase`; failure there is non-fatal (warning only).

## Verification (no test suite)

- `python3 -m py_compile libexec/oracle-systemd-service.py3` (the file has
  a `.py3` extension; py_compile works on it directly).
- `bash -n libexec/network-reachable` for the shell script.
- On a test host: `systemctl daemon-reload`, `journalctl -u oracle -f`,
  `systemctl reload oracle` to test SIGHUP, `systemctl kill -s USR2
  oracle.service` to test the DB-stopping path.

## Conventions

- Keep the GPLv3 license header at the top of every `libexec/` file.
- All logging goes through the `logging` module with a `JournalHandler`
  (no print); debug lines use `log.debug` (log level default is INFO).
- Error log messages must name the file that actually failed, not a
  constant from elsewhere (a past copy-paste bug).
- Paths to the filesystem (cgroup, /proc, oratab) are written as raw
  strings (a past pylint fix); keep them raw.
- Commit style in this repo: short imperative subject lines, usually no
  body.
