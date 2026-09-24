# TODO / Improvements

Scan of `main` (Oracle Linux 8/9, Python 3 daemon). No in-code `TODO`/`FIXME`
markers exist; these are findings from a manual review.

## Daemon (`libexec/oracle-systemd-service.py3`)

### Correctness

- [ ] **Cgroup v2 support** — `get_cgroup_name()` only parses the v1
      `1:name=systemd:` line and `cgroups_checks()` hardcodes
      `/sys/fs/cgroup/systemd{...}`. Both break on a cgroup v2-only host.
      OL8/9 default to hybrid, so it works today, but v2-only is the trend.
- [ ] **`get_cgroup_name()` can return `None`** — then the checker builds
      `/sys/fs/cgroup/systemdNone/cgroup.procs` and the child dies with an
      unhandled `FileNotFoundError` (lines ~147, ~248).
- [ ] **`sync_pid_cgroups()` swallows `PermissionError`** — if the daemon
      loses root, cgroup sync silently degrades forever. Consider raising or
      escalating the error.
- [ ] **Signal handler does real work** — `handler_stop_oracle()` spawns
      processes and `join()`s inside the SIGUSR2 handler. A second SIGUSR2
      mid-stop causes re-entrancy; safer to set a flag and do the stop in
      `main()`.
- [ ] **Child exit codes never checked** — `join()` ignores failures; a
      failed `lsnrctl start` is invisible to the daemon (debug logs only).
      At least warn when `proc.exitcode != 0`.
- [ ] **`setugid()` uncaught `KeyError`** — if `ORACLE_DATABASE_USER` is a
      nonexistent user, start children crash with a traceback instead of a
      clear error.
- [ ] **`CGROUP_CHECK_INTERVAL`** — a non-integer in sysconfig crashes the
      daemon at import with a bare `ValueError`. Validate and exit with a
      clear message.

### Cleanups

- [ ] Dead code in `main()`: the `if oracle_ns.tnslsnr_oracle_home is not
      None: pass` block — the module-level check already exits on unset.
- [ ] `stop_db()` names its SQL string `startup_sql`; should be
      `shutdown_sql`.
- [ ] `pidof tnslsnr` matches *any* tnslsnr on the box — would adopt a
      listener from a different ORACLE_HOME into this cgroup.
- [ ] Typos in logs: "Succesfully" (start), "reregsiter" (cgroups-check
      comment), leftover debug line `#log.setLevel(logging.DEBUG)`.

## `libexec/network-reachable`

- [ ] Unquoted variables on the exit line: `exit $(networkup ${REPEAT} ${TEST_HOST})`.
- [ ] Inconsistent logging: success uses `${TEST_HOST}`, errors use `${2}`.
- [ ] Typo "quiting" in the give-up log message.

## Units & docs

- [ ] `INSTALL.md` does not mention the `pidof` dependency
      (`sysvinit-tools` package) — the daemon fails silently without it.
- [ ] `Requires=local-fs.target remote-fs.target` in `oracle.service` is
      largely redundant with `DefaultDependencies` (local-fs) — optional.
- [ ] `LimitMEMLOCK=128G` is unusual (RHEL default is effectively
      unlimited) — document the intent or drop it.
