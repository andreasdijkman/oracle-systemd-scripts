# Installation (Oracle Linux 8 / 9, Python 3)

This branch (`main`) supports **Oracle Linux 8 and 9**, using Python 3-based
daemons.

For Oracle Linux 7 (Python 2), use the **python2** branch instead.

---

## Requirements

The combined `oracle.service` daemon uses the systemd Python bindings:

```bash
sudo dnf install -y python3-systemd
```

`oracle-listener.service` implements journald logging and systemd notification
itself, but installing `python3-systemd` remains necessary when the combined
`oracle.service` is installed.

The `network-reachable` service additionally requires `fping`:

```bash
sudo dnf install -y fping
```

The daemon uses `pidof` to find running Oracle processes for the cgroup
sync; it ships in the `sysvinit-tools` package:

```bash
sudo dnf install -y sysvinit-tools
```

---

## File placement

### 1. libexec

Place the combined Python 3 daemon in `/usr/libexec` and **rename it**,
dropping the `.py3` suffix (the combined unit references it without the
suffix):

```bash
sudo cp libexec/oracle-systemd-service.py3 /usr/libexec/oracle-systemd-service
```

Ensure proper permissions and SELinux context:

```bash
sudo chmod 755 /usr/libexec/oracle-systemd-service
sudo restorecon -v /usr/libexec/oracle-systemd-service
```

To install the separate listener unit, copy its daemon without the `.py3`
suffix as well:

```bash
sudo cp libexec/oracle-systemd-listener-service.py3 \
  /usr/libexec/oracle-systemd-listener-service
sudo chmod 755 /usr/libexec/oracle-systemd-listener-service
sudo restorecon -v /usr/libexec/oracle-systemd-listener-service
```

The network-reachable script goes in the same place, keeping its name:

```bash
sudo cp libexec/network-reachable /usr/libexec/network-reachable
sudo chmod 755 /usr/libexec/network-reachable
sudo restorecon -v /usr/libexec/network-reachable
```

---

### 2. sysconfig configuration

Copy the files from the `sysconfig/` directory into `/etc/sysconfig/`:

```bash
sudo cp sysconfig/oracle /etc/sysconfig/oracle
sudo cp sysconfig/network-reachable /etc/sysconfig/network-reachable
```

Then adjust the following values:

* **TEST_HOST** – host to ping during boot (default: `www.google.com`)
* **REPEAT** – number of ping retries (default: `30`)
* **LISTENER_NAME** – optional listener alias passed directly to `lsnrctl`
  (default: `LISTENER`). It is not checked against `listener.ora`.
* **LISTENER_ORACLE_HOME** – required Oracle home containing `bin/tnslsnr`,
  or `@LATEST@` to select the reverse-lexically-last `/etc/oratab` Oracle home
  containing that binary.
* **ORACLE_DATABASE_USER** – user under which DB + listener start (default `oracle`)
* **CGROUP_CHECK_INTERVAL** – seconds between cgroup PID refresh scans (default `120`)

---

### 3. systemd units

Copy the units needed for the chosen layout from `systemd/` into
`/etc/systemd/system/`:

```bash
sudo cp systemd/network-reachable.service /etc/systemd/system/

# Combined database-and-listener layout:
sudo cp systemd/oracle.service /etc/systemd/system/

# Or separate listener layout:
sudo cp systemd/oracle-listener.service /etc/systemd/system/
```

Reload systemd:

```bash
sudo systemctl daemon-reload
```

Enable `network-reachable.service` and **one** Oracle service layout:

```bash
sudo systemctl enable network-reachable.service

# Combined layout: starts the listener and all selected /etc/oratab databases.
sudo systemctl enable oracle.service

# Separate listener layout: manages only the listener.
# Do not enable this together with oracle.service.
# sudo systemctl enable oracle-listener.service
```

Start and inspect the separate listener service with:

```bash
sudo systemctl start oracle-listener.service
sudo systemctl status oracle-listener.service
sudo journalctl -u oracle-listener.service -f
```

Reloading it re-parses `/etc/oratab` and repeats listener selection:

```bash
sudo systemctl reload oracle-listener.service
```

Reboot to test:

```bash
sudo reboot
```

---

## Problems / Support

If you encounter issues, please create an issue or pull request.
Any improvement is welcome.
