# Installation (Oracle Linux 8 / 9, Python 3)

This branch (`main`) supports **Oracle Linux 8 and 9**, using the
`python3-systemd` package and a Python 3-based daemon.

For Oracle Linux 7 (Python 2), use the **python2** branch instead.

---

## Requirements

Install the systemd python bindings:

```bash
sudo dnf install -y python3-systemd
```

The `network-reachable` service additionally requires `fping`:

```bash
sudo dnf install -y fping
```

---

## File placement

### 1. libexec

Place the Python 3 daemon in `/usr/libexec` and **rename it**, dropping the
`.py3` suffix (the unit file references it without the suffix):

```bash
sudo cp libexec/oracle-systemd-service.py3 /usr/libexec/oracle-systemd-service
```

Ensure proper permissions and SELinux context:

```bash
sudo chmod 755 /usr/libexec/oracle-systemd-service
sudo restorecon -v /usr/libexec/oracle-systemd-service
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
* **LISTENER_ORACLE_HOME** – ORACLE_HOME of the listener (required, no default)
* **ORACLE_DATABASE_USER** – user under which DB + listener start (default `oracle`)
* **CGROUP_CHECK_INTERVAL** – seconds between cgroup PID refresh scans (default `120`)

---

### 3. systemd units

Copy the `.service` files from `systemd/` into `/etc/systemd/system/`:

```bash
sudo cp systemd/oracle.service systemd/network-reachable.service /etc/systemd/system/
```

Reload systemd:

```bash
sudo systemctl daemon-reload
```

Enable services:

```bash
sudo systemctl enable oracle.service
sudo systemctl enable network-reachable.service
```

Reboot to test:

```bash
sudo reboot
```

---

## Problems / Support

If you encounter issues, please create an issue or pull request.
Any improvement is welcome.
