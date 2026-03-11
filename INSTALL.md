
# Installation (Oracle Linux 7 / Python 2)

This branch (`python2`) supports **Oracle Linux 7 only**, using the
`systemd-python` package and a Python 2‑based daemon.

For Oracle Linux 8 or 9 (Python 3), use the **master** branch instead.

---

## Requirements

Install dependencies:

```bash
sudo yum install -y systemd-python python
```

---

## File placement

### 1. libexec

Place the Python 2 daemon in:

```
/usr/libexec/oracle-systemd-service

```

> On this branch the file is already named correctly — **no renaming required**.

Ensure proper permissions:

```bash
sudo chmod 755 /usr/libexec/oracle-systemd-service
sudo restorecon -v /usr/libexec/oracle-systemd-service
```

---

### 2. sysconfig configuration

Copy the files from the `sysconfig/` directory into:

```
/etc/sysconfig/
```

Then adjust the following values:

* **TEST_HOST** – host to ping during boot (default: `www.google.com`)
* **REPEAT** – number of ping retries
* **LISTENER_ORACLE_HOME** – ORACLE_HOME of the listener (required)
* **ORACLE_DATABASE_USER** – user under which DB + listener start (default `oracle`)
* **CGROUP_CHECK_INTERVAL** – seconds between cgroup PID refresh scans

---

### 3. systemd unit

Copy the `.service` files from `systemd/` into:

```
/etc/systemd/system/
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
This branch is maintained only for environments still running OL7 + Python 2.

