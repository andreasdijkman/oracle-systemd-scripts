## Installation
It's a simple job of copy all files to the right location, give them the right context, exec-mode and content where necessary.

This script depends on one extra systemd-package for python, besides python itself.

On Oracle Linux 7 you need to install `systemd-python`.
On Oracle Linuy 8 you need to install `python3-systemd`.

* Place the files inside the folder `libexec` in `/usr/libexec` and mark them executable. Don't forget the SELinux-context!
  * For Oracle Linux 7, you need the file python2-version of this script (ending in [.py2](libexec/oracle-systemd-service.py2)) and rename it to oracle-systemd-service
  * For Oracle Linux 8, you need the file python3-version of this script (ending in [.py3](libexec/oracle-systemd-service.py3)) and rename it to oracle-systemd-service
* Place the files inside the folder `sysconfig` in `/etc/sysconfig` and check the content:
  * network-reachable:
    * `TEST_HOST`: host that get's pinged during boot (default: www.google.com)
    * `REPEAT`: number of retries to ping the host (default 30)
  * oracle:
    * `LISTENER_ORACLE_HOME`: ORACLE_HOME of the Listener that needs to be started (no default)
    * `ORACLE_DATABASE_USER`: user under which the databases and listener are started (default oracle)
    * `CGROUP_CHECK_INTERVAL`: repeat interval in seconds of the cgroup pid list
* Place the file inside the folder `systemd` in `/etc/systemd/system` and run a `systemctl daemon-reload`

Enable both services and reboot the server.

## Problems
If any problems arise, please create a pull request or an issue. I created this repo to share my work and make it easier for others to accomplish the same thing. So any improvement are welcome!
