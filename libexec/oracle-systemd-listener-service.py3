#!/usr/bin/env python3

"""Run and keep an Oracle Net listener registered with systemd.

This daemon is the executable for ``oracle-listener.service``.  It runs as
root so it can re-attach listener processes to the service unit's cgroup, but
starts and stops ``lsnrctl`` in child processes after dropping privileges to
``ORACLE_DATABASE_USER`` (``oracle`` by default).  Keeping this parent daemon
in the unit's cgroup allows a listener restarted outside systemd to be attached
again, so systemd continues to track its processes during shutdown.

The daemon sends ``READY=1`` after the listener has started and starts a child
cgroup checker which periodically discovers ``tnslsnr`` processes and attaches
any process outside this service's cgroup to the systemd unit named by
``ORACLE_SYSTEMD_UNIT``.  ``oracle-listener.service`` supplies that variable
as its own unit name.

Listener selection is performed by :func:`parse_listener` after Oracle homes
are collected from ``/etc/oratab``.  Configuration is read from the service's
``EnvironmentFile=/etc/sysconfig/oracle``:

    LISTENER_NAME:
        Optional listener alias passed to ``lsnrctl``. Defaults to ``LISTENER``.

    LISTENER_ORACLE_HOME:
        Required Oracle home containing ``bin/tnslsnr``, or ``@LATEST@`` to
        choose the reverse-lexically-last home from ``/etc/oratab`` containing
        that binary.

    ORACLE_DATABASE_USER:
        Account used for ``lsnrctl`` child processes.  Defaults to ``oracle``.

    CGROUP_CHECK_INTERVAL:
        Seconds between listener PID cgroup checks.  Defaults to ``120``.

Signals are wired by the unit: ``SIGUSR2`` stops the listener and exits,
``SIGTERM`` stops only this daemon, and ``SIGHUP`` re-reads ``/etc/oratab`` and
repeats listener selection.
"""

import logging
import multiprocessing
import os
import signal
import socket
import struct
import subprocess
import sys
import time
from pwd import getpwnam
from pwd import getpwuid


ORATAB_LOCATION = '/etc/oratab'
JOURNAL_SOCKET = '/run/systemd/journal/socket'
SERVICE_USER = os.environ.get('ORACLE_DATABASE_USER', 'oracle')
CGROUP_CHECK_INTERVAL = int(os.environ.get('CGROUP_CHECK_INTERVAL', 120))


manager = multiprocessing.Manager()
oracle_ns = manager.Namespace()
oracle_ns.running = True
oracle_ns.oracle_home_list = []
oracle_ns.tnslsnr_oracle_home = None
oracle_ns.listener_name = 'LISTENER'


class JournalHandler(logging.Handler):
    priority_map = {
        logging.DEBUG: 7,
        logging.INFO: 6,
        logging.WARNING: 4,
        logging.ERROR: 3,
        logging.CRITICAL: 2,
    }

    def __init__(self, identifier):
        super().__init__()
        self.identifier = identifier
        self.exception_formatter = logging.Formatter()

    def emit(self, record):
        try:
            message = record.getMessage()
            if record.exc_info:
                message = '{}\n{}'.format(message, self.exception_formatter.formatException(record.exc_info))

            fields = {
                'MESSAGE': message,
                'PRIORITY': str(self.priority_map.get(record.levelno, 5)),
                'SYSLOG_IDENTIFIER': self.identifier,
                'LOGGER': record.name,
                'CODE_FILE': record.pathname,
                'CODE_LINE': str(record.lineno),
                'CODE_FUNC': record.funcName,
            }
            payload = bytearray()
            for key, value in fields.items():
                payload.extend(self._journal_field(key, value))

            with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
                sock.connect(JOURNAL_SOCKET)
                sock.sendall(payload)
        except OSError:
            sys.stderr.write('{}: {}\n'.format(record.levelname, record.getMessage()))
        except Exception:
            self.handleError(record)

    @staticmethod
    def _journal_field(key, value):
        key_bytes = key.encode('ascii')
        value_bytes = str(value).encode('utf-8', errors='replace')
        if b'\n' not in value_bytes:
            return key_bytes + b'=' + value_bytes + b'\n'
        return key_bytes + b'\n' + struct.pack('<Q', len(value_bytes)) + value_bytes + b'\n'


log = logging.getLogger(__name__)
log.addHandler(JournalHandler(os.path.basename(__file__)))
log.setLevel(logging.INFO)


def notify(state):
    notify_socket = os.environ.get('NOTIFY_SOCKET')
    if not notify_socket:
        return False

    if notify_socket[0] == '@':
        notify_socket = '\0' + notify_socket[1:]

    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
            sock.connect(notify_socket)
            sock.sendall(state.encode('utf-8'))
        return True
    except OSError as err:
        log.debug('Unable to notify systemd: %s', err)
        return False


def child_process_env(base_env=None):
    child_env = (base_env or os.environ).copy()
    child_env.pop('NOTIFY_SOCKET', None)
    return child_env


def setugid(user):
    try:
        passwd = getpwuid(int(user))
    except ValueError:
        passwd = getpwnam(user)

    uid = os.getuid()
    if uid != 0:
        log.warning('Not running as root. Cannot drop permissions.')
    elif passwd.pw_uid == uid:
        log.debug('Already running as user %s', passwd.pw_name)
    else:
        log.debug('Switching to user %s', passwd.pw_name)
        os.initgroups(passwd.pw_name, passwd.pw_gid)
        os.setgid(passwd.pw_gid)
        os.setuid(passwd.pw_uid)
        os.environ['HOME'] = passwd.pw_dir


def parse_oratab_homes():
    oracle_home_list = []
    log.info('Parsing oratab: %s', ORATAB_LOCATION)
    with open(ORATAB_LOCATION, mode='r', encoding='utf-8') as oratab_fh:
        for line in oratab_fh:
            line = line.split('#', 1)[0].strip()
            if not line:
                continue

            parts = line.split(':')
            if len(parts) < 3:
                continue

            oracle_home = parts[1]
            if oracle_home not in oracle_home_list:
                oracle_home_list.append(oracle_home)

    oracle_ns.oracle_home_list = oracle_home_list


def parse_listener():
    """Select the listener name and Oracle home used by ``lsnrctl``.

    ``parse_oratab_homes()`` must run first and populate
    ``oracle_ns.oracle_home_list`` from ``/etc/oratab``. On success, this
    function sets ``oracle_ns.tnslsnr_oracle_home`` and
    ``oracle_ns.listener_name``.

    ``LISTENER_NAME`` is only the alias passed to ``lsnrctl``; it defaults to
    ``LISTENER`` and is not looked up in ``listener.ora``. The Oracle home is
    always selected by ``LISTENER_ORACLE_HOME``:

    1. An explicit ``LISTENER_ORACLE_HOME`` is accepted only when it contains
       ``bin/tnslsnr``.

    2. ``LISTENER_ORACLE_HOME=@LATEST@`` selects the first reverse-lexically
       sorted Oracle Home from ``/etc/oratab`` that contains ``bin/tnslsnr``.
       This is path ordering rather than Oracle-version comparison.

    A missing, invalid, or unresolved ``LISTENER_ORACLE_HOME`` logs an error,
    notifies systemd with ``ERRNO=1``, and exits the daemon with status 1.
    """
    oracle_ns.listener_name = os.environ.get('LISTENER_NAME', 'LISTENER')

    if os.environ.get('LISTENER_ORACLE_HOME') is None:
        log.error('LISTENER_ORACLE_HOME not set, cannot start listener')
        notify('ERRNO=1')
        sys.exit(1)

    if os.environ['LISTENER_ORACLE_HOME'] == '@LATEST@':
        for oracle_home in sorted(oracle_ns.oracle_home_list, reverse=True):
            if os.path.isfile(os.path.join(oracle_home, 'bin', 'tnslsnr')):
                oracle_ns.tnslsnr_oracle_home = oracle_home
                log.info('Listener in latest OH: %s', oracle_ns.tnslsnr_oracle_home)
                return
        log.error('LISTENER_ORACLE_HOME misconfigured, cannot start latest listener')
        notify('ERRNO=1')
        sys.exit(1)

    if not os.path.isfile(os.path.join(os.environ['LISTENER_ORACLE_HOME'], 'bin', 'tnslsnr')):
        log.error('LISTENER_ORACLE_HOME misconfigured, cannot start listener')
        notify('ERRNO=1')
        sys.exit(1)

    oracle_ns.tnslsnr_oracle_home = os.environ['LISTENER_ORACLE_HOME']
    log.info('Listener OH: %s', oracle_ns.tnslsnr_oracle_home)


def lsnrctl(command, oracle_home, listener_name):
    listener_action_msg = {'start': 'Starting', 'stop': 'Stopping'}
    log.info('%s TNSLSNR in %s', listener_action_msg[command], oracle_home)

    env = child_process_env()
    env['PATH'] = env['PATH'] + ':{}/bin'.format(oracle_home)
    env['ORACLE_HOME'] = oracle_home

    try:
        env['ORACLE_BASE'] = subprocess.check_output(
            ['{}/bin/orabase'.format(oracle_home)], env=env).decode('utf-8').strip()
    except subprocess.CalledProcessError as err:
        log.warning('Cannot determine ORACLE_BASE by using %s/bin/orabase', oracle_home)
        log.debug('Error: %s', repr(err))

    output = subprocess.check_output(['lsnrctl', command, listener_name],
                                     env=env,
                                     stderr=subprocess.STDOUT).decode('utf-8', errors='replace').splitlines()
    for line in output:
        log.debug('LSNRCTL> %s', repr(line))


def lsnrctl_start(oracle_home, listener_name):
    setugid(SERVICE_USER)
    lsnrctl('start', oracle_home, listener_name)


def lsnrctl_stop(oracle_home, listener_name):
    setugid(SERVICE_USER)
    lsnrctl('stop', oracle_home, listener_name)


def discover_listener_pids():
    try:
        return sorted(set(subprocess.check_output(['pidof', 'tnslsnr']).decode('utf-8').split()), key=int)
    except subprocess.CalledProcessError:
        return []


def attach_pids_to_systemd_unit(pids):
    pids = get_pids_outside_own_cgroup(pids)
    if not pids:
        return

    unit_name = os.environ.get('ORACLE_SYSTEMD_UNIT', 'oracle-listener.service')
    command = [
        'busctl',
        'call',
        'org.freedesktop.systemd1',
        '/org/freedesktop/systemd1',
        'org.freedesktop.systemd1.Manager',
        'AttachProcessesToUnit',
        'ssau',
        unit_name,
        '',
        str(len(pids)),
    ] + pids

    try:
        subprocess.run(command,
                       env=child_process_env(),
                       stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE,
                       check=True)
    except subprocess.CalledProcessError as err:
        stderr = err.stderr.decode('utf-8', errors='replace').strip() if err.stderr else ''
        if stderr:
            log.warning('busctl stderr: %s', stderr)
        log.warning('Failed to attach listener processes with systemd D-Bus: %s', err)
    except FileNotFoundError as err:
        log.warning('Failed to attach listener processes with systemd D-Bus: %s', err)


def get_pids_outside_own_cgroup(pids):
    try:
        own_cgroup_path = get_process_cgroup_path(os.getpid())
    except OSError as err:
        log.warning('Cannot determine own cgroup, attaching all discovered processes: %s', err)
        return pids

    missing_pids = []
    for pid in pids:
        try:
            pid_cgroup_path = get_process_cgroup_path(pid)
        except FileNotFoundError:
            continue
        except OSError:
            missing_pids.append(pid)
            continue

        if pid_cgroup_path != own_cgroup_path and not pid_cgroup_path.startswith(own_cgroup_path + '/'):
            missing_pids.append(pid)

    return missing_pids


def get_process_cgroup_path(pid):
    with open('/proc/{}/cgroup'.format(pid), mode='r', encoding='utf-8') as proc_fh:
        cgroup_path = None
        for line in proc_fh:
            parts = line.strip().split(':', 2)
            if len(parts) != 3:
                continue
            if parts[0] == '0':
                return parts[2]
            if parts[1] == 'name=systemd':
                cgroup_path = parts[2]

    if cgroup_path is None:
        raise FileNotFoundError('systemd cgroup entry not found for PID {}'.format(pid))
    return cgroup_path


def cgroups_checks():
    log.info('Running cgroups_checks for listener...')
    while oracle_ns.running:
        attach_pids_to_systemd_unit(discover_listener_pids())
        time.sleep(CGROUP_CHECK_INTERVAL)
    log.info('cgroups_checks stopped for listener')


def handler_stop_signals(_signum, _frame):
    log.info('Received TERM-signal')
    oracle_ns.running = False


def handler_stop_listener(_signum, _frame):
    log.info('Received STOP-signal')
    stopproc = multiprocessing.Process(target=lsnrctl_stop,
                                       args=(oracle_ns.tnslsnr_oracle_home, oracle_ns.listener_name),
                                       name='stop-listener')
    stopproc.start()
    stopproc.join()
    if stopproc.exitcode != 0:
        log.error('Listener stop process failed with exit code %s', stopproc.exitcode)
    oracle_ns.running = False


def handler_reload_oratab(_signum, _frame):
    log.info('Received SIGHUP-signal')
    parse_oratab_homes()
    parse_listener()


def main():
    signal.signal(signal.SIGTERM, handler_stop_signals)
    signal.signal(signal.SIGUSR2, handler_stop_listener)
    signal.signal(signal.SIGHUP, handler_reload_oratab)

    parse_oratab_homes()
    parse_listener()

    notify('STATUS=Starting listener {}'.format(oracle_ns.listener_name))
    startproc = multiprocessing.Process(target=lsnrctl_start,
                                        args=(oracle_ns.tnslsnr_oracle_home, oracle_ns.listener_name),
                                        name='start-listener')
    startproc.start()
    startproc.join()
    if startproc.exitcode != 0:
        log.error('Listener start process failed with exit code %s', startproc.exitcode)
        notify('ERRNO=1')
        return startproc.exitcode

    attach_pids_to_systemd_unit(discover_listener_pids())

    cgchecks = multiprocessing.Process(target=cgroups_checks, name='cgroups-checker-listener')
    cgchecks.start()

    notify('READY=1\nSTATUS=Started listener {}'.format(oracle_ns.listener_name))
    log.info('Started listener %s', oracle_ns.listener_name)

    while oracle_ns.running:
        time.sleep(CGROUP_CHECK_INTERVAL)

    cgchecks.terminate()
    cgchecks.join()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
