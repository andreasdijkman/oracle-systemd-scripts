#!/usr/bin/env python3

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

# imports
import time
import signal
import subprocess
import os
import errno
import logging
import multiprocessing
from pwd import getpwuid
from pwd import getpwnam
from systemd import journal
from systemd.daemon import notify

# Declarations
manager = multiprocessing.Manager()
oracle_ns = manager.Namespace()

# Create some multi-process-aware variables
oracle_ns.oratab = dict()
oracle_ns.oracle_home_list = []
oracle_ns.running = True
oracle_ns.tnslsnr_oracle_home = None

ORATAB_LOCATION = '/etc/oratab'

# Setup logging
log = logging.getLogger(__name__)
log.addHandler(journal.JournalHandler(SYSLOG_IDENTIFIER=os.path.basename(__file__)))
# log.setLevel(logging.INFO)
log.setLevel(logging.DEBUG)

# Drop privileges during database cycle to following user
service_user = os.environ.get('ORACLE_DATABASE_USER', 'oracle')

# Interval for the cgroup-check-process
cgroup_check_interval = int(os.environ.get('CGROUP_CHECK_INTERVAL', 120))

# determine ORACLE_HOME of listener
oracle_ns.tnslsnr_oracle_home = os.environ['LISTENER_ORACLE_HOME']


# Define functions


def start_oracle_services():
    '''Method for starting all Oracle-services'''
    log.info('Starting Oracle Services')

    log.info('Starting Listener...')
    listener_name = 'LISTENER'
    startlsnrproc = multiprocessing.Process(target=lsnrctl_start,
                                            args=(oracle_ns.tnslsnr_oracle_home, listener_name),
                                            name='start-listener')
    startlsnrproc.start()
    startlsnrproc.join()

    log.info('Starting Oracle databases....')

    # Spawn database-starters for all databases sequentially
    for oratab_sid, oratab_item in oracle_ns.oratab.items():
        log.info('Processing database %s...', oratab_sid)
        notify('STATUS=Starting databases {}'.format(oratab_sid))
        startproc = multiprocessing.Process(target=start_db,
                                            args=(oratab_sid, oratab_item),
                                            name='start-proc-{}'.format(oratab_sid))
        startproc.start()
        # wait for them to complete
        startproc.join()

    notify('STATUS=Started all databases')
    log.info('Succesfully started all Oracle Services')


def stop_oracle_services():
    '''Method for starting all Oracle-services'''
    log.info('Stopping all databases...')
    notify('STATUS=Stopping all databases...')

    stop_list = []
    # Spawn stop-database-processes for all databases at once
    for oratab_sid, oratab_item in oracle_ns.oratab.items():
        log.info('Processing database %s...', oratab_sid)
        stopproc = multiprocessing.Process(target=stop_db,
                                           args=(oratab_sid, oratab_item),
                                           name='stop-proc-{}'.format(oratab_sid))
        stop_list.append(stopproc)
        stopproc.start()

    for proc in stop_list:
        # And wait for them to finish
        proc.join()

    log.info('Stopped all databases')
    notify('STATUS=Stopped all databases')

    log.info('Stopping Listener')
    listener_name = 'LISTENER'
    stoplsnrproc = multiprocessing.Process(target=lsnrctl_stop,
                                           args=(oracle_ns.tnslsnr_oracle_home, listener_name),
                                           name='stop-listener')
    stoplsnrproc.start()
    stoplsnrproc.join()


def cgroups_checks():
    '''Check if all Oracle-processes are inside the correct CGroup
    This is to register restarted databases with the processes to systemd so that databases
    can properly be stopped instead of being terminated by systemd
    No arguments required
    '''
    log.info('Running cgroups_checks...')
    # declare some variables
    cgroup_file = '/proc/{}/cgroup'.format(os.getpid())
    cgroup_name = get_cgroup_name(cgroup_file)

    log.debug('cgroups_checks running in cgroup %s', cgroup_name)

    while oracle_ns.running:
        # Declare some variables
        cgroup_proc_list_file = '/sys/fs/cgroup/systemd{}/cgroup.procs'.format(cgroup_name)
        oracle_home_procs = []
        tnslsnr_proc = []
        cgroup_diff_list = []

        log.debug('Used ORACLE_HOME\'s')
        log.debug('\n'.join(map(str, oracle_ns.oracle_home_list)))

        cgroup_proc_list = get_cgroup_procs(cgroup_proc_list_file)

        log.debug('Number of procs in cgroup: %i', len(cgroup_proc_list))

        # loop through the original ORACLE_HOME-list to check all running database-processes
        for oracle_home in oracle_ns.oracle_home_list:
            try:
                # get the pidlist of the running database-processes of this specific ORACLE_HOME
                oracle_home_procs = subprocess.check_output(
                    ['pidof', '{}/bin/oracle'.format(oracle_home)]).decode('utf-8').split()

                # Determine if there are differences between the cgroup-list and the ORACLE_HOME-pidlist
                cgroup_diff_list.extend(set(oracle_home_procs).difference(set(cgroup_proc_list)))
            except subprocess.CalledProcessError:
                log.debug('No running processes in ORACLE_HOME %s', oracle_home)

        if len(cgroup_diff_list) > 0:
            # if there are missing pids in the cgroup (differences are not 0)
            log.debug('ORACLE_HOME-processes not found in cgroup: %s', repr(cgroup_diff_list))
            log.debug('Sync cgroups ORACLE_HOME')
            sync_pid_cgroups(cgroup_proc_list_file, cgroup_diff_list)

        # clear the list and redo this for the tnslnsr-process
        cgroup_diff_list = []

        try:
            tnslsnr_proc = subprocess.check_output(['pidof', 'tnslsnr']).decode('utf-8').split()
            log.debug('TNSLSNR-processes found: %s', repr(tnslsnr_proc))
            cgroup_diff_list.extend(set(tnslsnr_proc).difference(set(cgroup_proc_list)))
        except subprocess.CalledProcessError:
            log.debug('No running process TNSLSNR found')

        if len(cgroup_diff_list) > 0:
            # if there are missing pids in the cgroup (differences are not 0)
            log.debug('TNSLSNR-process not found in cgroup: %s', repr(cgroup_diff_list))
            log.debug('Sync cgroups TNSLSNR')
            sync_pid_cgroups(cgroup_proc_list_file, cgroup_diff_list)

        # sleep for a defined amount of time
        time.sleep(cgroup_check_interval)

    log.info('cgroups_checks stopped')


def handler_stop_signals(_signum, _frame):
    '''We received a SIGTERM, so set the running-boolean to False to stop some loops'''
    log.info('Received TERM-signal')
    oracle_ns.running = False


def handler_stop_oracle(_signum, _frame):
    '''We received a SIGUSR2, so set the running-boolean to False to stop some loops
    Addionaly stop the Oracle-databases and the Listener
    '''
    log.info('Received STOP-signal')
    stop_oracle_services()
    oracle_ns.running = False


def handler_reloadoratab(_signum, _frame):
    '''We received a SIGHUP, so reload the oratab'''
    log.info('Received SIGHUP-signal')
    parseoratab()


def sync_pid_cgroups(cgroup_proc_list_file, cgroup_diff_list):
    '''Let's sync the pids to the cgroup'''
    try:
        # add all those pids to the cgroup by adding them one by one to the cgroups-proc-file
        with open(cgroup_proc_list_file, 'a') as cgroup_proc_fh:
            for non_cgroup_proc in cgroup_diff_list:
                cgroup_proc_fh.write(non_cgroup_proc.decode('utf-8'))
    except PermissionError:
        log.error('Permission denied reading file %s', ORATAB_LOCATION)
        raise
    except FileNotFoundError:
        log.error('File not found %s', ORATAB_LOCATION)
        raise


def get_cgroup_name(cgroup_file):
    '''Get the name of the cgroup from the cgroup file
    Argument is the cgroup file from the (current) process
    Returns the name of the cgroup'''

    try:
        cgroup_name = None
        with open(cgroup_file) as proc_fh:
            for line in proc_fh.readlines():
                # Kernel 4.14 format
                # 1:name=systemd:/system.slice/oracle.service
                if line.startswith('1:name'):
                    cgroup_name = line.split(':')[2].strip()
        return cgroup_name
    except PermissionError:
        log.error('Permission denied reading file %s', ORATAB_LOCATION)
        raise
    except FileNotFoundError:
        log.error('File not found %s', ORATAB_LOCATION)
        raise


def get_cgroup_procs(cgroup_proc_list_file):
    '''Get the processes in the cgroup
    Argument is the cgroup process file of the cgroup
    Returns a list of processes in the cgroup'''
    try:
        cgroup_proc_list = []
        with open(cgroup_proc_list_file) as proc_fh:
            for line in proc_fh.readlines():
                # remove linebreak which is the last character of the string
                cgroup_proc = line[:-1]
                cgroup_proc_list.append(cgroup_proc)
        return cgroup_proc_list
    except PermissionError:
        log.error('Permission denied reading file %s', ORATAB_LOCATION)
        raise
    except FileNotFoundError:
        log.error('File not found %s', ORATAB_LOCATION)
        raise


def setugid(user):
    '''Change process user and group ID

    Argument is a numeric user id or a user name
    '''
    try:
        passwd = getpwuid(int(user))
    except ValueError:
        passwd = getpwnam(user)

    uid = os.getuid()

    if uid != 0:
        # We're not root so, like, whatever dude
        log.warning('Not running as root. Cannot drop permissions.')
    elif passwd.pw_uid == uid:
        # We already run as the user
        log.warning('Already running as user %s, no need to switch', passwd.pw_name)
    else:
        log.debug('Switching to user %s', passwd.pw_name)
        os.initgroups(passwd.pw_name, passwd.pw_gid)
        os.setgid(passwd.pw_gid)
        os.setuid(passwd.pw_uid)
        os.environ['HOME'] = passwd.pw_dir


def parseoratab():
    '''Function to parse the contents of the oratab
    Default in /etc/oratab

    No arguments
    '''
    # Check if oratab exists
    log.info('Parsing oratab: %s', ORATAB_LOCATION)

    try:
        with open(ORATAB_LOCATION) as oratab_fh:
            # declare vars
            oratab = dict()
            oracle_home_list = []
            # loop through every line
            for line in oratab_fh.readlines():
                # find lines that start with comment
                line = line.split('#', 1)[0].strip()
                count = line.count(':')
                oratab_line_keys = ['oracle_home', 'oracle_flag']
                # if we find a usable line (not commented), parse it
                if count >= 2:
                    oracle_sid = line.split(':')[0]
                    oracle_home = line.split(':')[1]
                    oracle_flag = line.split(':')[2]
                    oratab_line_values = (oracle_home, oracle_flag)
                    # add new ORACLE_SID-dict to local oratab-var
                    oratab[oracle_sid] = (dict(zip(oratab_line_keys, oratab_line_values)))
                    # and if the ORACLE_HOME isn't in the list, add it to the local list
                    if oracle_home not in oracle_home_list:
                        oracle_home_list.append(oracle_home)
            # endfor

            # now assign the local dict and list to the global, MultiProcess-aware Manager-vars
            oracle_ns.oratab = oratab
            oracle_ns.oracle_home_list = oracle_home_list
    except PermissionError:
        log.error('Permission denied reading file %s', ORATAB_LOCATION)
        raise
    except FileNotFoundError:
        log.error('File not found %s', ORATAB_LOCATION)
        raise


def run_sqlplus(query, oratab_sid, oratab_item):
    '''Function to run sqlplus
    Arguments are:
    query as string
    ORACLE_SID as string
    oratab_line as dictionary with (at least) the keys oracle_home (2nd item) and oracle_flag (3rd item)
    '''
    # set some variables for later use
    oracle_home = oratab_item['oracle_home']

    # Copy the OS ENV and set the Oracle-ENV-variabels in that ENV
    sqlplus_env = os.environ.copy()
    sqlplus_env['PATH'] = sqlplus_env['PATH'] + ':{}/bin'.format(oracle_home)
    sqlplus_env['ORACLE_SID'] = oratab_sid
    sqlplus_env['ORACLE_HOME'] = oracle_home

    # Get ORACLE_BASE from the new ORACLE_HOME
    try:
        sqlplus_env['ORACLE_BASE'] = subprocess.check_output(
            '{}/bin/orabase'.format(oracle_home), env=sqlplus_env).decode('utf-8')
    except subprocess.CalledProcessError as cpe:
        log.warning('Cannot determin ORACLE_BASE by using %s/bin/orabase', oracle_home)
        log.debug('Error: %s', repr(cpe))

    try:
        # Print some debug-output
        log.debug('ORACLE_SID: %s', sqlplus_env['ORACLE_SID'])
        if sqlplus_env.get('ORACLE_BASE') is not None:
            log.debug('ORACLE_BASE: %s', sqlplus_env['ORACLE_BASE'])
        log.debug('ORACLE_HOME: %s', sqlplus_env['ORACLE_HOME'])

        # Run sqlplus
        with subprocess.Popen(['sqlplus', '-S', '/nolog'],
                              env=sqlplus_env,
                              stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE) as sqlplus:

            # interact with the running sqlplus and push the query
            (stdout, dummy_stderr) = sqlplus.communicate(query.encode('utf-8'))
            stdout_lines = stdout.decode('utf-8').split('\n')

            # Spit out the response of sqlplus
            for line in stdout_lines:
                log.debug('SQLPLUS> %s', repr(line))

    except OSError as ose:
        log.warning('Running sqlplus went wrong: %s', repr(ose))
    except ValueError as vale:
        log.warning('Invalid argument given: %s', repr(vale))


def lsnrctl(command, tnslsnr_oracle_home, tnslsnr_name):
    '''run the command lsnrctl with given argument
    Needs ENV-variable LISTENER_ORACLE_HOME to start the Listener
    '''
    listener_action_msg = {"start": "Starting", "stop": "Stopping"}

    log.info('%s TNSLSNR in %s', listener_action_msg[command], tnslsnr_oracle_home)
    # Copy the OS ENV and set the Oracle-ENV-variabels in that ENV
    tnslsnr_env = os.environ.copy()
    tnslsnr_env['PATH'] = tnslsnr_env['PATH'] + ':{}/bin'.format(tnslsnr_oracle_home)
    tnslsnr_env['ORACLE_HOME'] = tnslsnr_oracle_home
    try:
        # Try to get the env-variable ORACLE_BASE
        tnslsnr_env['ORACLE_BASE'] = subprocess.check_output(
            '{}/bin/orabase'.format(tnslsnr_oracle_home), env=tnslsnr_env).decode('utf-8')
    except subprocess.CalledProcessError as cpe:
        log.warning('Cannot determin ORACLE_BASE by using %s/bin/orabase', tnslsnr_oracle_home)
        log.debug('Error: %s', repr(cpe))

    try:
        # Print some debug-output
        if tnslsnr_env.get('ORACLE_BASE') is not None:
            log.debug('ORACLE_BASE: %s', tnslsnr_env['ORACLE_BASE'])
        log.debug('ORACLE_BASE: %s', tnslsnr_env['ORACLE_HOME'])

        # Try and start the listener
        with subprocess.Popen(['lsnrctl', command, tnslsnr_name],
                              env=tnslsnr_env,
                              stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE) as proc:

            # Interact with the command
            (stdout, dummy_stderr) = proc.communicate()
            # Spit out the response of lsnrctl
            stdout_lines = stdout.decode('utf-8').split('\n')
            for line in stdout_lines:
                log.debug('LSNRCTL> %s', repr(line))

    except OSError as ose:
        log.warning('Running lsnrctl went wrong: %s', repr(ose))
    except ValueError as vale:
        log.warning('Invalid argument given: %s', repr(vale))


def start_db(oratab_sid, oratab_item):
    '''Start the correct database in the correct mode by running a SQL-command'''
    # Try to set the correct user
    setugid(service_user)

    # get the start-mode of the database, normal or standby (mount)
    oracle_flag = oratab_item['oracle_flag']

    if oracle_flag in ('Y', 'S'):
        # If we need to start something, build the SQL-command
        log.info('Starting database %s', oratab_sid)
        startup_sql = '''
set head off feedback off
set pages 0 lines 300 trimspool on trimout on
connect / as sysdba
{}
exit
'''
        startup_mode = 'startup'
        if oracle_flag == 'S':
            # if it is a standby-database, add mount to the startup-mode
            startup_mode.join(' mount')
        run_sqlplus(startup_sql.format(startup_mode), oratab_sid, oratab_item)
    else:
        log.info('Skipping database %s', oratab_sid)


def stop_db(oratab_sid, oratab_item):
    '''Stop the correct database by running a SQL-command'''
    # Try to set the correct user
    setugid(service_user)

    # get the start-mode of the database, normal or standby (mount)
    oracle_flag = oratab_item['oracle_flag']
    if oracle_flag in ('Y', 'S'):
        # If we need to start something, we also need to stop it
        log.info('Stopping database %s', oratab_sid)
        startup_sql = '''
set head off feedback off
set pages 0 lines 300 trimspool on trimout on
connect / as sysdba
shutdown immediate
exit
'''
        run_sqlplus(startup_sql, oratab_sid, oratab_item)
    else:
        log.info('Skipping database %s', oratab_sid)


def lsnrctl_start(tns_orahome, tns_name):
    '''Stop the Listener by running lsnrctl with the supplied argument as the correct user'''

    # Try to set the correct user
    setugid(service_user)

    lsnrctl('start', tns_orahome, tns_name)


def lsnrctl_stop(tns_orahome, tns_name):
    '''Start the Listener by running lsnrctl with the supplied argument as the correct user'''
    # Try to set the correct user
    setugid(service_user)

    lsnrctl('stop', tns_orahome, tns_name)


def main():
    '''Main function to be called'''
    # catch some signals to handle systemd-stop-commands or just stop the daemon if accidentally killed
    signal.signal(signal.SIGTERM, handler_stop_signals)
    signal.signal(signal.SIGUSR2, handler_stop_oracle)
    signal.signal(signal.SIGHUP, handler_reloadoratab)

    if oracle_ns.tnslsnr_oracle_home is not None:
        pass
    else:
        raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT),
                                'Cannot find lsnrctl in %s', oracle_ns.tnslsnr_oracle_home)

    # First, parse /etc/oratab
    parseoratab()
    # Then, start the databases found in oratab in the correct ORACLE_HOME
    start_oracle_services()

    # Spawn the cgroups-check-process to reregsiter databases that are manually restarted, outside the systemd-process
    cgchecks = multiprocessing.Process(target=cgroups_checks, name='cgroups-checker')

    cgchecks.start()
    # Notify systemd the service has been started
    notify('READY=1')

    # Run in a loop with set interval until stopped by some SIGNALS
    while oracle_ns.running:
        time.sleep(cgroup_check_interval)

    # If we are stopped, regain control of the only running subprocess and stop it
    cgchecks.terminate()
    # And clean up the process-remainders by pulling it back in
    cgchecks.join()


if __name__ == '__main__':
    main()
