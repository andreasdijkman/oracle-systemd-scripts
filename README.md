# Systemd-service to start and stop Oracle-databases
Under OracleLinux 7 and newer (or any other RHEL-clone, like CentOS) you can use systemd to start and stop the database during boot and shutdown of the system. When you start Oracle-databases with dbstart-script supplied by Oracle (`$ORACLE_HOME/bin/dbstart`), the databases are started inside a cgroup, which is tracked by systemd. Now systemd knows your Oracle-service has processes and it needs to stop the processes by running the stop-script. It also tracks the filesystem-usage of the database because the processes have files open on them. This process and filesystem tracking prevents early dismounts of filesystems during shutdown of the system.

If you restart you database outside of the systemd-service, because one of your database needs some parameter-change or you applied a patch, systemd has lost track of the database. Systemd is not aware at this moment that your database is running again (or still running for that matter) so systemd just unmounts the filesystems during shutdown of the system. During shutdown of the system, the Oracle-databases is doing a shutdown abort because all filesystems are gone and the dbstop just fails. Because systemd doesn't know the filesystem is still in use, it parallel stops services, which include filesystem-mounts that aren't in use by running services. This includes the filesystems that your databases are running on.

### Reregister databases with systemd
To avoid this, you can reregister the processes of the Oracle-database with systemd by adding the correct PIDs to the correct cgroup-procs-file, or one can run a script in crontab to do this. If all processes inside a service are gone, systemd also cleans up the cgroup so you can't add processes back to it.

By running a daemon as part of the systemd-service and inside the cgroup, the cgroup remains active so the processes can be added back to it. This daemon starts the database and reregisters the databases with systemd if they are (re)started. It scans the system of running databases registered in `/etc/oratab` and adds the PIDs back to the correct cgroup if they are not already in them. It also remains active after the databases and the listener are stopped so the cgroup remains active and databases can be added back to it.

## Systemd network-reachable.target
Part of the solution is the network-reachable target and service. When restarting the machine with physical, bonded or teamed interfaces, it can take some time (I've observed up to 15 seconds) that the network is actually up and reachable. This service is part of the network-reachable.target (which is normally empty under OL7) and pings a configured host (www.google.com by default). The network-reachable.target is online when this service successfully can ping the configured host. If you use a NFS or CIFS mount as backup for your Oracle-database (`db_recovery_file_dest`), the database will fail if the NFS or CIFS mount is unavailable. The mount of the NFS-mount will fail if the network is not up, hence the script to check if the network is ***REALLY*** up.

## Testing
I've tried to incorporate as much debugging and error-catching as possible but I can't catch everything. If you encounter some problems, please share it here, it always helps. Also if you see room for improvement, please share your thoughts.

I tested this on Oracle Linux 7.6+ with Oracle 12.2+ and on Oracle Linux 8.3+ with Oracle 19.

## Contributing ##
Please feel free to alter, enhance or debug the script, but please share your changes.
