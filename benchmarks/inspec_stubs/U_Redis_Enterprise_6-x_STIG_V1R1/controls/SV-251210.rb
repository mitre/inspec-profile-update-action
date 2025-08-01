control 'SV-251210' do
  title 'Redis Enterprise DBMS must limit privileges to change software modules; to include stored procedures, functions, and triggers, and links to software external to Redis Enterprise DBMS.'
  desc 'If the system were to allow any user to make changes to software libraries, those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

Accordingly, only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.

Unmanaged changes that occur to the database software libraries or configuration can lead to unauthorized or compromised installations.

For Redis Enterprise this is largely handled by the RHEL OS. The OS audit logs record any changes made to the database software libraries, related applications, and configuration files. Redis Enterprise also generates audit logs by default.  All log entries are shown on the Log page in the Redis Enterprise web UI as well as written in the syslog. Only users in the admin role on the Redis Enterprise web UI and users with privileged access to the server can view, add, or remove modules. In both cases, this is logged.'
  desc 'check', 'The RHEL server OS must be STIG-compliant to ensure only appropriate users have access. Verify user ownership, group ownership, and permissions on the directories where the Redis logs, binaries ,and modules reside:

From Linux command line as root, perform the command ls –ald on the following directory paths: 
/var/opt/redislabs  - Default storage location for the cluster data, system logs, backups and ephemeral, persisted data
/var/opt/redislabs/log - System logs for Redis Enterprise Software
/var/opt/redislabs/run  - Socket files for Redis Enterprise Software
/etc/opt/redislabs  - Default location for cluster manager configuration and certificates
/opt/redislabs - Main installation directory for all Redis Enterprise Software binaries
/opt/redislabs/bin - Binaries for all the utilities for command line access and managements such as "rladmin" or "redis-cli"
/opt/redislabs/config - System configuration files
/opt/redislabs/lib - System library files
/opt/redislabs/sbin - System binaries for tweaking provisioning
 
If the user owner is not a defined admin, this is a finding.

If the group owner is not a defined admin group, this is a finding.

If the directory is more permissive than 700, this is a finding.

Review monitoring procedures and implementation evidence to verify monitoring of changes to database software libraries, related applications, and configuration files is done. This is performed on the RHEL OS utilizing syslog.

Verify the list of files, directories, and database application objects (procedures, functions, and triggers) being monitored is complete.

If monitoring does not occur or the list of monitored objects is not complete, this is a finding.'
  desc 'fix', 'Implement procedures to monitor for unauthorized changes to DBMS software libraries, related software application libraries, and configuration files. If a third-party automated tool is not employed, an automated job that reports file information on the directories and files of interest and compares them to the baseline report for the same will meet the requirement. Syslog can be used to track and monitor access, deletions, and modification actions of the Redis logs, system configuration files, and binaries stored on the RHEL OS.

Ensure that the permissions of the Redis logs, system configuration files, and binaries are set so that only those with admin privileges can modify them on the hosting RHEL OS. Permissions can be modified using the chmod command.'
  impact 0.5
  ref 'DPMS Target Redis Enterprise 6.x'
  tag check_id: 'C-54645r804818_chk'
  tag severity: 'medium'
  tag gid: 'V-251210'
  tag rid: 'SV-251210r804820_rule'
  tag stig_id: 'RD6X-00-007300'
  tag gtitle: 'SRG-APP-000133-DB-000179'
  tag fix_id: 'F-54599r804819_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
