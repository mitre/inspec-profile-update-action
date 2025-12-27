control 'SV-253727' do
  title 'MariaDB must allocate audit record storage capacity in accordance with organization-defined audit record storage requirements.'
  desc 'To ensure sufficient storage capacity for the audit logs, MariaDB must be able to allocate audit record storage capacity. Although another requirement (SRG-APP-000515-DB-000318) mandates that audit data be off-loaded to a centralized log management system, it remains necessary to provide space on the database server to serve as a buffer against outages and capacity limits of the off-loading mechanism.

The task of allocating audit record storage capacity is usually performed during initial installation of MariaDB and is closely associated with the DBA and system administrator roles. The DBA or system administrator will usually coordinate the allocation of physical drive space with the application owner/installer and the application will prompt the installer to provide the capacity information, the physical location of the disk, or both.

In determining the capacity requirements, consider such factors as total number of users; expected number of concurrent users during busy periods; number and type of events being monitored; types and amounts of data being captured; the frequency/speed with which audit records are off-loaded to the central log management system; and any limitations that exist on MariaDB s ability to reuse the space formerly occupied by off-loaded records.'
  desc 'check', "Investigate whether there have been any incidents where MariaDB ran out of audit file log disk space since the last time the space was allocated or other corrective measures were taken.

If there have been incidents where MariaDB ran out of audit log file disk space, this is a finding.

MariaDB can be configured to use syslog or any OS system file to store audit records to designated disk directories.

Check the log file location:

To check how much storage capacity is available for audit records, first determine the location where the audit logs are being written by executing the following command. Run the following SQL:

show global variables like  'server_audit%' ;

For system logs (syslog): 
     From the query above verify the value of:
       server_audit_output_type=SYSLOG

For OS file:
     From the query above verify the value of:
       server_audit_output_type=FILE

If written to SYSLOG, follow the procedure for storage in the corresponding OS STIG.

If written to FILE, check the remaining storage on the disk. If it does not meet organizationally defined audit record storage requirements, this is a finding."
  desc 'fix', 'MariaDB audit log file location either goes to the syslog directory (if logging is set to SYSLOG) or is controlled by the server_audit_file_path in the MariaDB my.cnf configuration file.

If the audit log file directory does not have enough disk space available, then increase the diskspace available for the audit log file directory or move the audit log file directory to another location that has more disk space available.
Allocate sufficient audit file space to support peak demand.
 
If server_audit_output_type=FILE set the directory in /etc/my.cnf to one that is managed by the centralized management system.

[mariadb]
server_audit_file_path=  mydir / mylogfilename .log 

Now, as the system administrator, restart the server with the new configuration: 
        $ systemctl restart mysqld
 
Allocate sufficient audit file space to support peak demand for the log files.'
  impact 0.5
  ref 'DPMS Target MariaDB Enterprise 10.x'
  tag check_id: 'C-57179r841704_chk'
  tag severity: 'medium'
  tag gid: 'V-253727'
  tag rid: 'SV-253727r841706_rule'
  tag stig_id: 'MADB-10-007300'
  tag gtitle: 'SRG-APP-000357-DB-000316'
  tag fix_id: 'F-57130r841705_fix'
  tag 'documentable'
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end
