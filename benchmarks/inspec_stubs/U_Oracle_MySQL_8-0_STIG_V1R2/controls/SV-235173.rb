control 'SV-235173' do
  title 'The MySQL Database Server 8.0 must allocate audit record storage capacity in accordance with organization-defined audit record storage requirements.'
  desc "To ensure sufficient storage capacity for the audit logs, the Database Management System (DBMS) must be able to allocate audit record storage capacity. Although another requirement (SRG-APP-000515-DB-000318) mandates that audit data be off-loaded to a centralized log management system, it remains necessary to provide space on the database server to serve as a buffer against outages and capacity limits of the off-loading mechanism.

The task of allocating audit record storage capacity is usually performed during initial installation of the DBMS and is closely associated with the DBA and system administrator roles. The DBA or system administrator will usually coordinate the allocation of physical drive space with the application owner/installer and the application will prompt the installer to provide the capacity information, the physical location of the disk, or both.

In determining the capacity requirements, consider such factors as: total number of users; expected number of concurrent users during busy periods; number and type of events being monitored; types and amounts of data being captured; the frequency/speed with which audit records are off-loaded to the central log management system; and any limitations that exist on the DBMS's ability to reuse the space formerly occupied by off-loaded records."
  desc 'check', %q(Check the server documentation for the SQL Audit file size configurations. Locate the Audit file path and drive. 

SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_variables
WHERE VARIABLE_NAME = 'audit_log_file'
 OR VARIABLE_NAME= 'datadir'
 OR VARIABLE_NAME = 'audit_log_rotate_on_size';

If the value of audit_log_file contains a path, for example:
/var/log/mysql/audit.log
This is the location of the audit log, and the location to assess the storage capacity.

If the value of audit_log_file is the filename alone, for example:
audit.log
The audit logs are located in the path returned by datadir.

Calculate the space needed based on the audit file size and number of audit files to be stored simultaneously. 

Note that MySQL does not delete log files; that requires third-party tools or custom scripts.

If the calculated product of the "audit_log_rotate_on_size" times the number of audit files allowed will exceed the size of the storage location, this is a finding.)
  desc 'fix', 'Review the MySQL Audit file location, ensure the destination has enough space available to accommodate the maximum total size of all files that could be written. 

Use a script or third-party tool to manage the maximum number of audit log files that are to be stored, staying within the number of logs the system was sized to support. 

Use compression and JSON format to reduce file growth.

Update the location for audit_log_file in the MySQL configuration file, for example:
[mysqld]
audit-log-file=/var/log/mysql/audit.log
audit-log-format=JSON
audit-log-compression=GZIP'
  impact 0.5
  ref 'DPMS Target Oracle MySQL 8.0'
  tag check_id: 'C-38392r623639_chk'
  tag severity: 'medium'
  tag gid: 'V-235173'
  tag rid: 'SV-235173r623641_rule'
  tag stig_id: 'MYS8-00-009600'
  tag gtitle: 'SRG-APP-000357-DB-000316'
  tag fix_id: 'F-38355r623640_fix'
  tag 'documentable'
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end
