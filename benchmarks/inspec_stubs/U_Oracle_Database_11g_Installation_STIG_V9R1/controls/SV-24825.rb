control 'SV-24825' do
  title 'The DBMS audit logs should be included in backup operations.'
  desc 'DBMS audit logs are essential to the investigation and prosecution of unauthorized access to the DBMS data. Unless audit logs are available for review, the extent of data compromise may not be determined and the vulnerability exploited may not be discovered. Undiscovered vulnerabilities could lead to additional or prolonged compromise of the data.'
  desc 'check', "Oracle audit events are logged to error logs, trace files, host system logs and may be stored in database tables.

For each Oracle database on the host, determine the location of the database audit trail.

From SQL*Plus:

  select value from v$parameter where name = 'audit_trail';

If the audit trail is directed to database tables (DB*), ensure the audit table data is included in the database backups.

Backups of host system log files are covered in host system security reviews and are not covered here.

Other Oracle log files include:

-  Listener trace file (specified in the listener.ora file)
-  SQLNet trace file (specified in the sqlnet.ora file)
-  Oracle database alert and trace files (specified in Oracle parameters):
  -- audit_file_dest
  -- db_recovery_file_dest
  -- diagnostic_dest – 11.1 and higher
  -- log_archive_dest
  -- log_archive_dest_n

If evidence of inclusion of all audit log files in regular DBMS or host backups does not exist, this is a Finding."
  desc 'fix', 'Document and implement locations of trace, log and alert locations in the System Security Plan.

Include all trace, log and alert files in regular backups.'
  impact 0.5
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-29390r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15117'
  tag rid: 'SV-24825r1_rule'
  tag stig_id: 'DG0176-ORACLE11'
  tag gtitle: 'DBMS audit log backups'
  tag fix_id: 'F-26416r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
