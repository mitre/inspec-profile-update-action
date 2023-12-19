control 'SV-24872' do
  title 'The directory assigned to the AUDIT_FILE_DEST parameter should be protected from unauthorized access.'
  desc 'The AUDIT_FILE_DEST parameter specifies the directory where the database audit trail file is stored (when AUDIT_TRAIL parameter is set to ‘OS’, ‘xml’ or ‘xml, extended’ where supported by the DBMS). Unauthorized access or loss of integrity of the audit trail could result in loss of accountability or the ability to detect suspicious activity. This directory also contains the audit trail of the SYS and SYSTEM accounts that captures privileged database events when the database is not running (when AUDIT_SYS_OPERATIONS parameter is set to TRUE).'
  desc 'check', "From SQL*Plus:
  select value from v$parameter where name = 'audit_trail';
  select value from v$parameter where name = 'audit_file_dest';

If audit_trail is NOT set to TRUE, OS, XML or XML, EXTENDED per MetaLink Note 30690.1, this check is Not a Finding.

On UNIX Systems:
  ls -ld [pathname]

Substitute [pathname] with the directory path listed from the above SQL command for audit_file_dest.

If permissions are granted for world access, this is a Finding.

If any groups that include members other than the Oracle process and software owner accounts, DBAs, auditors, or backup accounts are listed, this is a Finding.

On Windows Systems (From Windows Explorer):
  Browse to the directory specified. Select and right-click on the directory, select Properties, select the Security tab. On Windows hosts, records are also written to the Windows application event log. The location of the application event log is listed under Properties for the log under the Windows console. The default location is C:\\WINDOWS\\system32\\config\\EventLogs\\AppEvent.Evt.

If permissions are granted to everyone, this is a Finding. If any accounts other than the Administrators, DBAs, System group, auditors or backup operators are listed, this is a Finding."
  desc 'fix', 'Alter host system permissions to the AUDIT_FILE_DEST directory to the Oracle process and software owner accounts, DBAs, backup accounts, SAs (if required) and auditors.

Authorize and document user access requirements to the directory outside of the Oracle, DBA and SA account list in the System Security Plan.'
  impact 0.5
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-26538r1_chk'
  tag severity: 'medium'
  tag gid: 'V-3850'
  tag rid: 'SV-24872r1_rule'
  tag stig_id: 'DO0234-ORACLE11'
  tag gtitle: 'Oracle AUDIT_FILE_DEST parameter'
  tag fix_id: 'F-26455r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
