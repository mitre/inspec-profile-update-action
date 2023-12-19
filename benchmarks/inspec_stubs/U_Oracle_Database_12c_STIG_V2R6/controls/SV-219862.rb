control 'SV-219862' do
  title 'The directory assigned to the AUDIT_FILE_DEST parameter must be protected from unauthorized access and must be stored in a dedicated directory or disk partition separate from software or other application files.'
  desc 'The AUDIT_FILE_DEST parameter specifies the directory where the database audit trail file is stored (when AUDIT_TRAIL parameter is set to ‘OS’, ‘xml’ or ‘xml, extended’ where supported by the DBMS). Unauthorized access or loss of integrity of the audit trail could result in loss of accountability or the ability to detect suspicious
activity. This directory also contains the audit trail of the SYS and SYSTEM accounts that captures privileged database events when the database is not running (when AUDIT_SYS_OPERATIONS parameter is set to TRUE).'
  desc 'check', "If Standard Auditing is used:

From SQL*Plus:

select value from v$parameter where name = 'audit_trail';
select value from v$parameter where name = 'audit_file_dest';

If audit_trail is NOT set to OS, XML or XML EXTENDED, this is not applicable (NA).

If audit_trail is set to OS, but the audit records are routed directly to a separate log server without writing to the local file system, this is not a finding.

On UNIX Systems:

ls -ld [pathname]

Replace [pathname] with the directory path listed from the above SQL command for audit_file_dest.

If permissions are granted for world access, this is a finding.

If any groups that include members other than the Oracle process and software owner accounts, DBAs, auditors, or backup accounts are listed, this is a finding.

Compare path to $ORACLE_HOME. If audit_file_dest is a subdirectory of $ORACLE_HOME, this is a finding.

On Windows Systems (From Windows Explorer):

Browse to the directory specified. Select and right-click on the directory, select Properties, select the Security tab. On Windows hosts, records are also written to the Windows application event log. The location of the application event log is listed under Properties for the log under the Windows console. The default location is C:\\WINDOWS\\system32\\config\\EventLogs\\AppEvent.Evt.

If permissions are granted to everyone, this is a finding. If any accounts other than the Administrators, DBAs, System group, auditors or backup operators are listed, this is a finding.

Compare path to %ORACLE_HOME%. If audit_file_dest is a subdirectory of %ORACLE_HOME%, this is a finding.

If Unified Auditing is used:
AUDIT_FILE_DEST parameter is not used in Unified Auditing"
  desc 'fix', 'For file-based auditing, establish an audit file directory separate from the Oracle Home.

Alter host system permissions to the AUDIT_FILE_DEST directory to the Oracle process and software owner accounts, DBAs, backup accounts, SAs (if required), and auditors.

Authorize and document user access requirements to the directory outside of the Oracle, DBA, and SA account list in the System Security Plan.'
  impact 0.5
  ref 'DPMS Target Oracle Database 12c'
  tag check_id: 'C-21573r533108_chk'
  tag severity: 'medium'
  tag gid: 'V-219862'
  tag rid: 'SV-219862r401224_rule'
  tag stig_id: 'O121-BP-025101'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-21572r533109_fix'
  tag 'documentable'
  tag legacy: ['SV-76455', 'V-61965']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
