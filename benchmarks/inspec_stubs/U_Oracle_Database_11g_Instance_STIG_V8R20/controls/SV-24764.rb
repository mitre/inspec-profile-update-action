control 'SV-24764' do
  title 'Access to sensitive data should be restricted to authorized users identified by the Information Owner.'
  desc 'The Oracle parameter file contains configuration settings that are applied to the database at database and instance startup. Unauthorized changes to these parameters could lead to a compromise of the database security posture. Oracle data and redo log files contain the data and transaction information that support the database use. Unauthorized access to these files bypasses access controls defined and enforced by the DBMS itself and can lead to a loss of confidentiality and integrity.'
  desc 'check', "Review file permissions defined for critical files.

Review the file permissions on the Binary initialization parameter file (the default name is spfile[SID].ora).

Binary initialization parameter files are by default located in the $ORACLE_HOME/dbs directory (UNIX) or %ORACLE_HOME%\\database directory (Windows).    

From SQL*Plus:
  select value from v$parameter where name = 'spfile';
  select member from v$logfile;
  select name from v$datafile;  
  select name from v$controlfile;
  
Check directory and file permissions for the files returned by the SQL commands above, for the files located in the $ORACLE_HOME/network/admin directory (UNIX) or %ORACLE_HOME%\\network\\admin directory (Windows) and the directory specified by the TNS_ADMIN environment variable, if defined.

On UNIX systems:

  ls –ld [pathname]

If permissions are granted for world access, this is a Finding.

If any groups that include members other than the Oracle process and software owner accounts, DBAs, auditors, or backup accounts are listed, this is a Finding.

On Windows Systems (From Windows Explorer):

 Browse to the directory specified.

 Select and right-click on the directory, select Properties, select the Security tab.

If permissions are granted to everyone, this is a Finding.

If any accounts other than the Oracle process and software owner accounts, Administrators, DBAs, System groups, auditors, or backup accounts are listed, this is a Finding."
  desc 'fix', 'Set UNIX permissions on critical files to 640 or more restrictive.

Check group membership of the group assigned access permissions to the database software to verify all members are authorized to have the assigned access.

Set Windows permissions to Full Control assigned to the Administrators, the Oracle service account and DBAs.

Remove any unauthorized account access.'
  impact 0.5
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-1005r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15630'
  tag rid: 'SV-24764r1_rule'
  tag stig_id: 'DG0122-ORACLE11'
  tag gtitle: 'Sensitive data access'
  tag fix_id: 'F-3800r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
