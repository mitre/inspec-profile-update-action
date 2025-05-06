control 'SV-24832' do
  title 'DBMS software libraries should be periodically backed up.'
  desc 'The DBMS application depends upon the availability and integrity of its software libraries. Without backups, compromise or loss of the software libraries can prevent a successful recovery of DBMS operations.'
  desc 'check', 'Review evidence of Oracle database and dependent application files and directories.

For UNIX Systems:

  These files are found in the directories $ORACLE_BASE and $ORACLE_HOME.

For Windows Systems:

  The Oracle software directory is specified on a Windows host in the registry value HKLM\\SOFTWARE\\Oracle\\KEY_[ORACLE_HOME_NAME]\\ORACLE_HOME.

Other Oracle software including, but not limited to Oracle tools and utilities, are usually found on Windows platforms in the C:\\Program Files\\Oracle directory and subdirectories.
 
Third-party applications may be located in other directory structures.  

Review the System Security Plan for a list of all DBMS application software libraries to be included in software library backups.

If any software library files are not included in regular backups, this is a Finding.'
  desc 'fix', 'Configure backups to include all ORACLE home directories and subdirectories and any other Oracle application and third-party database application software libraries.'
  impact 0.5
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-29394r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15121'
  tag rid: 'SV-24832r1_rule'
  tag stig_id: 'DG0187-ORACLE11'
  tag gtitle: 'DBMS software file backups'
  tag fix_id: 'F-26420r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
