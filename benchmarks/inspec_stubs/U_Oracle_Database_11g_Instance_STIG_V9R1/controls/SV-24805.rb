control 'SV-24805' do
  title 'Changes to configuration options must be audited.'
  desc 'The AUDIT_SYS_OPERATIONS parameter is used to enable auditing of actions taken by the user SYS. The SYS user account is a shared account by definition and holds all privileges in the Oracle database. It is the account accessed by users connecting to the database with SYSDBA or SYSOPER privileges.'
  desc 'check', "From SQL*Plus:

  select value from v$parameter where name = 'audit_sys_operations';

If the value returned is FALSE, this is a Finding."
  desc 'fix', 'From SQL*Plus:

  alter system set audit_sys_operations = TRUE scope = spfile;

The above SQL*Plus command will set the parameter to take effect at next system startup.'
  impact 0.5
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-29371r2_chk'
  tag severity: 'medium'
  tag gid: 'V-15645'
  tag rid: 'SV-24805r3_rule'
  tag stig_id: 'DG0142-ORACLE11'
  tag gtitle: 'DBMS Privileged action audit'
  tag fix_id: 'F-26396r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
