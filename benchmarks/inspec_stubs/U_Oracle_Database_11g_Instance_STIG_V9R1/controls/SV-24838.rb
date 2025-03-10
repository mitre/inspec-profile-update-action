control 'SV-24838' do
  title 'Remote database or other external access should use fully-qualified names.'
  desc 'The Oracle GLOBAL_NAMES parameter is used to set the requirement for database link names to be the same name as the remote database whose connection they define. By using the same name for both, ambiguity is avoided and unauthorized or unintended connections to remote databases are less likely.'
  desc 'check', "From SQL*Plus:

  select value from v$parameter where name = 'global_names';

If the value returned is FALSE, this is a Finding."
  desc 'fix', 'From SQL*Plus:

  alter system set global_names = TRUE scope = spfile;

NOTE: This parameter, if changed, will affect all currently defined Oracle database links.

The above SQL*Plus command will set the parameter to take effect at next system startup.'
  impact 0.5
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-29399r2_chk'
  tag severity: 'medium'
  tag gid: 'V-15660'
  tag rid: 'SV-24838r2_rule'
  tag stig_id: 'DG0192-ORACLE11'
  tag gtitle: 'DBMS fully-qualified name for remote access'
  tag fix_id: 'F-26424r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
