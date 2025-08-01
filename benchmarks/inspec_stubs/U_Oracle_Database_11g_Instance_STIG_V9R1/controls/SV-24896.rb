control 'SV-24896' do
  title 'Application role permissions should not be assigned to the Oracle PUBLIC role.'
  desc 'Application roles have been granted to PUBLIC. Permissions granted to PUBLIC are granted to all users of the database. Custom roles should be used to assign application permissions to functional groups of application users. The installation of Oracle does not assign role permissions to PUBLIC.'
  desc 'check', "From SQL*Plus:

  select granted_role from dba_role_privs where grantee = 'PUBLIC';

If any roles are listed, this is a Finding."
  desc 'fix', 'Revoke role grants from PUBLIC.

Do not assign role privileges to PUBLIC.

From SQL*Plus:

  revoke [role name] from PUBLIC;'
  impact 0.5
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-29447r2_chk'
  tag severity: 'medium'
  tag gid: 'V-3437'
  tag rid: 'SV-24896r2_rule'
  tag stig_id: 'DO0320-ORACLE11'
  tag gtitle: 'Oracle PUBLIC role privileges'
  tag fix_id: 'F-26510r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
