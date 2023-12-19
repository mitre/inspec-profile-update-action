control 'SV-24916' do
  title 'The Oracle REMOTE_OS_ROLES parameter should be set to FALSE.'
  desc 'Setting REMOTE_OS_ROLES to TRUE allows operating system groups to control Oracle roles. The default value of FALSE causes roles to be identified and managed by the database. If REMOTE_OS_ROLES is set to TRUE, a remote user could impersonate another operating system user over a network connection.'
  desc 'check', "From SQL*Plus:

  select value from v$parameter where name = 'remote_os_roles';

If the returned value is not FALSE or not documented in the System Security Plan as required, this is a Finding."
  desc 'fix', 'Document remote OS roles in the System Security Plan.

If not required, disable use of remote OS roles.

From SQL*Plus:

  alter system set remote_os_roles = FALSE scope = spfile;

The above SQL*Plus command will set the parameter to take effect at next system startup.'
  impact 0.7
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-29469r2_chk'
  tag severity: 'high'
  tag gid: 'V-2555'
  tag rid: 'SV-24916r2_rule'
  tag stig_id: 'DO3539-ORACLE11'
  tag gtitle: 'Oracle REMOTE_OS_ROLES parameter'
  tag fix_id: 'F-26533r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
