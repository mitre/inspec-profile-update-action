control 'SV-219831' do
  title 'The Oracle REMOTE_OS_ROLES parameter must be set to FALSE.'
  desc 'Setting REMOTE_OS_ROLES to TRUE allows operating system groups to control Oracle roles. The default value of FALSE causes roles to be identified and managed by the database. If REMOTE_OS_ROLES is set to TRUE, a remote user could impersonate another operating system user over a network connection.'
  desc 'check', "From SQL*Plus:

  select value from v$parameter where name = 'remote_os_roles';

If the returned value is not FALSE or not documented in the System Security Plan as required, this is a finding."
  desc 'fix', 'Document remote OS roles in the System Security Plan.

If not required, disable use of remote OS roles.

From SQL*Plus:

  alter system set remote_os_roles = FALSE scope = spfile;

The above SQL*Plus command will set the parameter to take effect at next system startup.'
  impact 0.7
  ref 'DPMS Target Oracle Database 12c'
  tag check_id: 'C-21542r533032_chk'
  tag severity: 'high'
  tag gid: 'V-219831'
  tag rid: 'SV-219831r533034_rule'
  tag stig_id: 'O121-BP-022000'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-21541r533033_fix'
  tag 'documentable'
  tag legacy: ['SV-75917', 'V-61427']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
