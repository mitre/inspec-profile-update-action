control 'SV-219703' do
  title 'The Oracle REMOTE_OS_ROLES parameter must be set to FALSE.'
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
  ref 'DPMS Target Oracle Database 11.2g'
  tag check_id: 'C-21428r306958_chk'
  tag severity: 'high'
  tag gid: 'V-219703'
  tag rid: 'SV-219703r401224_rule'
  tag stig_id: 'O112-BP-022000'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-21427r306959_fix'
  tag 'documentable'
  tag legacy: ['SV-68217', 'V-53977']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
