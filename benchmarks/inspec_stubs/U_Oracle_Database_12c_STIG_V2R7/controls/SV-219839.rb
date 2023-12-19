control 'SV-219839' do
  title 'Application role permissions must not be assigned to the Oracle PUBLIC role.'
  desc 'Permissions granted to PUBLIC are granted to all users of the database. Custom roles must be used to assign application permissions to functional groups of application users. The installation of Oracle does not assign role permissions to PUBLIC.'
  desc 'check', "From SQL*Plus:

  select granted_role from dba_role_privs where grantee = 'PUBLIC';

If any roles are listed, this is a finding."
  desc 'fix', 'Revoke role grants from PUBLIC.

Do not assign role privileges to PUBLIC.

From SQL*Plus:

  revoke [role name] from PUBLIC;'
  impact 0.5
  ref 'DPMS Target Oracle Database 12c'
  tag check_id: 'C-21550r533056_chk'
  tag severity: 'medium'
  tag gid: 'V-219839'
  tag rid: 'SV-219839r879887_rule'
  tag stig_id: 'O121-BP-022800'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-21549r533057_fix'
  tag 'documentable'
  tag legacy: ['SV-75933', 'V-61443']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
