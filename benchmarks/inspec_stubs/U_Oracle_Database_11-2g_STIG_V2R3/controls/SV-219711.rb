control 'SV-219711' do
  title 'Application role permissions must not be assigned to the Oracle PUBLIC role.'
  desc 'Application roles have been granted to PUBLIC. Permissions granted to PUBLIC are granted to all users of the database. Custom roles should be used to assign application permissions to functional groups of application users. The installation of Oracle does not assign role permissions to PUBLIC.'
  desc 'check', "From SQL*Plus:

select granted_role from dba_role_privs where grantee = 'PUBLIC';

If any roles are listed, this is a Finding."
  desc 'fix', 'Revoke role grants from PUBLIC.

Do not assign role privileges to PUBLIC.

From SQL*Plus:

revoke [role name] from PUBLIC;'
  impact 0.5
  ref 'DPMS Target Oracle Database 11.2g'
  tag check_id: 'C-21436r306982_chk'
  tag severity: 'medium'
  tag gid: 'V-219711'
  tag rid: 'SV-219711r401224_rule'
  tag stig_id: 'O112-BP-022800'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-21435r306983_fix'
  tag 'documentable'
  tag legacy: ['SV-68233', 'V-53993']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
