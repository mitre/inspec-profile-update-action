control 'SV-221159' do
  title 'MongoDB must enforce approved authorizations for logical access to information and system resources in accordance with applicable access control policies.'
  desc 'MongoDB must enforce approved authorizations for logical access to information and system resources in accordance with applicable access control policies.'
  desc 'check', 'Review the system documentation to determine the required levels of protection for DBMS server securables by type of login. Review the permissions actually in place on the server. If the actual permissions do not match the documented requirements, this is a finding.

MongoDB commands to view roles in a particular database:

db.getRoles(
{
rolesInfo: 1,
showPrivileges:true,
showBuiltinRoles: true
}
)'
  desc 'fix', 'Use createRole(), updateRole(), dropRole(), grantRole() statements to add and remove permissions on server-level securables, bringing them into line with the documented requirements.

MongoDB commands for role management can be found here:
https://docs.mongodb.com/v3.4/reference/method/js-role-management/'
  impact 0.7
  ref 'DPMS Target MongoDB Enterprise Advanced 3.x'
  tag check_id: 'C-22874r410971_chk'
  tag severity: 'high'
  tag gid: 'V-221159'
  tag rid: 'SV-221159r822435_rule'
  tag stig_id: 'MD3X-00-000020'
  tag gtitle: 'SRG-APP-000033-DB-000084'
  tag fix_id: 'F-22863r410972_fix'
  tag 'documentable'
  tag legacy: ['SV-96559', 'V-81845']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
