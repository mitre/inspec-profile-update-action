control 'SV-252150' do
  title 'MongoDB must enforce approved authorizations for logical access to information and system resources in accordance with applicable access control policies.'
  desc 'MongoDB must enforce approved authorizations for logical access to information and system resources in accordance with applicable access control policies.'
  desc 'check', 'The MongoDB administrator must ensure that additional application access control is enforced. 

Review the system documentation to determine the required levels of protection for MongoDB server securables by type of login. 

Review the permissions actually in place on the server. If the actual permissions do not match the documented requirements, this is a finding.

Run MongoDB command to view roles and privileges in a particular database:

 use database
 db.getRoles(
    {
      rolesInfo: 1,
      showPrivileges:true,
      showBuiltinRoles: true
    }
)'
  desc 'fix', 'Use 
createRole(), 
updateRole(), 
dropRole(), 
grantRole() statements 
to add and remove permissions on MongoDB serverl securables, bringing them into line with the documented requirements.

MongoDB commands for role management can be found here:
https://docs.mongodb.com/v4.4/reference/method/js-role-management/'
  impact 0.5
  ref 'DPMS Target MongoDB Enterprise Advanced 4.x'
  tag check_id: 'C-55606r813830_chk'
  tag severity: 'medium'
  tag gid: 'V-252150'
  tag rid: 'SV-252150r813832_rule'
  tag stig_id: 'MD4X-00-001700'
  tag gtitle: 'SRG-APP-000033-DB-000084'
  tag fix_id: 'F-55556r813831_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
