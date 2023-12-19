control 'SV-252155' do
  title 'The role(s)/group(s) used to modify database structure (including but not necessarily limited to tables, indexes, storage, etc.) and logic modules (stored procedures, functions, triggers, links to software external to MongoDB, etc.) must be restricted to authorized users.'
  desc 'If MongoDB were to allow any user to make changes to database structure or logic, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

Accordingly, only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.

Unmanaged changes that occur to the database software libraries or configuration can lead to unauthorized or compromised installations.'
  desc 'check', 'Run the following command to get the roles from a MongoDB database.

For each database in MongoDB:

use database
db.getRoles(
    {
      rolesInfo: 1,
      showPrivileges:true,
      showBuiltinRoles: true
    }
)

Run the following command to the roles assigned to users:

use admin
db.system.users.find()

Analyze the output and if any roles or users have unauthorized access, this is a finding. This will vary on an application basis.'
  desc 'fix', 'Use the following commands to remove unauthorized access to a MongoDB database.
 
db.revokePrivilegesFromRole()
db. revokeRolesFromUser()

MongoDB commands for role management can be found here:
https://docs.mongodb.com/v4.4/reference/method/js-role-management/'
  impact 0.5
  ref 'DPMS Target MongoDB Enterprise Advanced 4.x'
  tag check_id: 'C-55611r813845_chk'
  tag severity: 'medium'
  tag gid: 'V-252155'
  tag rid: 'SV-252155r813938_rule'
  tag stig_id: 'MD4X-00-002400'
  tag gtitle: 'SRG-APP-000133-DB-000362'
  tag fix_id: 'F-55561r813846_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
