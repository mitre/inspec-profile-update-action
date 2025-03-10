control 'SV-96625' do
  title 'MongoDB must enforce access restrictions associated with changes to the configuration of MongoDB or database(s).'
  desc 'Failure to provide logical access restrictions associated with changes to configuration may have significant effects on the overall security of the system.

When dealing with access restrictions pertaining to change control, it should be noted that any changes to the hardware, software, and/or firmware components of the information system can potentially have significant effects on the overall security of the system.

Accordingly, only qualified and authorized individuals should be allowed to obtain access to system components for the purposes of initiating changes, including upgrades and modifications.'
  desc 'check', 'Review the security configuration of the MongoDB database(s).

If unauthorized users can start the mongod or mongos processes or edit the MongoDB configuration file (default location: /etc/mongod.conf), this is a finding. 

If MongoDB does not enforce access restrictions associated with changes to the configuration of the database(s), this is a finding.

To assist in conducting reviews of permissions, the following MongoDB commands describe permissions of databases and users: 

Permissions of concern in this respect include the following, and possibly others: 
- any user with a role of userAdminAnyDatabase role or userAdmin role 
- any database or with a user have a role or privilege with "C" (create) or "w" (update) privileges that are not necessary

MongoDB commands to view roles in a particular database: 
db.getRoles( { rolesInfo: 1, showPrivileges:true, showBuiltinRoles: true })'
  desc 'fix', %q(Prereq: To view a user's roles, must have the "viewUser" privilege.
https://docs.mongodb.com/v3.4/reference/privilege-actions/ 

Connect to MongoDB.

For each database, identify the user's roles for the database. 

use <database> 
db.getUser("[username]") 

The server will return a document with the user's roles. 

To revoke a user's role from a database use the db.revokeRolesFromUser() method.
https://docs.mongodb.com/v3.4/reference/method/db.revokeRolesFromUser/

To grant a role to a user use the db.grantRolesToUser() method. https://docs.mongodb.com/v3.4/reference/method/db.grantRolesToUser/)
  impact 0.5
  ref 'DPMS Target MongoDB 3.x'
  tag check_id: 'C-81703r1_chk'
  tag severity: 'medium'
  tag gid: 'V-81911'
  tag rid: 'SV-96625r1_rule'
  tag stig_id: 'MD3X-00-000670'
  tag gtitle: 'SRG-APP-000380-DB-000360'
  tag fix_id: 'F-88761r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end
