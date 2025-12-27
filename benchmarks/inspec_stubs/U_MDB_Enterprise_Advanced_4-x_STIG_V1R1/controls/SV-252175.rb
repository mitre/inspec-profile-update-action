control 'SV-252175' do
  title 'MongoDB must enforce access restrictions associated with changes to the configuration of MongoDB or database(s).'
  desc 'Failure to provide logical access restrictions associated with changes to configuration may have significant effects on the overall security of the system.

When dealing with access restrictions pertaining to change control, it should be noted that any changes to the hardware, software, and/or firmware components of the information system can potentially have significant effects on the overall security of the system.

Accordingly, only qualified and authorized individuals should be allowed to obtain access to system components for the purposes of initiating changes, including upgrades and modifications.'
  desc 'check', 'To verify that access restrictions are being enforced, create a test user and a custom role and then confirm expected operations:

Once authenticated as a DBA administrator, use db.createUser() to create an additional user. The following operation adds a user myTester to the test database who has read-only access on the test database:

 use test
 db.createUser(
   {
      user: "myTester", pwd: password,
      roles: [
         { role: "read", db: "test" }
      ]
    }
 )

Log out, then log back in as the "test" database user. Issue the following to attempt to write to the test database with a read-only privilege:

 use test
 db.testCollection.insert( { x: 1 } )

This operation will fail with a WriteResult error:

WriteCommandError({
        "ok" : 0,
        "errmsg" : "not authorized on test to execute command { insert: \\"###\\", ordered: \\"###\\", lsid: { id: \\"###\\" }, $db: \\"###\\" }",
        "code" : 13,
        "codeName" : "Unauthorized"
})

If the operation does not fail, this is a finding.'
  desc 'fix', "Verify that authentication has been enabled in the %MongoDB configuration file%:

https://docs.mongodb.com/v4.4/reference/configuration-options/.

If authorization is enabled, review the following to list existing user permissions. 
 
https://docs.mongodb.com/v4.4/reference/privilege-actions/ 

Connect to MongoDB.

For each database (show dbs), identify the user's roles for the database.  

 use database 
 db.getUser(%username%) 

The server will return a document with the user's roles.  

To revoke a user's role from a database, use the method below: 

 db.revokeRolesFromUser( %username%, [ roles ], { writeConcern } )

https://docs.mongodb.com/v4.4/reference/method/db.revokeRolesFromUser/
 
To grant a role to a user, use the method below: 

 db.grantRolesToUser( %username%, [ roles ], { writeConcern } )

https://docs.mongodb.com/v4.4/reference/method/db.grantRolesToUser/"
  impact 0.5
  ref 'DPMS Target MongoDB Enterprise Advanced 4.x'
  tag check_id: 'C-55631r816989_chk'
  tag severity: 'medium'
  tag gid: 'V-252175'
  tag rid: 'SV-252175r816991_rule'
  tag stig_id: 'MD4X-00-005400'
  tag gtitle: 'SRG-APP-000380-DB-000360'
  tag fix_id: 'F-55581r816990_fix'
  tag 'documentable'
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end
