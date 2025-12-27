control 'SV-252149' do
  title 'MongoDB must integrate with an organization-level authentication/access mechanism providing account management and automation for all users, groups, roles, and any other principals.'
  desc 'MongoDB must integrate with an organization-level authentication/access mechanism providing account management and automation for all users, groups, roles, and any other principals.'
  desc 'check', 'Verify that the MongoDB configuration file (default location: /etc/mongod.conf) contains the following:

security:
  authorization: enabled
 
If this parameter is not present, this is a finding.

If using organization-mandated authorization, verify that the MongoDB configuration file (default location: /etc/mongod.conf) contains the following to ensure LDAP auth is enabled as well:

security:
   ldap:
      servers: [list of ldap servers]

If this parameter is not present, this is a finding.'
  desc 'fix', 'Edit the %MongoDB configuration file% (default location: /etc/mongod.conf) to include the following:

security:
  authorization: enabled

This will enable SCRAM-SHA-256 authentication (default).

Instruction on configuring the default authentication is provided here: https://docs.mongodb.com/v4.4/tutorial/enable-authentication/

The high-level steps described by the above will require the following:

1. Start MongoDB without access control.
2. Connect to the instance.
3. Create the user administrator.
4. Restart the MongoDB instance with access control.
5. Connect and authenticate as the user administrator.
6. Create additional users as needed for deployment.

Configuration information for LDAP for MongoDB can be found here: https://docs.mongodb.com/v4.4/core/security-ldap-external/
https://docs.mongodb.com/v4.4/core/security-ldap-external/#configuration'
  impact 0.5
  ref 'DPMS Target MongoDB Enterprise Advanced 4.x'
  tag check_id: 'C-55605r813827_chk'
  tag severity: 'medium'
  tag gid: 'V-252149'
  tag rid: 'SV-252149r813829_rule'
  tag stig_id: 'MD4X-00-001600'
  tag gtitle: 'SRG-APP-000023-DB-000001'
  tag fix_id: 'F-55555r813828_fix'
  tag 'documentable'
  tag cci: ['CCI-000015']
  tag nist: ['AC-2 (1)']
end
