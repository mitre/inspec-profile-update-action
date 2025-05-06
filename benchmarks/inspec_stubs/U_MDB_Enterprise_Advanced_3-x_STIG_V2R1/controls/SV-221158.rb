control 'SV-221158' do
  title 'MongoDB must integrate with an organization-level authentication/access mechanism providing account management and automation for all users, groups, roles, and any other principals.'
  desc 'MongoDB must integrate with an organization-level authentication/access mechanism providing account management and automation for all users, groups, roles, and any other principals.'
  desc 'check', 'Verify that the MongoDB configuration file (default location: /etc/mongod.conf) contains the following:

security:
authorization: "enabled"

If this parameter is not present, this is a finding.'
  desc 'fix', 'Edit the MongoDB configuration file (default location: /etc/mongod.con) to include the following:

security:
authorization: "enabled"

This will enable SCRAM-SHA-1 authentication (default).

Instruction on configuring the default authentication is provided here:

https://docs.mongodb.com/v3.4/tutorial/enable-authentication/

The high-level steps described by the above will require the following:

1. Start MongoDB without access control.
2. Connect to the instance.
3. Create the user administrator.
4. Restart the MongoDB instance with access control.
5. Connect and authenticate as the user administrator.
6. Create additional users as needed for your deployment.'
  impact 0.7
  ref 'DPMS Target MongoDB Enterprise Advanced 3.x'
  tag check_id: 'C-22873r410968_chk'
  tag severity: 'high'
  tag gid: 'V-221158'
  tag rid: 'SV-221158r822434_rule'
  tag stig_id: 'MD3X-00-000010'
  tag gtitle: 'SRG-APP-000023-DB-000001'
  tag fix_id: 'F-22862r410969_fix'
  tag 'documentable'
  tag legacy: ['SV-96557', 'V-81843']
  tag cci: ['CCI-000015']
  tag nist: ['AC-2 (1)']
end
