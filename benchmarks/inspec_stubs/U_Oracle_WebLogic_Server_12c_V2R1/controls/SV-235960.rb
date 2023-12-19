control 'SV-235960' do
  title 'Oracle WebLogic must limit privileges to change the software resident within software libraries (including privileged programs).'
  desc 'Application servers have the ability to specify that the hosted applications utilize shared libraries. The application server must have a capability to divide roles based upon duties wherein one project user (such as a developer) cannot modify the shared library code of another project user. The application server must also be able to specify that non-privileged users cannot modify any shared library code at all.'
  desc 'check', "1. Access AC
2. From 'Domain Structure', select 'Security Realms'
3. Select realm to configure (default is 'myrealm')
4. Select 'Users and Groups' tab -> 'Users' tab
5. From 'Users' table, select a user that must not have shared library modification access
6. From users settings page, select 'Groups' tab
7. Ensure the 'Chosen' table does not contain the roles - 'Admin', 'Deployer'
8. Repeat steps 5-7 for all users that must not have shared library modification access

If any users that are not permitted to change the software resident within software libraries (including privileged programs) have the role of 'Admin' or 'Deployer', this is a finding."
  desc 'fix', "1. Access AC
2. From 'Domain Structure', select 'Security Realms'
3. Select realm to configure (default is 'myrealm')
4. Select 'Users and Groups' tab -> 'Users' tab
5. From 'Users' table, select a user that must not have shared library modification access
6. From users settings page, select 'Groups' tab
7. From the 'Chosen' table, use the shuttle buttons to remove the role - 'Admin', 'Deployer'
8. Click 'Save'
9. Repeat steps 5-8 for all users that must not have shared library modification access"
  impact 0.5
  ref 'DPMS Target Oracle WebLogic Server 12c'
  tag check_id: 'C-39179r628656_chk'
  tag severity: 'medium'
  tag gid: 'V-235960'
  tag rid: 'SV-235960r628658_rule'
  tag stig_id: 'WBLC-03-000125'
  tag gtitle: 'SRG-APP-000133-AS-000092'
  tag fix_id: 'F-39142r628657_fix'
  tag 'documentable'
  tag legacy: ['SV-70523', 'V-56269']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
