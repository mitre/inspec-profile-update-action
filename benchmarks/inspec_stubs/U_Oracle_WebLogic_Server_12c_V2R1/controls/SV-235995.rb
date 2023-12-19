control 'SV-235995' do
  title 'Oracle WebLogic must restrict error messages so only authorized personnel may view them.'
  desc "If the application provides too much information in error logs and administrative messages to the screen, this could lead to compromise. The structure and content of error messages need to be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements. 

Application servers must protect the error messages that are created by the application server. All application server users' accounts are used for the management of the server and the applications residing on the application server. All accounts are assigned to a certain role with corresponding access rights. The application server must restrict access to error messages so only authorized personnel may view them. Error messages are usually written to logs contained on the file system. The application server will usually create new log files as needed and must take steps to ensure that the proper file permissions are utilized when the log files are created."
  desc 'check', "1. Access AC
2. From 'Domain Structure', select 'Security Realms'
3. Select realm to configure (default is 'myrealm')
4. Select 'Users and Groups' tab -> 'Users' tab
5. From 'Users' table, select a user that must not have access to view error messages
6. From users settings page, select 'Groups' tab
7. Ensure the 'Chosen' table does not contain any of the following roles - 'Admin', 'Deployer', 'Monitor', 'Operator'
8. Repeat steps 5-7 for all users that must not have access to view error messages

If any user that should not be able to view error messages has the roles of 'Admin', 'Deployer', 'Monitor' or 'Operator', this is a finding."
  desc 'fix', "1. Access AC
2. From 'Domain Structure', select 'Security Realms'
3. Select realm to configure (default is 'myrealm')
4. Select 'Users and Groups' tab -> 'Users' tab
5. From 'Users' table, select a user that must not have access to view error messages
6. From users settings page, select 'Groups' tab
7. From the 'Chosen' table, use the shuttle buttons to remove all of the following roles - 'Admin', 'Deployer', 'Monitor', 'Operator'
8. Click 'Save'
9. Repeat steps 5-8 for all users that must not have access to view error messages"
  impact 0.5
  ref 'DPMS Target Oracle WebLogic Server 12c'
  tag check_id: 'C-39214r628761_chk'
  tag severity: 'medium'
  tag gid: 'V-235995'
  tag rid: 'SV-235995r628763_rule'
  tag stig_id: 'WBLC-09-000254'
  tag gtitle: 'SRG-APP-000267-AS-000170'
  tag fix_id: 'F-39177r628762_fix'
  tag 'documentable'
  tag legacy: ['SV-70633', 'V-56379']
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
