control 'SV-251235' do
  title 'Redis Enterprise DBMS must separate user functionality (including user interface services) from database management functionality.'
  desc 'Information system management functionality includes functions necessary to administer databases, network components, workstations, or servers and typically requires privileged user access. 

The separation of user functionality from information system management functionality is either physical or logical and is accomplished by using different computers, different central processing units, different instances of the operating system, different network addresses, combinations of these methods, or other methods, as appropriate. 

An example of this type of separation is observed in web administrative interfaces that use separate authentication methods for users of any other information system resources. 

This may include isolating the administrative interface on a different domain and with additional access controls.

If administrative functionality or information regarding DBMS management is presented on an interface available for users, information on DBMS settings may be inadvertently made available to the user.'
  desc 'check', 'Redis Enterprise provides separate user functionality by default. An administrative control plane helps facilitate configuration and a database layer helps facilitate application integrations with the database. This functionality is provided by default; however, the same user may be used for both the database layer and the administrative control plane. 

First, obtain the list of authorized admin users and general users.
To check user functionality, perform the following steps:
1. Log in to the administrative control plane.
2. Navigate to the access controls tab.
3. Navigate to the roles tab.
4. Review all roles and verify that any role that provides access to the data path is configured with the cluster management role of "None". 

If a role provides access to both data and management paths, this is a finding.'
  desc 'fix', 'Configure DBMS to separate database administration and general user functionality.'
  impact 0.5
  ref 'DPMS Target Redis Enterprise 6.x'
  tag check_id: 'C-54670r804893_chk'
  tag severity: 'medium'
  tag gid: 'V-251235'
  tag rid: 'SV-251235r804895_rule'
  tag stig_id: 'RD6X-00-010100'
  tag gtitle: 'SRG-APP-000211-DB-000122'
  tag fix_id: 'F-54624r804894_fix'
  tag 'documentable'
  tag cci: ['CCI-001082']
  tag nist: ['SC-2']
end
