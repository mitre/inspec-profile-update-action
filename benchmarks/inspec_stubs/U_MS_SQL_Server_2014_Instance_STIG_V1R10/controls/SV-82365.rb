control 'SV-82365' do
  title 'SQL Server must be configured to separate user functionality (including user interface services) from database management functionality.'
  desc 'Information system management functionality includes functions necessary to administer databases, network components, workstations, or servers and typically requires privileged user access. 

The separation of user functionality from information system management functionality is either physical or logical and is accomplished by using different computers, different central processing units, different instances of the operating system, different network addresses, combinations of these methods, or other methods, as appropriate. 

An example of this type of separation is observed in web administrative interfaces that use separate authentication methods for users of any other information system resources. 

This may include isolating the administrative interface on a different domain and with additional access controls.

If administrative functionality or information regarding DBMS management is presented on an interface available for users, information on DBMS settings may be inadvertently made available to the user.'
  desc 'check', 'Check SQL Server permission settings to verify that administrative functionality is kept separate from user functionality.  The views and functions provided in the supplemental file Permissions.sql can help with this review.

If administrator and general user functionality are not separated either physically or logically, this is a finding.'
  desc 'fix', 'Establish one or more locally-defined server roles and one or more locally-defined database roles for organizing administrative permissions.  Grant administrative permissions to these roles.  Assign the appropriate administrative users to these roles.  Do not grant the roles and permissions to general users.'
  impact 0.5
  ref 'DPMS Target SQL Server Installation 2014'
  tag check_id: 'C-68443r1_chk'
  tag severity: 'medium'
  tag gid: 'V-67875'
  tag rid: 'SV-82365r1_rule'
  tag stig_id: 'SQL4-00-020500'
  tag gtitle: 'SRG-APP-000211-DB-000122'
  tag fix_id: 'F-73991r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001082']
  tag nist: ['SC-2']
end
