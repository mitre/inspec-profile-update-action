control 'SV-206564' do
  title 'The DBMS must separate user functionality (including user interface services) from database management functionality.'
  desc 'Information system management functionality includes functions necessary to administer databases, network components, workstations, or servers and typically requires privileged user access. 

The separation of user functionality from information system management functionality is either physical or logical and is accomplished by using different computers, different central processing units, different instances of the operating system, different network addresses, combinations of these methods, or other methods, as appropriate. 

An example of this type of separation is observed in web administrative interfaces that use separate authentication methods for users of any other information system resources. 

This may include isolating the administrative interface on a different domain and with additional access controls.

If administrative functionality or information regarding DBMS management is presented on an interface available for users, information on DBMS settings may be inadvertently made available to the user.'
  desc 'check', 'Check DBMS settings and vendor documentation to verify that administrative functionality is separate from user functionality.

If administrator and general user functionality are not separated either physically or logically, this is a finding.'
  desc 'fix', 'Configure DBMS to separate database administration and general user functionality.'
  impact 0.5
  ref 'DPMS Target Database Generic'
  tag check_id: 'C-6824r291360_chk'
  tag severity: 'medium'
  tag gid: 'V-206564'
  tag rid: 'SV-206564r617447_rule'
  tag stig_id: 'SRG-APP-000211-DB-000122'
  tag gtitle: 'SRG-APP-000211'
  tag fix_id: 'F-6824r291361_fix'
  tag 'documentable'
  tag legacy: ['SV-42851', 'V-32514']
  tag cci: ['CCI-001082']
  tag nist: ['SC-2']
end
