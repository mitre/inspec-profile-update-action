control 'SV-219796' do
  title 'The DBMS must separate user functionality (including user interface services) from database management functionality.'
  desc 'Information system management functionality includes functions necessary to administer databases, network components, workstations, or servers, and typically requires privileged user access. 

The separation of user functionality from information system management functionality is either physical or logical and is accomplished by using different computers, different central processing units, different instances of the operating system, different network addresses, combinations of these methods, or other methods, as appropriate. 

An example of this type of separation is observed in web administrative interfaces that use separate authentication methods for users of any other information system resources. 

This may include isolating the administrative interface on a different domain and with additional access controls.

If administrative functionality or information regarding DBMS management is presented on an interface available for users, information on DBMS settings may be inadvertently made available to the user.'
  desc 'check', 'Check DBMS settings and vendor documentation to verify administrative functionality is separate from user functionality. If administrator and general user functionality is not separated either physically or logically, this is a finding.'
  desc 'fix', 'Configure DBMS settings to separate database administration and general user functionality. Provide those who have both administrative and general-user responsibilities with separate accounts for these separate functions.'
  impact 0.5
  ref 'DPMS Target Oracle Database 11.2g'
  tag check_id: 'C-21521r307237_chk'
  tag severity: 'medium'
  tag gid: 'V-219796'
  tag rid: 'SV-219796r397711_rule'
  tag stig_id: 'O112-P2-017300'
  tag gtitle: 'SRG-APP-000211-DB-000122'
  tag fix_id: 'F-21520r307238_fix'
  tag 'documentable'
  tag legacy: ['SV-66675', 'V-52459']
  tag cci: ['CCI-001082']
  tag nist: ['SC-2']
end
