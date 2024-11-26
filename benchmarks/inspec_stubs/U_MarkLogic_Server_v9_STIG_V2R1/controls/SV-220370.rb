control 'SV-220370' do
  title 'MarkLogic Server must separate user functionality (including user interface services) from database management functionality.'
  desc 'Information system management functionality includes functions necessary to administer databases, network components, workstations, or servers, and typically requires privileged user access. 

The separation of user functionality from information system management functionality is either physical or logical and is accomplished by using different computers, different central processing units, different instances of the operating system, different network addresses, combinations of these methods, or other methods, as appropriate. 

An example of this type of separation is observed in web administrative interfaces that use separate authentication methods for users of any other information system resources. 

This may include isolating the administrative interface on a different domain and with additional access controls.

If administrative functionality or information regarding DBMS management is presented on an interface available for users, information on DBMS settings may be inadvertently made available to the user.'
  desc 'check', 'Validate MarkLogic User accounts to verify only Administrators have Administrative roles assigned and each Administrator has an individual account.

Perform the check from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

1. Click the Security icon.
2. Click the Users icon on the left tree menu.
3. Inspect the Users. If administrator and general user accounts are not separated, this is a finding.'
  desc 'fix', 'Configure MarkLogic user roles so that only actual Administrators are assigned Administrative roles and each Administrator has an individual account.

Perform the check from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

1. Click the Security icon.
2. Click the Users icon on the left tree menu.
3. Inspect the Users.
4. Remove administrative privileges from general user accounts, and ensure administrators have separate administrative accounts.'
  impact 0.5
  ref 'DPMS Target MarkLogic Server v9'
  tag check_id: 'C-22085r401561_chk'
  tag severity: 'medium'
  tag gid: 'V-220370'
  tag rid: 'SV-220370r622777_rule'
  tag stig_id: 'ML09-00-004500'
  tag gtitle: 'SRG-APP-000211-DB-000122'
  tag fix_id: 'F-22074r401562_fix'
  tag 'documentable'
  tag legacy: ['SV-110089', 'V-100985']
  tag cci: ['CCI-001082']
  tag nist: ['SC-2']
end
