control 'SV-224176' do
  title 'The EDB Postgres Advanced Server must separate user functionality (including user interface services) from database management functionality.'
  desc 'Information system management functionality includes functions necessary to administer databases, network components, workstations, or servers and typically requires privileged user access. 

The separation of user functionality from information system management functionality is either physical or logical and is accomplished by using different computers, different central processing units, different instances of the operating system, different network addresses, combinations of these methods, or other methods, as appropriate. 

An example of this type of separation is observed in web administrative interfaces that use separate authentication methods for users of any other information system resources. 

This may include isolating the administrative interface on a different domain and with additional access controls.

If administrative functionality or information regarding DBMS management is presented on an interface available for users, information on DBMS settings may inadvertently be made available to the user.'
  desc 'check', 'Check EDB Postgres Advanced Server permission settings to verify that administrative functionality is kept separate from user functionality.

As a database superuser user (e.g., enterprisedb), list the user and group roles and their permissions in an EDB Postgres Advanced Server instance; execute the following command in psql:

   \\du

If any non-administrative role has the attribute "Superuser", "Create role", "Create DB" or "Bypass RLS", this is a finding.

If administrator and general user functionality is not separated either physically or logically, this is a finding.'
  desc 'fix', 'Configure EDB Postgres Advanced Server to separate database administration and general user functionality.

Use the ALTER ROLE SQL command to remove "SUPERUSER", "CREATE Role", "Create DB", or "Bypass RLS" privileges from user and group roles that are not authorized for those roles.

For example:

  ALTER ROLE <username> NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;'
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server v11 on Windows'
  tag check_id: 'C-25849r495546_chk'
  tag severity: 'medium'
  tag gid: 'V-224176'
  tag rid: 'SV-224176r508023_rule'
  tag stig_id: 'EP11-00-005100'
  tag gtitle: 'SRG-APP-000211-DB-000122'
  tag fix_id: 'F-25837r495547_fix'
  tag 'documentable'
  tag legacy: ['V-101195', 'SV-110299']
  tag cci: ['CCI-001082']
  tag nist: ['SC-2']
end
