control 'SV-253705' do
  title 'MariaDB must separate user functionality (including user interface services) from database management functionality.'
  desc 'Information system management functionality includes functions necessary to administer databases, network components, workstations, or servers and typically requires privileged user access. 

The separation of user functionality from information system management functionality is either physical or logical and is accomplished by using different computers, different central processing units, different instances of the operating system, different network addresses, combinations of these methods, or other methods, as appropriate. 

An example of this type of separation is observed in web administrative interfaces that use separate authentication methods for users of any other information system resources. 

This may include isolating the administrative interface on a different domain and with additional access controls.

If administrative functionality or information regarding MariaDB management is presented on an interface available for users, information on MariaDB settings may be inadvertently made available to the user.'
  desc 'check', "Show the list of system privileges that the MariaDB server supports, run:
MariaDB> SHOW PRIVILEGES;
 
Gather a list of SHOW GRANTS commands. SHOW GRANTS will list the privileges granted to the account.

Run this database query to create the SHOW GRANTS script for each user: 

MariaDB> SELECT DISTINCT CONCAT( 'SHOW GRANTS FOR ', user,'@', host,';') AS grantQuery FROM mysql.user WHERE is_role = 'N';

Run each SHOW GRANTS command for each user.

MariaDB> SHOW GRANTS FOR 'user'@'host';

If any nonadministrative role has any one of the following privileges, this is a finding. 

Create user 
Event
Process 
Proxy
Reload
Replication client 
Replication slave 
Show databases 
Shutdown 
Supe, 
Usage

If administrator and general user functionality are not separated either physically or logically, this is a finding."
  desc 'fix', "Configure MariaDB Enterprise Server to separate database administration and general user functionality.

Do not grant Create user, Event, Process, Proxy, Reload, Replication client, Replication slave, Show databases, Shutdown, Super, Create tablespace, Usage privileges to users and roles that do not require it.

To remove privileges, see the following examples:
 
1. Revoke privileges from a specific user: 

MariaDB> REVOKE SUPER, PROCESS ON *.* FROM 'user'@'host';
 
2. Revoke privileges from a role:

MariaDB> REVOKE 'role' FROM 'user'@'host';"
  impact 0.5
  ref 'DPMS Target MariaDB Enterprise 10.x'
  tag check_id: 'C-57157r841638_chk'
  tag severity: 'medium'
  tag gid: 'V-253705'
  tag rid: 'SV-253705r841640_rule'
  tag stig_id: 'MADB-10-004600'
  tag gtitle: 'SRG-APP-000211-DB-000122'
  tag fix_id: 'F-57108r841639_fix'
  tag 'documentable'
  tag cci: ['CCI-001082']
  tag nist: ['SC-2']
end
