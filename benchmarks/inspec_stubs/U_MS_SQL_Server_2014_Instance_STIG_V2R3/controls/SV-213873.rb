control 'SV-213873' do
  title 'SQL Server and Windows must enforce access restrictions associated with changes to the configuration of the SQL Server instance or database(s).'
  desc 'Failure to provide logical access restrictions associated with changes to configuration may have significant effects on the overall security of the system. 

When dealing with access restrictions pertaining to change control, it should be noted that any changes to the hardware, software, and/or firmware components of the information system can potentially have significant effects on the overall security of the system. 

Accordingly, SQL Server and Windows must allow only qualified and authorized individuals to obtain access to system components for the purposes of initiating changes, including upgrades and modifications.'
  desc 'check', %q(Review the security configuration of the SQL Server instance and database(s).

If unauthorized Windows users can start the SQL Server Configuration Manager or SQL Server Management Studio, this is a finding.

If SQL Server does not enforce access restrictions associated with changes to the configuration of the SQL Server instance or database(s), this is a finding.

- - - - - 

To assist in conducting reviews of permissions, the following views and permissions are defined in the supplemental file Permissions.sql, provided with this STIG:
database_permissions
database_role_members
server_permissions
server_role_members
database_effective_permissions('<database user/role name>')
database_roles_of('<database user/role name>')
members_of_db_role('<database role name>')
members_of_server_role('<server role name>')
server_effective_permissions('<server login/role name>')
server_roles_of('<server login/role name>')

Permissions of concern in this respect include the following, and possibly others:
- any server permission except CONNECT SQL, but including CONNECT ANY DATABASE
- any database permission beginning with "CREATE" or "ALTER"
- CONTROL
- INSERT, UPDATE, DELETE, EXECUTE on locally-defined tables and procedures designed for supplemental configuration and security purposes.)
  desc 'fix', 'Configure SQL Server to enforce access restrictions associated with changes to the configuration of the SQL Server instance and database(s).'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2014 Instance'
  tag check_id: 'C-15092r312970_chk'
  tag severity: 'medium'
  tag gid: 'V-213873'
  tag rid: 'SV-213873r855545_rule'
  tag stig_id: 'SQL4-00-033900'
  tag gtitle: 'SRG-APP-000380-DB-000360'
  tag fix_id: 'F-15090r312971_fix'
  tag 'documentable'
  tag legacy: ['SV-82391', 'V-67901']
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end
