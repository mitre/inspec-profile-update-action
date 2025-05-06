control 'SV-213861' do
  title 'The role(s)/group(s) used to modify database structure (including but not necessarily limited to tables, indexes, storage, etc.) and logic modules (stored procedures, functions, triggers, links to software external to SQL Server, etc.) must be restricted to authorized users.'
  desc 'If SQL Server were to allow any user to make changes to database structure or logic, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

Accordingly, only qualified and authorized individuals shall be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.

Unmanaged changes that occur to the database software libraries or configuration can lead to unauthorized or compromised installations.'
  desc 'check', 'Using the system security plan, identify the group(s)/role(s) established for SQL Server DBMS and database modification, and the individuals authorized to modify the DBMS and database(s).  If helpful, the views STIG.server_permissions and STIG.database_permissions, provided in the supplemental file Permissions.sql, can be used to search for the relevant roles:  look for Permission values containing "Alter," "Create," "Control," etc.

Obtain the list of users in those group(s)/roles.  The provided functions STIG.members_of_db_role() and STIG.members_of_server_role(), can be used for this.

If unauthorized access to the group(s)/role(s) has been granted, this is a finding.'
  desc 'fix', 'Revoke unauthorized memberships in the group(s)/role(s) designated for DBMS and database modification.

Syntax examples:

ALTER ROLE Power DROP MEMBER JenUser; -- the member is a database role or database user.
ALTER SERVER ROLE GreatPower DROP MEMBER Irresponsibility; -- the member is a server role or login.'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2014 Instance'
  tag check_id: 'C-15080r312934_chk'
  tag severity: 'medium'
  tag gid: 'V-213861'
  tag rid: 'SV-213861r531244_rule'
  tag stig_id: 'SQL4-00-030700'
  tag gtitle: 'SRG-APP-000133-DB-000362'
  tag fix_id: 'F-15078r312935_fix'
  tag 'documentable'
  tag legacy: ['SV-82305', 'V-67815']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
