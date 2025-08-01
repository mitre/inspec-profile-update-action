control 'SV-53935' do
  title 'Database objects must be owned by accounts authorized for ownership.'
  desc 'SQL Server database ownership is a higher level privilege that grants full rights to everything in that database, including the right to grant privileges to others. SQL Server requires that the owner of a database object be a user, and only one user can be the assigned owner of a database object. This tends to minimize the risk that multiple users could gain unauthorized access, except the one individual who is the owner.

Within the database, object ownership implies full privileges to the owned object, including the privilege to assign access to the owned objects to other subjects. Unmanaged or uncontrolled ownership of databases can lead to unauthorized granting of privileges and database alterations.'
  desc 'check', "Review system documentation to identify SQL Server accounts authorized to own database objects.

If the SQL Server database ownership list does not exist or needs to be updated, this is a finding.

Run the following SQL query to determine SQL Server ownership of all database objects:
SELECT name AS 'Database name'
     , SUSER_SNAME(owner_sid) AS 'Database Owner'
     , state_desc AS 'Database state'
  FROM sys.databases"
  desc 'fix', %q(Add and/or update system documentation to include any accounts authorized for object ownership and remove any account not authorized.

Reassign database ownership to authorized database owner account:
Navigate to SQL Server Management Studio >> Object Explorer >> <'SQL Server name'> >> Databases >> right click <'database name'> >> Properties >> Files.
Select new database "Owner":
Navigate to click on […] >> Select new Database Owner >> Browse… >> click on box to indicate account >> <'OK'> >> <'OK'> >> <'OK'>)
  impact 0.5
  ref 'DPMS Target SQL Server Database 2012'
  tag check_id: 'C-47945r2_chk'
  tag severity: 'medium'
  tag gid: 'V-41407'
  tag rid: 'SV-53935r2_rule'
  tag stig_id: 'SQL2-00-015600'
  tag gtitle: 'SRG-APP-000133-DB-000200'
  tag fix_id: 'F-46835r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
