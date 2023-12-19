control 'SV-213924' do
  title 'SQL Server must enforce access restrictions associated with changes to the configuration of the database(s).'
  desc 'Failure to provide logical access restrictions associated with changes to configuration may have significant effects on the overall security of the system. 

When dealing with access restrictions pertaining to change control, it should be noted that any changes to the hardware, software, and/or firmware components of the information system can potentially have significant effects on the overall security of the system. 

Accordingly, only qualified and authorized individuals should be allowed to obtain access to system components for the purposes of initiating changes, including upgrades and modifications.'
  desc 'check', 'Execute the following query to obtain a listing of user databases whose owner is a member of a fixed server role:

 SELECT 
              D.name AS database_name, SUSER_SNAME(D.owner_sid) AS owner_name,
              FRM.is_fixed_role_member
FROM sys.databases D
OUTER APPLY (
              SELECT MAX(fixed_role_member) AS is_fixed_role_member
              FROM (
                            SELECT IS_SRVROLEMEMBER(R.name, SUSER_SNAME(D.owner_sid)) AS fixed_role_member
                            FROM sys.server_principals R
                            WHERE is_fixed_role = 1
              ) A
) FRM
WHERE D.database_id > 4
              AND (FRM.is_fixed_role_member = 1 
                            OR FRM.is_fixed_role_member IS NULL)
ORDER BY database_name 

If no databases are returned, this is not a finding. 

For each database/login returned, review the Server Role memberships 

1.	In SQL Server Management Studio, Expand “Logins”
2.	Double-click the name of the Login
3.	Click the “Server Roles” tab 

If any server roles are selected, but not documented and authorized, this is a finding.'
  desc 'fix', 'Remove unauthorized users from roles:

ALTER ROLE DROP MEMBER user;

https://msdn.microsoft.com/en-us/library/ms189775.aspx

Set the owner of the database to an authorized login:

ALTER AUTHORIZATION ON database::DatabaseName TO login;

https://msdn.microsoft.com/en-us/library/ms187359.aspx'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2016 Database'
  tag check_id: 'C-15142r313204_chk'
  tag severity: 'medium'
  tag gid: 'V-213924'
  tag rid: 'SV-213924r508025_rule'
  tag stig_id: 'SQL6-D0-003100'
  tag gtitle: 'SRG-APP-000380-DB-000360'
  tag fix_id: 'F-15140r313205_fix'
  tag 'documentable'
  tag legacy: ['V-79111', 'SV-93817']
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end
