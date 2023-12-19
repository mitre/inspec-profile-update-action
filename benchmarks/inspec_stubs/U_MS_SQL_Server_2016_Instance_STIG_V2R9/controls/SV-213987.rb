control 'SV-213987' do
  title 'SQL Server must enforce access restrictions associated with changes to the configuration of the instance.'
  desc 'Failure to provide logical access restrictions associated with changes to configuration may have significant effects on the overall security of the system.  
 
When dealing with access restrictions pertaining to change control, it should be noted that any changes to the hardware, software, and/or firmware components of the information system can potentially have significant effects on the overall security of the system.  
 
Accordingly, only qualified and authorized individuals should be allowed to obtain access to system components for the purposes of initiating changes, including upgrades and modifications.'
  desc 'check', "Obtain a list of logins who have privileged permissions and role memberships in SQL. 
 
Execute the following query to obtain a list of logins and roles and their respective permissions assignment: 
 
SELECT p.name AS Principal, 
p.type_desc AS Type, 
sp.permission_name AS Permission,  
sp.state_desc AS State 
FROM sys.server_principals p 
INNER JOIN sys.server_permissions sp ON p.principal_id = sp.grantee_principal_id 
WHERE sp.permission_name = 'CONTROL SERVER' 
OR sp.state = 'W' 
 
Execute the following query to obtain a list of logins and their role memberships. 
 
SELECT m.name AS Member, 
m.type_desc AS Type, 
r.name AS Role 
FROM sys.server_principals m 
INNER JOIN sys.server_role_members rm ON m.principal_id = rm.member_principal_id 
INNER JOIN sys.server_principals r ON rm.role_principal_id = r.principal_id 
WHERE r.name IN ('sysadmin','securityadmin','serveradmin') 
 
Check the server documentation to verify the logins and roles returned are authorized. If the logins and/or roles are not documented and authorized, this is a finding."
  desc 'fix', 'Revoke unauthorized permissions from principals. 
 
https://msdn.microsoft.com/en-us/library/ms186308.aspx 
 
Remove unauthorized logins from roles. 
 
ALTER SERVER ROLE DROP MEMBER login; 
 
https://technet.microsoft.com/en-us/library/ee677634.aspx'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2016 Instance'
  tag check_id: 'C-15204r313744_chk'
  tag severity: 'medium'
  tag gid: 'V-213987'
  tag rid: 'SV-213987r879753_rule'
  tag stig_id: 'SQL6-D0-011400'
  tag gtitle: 'SRG-APP-000380-DB-000360'
  tag fix_id: 'F-15202r313745_fix'
  tag 'documentable'
  tag legacy: ['SV-93941', 'V-79235']
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end
