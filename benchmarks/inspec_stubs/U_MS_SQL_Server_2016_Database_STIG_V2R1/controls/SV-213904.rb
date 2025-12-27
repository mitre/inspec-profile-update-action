control 'SV-213904' do
  title 'SQL Server must protect against a user falsely repudiating by ensuring databases are not in a trust relationship.'
  desc 'Non-repudiation of actions taken is required in order to maintain data integrity. Examples of particular actions taken by individuals include creating information, sending a message, approving information (e.g., indicating concurrence or signing a contract), and receiving a message. 

Non-repudiation protects against later claims by a user of not having created, modified, or deleted a particular data item or collection of data in the database.

SQL Server provides the ability for high privileged accounts to impersonate users in a database using the TRUSTWORTHY feature. This will allow members of the fixed database role to impersonate any user within the database.'
  desc 'check', "If the database being reviewed is MSDB, trustworthy is required to be enabled, and therefore this is not a finding.

Execute the following query:

SELECT SUSER_SNAME(d.owner_sid) AS DatabaseOwner,
CASE
WHEN d.is_trustworthy_on = 0 THEN 'No'
WHEN d.is_trustworthy_on = 1 THEN 'Yes'
END AS IsTrustworthy,
CASE
WHEN role.name IN ('sysadmin','securityadmin')
OR permission.permission_name = 'CONTROL SERVER'
THEN 'YES'
ELSE 'No'
END AS 'IsOwnerPrivileged'
FROM sys.databases d
LEFT JOIN sys.server_principals login ON d.owner_sid = login.sid
LEFT JOIN sys.server_role_members rm ON login.principal_id = rm.member_principal_id
LEFT JOIN sys.server_principals role ON rm.role_principal_id = role.principal_id
LEFT JOIN sys.server_permissions permission ON login.principal_id = permission.grantee_principal_id
WHERE d.name = DB_NAME()

If trustworthy is not enabled, this is not a finding.

If trustworthy is enabled and the database owner is not a privileged account, this is not a finding.

If trustworthy is enabled and the database owner is a privileged account, review the system documentation to determine if the trustworthy property is required and authorized. If this is not documented, this is a finding."
  desc 'fix', 'Disable trustworthy on the database.

ALTER DATABASE [<database name>] SET TRUSTWORTHY OFF'
  impact 0.7
  ref 'DPMS Target MS SQL Server 2016 Database'
  tag check_id: 'C-15122r457865_chk'
  tag severity: 'high'
  tag gid: 'V-213904'
  tag rid: 'SV-213904r508025_rule'
  tag stig_id: 'SQL6-D0-000600'
  tag gtitle: 'SRG-APP-000080-DB-000063'
  tag fix_id: 'F-15120r313145_fix'
  tag 'documentable'
  tag legacy: ['V-79071', 'SV-93777']
  tag cci: ['CCI-000166']
  tag nist: ['AU-10']
end
