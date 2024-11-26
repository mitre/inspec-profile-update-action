control 'SV-255302' do
  title 'Azure SQL Database must enforce approved authorizations for logical access to database information and system resources in accordance with applicable access control policies.'
  desc "Enterprise environments make account management for applications and databases challenging and complex. A manual process for account management functions adds the risk of a potential oversight or other error. Managing accounts for the same person in multiple places is inefficient and prone to problems with consistency and synchronization.

A comprehensive application account management process that includes automation helps to ensure that accounts designated as requiring attention are consistently and promptly addressed. 

Examples include, but are not limited to, using automation to take action on multiple accounts designated as inactive, suspended, or terminated, or by disabling accounts located in noncentralized account stores, such as multiple servers. Account management functions can also include assignment of group or role membership; identifying account type; specifying user access authorizations (i.e., privileges); account removal, update, or termination; and administrative alerts. The use of automated mechanisms can include, for example, using email or text messaging to notify account managers when users are terminated or transferred; using the information system to monitor account usage; and using automated telephone notification to report atypical system account usage.

Azure SQL Database must be configured to automatically utilize organization-level account management functions, and these functions must immediately enforce the organization's current account policy. 

Automation may be comprised of differing technologies that when placed together contain an overall mechanism supporting an organization's automated account management requirements."
  desc 'check', "Review the system documentation to determine the required levels of protection for securables in the database, by type of user.   

Review the permissions actually in place in the database. 

Execute the following query to find permissions assigned:

SELECT DISTINCT [Finding] = 'Database '   
	+ QUOTENAME(DB_NAME()) + ' '       
	+ CASE WHEN dbp.type = 'r' THEN 'Role ' ELSE 'User ' END      
	+ QUOTENAME(dbp.name)      
	+ CASE WHEN dbp.type = 'r' THEN ' owning schema ' ELSE ' in db role ' END 
	+ QUOTENAME(ISNULL(dbp2.name,'-')) + ' has db permission ' + QUOTENAME(ISNULL(dbper.permission_name,'-'))       --
	+ ' on object ' + QUOTENAME(ISNULL(OBJECT_NAME(dbper.major_id),'-'))    
	+ ' on object ' + QUOTENAME(ISNULL(CASE WHEN dbper.major_id = 0 THEN 'Database' ELSE OBJECT_NAME(dbper.major_id) END,'-'))       
	+ '.' COLLATE SQL_Latin1_General_CP1_CI_AS  
FROM sys.database_principals dbp LEFT JOIN sys.database_role_members dbrm 
	ON dbp.principal_Id = dbrm.member_principal_Id LEFT JOIN sys.database_principals dbp2 
	ON dbrm.role_principal_id = dbp2.principal_id LEFT JOIN sys.database_permissions dbper 
	ON dbper.grantee_principal_id = dbp.principal_id  
WHERE dbp.type IN ('u','s','g','r') /*Windows/Sql/Groups */
	AND NOT (dbp.name = 'public' AND dbper.permission_name IN ('select','execute') 
	AND  DB_NAME() = 'master') /*ignore public permissions in master*/
	AND NOT (dbp.name = 'public' AND dbper.permission_name IN ('select','execute') 
	AND OBJECT_SCHEMA_NAME(major_id, DB_ID()) = 'sys')      AND ( /*Filter out duplicate permissions in each database except for the base master database*/
	dbp2.name IS NOT NULL /* This seems to filter out permissions granted to a role.*/
	AND dbper.permission_name IS NOT NULL 
	AND dbper.major_id IS NOT NULL          
	OR DB_NAME() = 'master')

If the actual permissions do not match the documented requirements, this is a finding."
  desc 'fix', 'Use GRANT, REVOKE, DENY, ALTER ROLE … ADD MEMBER … and/or ALTER ROLE …. DROP MEMBER statements to add and remove permissions on database-level securables, bringing them in line with the documented requirements.

References:
Revoke:
https://docs.microsoft.com/en-us/sql/t-sql/statements/revoke-transact-sql?view=azuresqldb-current

Deny:
https://docs.microsoft.com/en-us/sql/t-sql/statements/deny-transact-sql?view=azuresqldb-current

DROP MEMBER:
https://docs.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/sp-droprolemember-transact-sql?view=azuresqldb-current'
  impact 0.7
  ref 'DPMS Target MS Azure SQL DB'
  tag check_id: 'C-58975r871030_chk'
  tag severity: 'high'
  tag gid: 'V-255302'
  tag rid: 'SV-255302r871032_rule'
  tag stig_id: 'ASQL-00-000200'
  tag gtitle: 'SRG-APP-000033-DB-000084'
  tag fix_id: 'F-58919r871031_fix'
  tag 'documentable'
  tag cci: ['CCI-000015']
  tag nist: ['AC-2 (1)']
end
