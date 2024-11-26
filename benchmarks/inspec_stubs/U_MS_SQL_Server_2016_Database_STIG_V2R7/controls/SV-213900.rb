control 'SV-213900' do
  title 'SQL Server databases must integrate with an organization-level authentication/access mechanism providing account management and automation for all users, groups, roles, and any other principals.'
  desc "Enterprise environments make account management for applications and databases challenging and complex. A manual process for account management functions adds the risk of a potential oversight or other error. Managing accounts for the same person in multiple places is inefficient and prone to problems with consistency and synchronization.

A comprehensive application account management process that includes automation helps to ensure that accounts designated as requiring attention are consistently and promptly addressed. 

Examples include, but are not limited to, using automation to take action on multiple accounts designated as inactive, suspended, or terminated, or by disabling accounts located in noncentralized account stores, such as multiple servers. Account management functions can also include: assignment of group or role membership; identifying account type; specifying user access authorizations (i.e., privileges); account removal, update, or termination; and administrative alerts. The use of automated mechanisms can include, for example: using email or text messaging to notify account managers when users are terminated or transferred; using the information system to monitor account usage; and using automated telephone notification to report atypical system account usage.

SQL Server must be configured to automatically utilize organization-level account management functions, and these functions must immediately enforce the organization's current account policy. 

Automation may be comprised of differing technologies that when placed together, contain an overall mechanism supporting an organization's automated account management requirements."
  desc 'check', %q(Determine if SQL Server is configured to allow the use of contained databases.

In the Object Explorer in SQL Server Management Studio (SSMS), right-click on the server instance, select "Properties", and then select the "Advanced" page.

If "Enabled Contained Databases" is "True", this is a finding. 

AND

In a query interface such as the SSMS Transact-SQL editor, run the statement:

EXEC sp_configure 'contained database authentication'

If the returned value in the "config_value" and/or "run_value" column is "1", this is a finding.

Determine whether SQL Server is configured to use only Windows authentication. 

In the Object Explorer in SQL Server Management Studio (SSMS), right-click on the server instance, select "Properties", and then select the "Security" page. If Windows Authentication Mode is not selected, this is a finding. 

AND

In a query interface such as the SSMS Transact-SQL editor, run the statement: 

SELECT CASE SERVERPROPERTY('IsIntegratedSecurityOnly')   
 WHEN 1 THEN 'Windows Authentication'   
 WHEN 0 THEN 'Windows and SQL Server Authentication'   
END as [Authentication Mode] 

If the returned value in the "Authentication Mode" column is not "Windows Authentication", this is a finding. 

Mixed mode (both SQL Server authentication and Windows authentication) is in use. If the need for mixed mode has not been documented and approved, this is a finding. 

From the documentation, obtain the list of accounts authorized to be managed by SQL Server. 

Determine the accounts (SQL Logins) actually managed by SQL Server. Run the statement: 

SELECT name
FROM sys.database_principals
WHERE type_desc = 'SQL_USER'
AND authentication_type_desc = 'DATABASE'; 

If any accounts listed by the query are not listed in the documentation, this is a finding.

Documentation must be approved by the ISSO/ISSM.)
  desc 'fix', %q(If mixed mode is required, document the need and justification; describe the measures taken to ensure the use of SQL Server authentication is kept to a minimum; describe the measures taken to safeguard passwords; list or describe the SQL Logins used; and obtain official approval.

If mixed mode is not required, disable it as follows: 

In the SSMS Object Explorer, right-click on the server instance, select Properties >> Security page. Click the radio button for "Windows Authentication Mode", and then click "OK".

Restart the SQL Server instance. 

OR

Run the statement: 

USE [master]
EXEC xp_instance_regwrite N'HKEY_LOCAL_MACHINE', N'Software\Microsoft\MSSQLServer\MSSQLServer', N'LoginMode', REG_DWORD, 2
GO

Restart the SQL Server instance. 

For each account being managed by SQL Server but not requiring it, drop or disable the SQL Database user. Replace it with an appropriately configured account, as needed.

To drop a User in the SSMS Object Explorer: 

Navigate to Databases >> Security Users. Right-click on the User name, and then click "Delete".

To drop a User via a query: 
USE database_name;
DROP USER <user_name>;)
  impact 0.7
  ref 'DPMS Target MS SQL Server 2016 Database'
  tag check_id: 'C-15118r929094_chk'
  tag severity: 'high'
  tag gid: 'V-213900'
  tag rid: 'SV-213900r929096_rule'
  tag stig_id: 'SQL6-D0-000100'
  tag gtitle: 'SRG-APP-000023-DB-000001'
  tag fix_id: 'F-15116r929095_fix'
  tag 'documentable'
  tag legacy: ['SV-93767', 'V-79061']
  tag cci: ['CCI-000015']
  tag nist: ['AC-2 (1)']
end
