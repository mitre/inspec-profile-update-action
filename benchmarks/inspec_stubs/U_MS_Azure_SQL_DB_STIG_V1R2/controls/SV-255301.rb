control 'SV-255301' do
  title 'Azure SQL Databases must integrate with Azure Active Directory for providing account management and automation for all users, groups, roles, and any other principals.'
  desc "Enterprise environments make account management for applications and databases challenging and complex. A manual process for account management functions adds the risk of a potential oversight or other error. Managing accounts for the same person in multiple places is inefficient and prone to problems with consistency and synchronization.

A comprehensive application account management process that includes automation helps to ensure that accounts designated as requiring attention are consistently and promptly addressed. 

Examples include, but are not limited to, using automation to take action on multiple accounts designated as inactive, suspended, or terminated, or by disabling accounts located in noncentralized account stores, such as multiple servers. Account management functions can also include assignment of group or role membership; identifying account type; specifying user access authorizations (i.e., privileges); account removal, update, or termination; and administrative alerts. The use of automated mechanisms can include, for example, using email or text messaging to notify account managers when users are terminated or transferred; using the information system to monitor account usage; and using automated telephone notification to report atypical system account usage.

SQL DB must be configured to automatically utilize organization-level account management functions, and these functions must immediately enforce the organization's current account policy. 

Automation may comprise differing technologies, that when placed together, contain an overall mechanism supporting an organization's automated account management requirements."
  desc 'check', %q(Determine if Azure SQL Database is configured to use Azure Active Directory authentication only.

Only Azure Active Directory will be used to authenticate to the server. SQL authentication will be disabled, including SQL Server administrators and users. 

In a PowerShell or Cloud Shell interface, run the statement: 

az sql server ad-only-auth get --resource-group myresource --name myserver

OR

Get-AzSqlServerActiveDirectoryOnlyAuthentication  -ServerName myserver -ResourceGroupName myresource

If the returned value in the "AzureADOnlyAuthentication" column is "True", this is not a finding. 

If Mixed mode (both SQL Server authentication and Windows authentication) is in use and the need for mixed mode has not been documented and approved, this is a finding. 

From the documentation, obtain the list of accounts authorized to be managed by Azure SQL Database. 

Determine the accounts (SQL Logins) actually managed by Azure SQL Database. Run the statement: 

SELECT name
FROM sys.database_principals
WHERE type_desc = 'SQL_USER'
AND authentication_type_desc = 'INSTANCE'; 

If any accounts listed by the query are not listed in the documentation, this is a finding.

Risk must be accepted by the ISSO/ISSM.

More information regarding this process is available at: 
https://docs.microsoft.com/en-us/azure/azure-sql/database/authentication-azure-ad-only-authentication)
  desc 'fix', 'If mixed mode is required, document the need and justification; describe the measures taken to ensure the use of Azure SQL Database authentication is kept to a minimum; describe the measures taken to safeguard passwords; list or describe the SQL Logins used; and obtain official approval.

If mixed mode is not required: 
For each account being managed by SQL DB but not requiring it, drop or disable the SQL Database user. Replace it with an appropriately configured account, as needed.

To drop a User in the SSMS Object Explorer: 
Navigate to Databases, choose database, then select Security >> Users. Right-click on the User name and then click "Delete".

To drop a User via a query: 
Change the context to the database_name to be evaluates;
DROP USER <user_name>;

To enable AzureADOnlyAuthentication, in a PowerShell or Cloud Shell interface, run the statement: 
az sql server ad-only-auth enable --resource-group myresource --name myserver

OR

Enable-AzSqlServerActiveDirectoryOnlyAuthentication -ServerName myserver -ResourceGroupName myresource

More information regarding this process is available at: 
https://docs.microsoft.com/en-us/azure/azure-sql/database/authentication-azure-ad-only-authentication'
  impact 0.7
  ref 'DPMS Target MS Azure SQL DB'
  tag check_id: 'C-58974r871027_chk'
  tag severity: 'high'
  tag gid: 'V-255301'
  tag rid: 'SV-255301r879522_rule'
  tag stig_id: 'ASQL-00-000100'
  tag gtitle: 'SRG-APP-000023-DB-000001'
  tag fix_id: 'F-58918r871028_fix'
  tag 'documentable'
  tag cci: ['CCI-000015']
  tag nist: ['AC-2 (1)']
end
