control 'SV-82249' do
  title 'SQL Server authentication and identity management must be integrated with an organization-level authentication/access mechanism providing account management and automation for all users, groups, roles, and any other principals.'
  desc "Enterprise environments make account management for applications and databases challenging and complex. A manual process for account management functions adds the risk of a potential oversight or other error. Managing accounts for the same person in multiple places is inefficient and prone to problems with consistency and synchronization.

A comprehensive application account management process that includes automation helps to ensure that accounts designated as requiring attention are consistently and promptly addressed. 

Examples include, but are not limited to, using automation to take action on multiple accounts designated as inactive, suspended, or terminated, or by disabling accounts located in non-centralized account stores, such as multiple servers. Account management functions can also include: assignment of group or role membership; identifying account type; specifying user access authorizations (i.e., privileges); account removal, update, or termination; and administrative alerts. The use of automated mechanisms can include, for example: using email or text messaging to notify account managers when users are terminated or transferred; using the information system to monitor account usage; and using automated telephone notification to report atypical system account usage.

Account management and authentication in a Windows environment normally use an LDAP-compatible directory service, usually Windows Active Directory.  This in turn, in the DoD environment, is typically integrated with the Public Key Infrastructure (PKI).  Additional technologies or products may be employed that when placed together constitute an overall mechanism supporting an organization's automated account management requirements.  An example is the use of Group Policy Objects to enforce rules concerning passwords.

SQL Server must be configured to use Windows authentication, with SQL Server authentication disabled.  If circumstances (such as the architecture of a purchased application) make it necessary to have SQL Server authentication available, its use must be kept to a minimum.  The reasons for its use, and the measures taken to restrict it to only the necessary cases, must be documented, with AO approval.

It is assumed throughout this STIG that this integration has been implemented."
  desc 'check', %q(Determine whether SQL Server is configured to use only Windows authentication.

In the Object Explorer in SQL Server Management Studio (SSMS), right-click on the server instance; select Properties.  Select the Security page.

If Windows Authentication Mode is selected, this is not a finding.

Alternatively, in a query interface such as the SSMS Transact-SQL editor, run the statement:
EXECUTE xp_instance_regread 
    N'HKEY_LOCAL_MACHINE',
    N'Software\Microsoft\MSSQLServer\MSSQLServer', 
    N'LoginMode'; 

If the returned value in the "Data" column is 1, this is not a finding.

Mixed mode (both SQL Server authentication and Windows authentication) is in use.

If the need for mixed mode has not been documented and approved, this is a finding.

From the documentation, obtain the list of accounts authorized to be managed by SQL Server.

Determine the accounts (SQL Logins) actually managed by SQL Server.  Run the statement:
SELECT
    name
FROM 
    sys.sql_logins 
WHERE
    type_desc = 'SQL_LOGIN'
    AND is_disabled = 0;

If any accounts listed by the query are not listed in the documentation, this is a finding.)
  desc 'fix', %q(If mixed mode is required, document the need and justification; describe the measures taken to ensure the use of SQL Server authentication is kept to a minimum; describe the measures taken to safeguard passwords; list or describe the SQL Logins used; obtain official approval.

If mixed mode is not required, disable it as follows:

In the SSMS Object Explorer, right-click on the server instance; select Properties.  Select the Security page.  Click on the radio button for Windows Authentication Mode.  Click on "OK."  Restart the SQL Server instance.

Alternatively, run the statement:
EXEC xp_instance_regwrite
    N'HKEY_LOCAL_MACHINE',
    N'Software\Microsoft\MSSQLServer\MSSQLServer',
    N'LoginMode', 
    REG_DWORD, 
    1;
Restart the SQL Server instance.

For each account being managed by SQL Server but not requiring it, drop or disable the SQL Login.  Replace it with an appropriately configured account, as needed.

To drop or disable a Login in the SSMS Object Explorer:
Navigate to <server name> >> Security >> Logins.
Right-click on the Login name; click on Delete or Disable.

To drop or disable a Login by using a query:
USE master;
DROP LOGIN <login name>; 
ALTER LOGIN <login name> DISABLE;

Dropping a Login does not delete the equivalent database User(s).  There may be more than one database containing a User mapped to the Login.  Drop the User(s) unless still needed..

To drop a User in the SSMS Object Explorer:
Navigate to <server name> >> Databases >> <database name> >> Security >> Users.
Right-click on the User name; click on Delete.

To drop a User via a query:
USE <database name>;
DROP USER <user name>;)
  impact 0.5
  ref 'DPMS Target SQL Server Installation 2014'
  tag check_id: 'C-68325r1_chk'
  tag severity: 'medium'
  tag gid: 'V-67759'
  tag rid: 'SV-82249r1_rule'
  tag stig_id: 'SQL4-00-030300'
  tag gtitle: 'SRG-APP-000023-DB-000001'
  tag fix_id: 'F-73873r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000015']
  tag nist: ['AC-2 (1)']
end
