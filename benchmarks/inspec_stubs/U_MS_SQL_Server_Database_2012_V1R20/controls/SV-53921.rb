control 'SV-53921' do
  title 'SQL Server must be protected from unauthorized access by developers on shared production/development host systems.'
  desc 'Applications employ the concept of least privilege for specific duties and information systems (including specific functions, ports, protocols, and services). The concept of least privilege is also applied to information system processes, ensuring that the processes operate at privilege levels no higher than necessary to accomplish required organizational missions and/or functions. Organizations consider the creation of additional processes, roles, and information system accounts as necessary to achieve least privilege. Organizations also apply least privilege concepts to the design, development, implementation, and operations of information systems.

Developers granted elevated database and/or operating system privileges on systems that support both development and production databases can affect the operation and/or security of the production database system. Operating system and database privileges assigned to developers on shared development and production systems must be restricted.'
  desc 'check', "Identify whether SQL Server contains both development and production databases from the system documentation.

If SQL Server is not hosting both production and development databases, this is NA.


If SQL Server is hosting both development and production databases, but this is not clearly documented in the system documentation, this is a finding.
Check the list of SQL Server users against the list of developer accounts by running the following SQL Server query:

SELECT name AS 'Account Name'
     , create_date AS 'Account Create Date'
     , LOGINPROPERTY(name, 'PasswordLastSetTime') AS 'Password Last Set on'
  FROM sys.server_principals
 WHERE NOT TYPE IN ('C', 'R', 'U') -- ('C', 'G', 'K', 'R', 'S', 'U')
  AND NOT name IN ('##MS_PolicyEventProcessingLogin##', '##MS_PolicyTsqlExecutionLogin##')
  AND sid <> CONVERT(VARBINARY(85), 0x01) -- no 'sa' account
  AND is_disabled <> 1
 ORDER BY name


If no developer user account is listed, this is not a finding.

Check each developer user account privilege listed above.

Navigate to SQL Server Management Studio >> Object Explorer >> <'SQL Server name'> >> Security >> Logins >> right click <'developer account name'> >> Properties >> User >> Securables.

If any item in the 'Permission' listing, for each highlighted item that exists in the 'Securables' listing, grants production privileges, this is a finding.

Navigate from 'Securables' to 'Server Roles'.

If any 'Server roles' are checked that grant production privileges, this is a finding.

Navigate from 'Server Roles' to 'Users mapped to the login'.

If any checked 'Database role membership' of each highlighted and checked 'Database' are determined to be granting production privileges, this is a finding."
  desc 'fix', "Within the system documentation, clearly identify if SQL Server is hosting both development and production databases.

Restrict developer privileges to production objects to only objects and data where those privileges are required and authorized by running the following scripts as needed:

Remove the user from direct access to server permission by running the following script:
USE master
REVOKE <'server permission name'> TO <'account name'> CASCADE

Remove the user from user-defined role access by running the following script:
USE master
ALTER SERVER ROLE [<'server role name'>] DROP MEMBER <'user name'>

Remove permissions from developer user accounts that grant permissions beyond the development database.

Navigate to SQL Server Management Studio >> Object Explorer >> <'SQL Server name'> >> Security >> Logins >> right click <'administrator account name'> >> Properties >> User >> Securables.

Remove 'Securables' permissions from accounts that are beyond what is required.

Navigate from 'Securables' to 'Server Roles'.

Remove 'Server Roles' permissions from accounts that are beyond what is required.

Navigate from 'Server Roles' to 'Users mapped to the login'.

Remove 'Users mapped to the login' permissions from accounts that are beyond what is required."
  impact 0.5
  ref 'DPMS Target SQL Server Database 2012'
  tag check_id: 'C-47933r2_chk'
  tag severity: 'medium'
  tag gid: 'V-41396'
  tag rid: 'SV-53921r2_rule'
  tag stig_id: 'SQL2-00-009300'
  tag gtitle: 'SRG-APP-000062-DB-000015'
  tag fix_id: 'F-46821r2_fix'
  tag 'documentable'
  tag cci: ['CCI-002220']
  tag nist: ['AC-5 b']
end
