control 'SV-53951' do
  title 'SQL Server must protect against or limit the effects of the organization-defined types of Denial of Service (DoS) attacks.'
  desc 'Application management includes the ability to control the number of users and user sessions utilizing an application. Limiting the number of allowed users, and sessions per user, is helpful in limiting risks related to DoS attacks.

This requirement addresses concurrent session control for a single information system account and does not address concurrent sessions by a single user via multiple system accounts.

This requirement may be met via the application or by utilizing information system session control provided by a web server with specialized session management capabilities. If it has been specified that this requirement will be handled by the application, the capability to limit the maximum number of concurrent single user sessions must be designed and built into the application.

The organization will need to define the maximum number of concurrent sessions for SQL Server accounts by account type, by account, or a combination thereof and SQL Server shall enforce this requirement.

Unlimited concurrent connections to SQL Server could allow a successful DoS attack by exhausting connection resources.'
  desc 'check', "Check SQL Server settings for the number of concurrent Check SQL Server settings for the number of concurrent sessions by running the following script:

USE MASTER
GO

EXEC sys.sp_configure N'show advanced options', N'1'  RECONFIGURE WITH OVERRIDE
GO
EXEC sys.sp_configure N'user connections'
EXEC sys.sp_configure N'show advanced options', N'0'  RECONFIGURE WITH OVERRIDE
GO

If SQL Server settings for concurrent sessions is not lower than or equal to the organization-defined maximum number of sessions, this is a finding."
  desc 'fix', "Configure SQL Server number of concurrent sessions to the organization-defined maximum number of sessions by running the following script:

USE MASTER
GO

EXEC sys.sp_configure N'show advanced options', N'1'  RECONFIGURE WITH OVERRIDE
GO
EXEC sys.sp_configure N'user connections', <'maximum number of SQL Server concurrent connections'>
EXEC sys.sp_configure N'show advanced options', N'0'  RECONFIGURE WITH OVERRIDE
GO"
  impact 0.5
  ref 'DPMS Target SQL Server Database 2012'
  tag check_id: 'C-47957r2_chk'
  tag severity: 'medium'
  tag gid: 'V-41422'
  tag rid: 'SV-53951r2_rule'
  tag stig_id: 'SQL2-00-022000'
  tag gtitle: 'SRG-APP-000245-DB-000132'
  tag fix_id: 'F-46851r2_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
