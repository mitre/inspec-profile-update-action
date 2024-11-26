control 'SV-53422' do
  title 'SQL Server processes or services must run under custom, dedicated OS or domain accounts.'
  desc 'Separation of duties is a prevalent Information Technology control that is implemented at different layers of the information system, including the operating system and in applications. It serves to eliminate or reduce the possibility that a single user may carry out a prohibited action. Separation of duties requires that the person accountable for approving an action is not the same person who is tasked with implementing or carrying out that action. 

The concept of separation of duties extends to processes.  The DBMS must run under a custom, dedicated OS or domain account.  When the DBMS is running under a shared account, users with access to that account could inadvertently or maliciously make changes to the DBMS’s settings, files, or permissions.  Similarly, related services must run under dedicated accounts where this is possible.  The SQL Server Browser and Writer services are exceptions: see http://msdn.microsoft.com/en-us/library/hh510203(v=sql.110).aspx  and  http://msdn.microsoft.com/en-us/library/ms175536(v=sql.110).aspx.'
  desc 'check', 'Check OS settings to determine whether SQL Server processes are running under a dedicated OS or domain account. If the SQL Server processes are running under shared accounts, this is a finding.

From a Command Prompt, type services.msc, and press [ENTER]. Scroll down to the SQL Server Services. SQL Server Services begin with SQL.  The following services, when present, should be listed as follows:

Service Name:					Log On As:
SQL Full-text Filter Daemon Launcher:		NT Service\\UNIQUE CUSTOM ACCOUNT
SQL Server [stand-alone]:			NT Service\\UNIQUE CUSTOM ACCOUNT
SQL Server [cluster]:				<domain>\\<CustomServiceAccount>
SQL Server Agent:				NT Service\\UNIQUE CUSTOM ACCOUNT
SQL Server Analysis Services:			NT Service\\UNIQUE CUSTOM ACCOUNT
SQL Server Browser:				Local Service
SQL Server Distributed Replay Client:		NT Service\\UNIQUE CUSTOM ACCOUNT
SQL Server Distributed Replay Controller:	NT Service\\UNIQUE CUSTOM ACCOUNT
SQL Server Integration Services 11.0:		NT Service\\UNIQUE CUSTOM ACCOUNT
SQL Server Reporting Services:			NT Service\\UNIQUE CUSTOM ACCOUNT
SQL Server VSS Writer:				Local System

UNIQUE CUSTOM ACCOUNT refers to an account with which no other service listed in the services.msc window is assigned. If any account requiring a unique custom account uses an account that any other service utilizes (regardless of service status), this is a finding.'
  desc 'fix', 'Configure the SQL Server services to use a custom, dedicated OS or domain account.'
  impact 0.5
  ref 'DPMS Target SQL Server Installation 2012'
  tag check_id: 'C-47664r7_chk'
  tag severity: 'medium'
  tag gid: 'V-41047'
  tag rid: 'SV-53422r4_rule'
  tag stig_id: 'SQL2-00-008900'
  tag gtitle: 'SRG-APP-000062-DB-000010'
  tag fix_id: 'F-46346r2_fix'
  tag cci: ['CCI-000366', 'CCI-002220']
  tag nist: ['CM-6 b', 'AC-5 b']
end
