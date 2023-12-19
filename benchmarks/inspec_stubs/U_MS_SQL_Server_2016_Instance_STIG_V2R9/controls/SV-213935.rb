control 'SV-213935' do
  title 'SQL Server must protect against a user falsely repudiating by ensuring only clearly unique Active Directory user accounts can connect to the instance.'
  desc "Non-repudiation of actions taken is required in order to maintain data integrity. Examples of particular actions taken by individuals include creating information, sending a message, approving information (e.g., indicating concurrence or signing a contract), and receiving a message.  
 
Non-repudiation protects against later claims by a user of not having created, modified, or deleted a particular data item or collection of data in the database. 
 
In designing a database, the organization must define the types of data and the user actions that must be protected from repudiation. The implementation must then include building audit features into the application data tables and configuring the DBMS's audit tools to capture the necessary audit trail. Design and implementation also must ensure that applications pass individual user identification to the DBMS, even where the application connects to the DBMS with a standard, shared account. 
 
If the computer account of a remote computer is granted access to SQL Server, any service or scheduled task running as NT AUTHORITY\\SYSTEM or NT AUTHORITY\\NETWORK SERVICE can log into the instance and perform actions. These actions cannot be traced back to a specific user or process."
  desc 'check', %q(Execute the following query:

SELECT name
FROM sys.server_principals
WHERE type in ('U','G')
AND name LIKE '%$'

If no logins are returned, this is not a finding.

If logins are returned, determine whether each login is a computer account.

Launch PowerShell.

Execute the following code:

Note: <name> represents the username portion of the login. For example, if the login is "CONTOSO\user1$", the username is "user1".

([ADSISearcher]"(&(ObjectCategory=Computer)(Name=<name>))").FindAll()

If no account information is returned, this is not a finding.

If account information is returned, this is a finding.)
  desc 'fix', 'Remove all logins that were returned in the check content.'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2016 Instance'
  tag check_id: 'C-15152r313588_chk'
  tag severity: 'medium'
  tag gid: 'V-213935'
  tag rid: 'SV-213935r879554_rule'
  tag stig_id: 'SQL6-D0-004200'
  tag gtitle: 'SRG-APP-000080-DB-000063'
  tag fix_id: 'F-15150r313589_fix'
  tag 'documentable'
  tag legacy: ['SV-93837', 'V-79131']
  tag cci: ['CCI-000166']
  tag nist: ['AU-10']
end
