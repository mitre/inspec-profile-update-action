control 'SV-213902' do
  title 'SQL Server must protect against a user falsely repudiating by ensuring only clearly unique Active Directory user accounts can connect to the database.'
  desc "Non-repudiation of actions taken is required in order to maintain data integrity. Examples of particular actions taken by individuals include creating information, sending a message, approving information (e.g., indicating concurrence or signing a contract), and receiving a message. 

Non-repudiation protects against later claims by a user of not having created, modified, or deleted a particular data item or collection of data in the database.

In designing a database, the organization must define the types of data and the user actions that must be protected from repudiation. The implementation must then include building audit features into the application data tables and configuring the DBMS's audit tools to capture the necessary audit trail. Design and implementation also must ensure that applications pass individual user identification to the DBMS, even where the application connects to the DBMS with a standard, shared account.

If the computer account of a remote computer is granted access to a SQL Server database, any service or scheduled task running as NT AUTHORITY\\SYSTEM or NT AUTHORITY\\NETWORK SERVICE can log into the instance and perform actions. These actions cannot be traced back to a specific user or process."
  desc 'check', %q(Execute the following query:

SELECT name
FROM sys.database_principals
WHERE type in ('U','G')
AND name LIKE '%$'

If no users are returned, this is not a finding.

If users are returned, determine whether each user is a computer account.

Launch PowerShell.

Execute the following code:

Note: <name> represents the username portion of the user. For example; if the user is "CONTOSO\user1$", the username is "user1".

([ADSISearcher]"(&(ObjectCategory=Computer)(Name=<name>))").FindAll()

If no account information is returned, this is not a finding.

If account information is returned, this is a finding.)
  desc 'fix', "Remove all users that were returned in the check SQL Statement:

SELECT name
FROM sys.database_principals
WHERE type in ('U','G')
AND name LIKE '%$'

To remove users:

Run the following command for each user:

DROP USER [ IF EXISTS ] <user_name>;"
  impact 0.7
  ref 'DPMS Target MS SQL Server 2016 Database'
  tag check_id: 'C-15120r313138_chk'
  tag severity: 'high'
  tag gid: 'V-213902'
  tag rid: 'SV-213902r508025_rule'
  tag stig_id: 'SQL6-D0-000400'
  tag gtitle: 'SRG-APP-000080-DB-000063'
  tag fix_id: 'F-15118r313139_fix'
  tag 'documentable'
  tag legacy: ['SV-93773', 'V-79067']
  tag cci: ['CCI-000166']
  tag nist: ['AU-10']
end
