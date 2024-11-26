control 'SV-213934' do
  title 'SQL Server must protect against a user falsely repudiating by ensuring the NT AUTHORITY SYSTEM account is not used for administration.'
  desc "Non-repudiation of actions taken is required in order to maintain data integrity. Examples of particular actions taken by individuals include creating information, sending a message, approving information (e.g., indicating concurrence or signing a contract), and receiving a message.  
 
Non-repudiation protects against later claims by a user of not having created, modified, or deleted a particular data item or collection of data in the database. 
 
In designing a database, the organization must define the types of data and the user actions that must be protected from repudiation. The implementation must then include building audit features into the application data tables and configuring the DBMS's audit tools to capture the necessary audit trail. Design and implementation also must ensure that applications pass individual user identification to the DBMS, even where the application connects to the DBMS with a standard, shared account. 
 
Any user with enough access to the server can execute a task that will be run as NT AUTHORITY\\SYSTEM either using task scheduler or other tools. At this point, NT AUTHORITY\\SYSTEM essentially becomes a shared account because the operating system and SQL Server are unable to determine who created the process. 
 
Prior to SQL Server 2012, NT AUTHORITY\\SYSTEM was a member of the sysadmin role by default. This allowed jobs/tasks to be executed in SQL Server without the approval or knowledge of the DBA because it looked like operating system activity."
  desc 'check', %q(Execute the following queries. The first query checks for Clustering and Availability Groups being provisioned in the Database Engine. The second query lists permissions granted to the Local System account.

SELECT
    SERVERPROPERTY('IsClustered') AS [IsClustered],
    SERVERPROPERTY('IsHadrEnabled') AS [IsHadrEnabled]

EXECUTE AS LOGIN = 'NT AUTHORITY\SYSTEM'

SELECT * FROM fn_my_permissions(NULL, 'server')

REVERT

GO

 
If IsClustered returns 1, IsHadrEnabled returns 0, and any permissions have been granted to the Local System account beyond "CONNECT SQL", "VIEW SERVER STATE", and "VIEW ANY DATABASE", this is a finding.
 
If IsHadrEnabled returns 1 and any permissions have been granted to the Local System account beyond "CONNECT SQL", "CREATE AVAILABILITY GROUP", "ALTER ANY AVAILABILITY GROUP", "VIEW SERVER STATE", and "VIEW ANY DATABASE", this is a finding.
 
If both IsClustered and IsHadrEnabled return 0 and any permissions have been granted to the Local System account beyond "CONNECT SQL" and "VIEW ANY DATABASE", this is a finding.)
  desc 'fix', 'Remove permissions that were identified as not allowed in the check content.

USE Master;

REVOKE <Permission> TO [NT AUTHORITY\\SYSTEM]

GO


To grant permissions to services or applications, utilize the Service SID of the service or a domain service account.'
  impact 0.7
  ref 'DPMS Target MS SQL Server 2016 Instance'
  tag check_id: 'C-15151r313585_chk'
  tag severity: 'high'
  tag gid: 'V-213934'
  tag rid: 'SV-213934r617437_rule'
  tag stig_id: 'SQL6-D0-004100'
  tag gtitle: 'SRG-APP-000080-DB-000063'
  tag fix_id: 'F-15149r313586_fix'
  tag 'documentable'
  tag legacy: ['SV-93835', 'V-79129']
  tag cci: ['CCI-000166']
  tag nist: ['AU-10']
end
