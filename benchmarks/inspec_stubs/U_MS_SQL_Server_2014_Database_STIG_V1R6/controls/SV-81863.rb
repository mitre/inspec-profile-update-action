control 'SV-81863' do
  title 'In a database owned by a login not having administrative privileges at the instance level, the database property TRUSTWORTHY must be OFF unless required and authorized.'
  desc "SQL Server's fixed (built-in) server roles, especially [sysadmin], have powerful capabilities that could cause great harm if misused, so their use must be tightly controlled.

The SQL Server instance uses each database's TRUSTWORTHY property to guard against tampering that could enable unwarranted privilege escalation. When TRUSTWORTHY is 0/False/Off, SQL Server prevents the database from accessing resources in other databases. When TRUSTWORTHY is 1/True/On, SQL Server permits access to other databases (subject to other protections). SQL Server sets TRUSTWORTHY OFF when it creates a new database. SQL Server forces TRUSTWORTHY OFF, irrespective of its prior value, when an existing database is attached to it, to address the possibility that an adversary may have tampered with the database, introducing malicious code. To set TRUSTWORTHY ON, an account with the [sysadmin] role must issue an ALTER DATABASE command.

Although SQL Server itself treats this property conservatively, application installer programs may set TRUSTWORTHY ON and leave it on. This provides an opportunity for misuse.

When TRUSTWORTHY is ON, users of the database can take advantage of the database owner's privileges, by impersonating the owner. This can have particularly serious consequences if the database owner is the [sa] login (which may have been renamed in accordance with SQL4-00-010200, and disabled in accordance with SQL4-00-017100, but nonetheless can be invoked in an EXECUTE AS USER = 'dbo' statement, or CREATE PROCEDURE ... WITH EXECUTE AS OWNER ...). The [sa] login cannot be removed from the [sysadmin] role. The user impersonating [sa] - or another [sysadmin] account - is then able to perform administrative actions across all databases under the instance, including making any himself or any other login a member of [sysadmin].

Most of the other fixed server roles could be similarly abused.

Therefore, TRUSTWORTHY must not be used on databases owned by logins that are members of the fixed server roles. Further, if TRUSTWORTHY is to be used for any other database, the need must be documented and approved.

The system database [msdb] is an exception: it is required to be TRUSTWORTHY."
  desc 'check', "If the database is owned by an account that is directly or indirectly a member of a fixed (built-in) server role, this is not applicable (NA).

Run the query:
USE <database name>;
GO
SELECT
DB_NAME() AS [Database],
SUSER_SNAME(D.owner_sid) AS [Database Owner],
CASE WHEN D.is_trustworthy_on = 1 THEN 'ON' ELSE 'off' END
AS [Trustworthy]
FROM
sys.databases D
WHERE
D.[name] = DB_NAME()
AND DB_NAME() <> 'msdb'
AND D.is_trustworthy_on = 1;
GO
If the query returns a row indicating that the TRUSTWORTHY setting is OFF, or returns no rows, this is not a finding.

Review the system security plan to determine whether the need for TRUSTWORTHY is documented and approved. If not, this is a finding."
  desc 'fix', 'Run the SQL statements:
USE [master];
GO
ALTER DATABASE <name> SET TRUSTWORTHY OFF;
GO'
  impact 0.5
  ref 'DPMS Target SQL Server Database 2014'
  tag check_id: 'C-67951r1_chk'
  tag severity: 'medium'
  tag gid: 'V-67373'
  tag rid: 'SV-81863r1_rule'
  tag stig_id: 'SQL4-00-015620'
  tag gtitle: 'SRG-APP-000133-DB-000200'
  tag fix_id: 'F-73485r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
