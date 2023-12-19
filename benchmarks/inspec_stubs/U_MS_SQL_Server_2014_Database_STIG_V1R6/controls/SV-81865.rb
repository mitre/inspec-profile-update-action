control 'SV-81865' do
  title 'In a database owned by [sa], or by any other login having administrative privileges at the instance level, the database property TRUSTWORTHY must be OFF.'
  desc "SQL Server's fixed (built-in) server roles, especially [sysadmin], have powerful capabilities that could cause great harm if misused, so their use must be tightly controlled.

The SQL Server instance uses each database's TRUSTWORTHY property to guard against tampering that could enable unwarranted privilege escalation. When TRUSTWORTHY is 0/False/Off, SQL Server prevents the database from accessing resources in other databases. When TRUSTWORTHY is 1/True/On, SQL Server permits access to other databases (subject to other protections). SQL Server sets TRUSTWORTHY OFF when it creates a new database. SQL Server forces TRUSTWORTHY OFF, irrespective of its prior value, when an existing database is attached to it, to address the possibility that an adversary may have tampered with the database, introducing malicious code. To set TRUSTWORTHY ON, an account with the [sysadmin] role must issue an ALTER DATABASE command.

Although SQL Server itself treats this property conservatively, application installer programs may set TRUSTWORTHY ON and leave it on. This provides an opportunity for misuse.

When TRUSTWORTHY is ON, users of the database can take advantage of the database owner's privileges, by impersonating the owner. This can have particularly serious consequences if the database owner is the [sa] login (which may have been renamed in accordance with SQL4-00-010200, and disabled in accordance with SQL4-00-017100, but nonetheless can be invoked in an EXECUTE AS USER = 'dbo' statement, or CREATE PROCEDURE ... WITH EXECUTE AS OWNER ...). The [sa] login cannot be removed from the [sysadmin] role. The user impersonating [sa] - or another [sysadmin] account - is then able to perform administrative actions across all databases under the instance, including making any himself or any other login a member of [sysadmin].

Most of the other fixed server roles could be similarly abused.

Therefore, TRUSTWORTHY must not be used on databases owned by logins that are members of the fixed server roles. Further, if TRUSTWORTHY is to be used for any other database, the need must be documented and approved.

The system database [msdb] is an exception: it is required to be TRUSTWORTHY."
  desc 'check', "Run the SQL statements:
USE <database name>;
GO
WITH FixedServerRoles(RoleName) AS
(
      SELECT 'sysadmin'
      UNION SELECT 'securityadmin'
      UNION SELECT 'serveradmin'
      UNION SELECT 'setupadmin'
      UNION SELECT 'processadmin'
      UNION SELECT 'diskadmin'
      UNION SELECT 'dbcreator'
      UNION SELECT 'bulkadmin'
)
SELECT
      DB_NAME() AS [Database],
      SUSER_SNAME(D.owner_sid) AS [Database Owner],
      F.RoleName AS [Fixed Server Role],
      CASE WHEN D.is_trustworthy_on = 1 THEN 'ON' ELSE 'off' END
            AS [Trustworthy]      
FROM
      FixedServerRoles F
      INNER JOIN sys.databases D ON D.Name = DB_NAME()
WHERE
      IS_SRVROLEMEMBER(F.RoleName, SUSER_SNAME(D.owner_sid)) = 1
AND   DB_NAME() <> 'msdb'
AND   D.is_trustworthy_on = 1;
GO

If the query returns any rows, this is a finding."
  desc 'fix', "Set the TRUSTWORTHY property OFF; or remove the database owner from the fixed server role(s); or change the database owner.

To set the TRUSTWORTHY property OFF:
USE [master];
GO
ALTER DATABASE <name> SET TRUSTWORTHY OFF;
GO
Verify that this produced the intended result by re-running the query specified in the Check.

To determine the path or paths by which the database owner is assigned the fixed server role or roles, run this query:

USE <database name>;
GO
WITH C AS
(
SELECT
      P.name      AS [Parent Server Role],
      CAST('Fixed' AS varchar(8))
                  AS [Server Role Type],
      M.name      AS [Member],
      M.type_desc AS [Member Type],
      P.name      AS [Root],
      1           AS [Level]
FROM
      [sys].[server_role_members] X
      INNER JOIN [sys].[server_principals] P ON P.principal_id = X.role_principal_id
      INNER JOIN [sys].[server_principals] M ON M.principal_id = X.member_principal_id
WHERE
      P.is_fixed_role = 1
UNION ALL
SELECT
      P.name        AS [Parent Server Role],
      CASE WHEN M.is_fixed_role = 1 THEN CAST('Fixed' AS varchar(8)) ELSE CAST('Custom' AS varchar(8)) END
                    AS [Server Role Type],
      M.name        AS [Member],
      M.type_desc   AS [Member Type],
      C.[Root]      AS [Root],
      C.[Level] + 1 AS [Level]
FROM
      [sys].[server_role_members] X
      INNER JOIN [sys].[server_principals] P ON P.principal_id = X.role_principal_id
      INNER JOIN [sys].[server_principals] M ON M.principal_id = X.member_principal_id
      INNER JOIN C ON P.name = C.Member
)
,
B AS
(
SELECT
      C.[Member] AS [Leaf],
      C.[Root],
      C.[Parent Server Role],
      C.[Server Role Type],
      C.[Member],
      C.[Member Type],
      C.[Level]
FROM C
WHERE
      C.[Member Type] NOT LIKE '%ROLE%'
UNION ALL
SELECT
      B.[Leaf],
      C.[Root],
      C.[Parent Server Role],
      C.[Server Role Type],
      C.[Member],
      C.[Member Type],
      C.[Level]
FROM C
INNER JOIN B
      ON       C.[Member] = B.[Parent Server Role]
      AND       C.[Level] = B.[Level] - 1
      AND       C.[Root] = B.[Root]
)
SELECT
      DB_NAME() AS [Database],
      B.[Leaf]  AS [Owner Login],
      B.[Root]  AS[Top-Level Server Role],
      B.[Parent Server Role],
      B.[Server Role Type],
      B.[Member],
      B.[Member Type],
      B.[Level]
FROM B
WHERE B.[Leaf] = (SELECT SUSER_SNAME(D.owner_sid) FROM sys.databases D WHERE D.Name = DB_NAME())
ORDER BY B.[Root], B.[Level], B.[Parent Server Role], B.[Member]
;
GO

To remove the database owner from a fixed server role or a custom server role:
USE [master];
GO
ALTER SERVER ROLE <fixed/custom server role name>
      DROP MEMBER <database owner name>;
GO
Verify that this produced the intended result by re-running the Check query.

To change the database owner:
USE [master];
GO
ALTER AUTHORIZATION ON DATABASE::<DB name> TO <new owner name>;
GO
Verify that this produced the intended result by re-running the Check query."
  impact 0.5
  ref 'DPMS Target SQL Server Database 2014'
  tag check_id: 'C-67953r1_chk'
  tag severity: 'medium'
  tag gid: 'V-67375'
  tag rid: 'SV-81865r1_rule'
  tag stig_id: 'SQL4-00-015610'
  tag gtitle: 'SRG-APP-000133-DB-000200'
  tag fix_id: 'F-73487r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
